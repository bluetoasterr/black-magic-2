import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, cmifReply: cmifReply, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read8: read8, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write8: write8, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("trace-restore: " + message);
};

const u32 = a => Number(read32(a)) >>> 0;

const TEXT_SIZE = 0x24e000n;

const ENTRY_OFF = 0xedb64n;

const CAVE_OFF = 0x24d100n;

const ENTRY_ORIG = [ 255, 195, 0, 209 ];

const ENTRY_PATCH = [ 103, 125, 5, 20 ];

const CAVE_ORIG = [ 0, 0, 0, 0, 0, 0, 0, 0 ];

const CAVE_STUB = [ 255, 195, 0, 209, 153, 130, 250, 23 ];

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    const walk = globalThis.civHomeFsWalk;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (need ro-service-lookup, fs-pid)");
    check(!globalThis.civHomePatchHalt, "patch traffic is halted in this session: " + JSON.stringify(globalThis.civHomePatchHalt));
    check(walk?.code?.length, "run zz-home-fs-walk.mjs first");
    const candidates = walk.code.filter(c => c.type === 3 && parseInt(c.perm, 16) & 4 && BigInt("0x" + c.size) >= TEXT_SIZE);
    check(candidates.length === 1, "text candidate not unique");
    const base = BigInt("0x" + candidates[0].base);
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const tracking = beginAllocationTracking();
    check(tracking, "allocation tracker busy");
    let pending = false;
    const packet = allocPage(8192);
    const output = allocPage(4096);
    const expected = allocPage(4096);
    const replacement = allocPage(4096);
    const dispatch = () => {
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        } ]);
        const worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "IPC worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civHomePatchHalt = Object.freeze({
                reason: "ipc-timeout"
            });
            globalThis.civHomePendingTrace = {
                worker: worker,
                frame: frame,
                packet: packet,
                output: output,
                expected: expected,
                replacement: replacement,
                tracking: tracking
            };
            pending = true;
            throw new Error("IPC timed out; PATCH TRAFFIC HALTED");
        }
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        closeRawThread(worker.handle);
        check(transport === 0, "transport=0x" + transport.toString(16));
    };
    const bulkRead = (source, size) => {
        for (let i = 0; i < 32; i++) write32(packet + BigInt(i * 4), 0n);
        write32(packet, (4 | 1 << 24) >>> 0);
        write32(packet + 4n, (14 | 2147483648) >>> 0);
        write32(packet + 8n, 2n);
        write32(packet + 12n, BigInt(process.handle));
        write32(packet + 16n, BigInt(size));
        write32(packet + 20n, output & 0xffffffffn);
        write32(packet + 24n, 1n | (output >> 36n & 7n) << 2n | (output >> 32n & 15n) << 28n);
        write32(packet + 32n, 0x49434653n);
        write32(packet + 40n, 0x524f0016n);
        write64(packet + 48n, BigInt(pid));
        write64(packet + 56n, source);
        write64(packet + 64n, BigInt(size));
        write64(packet + 72n, 0n);
        dispatch();
        const reply = cmifReply(packet);
        check(reply.result === 0, "read failed at 0x" + source.toString(16) + ": 0x" + reply.result.toString(16));
        const bytes = [];
        for (let i = 0; i < size; i++) bytes.push(Number(read8(output + BigInt(i))));
        return bytes;
    };
    const desc = (at, buffer, size) => {
        write32(at, BigInt(size));
        write32(at + 4n, buffer & 0xffffffffn);
        write32(at + 8n, 1n | (buffer >> 36n & 7n) << 2n | (buffer >> 32n & 15n) << 28n);
    };
    const fill = (buffer, bytes) => {
        for (let i = 0; i < bytes.length; i++) write8(buffer + BigInt(i), BigInt(bytes[i]));
    };
    const hex = bytes => bytes.map(b => b.toString(16).padStart(2, "0")).join("");
    const patch = (address, expectedBytes, replacementBytes) => {
        check(!globalThis.civHomePatchHalt, "patch traffic halted after a timeout; outcome unknown");
        fill(expected, expectedBytes);
        fill(replacement, replacementBytes);
        const size = expectedBytes.length;
        for (let i = 0; i < 40; i++) write32(packet + BigInt(i * 4), 0n);
        write32(packet, (4 | 2 << 20) >>> 0);
        write32(packet + 4n, (14 | 2147483648) >>> 0);
        write32(packet + 8n, 2n);
        write32(packet + 12n, BigInt(process.handle));
        desc(packet + 16n, expected, size);
        desc(packet + 28n, replacement, size);
        write32(packet + 48n, 0x49434653n);
        write32(packet + 56n, 0x524f0018n);
        write64(packet + 64n, BigInt(pid));
        write64(packet + 72n, address);
        write64(packet + 80n, BigInt(size));
        write64(packet + 88n, 0n);
        dispatch();
        const reply = cmifReply(packet);
        check(u32(packet + BigInt(reply.at)) === 1329808979, "missing SFCO");
        const d = packet + BigInt(reply.data);
        const journal = {
            address: "0x" + read64(d + 8n).toString(16),
            size: Number(read64(d + 16n)),
            permissionBefore: u32(d + 24n),
            rollback: u32(d + 28n),
            original: hex(Array.from({
                length: size
            }, (_, i) => Number(read8(d + 32n + BigInt(i)))))
        };
        if (reply.result !== 0) {
            check(journal.rollback !== 2, "PATCH FAILED AT " + journal.address + " AND ROLLBACK FAILED; recover on host " + "from journal: " + JSON.stringify(journal));
            check(false, "patch at " + journal.address + " rc=0x" + reply.result.toString(16) + " rollback=" + journal.rollback + " journal=" + JSON.stringify(journal));
        }
        return journal;
    };
    try {
        const entryNow = hex(bulkRead(base + ENTRY_OFF, 4));
        const caveNow = hex(bulkRead(base + CAVE_OFF, 8));
        const entryPatched = entryNow === hex(ENTRY_PATCH);
        const entryOriginal = entryNow === hex(ENTRY_ORIG);
        const cavePatched = caveNow === hex(CAVE_STUB);
        const caveOriginal = caveNow === hex(CAVE_ORIG);
        check(entryPatched || entryOriginal, "entry bytes are neither the patch nor the original: " + entryNow + "; STOP and use the host journal");
        check(cavePatched || caveOriginal, "cave bytes are neither the stub nor zeros: " + caveNow + "; STOP and use the host journal");
        if (entryPatched) check(cavePatched, "entry is patched but the cave does not " + "hold the stub; refusing to touch anything; host journal");
        if (!entryPatched && !cavePatched) {
            await log("TRACE SMOKE already fully original; nothing to do");
            return;
        }
        if (entryPatched) {
            const j1 = patch(base + ENTRY_OFF, ENTRY_PATCH, ENTRY_ORIG);
            await log("entry restored, journal=" + JSON.stringify(j1));
            check(hex(bulkRead(base + ENTRY_OFF, 4)) === hex(ENTRY_ORIG), "entry restore verify failed; cave LEFT INTACT with the " + "stub so the branch keeps a valid target");
        }
        if (cavePatched) {
            const j2 = patch(base + CAVE_OFF, CAVE_STUB, CAVE_ORIG);
            await log("cave restored, journal=" + JSON.stringify(j2));
            check(hex(bulkRead(base + CAVE_OFF, 8)) === hex(CAVE_ORIG), "cave restore verify failed");
        }
        globalThis.civHomeTrace = Object.freeze({
            installed: false
        });
        await log("TRACE SMOKE RESTORED and verified: original bytes back " + "at +0xedb64 and +0x24d100");
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
