import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, cmifReply: cmifReply, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read8: read8, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("FS gates probe: " + message);
};

const u32 = a => Number(read32(a)) >>> 0;

const USED_WINDOWS = [ [ 2412800, 1024 ], [ 2414592, 256 ] ];

const DATA_GLOBALS = [ 18748112, 18803040 ];

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    const walk = globalThis.civHomeFsWalk;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (need ro-service-lookup, fs-pid)");
    check(walk?.code?.length, "run zz-home-fs-walk.mjs first");
    const candidates = walk.code.filter(c => c.type === 3 && parseInt(c.perm, 16) & 4 && BigInt("0x" + c.size) >= 0x24e000n);
    check(candidates.length === 1, "text candidate not unique");
    const base = BigInt("0x" + candidates[0].base);
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const tracking = beginAllocationTracking();
    check(tracking, "allocation tracker busy");
    let pending = false;
    const packet = allocPage(8192);
    const output = allocPage(4096);
    const dispatch = () => {
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        } ]);
        const worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "IPC worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civHomePendingGates = {
                worker: worker,
                frame: frame,
                packet: packet,
                output: output,
                tracking: tracking
            };
            pending = true;
            throw new Error("request timed out; buffers retained");
        }
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        closeRawThread(worker.handle);
        check(transport === 0, "transport=0x" + transport.toString(16));
    };
    const query = address => {
        for (let i = 0; i < 32; i++) write32(packet + BigInt(i * 4), 0n);
        write32(packet, 4n);
        write32(packet + 4n, (16 | 2147483648) >>> 0);
        write32(packet + 8n, 2n);
        write32(packet + 12n, BigInt(process.handle));
        write32(packet + 16n, 0x49434653n);
        write32(packet + 24n, 0x524f0010n);
        write64(packet + 32n, BigInt(pid));
        write64(packet + 40n, BigInt(address));
        write64(packet + 48n, 0n);
        write64(packet + 56n, 0n);
        dispatch();
        const reply = cmifReply(packet);
        check(u32(packet + BigInt(reply.at)) === 1329808979, "missing SFCO");
        const d = packet + BigInt(reply.data);
        return {
            result: reply.result,
            pid: read64(d),
            program: read64(d + 8n),
            base: read64(d + 16n),
            size: read64(d + 24n),
            type: u32(d + 32n),
            attr: u32(d + 36n),
            perm: u32(d + 40n)
        };
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
        write64(packet + 56n, BigInt(source));
        write64(packet + 64n, BigInt(size));
        write64(packet + 72n, 0n);
        dispatch();
        const reply = cmifReply(packet);
        check(reply.result === 0, "bulk read failed at 0x" + source.toString(16) + ": 0x" + reply.result.toString(16));
    };
    try {
        for (const [offset, size] of USED_WINDOWS) {
            bulkRead(base + BigInt(offset), size);
            const nonzero = [];
            for (let i = 0; i < size; i++) if (Number(read8(output + BigInt(i))) !== 0) nonzero.push(i);
            await log("GATE-A used window +0x" + offset.toString(16) + " (" + size + " bytes): nonzero=" + nonzero.length + (nonzero.length ? " at " + nonzero.slice(0, 16).map(o => "0x" + o.toString(16)).join(",") : ""));
            check(nonzero.length === 0, "used window +0x" + offset.toString(16) + " is NOT zero");
        }
        for (const offset of DATA_GLOBALS) {
            const address = base + BigInt(offset);
            const q = query(address);
            check(q.result === 0, "query failed at 0x" + address.toString(16) + ": 0x" + q.result.toString(16));
            const end = address + 16n;
            const mapEnd = q.base + q.size;
            const inside = q.size > 0n && address >= q.base && end <= mapEnd;
            const writable = (q.perm & 3) === 3 && q.attr === 0;
            await log("GATE-B global +0x" + offset.toString(16) + " @0x" + address.toString(16) + " -> map base=0x" + q.base.toString(16) + " size=0x" + q.size.toString(16) + " type=" + q.type + " attr=" + q.attr + " perm=" + q.perm + " span-inside=" + inside + " writable-attr0=" + writable);
            check(inside && writable, "data global +0x" + offset.toString(16) + " not in a writable attribute-zero mapping");
        }
        globalThis.civHomeGatesPass = Object.freeze({
            base: base.toString(),
            at: Date.now()
        });
        await log("FS GATES PASS: used windows zero; both data globals " + "in writable attribute-zero mappings (base=0x" + base.toString(16) + ")");
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
