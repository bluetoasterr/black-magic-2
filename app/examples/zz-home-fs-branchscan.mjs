import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, cmifReply: cmifReply, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("FS branch scan: " + message);
};

const u32 = a => Number(read32(a)) >>> 0;

const TARGET = 0xedb64n;

const TEXT_SIZE = 0x24e000n;

const CHUNK = 16384;

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    const walk = globalThis.civHomeFsWalk;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (need ro-service-lookup, fs-pid)");
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
    const output = allocPage(32768);
    try {
        const hits = [];
        for (let off = 0n; off < TEXT_SIZE; off += BigInt(CHUNK)) {
            const size = Number(TEXT_SIZE - off < BigInt(CHUNK) ? TEXT_SIZE - off : BigInt(CHUNK));
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
            write64(packet + 56n, base + off);
            write64(packet + 64n, BigInt(size));
            write64(packet + 72n, 0n);
            const frame = buildRawFrame([ {
                fn: IPC_SEND_DISPATCHER,
                args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
            } ]);
            const worker = launchRawWorker(frame.frame, schedule);
            check(worker?.handle && worker.rc === 0 && worker.started, "IPC worker did not start");
            if (waitRawThread(worker.handle, 2000000000n) !== 0) {
                globalThis.civHomePendingScan = {
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
            check(reply.result === 0, "read failed at +0x" + off.toString(16) + ": 0x" + reply.result.toString(16));
            for (let i = 0; i + 4 <= size; i += 4) {
                const w = u32(output + BigInt(i));
                const pc = off + BigInt(i);
                let target = null;
                if ((w & 4227858432) === 335544320 || (w & 4227858432) === 2483027968) {
                    let imm = BigInt(w & 67108863);
                    if (imm & 0x2000000n) imm -= 0x4000000n;
                    target = pc + imm * 4n;
                } else if ((w & 4278190096) === 1409286144) {
                    let imm = BigInt(w >> 5 & 524287);
                    if (imm & 0x40000n) imm -= 0x80000n;
                    target = pc + imm * 4n;
                } else if ((w & 2113929216) === 872415232) {
                    let imm = BigInt(w >> 5 & 524287);
                    if (imm & 0x40000n) imm -= 0x80000n;
                    target = pc + imm * 4n;
                } else if ((w & 2113929216) === 905969664) {
                    let imm = BigInt(w >> 5 & 16383);
                    if (imm & 0x2000n) imm -= 0x4000n;
                    target = pc + imm * 4n;
                }
                if (target === TARGET) hits.push("+0x" + pc.toString(16) + " word=0x" + w.toString(16).padStart(8, "0"));
            }
        }
        await log("BRANCH-SCAN text+0xedb64 hits=" + hits.length + (hits.length ? " " + hits.join(" ") : "") + " (scanned 0x" + TEXT_SIZE.toString(16) + " bytes, base=0x" + base.toString(16) + ")");
        globalThis.civHomeBranchScan = Object.freeze({
            target: "0xedb64",
            hits: Object.freeze(hits)
        });
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
