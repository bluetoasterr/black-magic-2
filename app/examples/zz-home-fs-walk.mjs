import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("FS walk: " + message);
};

const u32 = a => Number(read32(a)) >>> 0;

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (ro-service-lookup, fs-pid)");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const tracking = beginAllocationTracking();
    check(tracking, "allocation tracker busy");
    let pending = false;
    const packet = allocPage(8192);
    try {
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
            const frame = buildRawFrame([ {
                fn: IPC_SEND_DISPATCHER,
                args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
            } ]);
            const worker = launchRawWorker(frame.frame, schedule);
            check(worker?.handle && worker.rc === 0 && worker.started, "query worker did not start");
            if (waitRawThread(worker.handle, 2000000000n) !== 0) {
                globalThis.civHomePendingWalk = {
                    worker: worker,
                    frame: frame,
                    packet: packet,
                    tracking: tracking
                };
                pending = true;
                return null;
            }
            const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
            closeRawThread(worker.handle);
            check(transport === 0, "transport=0x" + transport.toString(16));
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
                perm: u32(d + 40n)
            };
        };
        const first = query(0n);
        check(first, "first query timed out; worker retained");
        check(first.result === 0, "query rejected: 0x" + first.result.toString(16) + " (old frontend without 0x524f0010?)");
        check(first.program === 0x400000000000000n, "not the FS program: 0x" + first.program.toString(16));
        await log("FS walk: query command accepted, FS pid=" + first.pid);
        let at = first.base + first.size, steps = 1;
        const code = [];
        if (first.type === 3 || first.type === 4) code.push({
            base: first.base,
            size: first.size,
            type: first.type,
            perm: first.perm
        });
        while (steps < 400) {
            const r = query(at);
            if (!r) {
                await log("FS walk: TIMEOUT at 0x" + at.toString(16) + "; worker retained");
                return;
            }
            if (r.result !== 0) {
                await log("FS walk: end at 0x" + at.toString(16) + " result=0x" + r.result.toString(16) + " after " + steps + " mappings");
                break;
            }
            if (r.size === 0n || r.base + r.size <= at) break;
            if (r.type === 3 || r.type === 4) code.push({
                base: r.base,
                size: r.size,
                type: r.type,
                perm: r.perm
            });
            at = r.base + r.size;
            steps++;
        }
        globalThis.civHomeFsWalk = Object.freeze({
            steps: steps,
            code: code.map(c => ({
                base: c.base.toString(16),
                size: c.size.toString(16),
                type: c.type,
                perm: c.perm.toString(16)
            }))
        });
        await log("FS walk complete: " + steps + " mappings, " + code.length + " code regions");
        for (const c of code) await log("FS code region: base=0x" + c.base.toString(16) + " size=0x" + c.size.toString(16) + " type=" + c.type + " perm=" + c.perm.toString(16) + (c.type === 3 && (c.perm & 5) === 5 && c.size >= 0x24e000n ? " <-- ABI capture candidate" : ""));
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
