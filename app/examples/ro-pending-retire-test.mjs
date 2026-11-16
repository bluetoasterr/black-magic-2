import coreRuntime, { waitMs } from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, GADGET_MEMSET: GADGET_MEMSET, launchRawWorker: launchRawWorker, log: log} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    if (!fs?.status().ready || typeof fs.retireBoundedNativeRead !== "function" || globalThis.civFsPendingProbe) throw new Error("pending-retire endpoint unavailable");
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("pending-retire schedule unavailable");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("pending-retire tracker busy");
    let worker = null, trackerEnded = false, installed = false;
    try {
        const packet = allocPage(8192);
        const output = allocPage(256);
        call_rop(GADGET_MEMSET, packet, 0n, 0x2000n);
        call_rop(GADGET_MEMSET, output, 0n, 0x100n);
        const frame = buildRawFrame([ {
            fn: F_Sleep,
            args: [ 500000000n, 0n, 0n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("pending-retire worker did not start");
        trackerEnded = endAllocationTracking(allocations);
        if (!trackerEnded) throw new Error("pending-retire tracker did not end");
        globalThis.civFsPendingProbe = Object.freeze({
            worker: worker,
            frame: frame,
            packet: packet,
            output: output,
            allocations: allocations,
            length: 8,
            wait: 59905
        });
        installed = true;
        if (fs.status().ready) throw new Error("endpoint did not block pending FS access");
        let blocked = false;
        try {
            await fs.read(fs.status().fsRoot.object, 8);
        } catch (_) {
            blocked = true;
        }
        if (!blocked) throw new Error("pending FS read was not rejected");
        const first = fs.retireBoundedNativeRead();
        if (!first.pending) throw new Error("pending worker retired before delayed exit");
        await waitMs(600);
        const second = fs.retireBoundedNativeRead();
        installed = false;
        if (second.pending || !second.completed || !fs.status().ready) throw new Error("endpoint did not recover after delayed exit");
        const bytes = await fs.read(fs.status().fsRoot.object, 8);
        if (bytes.length !== 8) throw new Error("endpoint read after retirement failed");
        await log("Pending FS probe retirement qualified: read blocked " + "while worker ran; buffers freed after exit; endpoint responsive");
    } finally {
        if (!trackerEnded && endAllocationTracking(allocations) && !worker?.started) freeTrackedAllocations(allocations);
        if (installed) await log("Pending-retire worker still owned; buffers retained");
    }
}
