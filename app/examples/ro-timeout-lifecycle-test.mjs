import coreRuntime from "../src/core/runtime.mjs";

const {beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, launchRawWorker: launchRawWorker, log: log, readFrameResult: readFrameResult, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("timeout lifecycle schedule unavailable");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("timeout lifecycle tracker busy");
    let worker = null, exited = false, trackingEnded = false, freed = false;
    try {
        const frame = buildRawFrame([ {
            fn: F_Sleep,
            args: [ 300000000n, 0n, 0n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("timeout lifecycle thread did not start");
        globalThis.civRoTimeoutLifecycle = {
            worker: worker,
            frame: frame,
            allocations: allocations
        };
        const early = waitRawThread(worker.handle, 1000000n);
        if (early === 0) throw new Error("delayed worker finished before timeout check");
        trackingEnded = endAllocationTracking(allocations);
        if (!trackingEnded) throw new Error("timeout lifecycle tracker did not end");
        const late = waitRawThread(worker.handle, 2000000000n);
        if (late !== 0 || readFrameResult(frame.frame, 0) !== 0n) throw new Error("delayed worker did not finish cleanly: 0x" + late.toString(16));
        exited = true;
        closeRawThread(worker.handle);
        freeTrackedAllocations(allocations);
        freed = true;
        delete globalThis.civRoTimeoutLifecycle;
        await log("Timeout lifecycle qualified: first wait timed out, " + "worker later exited, retained buffers then freed");
    } finally {
        if (!trackingEnded) trackingEnded = endAllocationTracking(allocations);
        if (!freed && (!worker?.started || exited) && trackingEnded) freeTrackedAllocations(allocations);
    }
}
