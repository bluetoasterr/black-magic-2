import coreRuntime from "../src/core/runtime.mjs";

const {beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, F_Tick: F_Tick, launchRawWorker: launchRawWorker, log: log, readFrameResult: readFrameResult, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("RO watchdog: no valid thread schedule");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("RO watchdog: tracker busy");
    let worker = null, joined = false;
    try {
        const frame = buildRawFrame([ {
            fn: F_Sleep,
            args: [ 50000000n, 0n, 0n, 0n ]
        }, {
            fn: F_Tick,
            args: [ 0n, 0n, 0n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("RO watchdog: raw thread did not start");
        const result = waitRawThread(worker.handle, 2000000000n);
        if (result !== 0) throw new Error("RO watchdog: thread wait result 0x" + result.toString(16));
        joined = true;
        const tick = readFrameResult(frame.frame, 1);
        if (tick === 0xfedcba9876543210n || tick === 0n) throw new Error("RO watchdog: tick step did not execute");
        await log("RO watchdog app-only thread verified: sleep=50ms " + "tick=" + tick + " core=" + schedule.core);
    } finally {
        if (joined && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && joined) freeTrackedAllocations(allocations);
    }
}
