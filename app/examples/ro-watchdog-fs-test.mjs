import coreRuntime from "../src/core/runtime.mjs";

const {beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, launchRawWorker: launchRawWorker, log: log, read8: read8, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const state = globalThis.civRoWorkers;
    if (!fs?.status().ready || state?.list?.length !== 7) throw new Error("RO watchdog FS endpoint or workers unavailable");
    const cancel = sdk_base + 0x168c0cn;
    const code = "210300d4c0035fd6";
    for (let i = 0; i < code.length / 2; i++) if (Number(read8(cancel + BigInt(i))) !== parseInt(code.slice(i * 2, i * 2 + 2), 16)) throw new Error("RO watchdog cancel wrapper differs");
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("RO watchdog invalid thread schedule");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("RO watchdog allocation tracker busy");
    let worker = null, joined = false;
    try {
        const frame = buildRawFrame([ {
            fn: F_Sleep,
            args: [ 50000000n, 0n, 0n, 0n ]
        }, ...state.list.map(item => ({
            fn: cancel,
            args: [ BigInt(item.handle), 0n, 0n, 0n ]
        })) ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("RO watchdog thread did not start");
        const wait = waitRawThread(worker.handle, 2000000000n);
        if (wait !== 0) throw new Error("RO watchdog thread wait result 0x" + wait.toString(16));
        joined = true;
        for (let i = 1; i <= 7; i++) if (readFrameResult(frame.frame, i) !== 0n) throw new Error("RO watchdog FS worker " + i + " cancellation failed");
        const root = fs.status().fsRoot;
        const bytes = await fs.read(root.object, 64);
        if (bytes.length !== 64 || !fs.status().ready) throw new Error("RO watchdog FS endpoint did not respond");
        await log("RO watchdog FS qualification passed: 7 cancellations=0 " + "and FS read responsive");
    } finally {
        if (joined && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && joined) freeTrackedAllocations(allocations);
    }
}
