import coreRuntime, { waitMs } from "../src/core/runtime.mjs";

const {beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, launchRawWorker: launchRawWorker, log: log, read8: read8, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const state = globalThis.civRoWorkers;
    if (!fs?.status().ready || state?.list?.length !== 7) throw new Error("RO loop watchdog FS endpoint or workers unavailable");
    const cancel = sdk_base + 0x168c0cn;
    const code = "210300d4c0035fd6";
    for (let i = 0; i < code.length / 2; i++) if (Number(read8(cancel + BigInt(i))) !== parseInt(code.slice(i * 2, i * 2 + 2), 16)) throw new Error("RO loop watchdog wrapper differs");
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("RO loop watchdog schedule unavailable");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("RO loop watchdog tracker busy");
    let worker = null, joined = false;
    try {
        const rounds = 10, calls = [];
        for (let round = 0; round < rounds; round++) {
            calls.push({
                fn: F_Sleep,
                args: [ 30000000n, 0n, 0n, 0n ]
            });
            for (const item of state.list) calls.push({
                fn: cancel,
                args: [ BigInt(item.handle), 0n, 0n, 0n ]
            });
        }
        const frame = buildRawFrame(calls);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("RO loop watchdog thread did not start");
        const root = fs.status().fsRoot;
        for (let i = 0; i < 5; i++) {
            const bytes = await fs.read(root.object, 64);
            if (bytes.length !== 64 || !fs.status().ready) throw new Error("RO loop watchdog FS read " + i + " failed");
            await waitMs(40);
        }
        const result = waitRawThread(worker.handle, 2000000000n);
        if (result !== 0) throw new Error("RO loop watchdog wait result 0x" + result.toString(16));
        joined = true;
        for (let i = 0; i < calls.length; i++) if (i % 8 !== 0 && readFrameResult(frame.frame, i) !== 0n) throw new Error("RO loop watchdog cancellation " + i + " failed");
        await log("RO loop watchdog qualified: 10 rounds, 70 wakeups, " + "5 concurrent FS reads, endpoint responsive");
    } finally {
        if (joined && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && joined) freeTrackedAllocations(allocations);
    }
}
