import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO activate: " + message);
};

export async function run() {
    const launch = globalThis.civRoLaunch?.result;
    const originalPid = globalThis.civRoOriginalPid;
    const identities = globalThis.civRoPmProcessIdentities;
    const monitor = globalThis.civRoPmMonitor;
    const shell = globalThis.civRoPmShell;
    check(globalThis.civFsMemory?.status().ready && launch?.swapped && launch?.restored && launch.transport === 0 && launch.result === 0 && Number.isSafeInteger(originalPid) && originalPid > 1 && originalPid !== launch.pid && identities?.length === 2 && identities[0].pid === originalPid && identities[1].pid === launch.pid && monitor?.handle && shell?.handle && !globalThis.civRoActivation, "accepted image or PM identity proof unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const state = globalThis.civRoActivation = {
        replacement: launch.pid,
        original: originalPid,
        stage: "prepared"
    };
    async function command(label, handle, pid) {
        const allocations = beginAllocationTracking();
        check(allocations, "allocation tracker busy for " + label);
        let worker = null, exited = false;
        try {
            const packet = allocPage(8192);
            prepPacket(packet, 4, 10, [ [ 16, 1229145683 ], [ 24, 1 ] ]);
            write64(packet + 32n, BigInt(pid));
            const frame = buildRawFrame([ {
                fn: IPC_SEND_DISPATCHER,
                args: [ BigInt(handle), packet, 0x1000n, 0n ]
            } ]);
            worker = launchRawWorker(frame.frame, schedule);
            check(worker?.handle && worker.rc === 0 && worker.started, label + " worker did not start");
            if (waitRawThread(worker.handle, 4000000000n) !== 0) {
                state.pending = {
                    label: label,
                    worker: worker,
                    frame: frame,
                    packet: packet,
                    allocations: allocations
                };
                await log("RO activate " + label + " timed out; native buffers retained");
                return null;
            }
            exited = true;
            const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
            const reply = transport === 0 ? cmifReply(packet) : null;
            closeRawThread(worker.handle);
            worker = null;
            return {
                transport: transport,
                result: reply?.result ?? 4294967295
            };
        } finally {
            if (exited && worker?.handle) closeRawThread(worker.handle);
            if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
        }
    }
    state.stage = "starting replacement";
    const start = await command("start replacement", monitor.handle, launch.pid);
    if (!start) return;
    state.start = start;
    check(start.transport === 0 && start.result === 0, "replacement start failed: " + JSON.stringify(start));
    await log("RO replacement started: pid=" + launch.pid);
    state.stage = "terminating original";
    const terminate = await command("terminate original", shell.handle, originalPid);
    if (!terminate) return;
    state.terminate = terminate;
    check(terminate.transport === 0 && terminate.result === 0, "original termination failed: " + JSON.stringify(terminate));
    state.stage = "activated";
    await log("RO activation completed: replacement=" + launch.pid + " original=" + originalPid);
}
