import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO PM process verify: " + message);
};

export async function run() {
    const launch = globalThis.civRoLaunch?.result;
    const pm = globalThis.civRoPmMonitor;
    const originalPid = globalThis.civRoOriginalPid;
    check(globalThis.civFsMemory?.status().ready && launch?.swapped && launch?.restored && launch.transport === 0 && launch.result === 0 && Number.isSafeInteger(originalPid) && originalPid > 1 && originalPid !== launch.pid && pm?.handle, "accepted RO launch or PM monitor unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false;
    try {
        const packets = [ allocPage(8192), allocPage(8192) ];
        for (let i = 0; i < 2; i++) {
            prepPacket(packets[i], 4, 10, [ [ 16, 1229145683 ], [ 24, 7 ] ]);
            write64(packets[i] + 32n, BigInt(i === 0 ? originalPid : launch.pid));
        }
        const frame = buildRawFrame(packets.map(packet => ({
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(pm.handle), packet, 0x1000n, 0n ]
        })));
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civRoPendingPmProcessVerify = {
                worker: worker,
                frame: frame,
                packets: packets,
                allocations: allocations
            };
            await log("RO PM process identity timed out; buffers retained");
            return;
        }
        exited = true;
        const identities = [];
        for (let i = 0; i < 2; i++) {
            const transport = Number(readFrameResult(frame.frame, i)) >>> 0;
            const reply = transport === 0 ? cmifReply(packets[i]) : null;
            const title = reply?.result === 0 ? read64(packets[i] + BigInt(reply.data)) : 0n;
            check(transport === 0 && reply?.result === 0 && title === 0x0400000000000037n, "PID " + (i === 0 ? originalPid : launch.pid) + " is not the selected RO title");
            identities.push({
                pid: i === 0 ? originalPid : launch.pid,
                title: title.toString(16)
            });
        }
        globalThis.civRoPmProcessIdentities = identities;
        closeRawThread(worker.handle);
        worker = null;
        await log("RO PM process identity verified: original=" + originalPid + " replacement=" + launch.pid + " title=0400000000000037");
    } finally {
        if (exited && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
