import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO frontend ready: " + message);
};

export async function run() {
    const frontend = globalThis.civRoFrontendService;
    const stage = globalThis.civRoFrontendStaged;
    const launch = globalThis.civRoLaunch?.result;
    check(globalThis.civRoActivation?.stage === "activated" && stage?.bytes === 26367 && launch?.swapped && launch?.restored && frontend?.handle && !globalThis.civRoFrontendReady, "verified frontend launch or service unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false;
    try {
        const packet = allocPage(8192);
        prepPacket(packet, 4, (10 | 2147483648) >>> 0, []);
        write32(packet + 8n, 3n);
        write32(packet + 20n, 0xffff8001n);
        write32(packet + 32n, 0x49434653n);
        write32(packet + 40n, 4n);
        write64(packet + 48n, 0n);
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(frontend.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "Initialize worker did not start");
        if (waitRawThread(worker.handle, 4000000000n) !== 0) {
            globalThis.civRoPendingFrontendReady = {
                worker: worker,
                frame: frame,
                packet: packet,
                allocations: allocations
            };
            await log("RO frontend Initialize timed out; buffers retained");
            return;
        }
        exited = true;
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        check(transport === 0 && reply?.result === 0, "Initialize transport/result differed: 0x" + transport.toString(16) + "/0x" + (reply?.result ?? 4294967295).toString(16));
        closeRawThread(worker.handle);
        worker = null;
        globalThis.civRoFrontendReady = Object.freeze({
            pid: launch.pid,
            initialized: true
        });
        await log("kaiHEN ldr:ro frontend verified: Initialize accepted " + "from Civ VII, pid=" + launch.pid);
    } finally {
        if (exited && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
