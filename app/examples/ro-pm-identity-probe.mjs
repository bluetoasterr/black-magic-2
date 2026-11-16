import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeHandle: closeHandle, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, readFrameResult: readFrameResult, read64: read64, waitRawThread: waitRawThread, write64: write64} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const pm = globalThis.civRoPmShell;
    if (!fs?.status().ready || !pm?.handle) throw new Error("RO PM identity: verified service unavailable");
    const schedule = borrowThreadScheduling();
    if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("RO PM identity: worker schedule unavailable");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("RO PM identity: tracker busy");
    let worker = null, exited = false;
    try {
        const packet = allocPage(8192);
        prepPacket(packet, 4, 10, [ [ 16, 1229145683 ], [ 24, 12 ] ]);
        write64(packet + 32n, 0x0400000000000037n);
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(pm.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("RO PM identity: native worker did not start");
        const wait = waitRawThread(worker.handle, 2000000000n);
        if (wait !== 0) {
            globalThis.civRoPendingPmIdentity = {
                worker: worker,
                frame: frame,
                packet: packet,
                allocations: allocations
            };
            await log("RO PM identity timed out; buffers retained");
            return;
        }
        exited = true;
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        closeRawThread(worker.handle);
        worker = null;
        if (reply) for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle) closeHandle(handle);
        await log("RO PM identity query: transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16) + " pid=" + (reply?.result === 0 ? read64(packet + BigInt(reply.data)).toString() : "none"));
        if (transport !== 0 || reply?.result !== 0) throw new Error("RO PM identity query did not verify");
        globalThis.civRoOriginalPid = Number(read64(packet + BigInt(reply.data)));
    } finally {
        if (exited && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
