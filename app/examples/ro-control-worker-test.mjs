import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread, write32: write32} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO control worker: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    check(fs?.status().ready && owned?.handle, "verified owned FS session unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false;
    const init = sdk_base + 1254624n;
    const signal = sdk_base + 1254688n;
    const finalize = sdk_base + 1254672n;
    const wait = sdk_base + 1255040n;
    try {
        const gate = allocPage(16);
        call_rop(init, gate, 0n, 0n, 0n);
        const packets = [ allocPage(8192), allocPage(8192) ];
        for (const packet of packets) {
            prepPacket(packet, 5, 8, []);
            write32(packet + 0x10n, 0x49434653n);
            write32(packet + 0x18n, 3n);
        }
        const frame = buildRawFrame([ {
            fn: wait,
            args: [ gate, 0n, 0n, 0n ]
        }, ...packets.map(packet => ({
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(owned.handle), packet, 0x1000n, 0n ]
        })) ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native worker did not start");
        if (waitRawThread(worker.handle, 1000000n) === 0) {
            exited = true;
            closeRawThread(worker.handle);
            call_rop(finalize, gate, 0n, 0n, 0n);
            throw new Error("worker passed the unsignaled gate");
        }
        call_rop(signal, gate, 0n, 0n, 0n);
        const joined = waitRawThread(worker.handle, 2000000000n);
        if (joined !== 0) {
            globalThis.civRoPendingControlWorker = {
                worker: worker,
                frame: frame,
                packets: packets,
                gate: gate,
                allocations: allocations
            };
            await log("RO control worker did not finish; buffers retained");
            return;
        }
        exited = true;
        const transport = [ 1, 2 ].map(i => Number(readFrameResult(frame.frame, i)) >>> 0);
        const replies = packets.map(packet => cmifReply(packet).result);
        closeRawThread(worker.handle);
        call_rop(finalize, gate, 0n, 0n, 0n);
        check(transport.every(code => code === 0) && replies.every(code => code === 0), "control request transport or result differs");
        await log("RO control worker qualified: two native control " + "requests completed on owned FS session");
    } finally {
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
