import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeHandle: closeHandle, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read32: read32, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write8: write8} = coreRuntime;

const u32 = address => Number(read32(address)) >>> 0;

const check = (ok, message) => {
    if (!ok) throw new Error("RO PM lookup: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const sm = globalThis.civRoSmCopy;
    check(fs?.status().ready && sm?.handle && globalThis.civRoActivation?.stage === "activated" && !globalThis.civRoFrontendService && !globalThis.civRoPendingFrontendLookup, "verified SM client unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false, closed = false;
    try {
        const packet = allocPage(4096);
        write32(packet, 0x11n);
        write32(packet + 4n, 2n);
        const name = "ldr:ro";
        for (let i = 0; i < name.length; i++) write8(packet + 8n + BigInt(i), BigInt(name.charCodeAt(i)));
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(sm.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native SM worker did not start");
        const waited = waitRawThread(worker.handle, 2000000000n);
        if (waited !== 0) {
            globalThis.civRoPendingFrontendLookup = {
                worker: worker,
                frame: frame,
                packet: packet,
                allocations: allocations
            };
            await log("RO ldr:ro lookup timed out; buffers retained");
            return;
        }
        exited = true;
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        check(transport === 0, "SM transport=0x" + transport.toString(16));
        const first = u32(packet), second = u32(packet + 4n);
        check(first >>> 16 === 0 && (second & 1023) >= 1, "SM TIPC response shape differs");
        let at = 8n, copies = [], moves = [];
        if (second >>> 31) {
            const special = u32(packet + at);
            at += 4n;
            check(!(special & 1), "SM reply unexpectedly includes PID");
            for (let i = 0; i < (special >>> 1 & 15); i++, at += 4n) copies.push(u32(packet + at));
            for (let i = 0; i < (special >>> 5 & 15); i++, at += 4n) moves.push(u32(packet + at));
        }
        const result = u32(packet + at);
        closeRawThread(worker.handle);
        closed = true;
        if (result !== 0) {
            for (const handle of [ ...copies, ...moves ]) if (handle) closeHandle(handle);
            await log("RO ldr:ro lookup returned 0x" + result.toString(16));
            return;
        }
        check(copies.length === 0 && moves.length === 1 && moves[0] >= 32768, "SM did not return exactly one moved ldr:ro handle");
        globalThis.civRoFrontendService = Object.freeze({
            handle: moves[0],
            sm: sm.handle,
            release() {
                if (globalThis.civRoFrontendService !== this) return;
                closeHandle(this.handle);
                delete globalThis.civRoFrontendService;
            }
        });
        await log("RO ldr:ro service opened via FS SM client: handle=" + moves[0]);
    } finally {
        if (exited && worker?.handle && !closed) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
