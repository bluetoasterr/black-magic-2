import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read8: read8, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    const row = globalThis.civRoLoaderRow;
    if (!service?.handle || !process?.handle || !pid || !row) throw new Error("RO reader probe prerequisites unavailable");
    const schedule = borrowThreadScheduling();
    const tracking = beginAllocationTracking();
    if (!tracking || !schedule) throw new Error("Native worker unavailable");
    let worker = null, finished = false;
    try {
        const packet = allocPage(8192);
        const output = allocPage(4096);
        prepPacket(packet, (4 | 1 << 24) >>> 0, (14 | 2147483648) >>> 0, []);
        write32(packet + 8n, 2n);
        write32(packet + 12n, BigInt(process.handle));
        write32(packet + 16n, 16n);
        write32(packet + 20n, output & 0xffffffffn);
        write32(packet + 24n, 1n | (output >> 36n & 7n) << 2n | (output >> 32n & 15n) << 28n);
        write32(packet + 32n, 0x49434653n);
        write32(packet + 40n, 0x524f0016n);
        write64(packet + 48n, pid);
        write64(packet + 56n, BigInt(row.request));
        write64(packet + 64n, 16n);
        write64(packet + 72n, 0n);
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("RO reader worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civRoPendingReaderProbe = {
                worker: worker,
                frame: frame,
                packet: packet,
                output: output,
                tracking: tracking
            };
            await log("RO reader request timed out; buffers retained");
            return;
        }
        finished = true;
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        let first = "";
        for (let i = 0; i < 8; i++) first += Number(read8(output + BigInt(i))).toString(16).padStart(2, "0");
        await log("RO reader probe: transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16) + " first8=" + first);
        closeRawThread(worker.handle);
        worker = null;
    } finally {
        if (finished && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(tracking) && (finished || !worker?.started)) freeTrackedAllocations(tracking);
    }
}
