import coreRuntime from "../src/core/runtime.mjs";

import { buildBootstrapImage } from "./kaihen-bootstrap-image.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read64: read64, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread, write8: write8, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO bootstrap map: " + message);
};

export async function run() {
    const frontend = globalThis.civRoFrontendService;
    const ready = globalThis.civRoFrontendReady;
    const fs = globalThis.civFsMemory;
    check(fs?.status().ready && frontend?.handle && ready?.initialized && globalThis.civRoRootPromotion?.root === fs.status().fsRoot.object && globalThis.civRoSdStaged?.["/kaihen/bin/hen/main"]?.bytes === 78761 && globalThis.civRoSdStaged?.["/kaihen/bin/game/main"]?.bytes === 62943 && !globalThis.civRoBootstrapMap, "frontend, promoted root, or staged HEN files missing");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const {image: image, adapterOffset: adapterOffset, entryOffset: entryOffset} = buildBootstrapImage(sdk_base);
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null;
    try {
        const source = allocPage(image.length);
        const bss = allocPage(4096);
        for (let i = 0; i < image.length; i++) write8(source + BigInt(i), BigInt(image[i]));
        for (let i = 0; i < 4096; i += 8) write64(bss + BigInt(i), 0n);
        const packet = allocPage(8192);
        prepPacket(packet, 4, (18 | 2147483648) >>> 0, []);
        write32(packet + 8n, 1n);
        write32(packet + 32n, 0x49434653n);
        write32(packet + 40n, 0n);
        write64(packet + 48n, 0n);
        write64(packet + 56n, source);
        write64(packet + 64n, BigInt(image.length));
        write64(packet + 72n, bss);
        write64(packet + 80n, 0x1000n);
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(frontend.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native mapping worker did not start");
        const retained = {
            worker: worker,
            frame: frame,
            packet: packet,
            source: source,
            bss: bss,
            allocations: allocations,
            imageBytes: image.length,
            adapterOffset: adapterOffset,
            entryOffset: entryOffset,
            state: "pending"
        };
        globalThis.civRoBootstrapMap = retained;
        if (waitRawThread(worker.handle, 4000000000n) !== 0) {
            await log("RO bootstrap LoadNro timed out; " + "source/BSS/frame retained");
            return;
        }
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        const destination = reply?.result === 0 ? read64(packet + BigInt(reply.data)) : 0n;
        check(transport === 0 && reply?.result === 0 && destination >= 0x1000000n && destination < 0x8000000000n && destination % 0x1000n === 0n, "LoadNro transport/result/destination differed");
        closeRawThread(worker.handle);
        retained.worker = null;
        retained.destination = destination;
        retained.entry = destination + BigInt(entryOffset);
        retained.tryWaitAdapter = retained.entry + BigInt(adapterOffset);
        retained.state = "mapped";
        await log("kaiHEN bootstrap NRO mapped: destination=0x" + destination.toString(16) + " adapter=0x" + retained.tryWaitAdapter.toString(16));
    } finally {
        endAllocationTracking(allocations);
    }
}
