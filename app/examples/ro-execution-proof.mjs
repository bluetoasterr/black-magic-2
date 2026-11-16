import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write64: write64} = coreRuntime;

const MAGIC = 0x4558454f5232534en;

const XOR = 0x9d7c3a51e6b2048fn;

const check = (ok, message) => {
    if (!ok) throw new Error("RO execution proof: " + message);
};

export async function run() {
    const launch = globalThis.civRoLaunch?.result;
    const service = globalThis.civRoService;
    check(globalThis.civRoActivation?.stage === "activated" && launch?.pid > 1 && service?.handle && !globalThis.civRoExecutionProof, "replacement RO service unavailable");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false;
    try {
        const packets = [ allocPage(8192), allocPage(8192) ];
        const nonce = BigInt(Date.now()) << 16n ^ BigInt(Math.floor(Math.random() * 65536));
        const challenges = [ nonce, nonce ^ 0x87a5369c42b1d0e3n ];
        for (let i = 0; i < packets.length; i++) {
            prepPacket(packets[i], 4, 10, [ [ 16, 1229145683 ], [ 24, 1380909057 ] ]);
            write64(packets[i] + 32n, challenges[i]);
        }
        const frame = buildRawFrame(packets.map(packet => ({
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        })));
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native challenge worker did not start");
        if (waitRawThread(worker.handle, 4000000000n) !== 0) {
            globalThis.civRoPendingExecutionProof = {
                worker: worker,
                frame: frame,
                packets: packets,
                allocations: allocations,
                challenges: challenges
            };
            await log("RO challenge worker timed out; buffers retained");
            return;
        }
        exited = true;
        let previousTick = 0n;
        const proof = [];
        for (let i = 0; i < packets.length; i++) {
            const packet = packets[i];
            const transport = Number(readFrameResult(frame.frame, i)) >>> 0;
            const reply = transport === 0 ? cmifReply(packet) : null;
            const special = Number(read32(packet + 8n)) >>> 0;
            const kernelPid = special & 1 ? read64(packet + 12n) : 0n;
            check(transport === 0 && reply?.result === 0 && kernelPid === BigInt(launch.pid), "challenge " + (i + 1) + " transport/result/kernel PID differs");
            const at = packet + BigInt(reply.data);
            const magic = read64(at);
            const response = read64(at + 8n);
            const payloadPid = read64(at + 16n);
            const thread = read64(at + 24n);
            const tick = read64(at + 32n);
            const registration = read64(at + 40n);
            check(magic === MAGIC && response === (challenges[i] ^ XOR) && payloadPid === BigInt(launch.pid) && thread > 0n && tick > previousTick, "native challenge " + (i + 1) + " data differs");
            previousTick = tick;
            proof.push({
                nonce: challenges[i].toString(16),
                pid: launch.pid,
                thread: thread.toString(),
                tick: tick.toString(),
                registration: registration.toString(16)
            });
        }
        globalThis.civRoExecutionProof = proof;
        closeRawThread(worker.handle);
        worker = null;
        await log("RO execution verified: two challenges, kernel PID=" + launch.pid + ", advancing native ticks");
    } finally {
        if (exited && worker?.handle) closeRawThread(worker.handle);
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
