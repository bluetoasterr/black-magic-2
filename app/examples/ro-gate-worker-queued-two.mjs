import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, FRAME_SENTINEL: FRAME_SENTINEL, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read8: read8, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const bytes32 = n => [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];

const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

const check = (ok, message) => {
    if (!ok) throw new Error(message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    const workers = globalThis.civRoWorkers?.list;
    const server = globalThis.civRoServerCopy;
    check(fs?.status().ready && owned?.row && workers?.length === 7 && server?.handle && !globalThis.civRoQueued && typeof fs.selectPointerBounded === "function" && typeof fs.writeSelectedBounded === "function" && typeof fs.probeBoundedNativeRead === "function" && typeof fs.injectRoHolder === "function" && typeof fs.restoreRoWaitNative === "function", "RO queued gate prerequisites unavailable");
    const row = owned.row, park = workers[0].source;
    const workerHandles = workers.map(worker => worker.handle);
    const cancelCode = sdk_base + 0x168c0cn;
    const init = sdk_base + 1254624n;
    const signal = sdk_base + 1254688n;
    const finalize = sdk_base + 1254672n;
    const eventWait = sdk_base + 1255040n;
    const waitBuf = allocPage(32);
    const readiness = () => {
        write64(waitBuf, 0n);
        write32(waitBuf + 8n, BigInt(server.handle));
        const rc = Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0;
        check(rc === 0 || rc === 59905, "RO server readiness returned 0x" + rc.toString(16));
        return rc === 0;
    };
    const cancel = () => {
        const codes = workerHandles.map(handle => Number(call_rop(cancelCode, BigInt(handle))) >>> 0);
        check(codes.every(code => code === 0), "RO worker cancellation differed");
    };
    const boundedRead = async (address, length) => {
        const selected = await fs.selectPointerBounded(address);
        check(selected.completed && selected.verified, "bounded pointer retarget failed at " + selected.stage);
        const read = await fs.probeBoundedNativeRead(address, length, true);
        check(read.completed && read.transport === 0 && read.result === 0 && read.bytes?.length === length, "bounded FS read failed at 0x" + address.toString(16));
        return read.bytes;
    };
    const boundedWrite = async (address, bytes) => {
        const selected = await fs.selectPointerBounded(address);
        check(selected.completed && selected.verified, "bounded write pointer failed at " + selected.stage);
        const write = fs.writeSelectedBounded(address, bytes);
        check(write.completed && write.transport === 0 && write.result === 0, "bounded FS write failed at 0x" + address.toString(16));
        const observed = await fs.probeBoundedNativeRead(address, bytes.length, true);
        check(observed.completed && observed.transport === 0 && observed.result === 0 && equal(observed.bytes, bytes), "bounded FS write readback differed at 0x" + address.toString(16));
    };
    const inspect = async expectedWait => {
        const bytes = await boundedRead(row.address, 136);
        check(u64(bytes, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(bytes, 48) === expectedWait && u32(bytes, 72) === row.receive && u64(bytes, 96) === row.request && u64(bytes, 112) === row.domain && u64(bytes, 120) === row.metadata && u32(bytes, 64) === 1 && owned.waiters.includes(u64(bytes, 40)), "RO owned server identity or idle state differed");
        return {
            parent: u64(bytes, 40),
            receiveResult: u32(bytes, 68)
        };
    };
    const inject = async (parent, waitHandle) => {
        const result = await fs.injectRoHolder({
            server: row.address,
            parent: parent,
            vptr: fs.status().fsRoot.rootVptr - 32120,
            park: waitHandle,
            receive: row.receive,
            buffer: row.request,
            domain: row.domain,
            metadata: row.metadata,
            workers: workerHandles,
            native: true
        });
        check(result.injected === true, "RO waiter injection failed or was not selected");
        return result;
    };
    const emptyStep = async (label, waitHandle) => {
        const session = await inspect(waitHandle);
        check(!readiness(), label + " server unexpectedly ready");
        const marker = await boundedRead(row.request, 4);
        await boundedWrite(row.request, bytes32(4294967295));
        const waiter = await boundedRead(session.parent + 16, 24);
        check(u64(waiter, 0) === 0, label + " waiter busy");
        const epoch = u64(waiter, 8);
        await inject(session.parent, waitHandle);
        let selection = null, afterEpoch = epoch;
        for (let i = 0; i < 12; i++) {
            const bytes = await boundedRead(session.parent + 16, 24);
            selection = u64(bytes, 0);
            afterEpoch = u64(bytes, 8);
            if (selection === 0 && afterEpoch !== epoch) break;
        }
        const after = await inspect(waitHandle);
        check(selection === 0 && afterEpoch !== epoch && after.receiveResult === 3 && (after.parent !== session.parent || afterEpoch !== epoch), label + " waiter did not advance");
        check(u32(await boundedRead(row.request, 4), 0) === 4294967295, label + " request marker changed unexpectedly");
        await boundedWrite(row.request, marker);
        await log("RO queued gate " + label + " empty step settled");
    };
    const initial = await inspect(row.wait);
    check(!readiness() && initial.parent, "RO owned server not idle before worker preparation");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "RO native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "RO worker allocation tracker busy");
    let worker = null, frame = null, gate = 0n, packets = [];
    let trackingEnded = false;
    try {
        gate = allocPage(16);
        call_rop(init, gate, 0n, 0n, 0n);
        packets = [ allocPage(8192), allocPage(8192) ];
        for (const packet of packets) {
            prepPacket(packet, 5, 8, []);
            write32(packet + 0x10n, 0x49434653n);
            write32(packet + 0x18n, 3n);
        }
        frame = buildRawFrame([ {
            fn: eventWait,
            args: [ gate, 0n, 0n, 0n ]
        }, ...packets.map(packet => ({
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(owned.handle), packet, 0x1000n, 0n ]
        })) ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "RO control worker did not start");
        trackingEnded = endAllocationTracking(allocations);
        check(trackingEnded, "RO worker tracker did not close");
        globalThis.civRoQueued = {
            worker: worker,
            frame: frame,
            gate: gate,
            packets: packets,
            allocations: allocations
        };
        check(waitRawThread(worker.handle, 1000000n) !== 0, "RO control worker passed unsignaled gate");
        await log("RO queued gate 1: parking owned FS server");
        const selected = await fs.selectPointerBounded(row.address);
        check(selected.completed && selected.verified, "RO park pointer retarget failed");
        const parked = fs.parkRoWaitNative(true, "worker");
        check(parked.completed && parked.transport === 0 && parked.result === 0 && parked.cancellations?.length === 7 && parked.cancellations.every(code => code === 0), "RO worker-handle parking did not verify");
        await inspect(park);
        await emptyStep("prime", park);
        await log("RO queued gate 2: releasing native control request");
        call_rop(signal, gate, 0n, 0n, 0n);
        let pending = false;
        for (let i = 0; i < 200; i++) {
            if (readiness()) {
                pending = true;
                break;
            }
            if (waitRawThread(worker.handle, 0n) === 0) break;
            call_rop(F_Sleep, 1000000n, 0n, 0n, 0n);
        }
        check(pending && waitRawThread(worker.handle, 0n) !== 0, "RO control request did not queue behind parked server");
        for (let step = 1; step <= 2; step++) {
            if (step === 2) {
                pending = false;
                for (let i = 0; i < 200; i++) {
                    if (readiness()) {
                        pending = true;
                        break;
                    }
                    if (waitRawThread(worker.handle, 0n) === 0) break;
                    call_rop(F_Sleep, 1000000n, 0n, 0n, 0n);
                }
                check(pending, "second control request did not queue");
            }
            const beforeRequest = await inspect(park);
            await boundedRead(row.request, 4);
            await boundedWrite(row.request, bytes32(4294967295));
            const waiterBefore = await boundedRead(beforeRequest.parent + 16, 24);
            check(u64(waiterBefore, 0) === 0, "RO queued request waiter already selected");
            await log("RO queued gate step " + step + ": releasing request");
            await inject(beforeRequest.parent, park);
            let requestSeen = false;
            for (let i = 0; i < 30; i++) {
                const header = await boundedRead(row.request, 4);
                const current = await inspect(park);
                const first = readFrameResult(frame.frame, 1);
                const second = readFrameResult(frame.frame, 2);
                const finished = waitRawThread(worker.handle, 0n) === 0;
                const progressed = step === 1 ? first === 0n && second === FRAME_SENTINEL && !finished : first === 0n && second === 0n && finished;
                if (u32(header, 0) !== 4294967295 && current.parent && progressed) {
                    requestSeen = true;
                    break;
                }
                cancel();
            }
            check(requestSeen, "RO queued control step " + step + " did not settle one request");
            check(cmifReply(packets[step - 1]).result === 0, "RO queued control response " + step + " failed");
            await log("RO queued gate step " + step + " settled; next=" + (readFrameResult(frame.frame, 2) === FRAME_SENTINEL ? "pending" : "complete"));
        }
        const restoreRow = await inspect(park);
        check(restoreRow.parent && !readiness(), "RO session did not return to idle before restore");
        await boundedWrite(row.address + 48, bytes32(row.wait));
        cancel();
        await inspect(row.wait);
        await emptyStep("restore", row.wait);
        await inspect(row.wait);
        check(u32(await boundedRead(row.request, 4), 0) !== 4294967295, "RO request marker was not restored");
        check(!readiness(), "RO server not idle after restoration");
        closeRawThread(worker.handle);
        call_rop(finalize, gate, 0n, 0n, 0n);
        freeTrackedAllocations(allocations);
        delete globalThis.civRoQueued;
        await log("RO queued gate verified and restored: two native " + "control requests completed one at a time, owned server idle");
    } catch (error) {
        await log("RO queued gate stopped: " + (error?.message || String(error)) + "; no cleanup writes, inspect state before retrying");
    } finally {
        if (!trackingEnded) trackingEnded = endAllocationTracking(allocations);
        if (!worker?.started && trackingEnded) freeTrackedAllocations(allocations);
    }
}
