import coreRuntime from "../src/core/runtime.mjs";

import { requestInfo, targetCodeFsRequest } from "./ro-launch-wire.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, FRAME_SENTINEL: FRAME_SENTINEL, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread, write8: write8, write32: write32, write64: write64} = coreRuntime;

const TITLE = 0x0400000000000037n;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const bytes32 = n => [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];

const bytes64 = n => {
    let value = BigInt(n);
    const out = [];
    for (let i = 0; i < 8; i++) {
        out.push(Number(value & 255n));
        value >>= 8n;
    }
    return out;
};

const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

const check = (ok, message) => {
    if (!ok) throw new Error("RO launch: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const loader = globalThis.civRoLoaderRootCopy;
    const donor = globalThis.civRoDonor;
    const row = globalThis.civRoLoaderRow;
    const server = globalThis.civRoLoaderServerCopy;
    const owned = globalThis.civRoOwned;
    const workers = globalThis.civRoWorkers?.list;
    const pm = globalThis.civRoPmShell;
    check(fs?.status().ready && loader?.handle && donor?.handle && row && server?.handle && pm?.handle && owned?.waiters?.length === 7 && workers?.length === 7 && globalThis.civRoLoaderDomainBaseline?.length === 1 && globalThis.civRoLoaderDomainBaseline[0].id === 9 && !globalThis.civRoLaunch, "live proofs missing or launch already pending");
    check(row.domain === loader.targetDomain && donor.metadata === globalThis.civRoDonorType?.metadata && donor.vptr === globalThis.civRoDonorType?.vptr, "donor or Loader identity changed");
    const root = fs.status().fsRoot;
    const workerHandles = workers.map(worker => worker.handle);
    const park = workers[0].source;
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
        check(rc === 0 || rc === 59905, "Loader readiness returned 0x" + rc.toString(16));
        return rc === 0;
    };
    const cancel = () => {
        const codes = workerHandles.map(handle => Number(call_rop(cancelCode, BigInt(handle))) >>> 0);
        check(codes.every(code => code === 0), "worker cancellation differed");
    };
    const boundedRead = async (address, length) => {
        const selected = await fs.selectPointerBounded(address);
        check(selected.completed && selected.verified, "pointer retarget failed at " + selected.stage);
        const read = await fs.probeBoundedNativeRead(address, length, true);
        check(read.completed && read.transport === 0 && read.result === 0 && read.bytes?.length === length, "bounded FS read failed at 0x" + address.toString(16));
        return read.bytes;
    };
    const boundedWrite = async (address, expected, next) => {
        const before = await boundedRead(address, expected.length);
        check(equal(before, expected), "write preimage changed at 0x" + address.toString(16));
        const selected = await fs.selectPointerBounded(address);
        check(selected.completed && selected.verified, "write pointer retarget failed");
        const write = fs.writeSelectedBounded(address, next);
        check(write.completed && write.transport === 0 && write.result === 0, "bounded FS write failed at 0x" + address.toString(16));
        check(equal(await boundedRead(address, next.length), next), "write readback differed at 0x" + address.toString(16));
    };
    const inspect = async expectedWait => {
        const b = await boundedRead(row.address, 136);
        check(u64(b, 0) === root.rootVptr - 32120 && u32(b, 48) === expectedWait && u32(b, 72) === row.receive && u64(b, 96) === row.request && u64(b, 112) === row.domain && u64(b, 120) === row.metadata && u32(b, 64) === 1 && owned.waiters.includes(u64(b, 40)), "Loader server identity or idle state changed");
        return {
            parent: u64(b, 40),
            receiveResult: u32(b, 68)
        };
    };
    const inject = async (parent, waitHandle) => {
        const result = await fs.injectRoHolder({
            server: row.address,
            parent: parent,
            vptr: root.rootVptr - 32120,
            park: waitHandle,
            receive: row.receive,
            buffer: row.request,
            domain: row.domain,
            metadata: row.metadata,
            workers: workerHandles,
            native: true
        });
        check(result.injected === true, "Loader waiter injection did not verify");
    };
    const entries = async () => {
        const sentinel = loader.targetDomain + 32;
        let at = u64(await boundedRead(sentinel, 8), 0);
        const seen = new Set, result = [];
        while (at !== sentinel) {
            check(at >= root.table && at + 48 <= root.captureEnd && (at - root.table) % 48 === 0 && !seen.has(at) && result.length < 128, "domain list left verified table");
            seen.add(at);
            const b = await boundedRead(at, 48);
            check(u64(b, 24) === loader.targetDomain, "domain entry owner changed");
            result.push({
                id: (at - root.table) / 48 + 1,
                entry: at,
                object: u64(b, 32),
                metadata: u64(b, 40)
            });
            at = u64(b, 0);
        }
        return result;
    };
    const emptyStep = async (waitHandle, label) => {
        const before = await inspect(waitHandle);
        check(!readiness(), label + " server unexpectedly ready");
        const marker = await boundedRead(row.request, 4);
        await boundedWrite(row.request, marker, bytes32(4294967295));
        const waiter = await boundedRead(before.parent + 16, 24);
        check(u64(waiter, 0) === 0, label + " waiter busy");
        const epoch = u64(waiter, 8);
        await inject(before.parent, waitHandle);
        let next = epoch, selected = 0;
        for (let i = 0; i < 12; i++) {
            const b = await boundedRead(before.parent + 16, 24);
            selected = u64(b, 0);
            next = u64(b, 8);
            if (selected === 0 && next !== epoch) break;
        }
        const after = await inspect(waitHandle);
        check(selected === 0 && next !== epoch && after.receiveResult === 3, label + " idle selection did not settle");
        await boundedWrite(row.request, bytes32(4294967295), marker);
    };
    const requestStep = async (waitHandle = park) => {
        const before = await inspect(waitHandle);
        check(readiness(), "no queued Loader request");
        const marker = await boundedRead(row.request, 4);
        await boundedWrite(row.request, marker, bytes32(4294967295));
        const waiter = await boundedRead(before.parent + 16, 24);
        check(u64(waiter, 0) === 0, "queued waiter busy");
        await inject(before.parent, waitHandle);
        for (let i = 0; i < 30; i++) {
            const header = await boundedRead(row.request, 4);
            const current = await inspect(waitHandle);
            if (u32(header, 0) !== 4294967295 && current.parent) {
                const packet = await boundedRead(row.request, 256);
                return requestInfo(packet);
            }
            cancel();
        }
        throw new Error("RO launch: queued Loader request did not settle");
    };
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "worker allocation tracker busy");
    let worker = null, frame = null, gate = 0n, packet = 0n;
    let trackingEnded = false, parked = false, restored = false;
    let swapped = false, mounts = 0, steps = 0;
    try {
        gate = allocPage(16);
        call_rop(init, gate, 0n, 0n, 0n);
        packet = allocPage(8192);
        prepPacket(packet, 4, 14, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
        write32(packet + 32n, 0x10n);
        write64(packet + 40n, TITLE);
        write8(packet + 48n, 3n);
        frame = buildRawFrame([ {
            fn: eventWait,
            args: [ gate, 0n, 0n, 0n ]
        }, {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(pm.handle), packet, 0x1000n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "PM launch worker did not start");
        trackingEnded = endAllocationTracking(allocations);
        check(trackingEnded, "worker allocation tracker did not close");
        globalThis.civRoLaunch = {
            worker: worker,
            frame: frame,
            gate: gate,
            packet: packet,
            allocations: allocations,
            stage: "prepared"
        };
        check(waitRawThread(worker.handle, 1000000n) !== 0, "PM worker passed unsignaled gate");
        await log("RO launch 1: parking Loader server");
        await inspect(row.wait);
        check(!readiness(), "Loader has pending request before park");
        await boundedWrite(row.address + 48, bytes32(row.wait), bytes32(park));
        parked = true;
        globalThis.civRoLaunch.stage = "parked";
        cancel();
        await inspect(park);
        await emptyStep(park, "prime");
        await log("RO launch 2: releasing PM worker");
        call_rop(signal, gate, 0n, 0n, 0n);
        const deadline = Date.now() + 24e4;
        for (let i = 0; i < 160; i++) {
            let pending = false;
            for (let poll = 0; poll < 200; poll++) {
                if (readiness()) {
                    pending = true;
                    break;
                }
                if (waitRawThread(worker.handle, 0n) === 0) break;
                check(Date.now() < deadline, "PM launch timed out");
                call_rop(F_Sleep, 1000000n, 0n, 0n, 0n);
            }
            if (!pending && waitRawThread(worker.handle, 0n) === 0) break;
            check(pending, "PM did not reach parked Loader server");
            const before = await entries();
            const info = await requestStep();
            const after = await entries();
            const added = after.filter(a => !before.some(b => b.id === a.id && b.object === a.object));
            steps++;
            if (targetCodeFsRequest(info, 9, TITLE)) {
                mounts++;
                check(added.length === 1 && added[0].metadata === donor.metadata, "target CodeFS mount did not add one compatible FS");
                await log("RO launch mount " + mounts + " codeID=" + added[0].id);
                if (mounts === 2) {
                    const code = added[0];
                    const current = await boundedRead(donor.entry, 48);
                    check(u64(current, 24) === donor.domain && u64(current, 32) === donor.object && u64(current, 40) === donor.metadata && u64(await boundedRead(code.object, 8), 0) === donor.vptr && u64(await boundedRead(donor.object, 8), 0) === donor.vptr, "CodeFS or donor concrete type changed");
                    await boundedWrite(code.entry + 32, bytes64(code.object), bytes64(donor.object));
                    try {
                        await boundedWrite(donor.entry + 32, bytes64(donor.object), bytes64(code.object));
                    } catch (error) {
                        if (u64(await boundedRead(donor.entry + 32, 8), 0) === donor.object) await boundedWrite(code.entry + 32, bytes64(donor.object), bytes64(code.object));
                        throw error;
                    }
                    swapped = true;
                    globalThis.civRoLaunch.stage = "swapped";
                    globalThis.civRoLaunch.code = code;
                    check(u64(await boundedRead(code.entry + 32, 8), 0) === donor.object && u64(await boundedRead(donor.entry + 32, 8), 0) === code.object, "owning-reference exchange did not verify");
                    await log("RO launch 3: CodeFS reference exchange verified");
                    break;
                }
            }
            if (i < 16 || i % 10 === 9) await log("RO launch step " + steps + ": " + info.kind + " object=" + (info.object ?? 0) + " command=" + (info.command ?? 0));
        }
        await log("RO launch 4: restoring Loader gate");
        const final = await inspect(park);
        check(final.parent, "Loader server unsettled before restore");
        await boundedWrite(row.address + 48, bytes32(park), bytes32(row.wait));
        cancel();
        await inspect(row.wait);
        if (readiness()) await requestStep(row.wait); else await emptyStep(row.wait, "restore");
        await inspect(row.wait);
        check(!readiness(), "Loader server not idle after restore");
        parked = false;
        restored = true;
        globalThis.civRoLaunch.stage = "restored";
        for (let poll = 0; poll < 2e4; poll++) {
            if (waitRawThread(worker.handle, 0n) === 0) break;
            call_rop(F_Sleep, 1000000n, 0n, 0n, 0n);
        }
        check(waitRawThread(worker.handle, 0n) === 0, "PM worker did not finish after gate restore");
        const transport = Number(readFrameResult(frame.frame, 1)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        const pid = reply?.result === 0 ? u64(Array.from({
            length: 8
        }, (_, i) => Number(coreRuntime.read8(packet + BigInt(reply.data + i)))), 0) : 0;
        await log("RO launch result: swapped=" + swapped + " mounts=" + mounts + " steps=" + steps + " transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16) + " pid=" + pid + " restored=" + restored);
        globalThis.civRoLaunch.result = {
            swapped: swapped,
            mounts: mounts,
            steps: steps,
            transport: transport,
            result: reply?.result,
            pid: pid,
            restored: restored
        };
        closeRawThread(worker.handle);
        call_rop(finalize, gate, 0n, 0n, 0n);
        freeTrackedAllocations(allocations);
        globalThis.civRoLaunch.stage = "completed";
    } catch (error) {
        await log("RO launch stopped: " + (error?.message || String(error)) + "; parked=" + parked + " swapped=" + swapped + "; native buffers retained");
        globalThis.civRoLaunch ||= {};
        globalThis.civRoLaunch.error = error?.message || String(error);
        globalThis.civRoLaunch.parked = parked;
        globalThis.civRoLaunch.swapped = swapped;
    } finally {
        if (!trackingEnded) trackingEnded = endAllocationTracking(allocations);
        if (!worker?.started && trackingEnded) freeTrackedAllocations(allocations);
    }
}
