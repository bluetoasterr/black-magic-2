import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, launchRawWorker: launchRawWorker, log: log, read8: read8, readFrameResult: readFrameResult, sdk_base: sdk_base, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

function u32(b, o) {
    return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;
}

function u64(b, o) {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
}

function bytes32(n) {
    return [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];
}

function check(ok, message) {
    if (!ok) throw new Error("RO empty gate: " + message);
}

function verifyCode(address, hex) {
    for (let i = 0; i < hex.length / 2; i++) check(Number(read8(address + BigInt(i))) === parseInt(hex.slice(i * 2, i * 2 + 2), 16), "native syscall wrapper differs");
}

function findSyscall(hex) {
    let found = 0n, count = 0;
    for (let off = 0; off + hex.length / 2 <= 288; off += 4) {
        const address = sdk_base + 0x168b00n + BigInt(off);
        let same = true;
        for (let i = 0; i < hex.length / 2; i++) same = same && Number(read8(address + BigInt(i))) === parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        if (same) {
            found = address;
            count++;
        }
    }
    check(count === 1, "event syscall wrapper is not unique");
    return found;
}

export async function run() {
    await log("RO guarded gate stage 0: checking retained endpoint and wrappers");
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    const event = globalThis.civRoEvent;
    const serverCopy = globalThis.civRoServerCopy;
    const workers = globalThis.civRoWorkers;
    check(fs?.status().ready && typeof fs.injectRoHolder === "function" && typeof fs.probeBoundedNativeRead === "function" && typeof fs.parkRoWaitNative === "function" && owned?.row && event?.sourceHandle && event?.read && event?.write && serverCopy?.handle && workers?.list?.length === 7, "fresh endpoint or retained gate prerequisites unavailable");
    const row = owned.row, park = event.sourceHandle;
    const workerHandles = workers.list.map(item => item.handle);
    const cancelAddress = sdk_base + 0x168c0cn;
    verifyCode(cancelAddress, "210300d4c0035fd6");
    verifyCode(SVC_WaitSync, "e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6");
    const signal = findSyscall("210200d4c0035fd6");
    const clear = findSyscall("410200d4c0035fd6");
    const waitBuf = allocPage(32);
    const pending = () => {
        write64(waitBuf, 0n);
        write32(waitBuf + 8n, BigInt(serverCopy.handle));
        const rc = Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0;
        check(rc === 0 || rc === 59905, "server readiness check failed: 0x" + rc.toString(16));
        return rc === 0;
    };
    const cancel = () => {
        const results = workerHandles.map(handle => Number(call_rop(cancelAddress, BigInt(handle))) >>> 0);
        check(results.every(rc => rc === 0), "worker cancellation failed");
    };
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "watchdog thread schedule unavailable");
    const armWatchdog = () => {
        const allocations = beginAllocationTracking();
        check(allocations, "watchdog allocation tracker busy");
        try {
            const frame = buildRawFrame([ {
                fn: F_Sleep,
                args: [ 50000000n, 0n, 0n, 0n ]
            }, ...workerHandles.map(handle => ({
                fn: cancelAddress,
                args: [ BigInt(handle), 0n, 0n, 0n ]
            })) ]);
            const worker = launchRawWorker(frame.frame, schedule);
            check(worker?.handle && worker.rc === 0 && worker.started, "watchdog thread did not start");
            return {
                allocations: allocations,
                frame: frame,
                worker: worker,
                finished: false
            };
        } catch (error) {
            if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
            throw error;
        }
    };
    const finishWatchdog = watchdog => {
        if (!watchdog || watchdog.finished) return;
        const wait = waitRawThread(watchdog.worker.handle, 2000000000n);
        check(wait === 0, "watchdog did not finish: 0x" + wait.toString(16));
        for (let i = 1; i <= 7; i++) check(readFrameResult(watchdog.frame.frame, i) === 0n, "watchdog cancellation " + i + " failed");
        closeRawThread(watchdog.worker.handle);
        watchdog.finished = true;
        if (endAllocationTracking(watchdog.allocations)) freeTrackedAllocations(watchdog.allocations);
    };
    const inspect = async parked => {
        const b = await fs.read(row.address, 136);
        check(u64(b, 0) === fs.status().fsRoot.rootVptr - 32120 && u64(b, 112) === row.domain && u64(b, 120) === row.metadata && u32(b, 72) === row.receive && u64(b, 96) === row.request && u64(b, 104) === 256 && u32(b, 48) === (parked ? park : row.wait), "bound server session changed");
        return {
            parent: u64(b, 40),
            state: u32(b, 64),
            receiveResult: u32(b, 68)
        };
    };
    const selections = async () => {
        const b = await fs.read(owned.waiters[0] + 16, 6 * 272 + 8);
        return owned.waiters.map((_, i) => u64(b, i * 272));
    };
    let parked = false, marker = null, markerActive = false;
    let restored = false, attempts = 0, timedOut = false;
    let injectionInFlight = false;
    try {
        await log("RO gate stage 1: checking idle server");
        const before = await inspect(false);
        check(before.state === 1 && owned.waiters.includes(before.parent) && !pending(), "owned server is not idle before park");
        await log("RO guarded gate stage 2: writing parking handle");
        const parkWrite = fs.parkRoWaitNative();
        if (!parkWrite.completed || parkWrite.transport !== 0 || parkWrite.result !== 0 || parkWrite.cancellations?.length !== 7 || parkWrite.cancellations.some(code => code !== 0)) {
            timedOut = true;
            await log("RO park native write/cancel did not verify; " + "skipping further FS requests");
            return;
        }
        parked = true;
        const parkRead = await fs.probeBoundedNativeRead(row.address + 48, 4, true);
        if (!parkRead.completed || parkRead.transport !== 0 || parkRead.result !== 0 || u32(parkRead.bytes, 0) !== park) {
            timedOut = true;
            await log("RO park bounded read did not verify; " + "skipping further FS requests");
            return;
        }
        await log("RO gate stage 3: park write and worker cancellations verified");
        const afterProbe = await fs.probeBoundedNativeRead(row.address, 136, true);
        if (!afterProbe.completed || afterProbe.transport !== 0 || afterProbe.result !== 0 || afterProbe.bytes?.length !== 136) {
            timedOut = true;
            await log("RO parked session bounded read did not verify; " + "skipping further FS requests");
            return;
        }
        const afterBytes = afterProbe.bytes;
        if (!(u64(afterBytes, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(afterBytes, 48) === park && u32(afterBytes, 72) === row.receive && u64(afterBytes, 96) === row.request && u64(afterBytes, 112) === row.domain && u64(afterBytes, 120) === row.metadata)) {
            timedOut = true;
            await log("RO bounded parked session identity differs; " + "skipping further FS requests");
            return;
        }
        const after = {
            parent: u64(afterBytes, 40),
            state: u32(afterBytes, 64)
        };
        if (after.state !== 1 || !owned.waiters.includes(after.parent)) {
            timedOut = true;
            await log("RO parked server did not rearm; " + "skipping further FS requests");
            return;
        }
        await log("RO gate stage 4: priming empty request marker");
        marker = await fs.read(row.request, 4);
        await fs.compareWrite(row.request, marker, bytes32(4294967295));
        markerActive = true;
        let injection = null, rebuilt = false;
        for (let i = 0; i < 30; i++) {
            const selected = await selections();
            const session = await inspect(true);
            const epoch = owned.waiters.includes(session.parent) ? u64(await fs.read(session.parent + 24, 8), 0) : null;
            const header = u32(await fs.read(row.request, 4), 0);
            if (injection && !selected.includes(row.address) && header === 4294967295 && session.state === 1 && session.receiveResult === 3 && owned.waiters.includes(session.parent) && (session.parent !== injection.parent || String(epoch) !== injection.epoch)) {
                rebuilt = true;
                break;
            }
            check(header === 4294967295, "unexpected request during empty gate rebuild");
            if (selected.includes(row.address) || session.state !== 1 || !owned.waiters.includes(session.parent)) {
                cancel();
                continue;
            }
            check(!pending(), "owned server became ready during idle rebuild");
            await log("RO gate stage 5: injecting idle selection " + (attempts + 1));
            injectionInFlight = true;
            const result = await fs.injectRoHolder({
                server: row.address,
                parent: session.parent,
                vptr: fs.status().fsRoot.rootVptr - 32120,
                park: park,
                receive: row.receive,
                buffer: row.request,
                domain: row.domain,
                metadata: row.metadata,
                workers: workerHandles,
                native: true
            });
            attempts++;
            await log("RO gate stage 5 result " + attempts + ": injected=" + !!result.injected + " selected=" + (result.selected || 0) + " retry=" + !!result.retry);
            if (result.nativeFailure) {
                timedOut = true;
                await log("RO gate native write/cancel did not verify: " + "completed=" + !!result.completed + " transport=" + result.transport + " result=" + result.result);
                return;
            }
            if (result.injected) {
                injection = result;
                let probe;
                try {
                    probe = await fs.probeBoundedNativeRead(session.parent + 16, 8, true);
                } catch (error) {
                    timedOut = true;
                    await log("RO gate bounded read setup failed: " + String(error?.message || error) + "; skipping further FS requests");
                    return;
                }
                if (!probe.completed || probe.transport !== 0 || probe.result !== 0 || probe.bytes?.length !== 8) {
                    timedOut = true;
                    await log("RO gate bounded read did not verify: " + "completed=" + !!probe.completed + " transport=" + probe.transport + " result=" + probe.result + "; skipping further FS requests");
                    return;
                }
                await log("RO gate bounded post-injection read completed; " + "continuing settlement checks");
            }
            injectionInFlight = false;
        }
        check(rebuilt, "empty gate step did not settle in 30 checks");
        await log("RO gate stage 6: restoring request marker");
        await fs.compareWrite(row.request, bytes32(4294967295), marker);
        markerActive = false;
        const stable = await inspect(true);
        check(stable.state === 1 && owned.waiters.includes(stable.parent), "parked session is not idle before restore");
        const epoch = u64(await fs.read(stable.parent + 24, 8), 0);
        await log("RO gate stage 7: restoring server wait handle");
        await fs.compareWrite(row.address + 48, bytes32(park), bytes32(row.wait));
        parked = false;
        check(Number(call_rop(signal, BigInt(event.write))) === 0, "restoration event did not signal");
        let retired = false;
        for (let i = 0; i < 30; i++) {
            const current = await inspect(false);
            const nextEpoch = u64(await fs.read(stable.parent + 24, 8), 0);
            if (nextEpoch !== epoch || current.parent !== stable.parent || current.state === 2 || current.state === 3) {
                retired = true;
                break;
            }
        }
        check(Number(call_rop(clear, BigInt(event.read))) === 0, "restoration event did not clear");
        check(retired, "restoration did not retire old wait snapshot");
        restored = true;
        await log("RO empty gate cycle verified: park/rebuild/restore " + "attempts=" + attempts + " event cleared");
    } catch (error) {
        await log("RO empty gate primary failure: " + (error?.message || String(error)));
        throw error;
    } finally {
        if (timedOut || injectionInFlight) {
            await log("RO gate stopped before settlement; no further FS " + "requests or cleanup writes issued. Restart Civ VII.");
            return;
        }
        if (markerActive && marker) {
            const session = await inspect(true);
            check(session.state === 1 && owned.waiters.includes(session.parent) && !(await selections()).includes(row.address), "gate marker is unsettled; cannot restore request buffer");
            const now = await fs.read(row.request, 4);
            if (u32(now, 0) === 4294967295) await fs.compareWrite(row.request, bytes32(4294967295), marker);
        }
        if (parked) {
            const session = await inspect(true);
            check(session.state === 1 && owned.waiters.includes(session.parent) && !(await selections()).includes(row.address), "gate did not settle; unsafe to restore wait word");
            await fs.compareWrite(row.address + 48, bytes32(park), bytes32(row.wait));
            call_rop(signal, BigInt(event.write));
            call_rop(clear, BigInt(event.read));
        }
        if (!restored) await log("RO empty gate did not verify; " + "inspect session before further RO probes");
    }
}
