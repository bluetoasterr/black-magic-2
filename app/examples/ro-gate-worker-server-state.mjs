import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, call_rop: call_rop, log: log, write32: write32, write64: write64} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const bytes32 = n => [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];

const check = (ok, message) => {
    if (!ok) throw new Error("RO worker gate: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    const workers = globalThis.civRoWorkers?.list;
    const server = globalThis.civRoServerCopy;
    check(fs?.status().ready && owned?.row && workers?.length === 7 && server?.handle && typeof fs.parkRoWaitNative === "function" && typeof fs.injectRoHolder === "function" && typeof fs.probeBoundedNativeRead === "function" && typeof fs.selectPointerBounded === "function", "verified endpoint or handles unavailable");
    const row = owned.row, park = workers[0].source;
    const before = await fs.read(row.address, 136);
    check(u64(before, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(before, 48) === row.wait && u32(before, 64) === 1 && owned.waiters.includes(u64(before, 40)), "owned session changed before park");
    const waitBuf = allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(server.handle));
    check(Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0 === 59905, "owned session is not idle");
    await log("RO worker gate 1: parking and cancelling seven workers");
    const write = fs.parkRoWaitNative(true, "worker");
    if (!write.completed || write.transport !== 0 || write.result !== 0 || write.cancellations?.length !== 7 || write.cancellations.some(result => result !== 0)) {
        await log("RO worker gate: park did not verify; stop and reboot");
        return;
    }
    const parked = await fs.probeBoundedNativeRead(row.address, 136, true);
    if (!parked.completed || parked.transport !== 0 || parked.result !== 0 || parked.bytes?.length !== 136 || u32(parked.bytes, 48) !== park || u32(parked.bytes, 64) !== 1 || !owned.waiters.includes(u64(parked.bytes, 40))) {
        await log("RO worker gate: parked read timed out or differed; " + "no more FS requests, reboot console");
        return;
    }
    await log("RO worker gate 2: priming empty request marker");
    const original = await fs.read(row.request, 4);
    await fs.compareWrite(row.request, original, bytes32(4294967295));
    const parent = u64(parked.bytes, 40);
    const waiterBefore = await fs.read(parent + 16, 24);
    if (u64(waiterBefore, 0) !== 0) {
        await log("RO worker gate: waiter already selected; stop and reboot");
        return;
    }
    await log("RO worker gate 3: injecting one idle selection");
    const injected = await fs.injectRoHolder({
        server: row.address,
        parent: parent,
        vptr: fs.status().fsRoot.rootVptr - 32120,
        park: park,
        receive: row.receive,
        buffer: row.request,
        domain: row.domain,
        metadata: row.metadata,
        workers: workers.map(worker => worker.handle),
        native: true
    });
    await log("RO worker gate injection returned: injected=" + !!injected.injected + " retry=" + !!injected.retry + " nativeFailure=" + !!injected.nativeFailure);
    if (!injected.injected) {
        await log("RO worker gate: no injection; stop and reboot");
        return;
    }
    const epochBefore = u64(waiterBefore, 8);
    let epochAfter = epochBefore, selection = null;
    for (let i = 0; i < 12; i++) {
        const probe = await fs.probeBoundedNativeRead(parent + 16, 24, true);
        if (!probe.completed || probe.transport !== 0 || probe.result !== 0 || probe.bytes?.length !== 24) {
            await log("RO worker gate: post-injection FS read timed out; " + "no more FS requests, reboot console");
            return;
        }
        selection = u64(probe.bytes, 0);
        epochAfter = u64(probe.bytes, 8);
        if (selection === 0 && epochAfter !== epochBefore) break;
    }
    await log("RO worker gate: post-injection waiter selected=0x" + selection.toString(16) + " epochBefore=" + epochBefore + " epochAfter=" + epochAfter);
    await log("RO worker gate 4: selecting server row with bounded control write");
    const retarget = await fs.selectPointerBounded(row.address);
    if (!retarget.completed || !retarget.verified) {
        await log("RO worker gate: pointer retarget timed out at " + retarget.stage + "; no more FS requests, reboot console");
        return;
    }
    const serverAfter = await fs.probeBoundedNativeRead(row.address, 136, true);
    if (!serverAfter.completed || serverAfter.transport !== 0 || serverAfter.result !== 0 || serverAfter.bytes?.length !== 136) {
        await log("RO worker gate: server-state read timed out; " + "no more FS requests, reboot console");
        return;
    }
    await log("RO worker gate server: state=" + u32(serverAfter.bytes, 64) + " receiveResult=" + u32(serverAfter.bytes, 68) + " parent=0x" + u64(serverAfter.bytes, 40).toString(16) + " parked=" + (u32(serverAfter.bytes, 48) === park) + "; stop and reboot before another test");
}
