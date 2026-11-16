import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, call_rop: call_rop, log: log, sdk_base: sdk_base, write32: write32, write64: write64} = coreRuntime;

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
    const owned = {
        row: globalThis.civRoLoaderRow,
        waiters: globalThis.civRoOwned?.waiters
    };
    const workers = globalThis.civRoWorkers?.list;
    const server = globalThis.civRoLoaderServerCopy;
    check(fs?.status().ready && owned?.row && owned.waiters?.length === 7 && workers?.length === 7 && server?.handle && typeof fs.injectRoHolder === "function" && typeof fs.probeBoundedNativeRead === "function" && typeof fs.selectPointerBounded === "function" && typeof fs.writeSelectedBounded === "function", "verified endpoint or handles unavailable");
    const row = owned.row, park = workers[0].source;
    const before = await fs.read(row.address, 136);
    check(u64(before, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(before, 48) === row.wait && u32(before, 64) === 1 && owned.waiters.includes(u64(before, 40)), "owned session changed before park");
    const waitBuf = allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(server.handle));
    check(Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0 === 59905, "owned session is not idle");
    await log("RO Loader gate 1: parking with worker handle");
    const parkSelected = await fs.selectPointerBounded(row.address + 48);
    if (!parkSelected.completed || !parkSelected.verified) {
        await log("RO Loader gate: park pointer failed; stop and reboot");
        return;
    }
    const write = fs.writeSelectedBounded(row.address + 48, bytes32(park));
    if (!write.completed || write.transport !== 0 || write.result !== 0) {
        await log("RO Loader gate: park write failed; stop and reboot");
        return;
    }
    const parkCancel = workers.map(worker => Number(call_rop(sdk_base + 0x168c0cn, BigInt(worker.handle))) >>> 0);
    if (parkCancel.some(result => result !== 0)) {
        await log("RO Loader gate: park cancellation failed; reboot console");
        return;
    }
    const parkedPointer = await fs.selectPointerBounded(row.address);
    if (!parkedPointer.completed || !parkedPointer.verified) {
        await log("RO Loader gate: parked row pointer failed; reboot console");
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
    if (u32(serverAfter.bytes, 64) !== 1 || u32(serverAfter.bytes, 68) !== 3 || u32(serverAfter.bytes, 48) !== park || !owned.waiters.includes(u64(serverAfter.bytes, 40)) || selection !== 0 || epochAfter === epochBefore) {
        await log("RO worker gate: empty step did not settle; stop and reboot");
        return;
    }
    await log("RO worker gate 5: verifying and restoring marker");
    const markerSelected = await fs.selectPointerBounded(row.request);
    if (!markerSelected.completed || !markerSelected.verified) {
        await log("RO worker gate: marker pointer timed out; stop and reboot");
        return;
    }
    const marker = await fs.probeBoundedNativeRead(row.request, 4, true);
    if (!marker.completed || marker.transport !== 0 || marker.result !== 0 || u32(marker.bytes, 0) !== 4294967295) {
        await log("RO worker gate: marker read timed out or differed; " + "stop and reboot");
        return;
    }
    const markerWrite = fs.writeSelectedBounded(row.request, original);
    if (!markerWrite.completed || markerWrite.transport !== 0 || markerWrite.result !== 0) {
        await log("RO worker gate: marker restore failed; stop and reboot");
        return;
    }
    const markerRestored = await fs.probeBoundedNativeRead(row.request, 4, true);
    if (!markerRestored.completed || markerRestored.transport !== 0 || markerRestored.result !== 0 || u32(markerRestored.bytes, 0) !== u32(original, 0)) {
        await log("RO worker gate: marker restore read failed; " + "stop and reboot");
        return;
    }
    await log("RO worker gate 6: restoring original wait word");
    const rowSelected = await fs.selectPointerBounded(row.address);
    if (!rowSelected.completed || !rowSelected.verified) {
        await log("RO worker gate: row pointer timed out; stop and reboot");
        return;
    }
    const restoreSelected = await fs.selectPointerBounded(row.address + 48);
    if (!restoreSelected.completed || !restoreSelected.verified) {
        await log("RO Loader gate: restore pointer failed; reboot console");
        return;
    }
    const restore = fs.writeSelectedBounded(row.address + 48, bytes32(row.wait));
    if (!restore.completed || restore.transport !== 0 || restore.result !== 0) {
        await log("RO worker gate: wait restore failed; stop and reboot");
        return;
    }
    const waitRestored = await fs.probeBoundedNativeRead(row.address + 48, 4, true);
    if (!waitRestored.completed || waitRestored.transport !== 0 || waitRestored.result !== 0 || u32(waitRestored.bytes, 0) !== row.wait) {
        await log("RO worker gate: wait restore read failed; " + "stop and reboot");
        return;
    }
    const cancel = sdk_base + 0x168c0cn;
    const cancellations = workers.map(worker => Number(call_rop(cancel, BigInt(worker.handle))) >>> 0);
    if (cancellations.some(result => result !== 0)) {
        await log("RO worker gate: restore cancellation failed; " + "stop and reboot");
        return;
    }
    const finalPointer = await fs.selectPointerBounded(row.address);
    if (!finalPointer.completed || !finalPointer.verified) {
        await log("RO Loader gate: final row pointer failed; reboot console");
        return;
    }
    const final = await fs.probeBoundedNativeRead(row.address, 136, true);
    if (!final.completed || final.transport !== 0 || final.result !== 0 || final.bytes?.length !== 136) {
        await log("RO worker gate: final server read timed out; " + "stop and reboot");
        return;
    }
    if (u32(final.bytes, 48) !== row.wait || u32(final.bytes, 64) !== 1 || !owned.waiters.includes(u64(final.bytes, 40))) {
        await log("RO worker gate: restored row shape differs; reboot console");
        return;
    }
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(server.handle));
    if (Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0 !== 59905) {
        await log("RO worker gate: restored server is not idle; reboot console");
        return;
    }
    await log("RO worker gate 7: retiring old wait snapshot");
    const secondMarker = await fs.selectPointerBounded(row.request);
    if (!secondMarker.completed || !secondMarker.verified) {
        await log("RO worker gate: second marker pointer failed; reboot console");
        return;
    }
    const markerBefore = await fs.probeBoundedNativeRead(row.request, 4, true);
    if (!markerBefore.completed || markerBefore.transport !== 0 || markerBefore.result !== 0 || u32(markerBefore.bytes, 0) !== u32(original, 0)) {
        await log("RO worker gate: second marker preimage differs; reboot console");
        return;
    }
    const primeAgain = fs.writeSelectedBounded(row.request, bytes32(4294967295));
    if (!primeAgain.completed || primeAgain.transport !== 0 || primeAgain.result !== 0) {
        await log("RO worker gate: second marker write failed; reboot console");
        return;
    }
    const parent2 = u64(final.bytes, 40);
    const waiter2 = await fs.selectPointerBounded(parent2 + 16);
    if (!waiter2.completed || !waiter2.verified) {
        await log("RO worker gate: second waiter pointer failed; reboot console");
        return;
    }
    const before2 = await fs.probeBoundedNativeRead(parent2 + 16, 24, true);
    if (!before2.completed || before2.transport !== 0 || before2.result !== 0 || u64(before2.bytes, 0) !== 0) {
        await log("RO worker gate: second waiter is busy; reboot console");
        return;
    }
    const epoch2 = u64(before2.bytes, 8);
    const second = await fs.injectRoHolder({
        server: row.address,
        parent: parent2,
        vptr: fs.status().fsRoot.rootVptr - 32120,
        park: row.wait,
        receive: row.receive,
        buffer: row.request,
        domain: row.domain,
        metadata: row.metadata,
        workers: workers.map(worker => worker.handle),
        native: true
    });
    if (!second.injected) {
        await log("RO worker gate: second injection did not verify; " + "reboot console");
        return;
    }
    let selected2 = null, epoch2After = epoch2;
    for (let i = 0; i < 12; i++) {
        const probe = await fs.probeBoundedNativeRead(parent2 + 16, 24, true);
        if (!probe.completed || probe.transport !== 0 || probe.result !== 0 || probe.bytes?.length !== 24) {
            await log("RO worker gate: second waiter read timed out; " + "reboot console");
            return;
        }
        selected2 = u64(probe.bytes, 0);
        epoch2After = u64(probe.bytes, 8);
        if (selected2 === 0 && epoch2After !== epoch2) break;
    }
    const rowAgain = await fs.selectPointerBounded(row.address);
    if (!rowAgain.completed || !rowAgain.verified) {
        await log("RO worker gate: final row pointer failed; reboot console");
        return;
    }
    const settled2 = await fs.probeBoundedNativeRead(row.address, 136, true);
    if (!settled2.completed || settled2.transport !== 0 || settled2.result !== 0 || settled2.bytes?.length !== 136 || selected2 !== 0 || epoch2After === epoch2 || u32(settled2.bytes, 48) !== row.wait || u32(settled2.bytes, 64) !== 1 || u32(settled2.bytes, 68) !== 3 || !owned.waiters.includes(u64(settled2.bytes, 40))) {
        await log("RO worker gate: old snapshot did not settle; " + "reboot console");
        return;
    }
    const markerAgain = await fs.selectPointerBounded(row.request);
    if (!markerAgain.completed || !markerAgain.verified) {
        await log("RO worker gate: final marker pointer failed; reboot console");
        return;
    }
    const marker2 = await fs.probeBoundedNativeRead(row.request, 4, true);
    if (!marker2.completed || marker2.transport !== 0 || marker2.result !== 0 || u32(marker2.bytes, 0) !== 4294967295) {
        await log("RO worker gate: final marker changed; reboot console");
        return;
    }
    const restore2 = fs.writeSelectedBounded(row.request, original);
    if (!restore2.completed || restore2.transport !== 0 || restore2.result !== 0) {
        await log("RO worker gate: final marker restore failed; reboot console");
        return;
    }
    const lastMarker = await fs.probeBoundedNativeRead(row.request, 4, true);
    if (!lastMarker.completed || lastMarker.transport !== 0 || lastMarker.result !== 0 || u32(lastMarker.bytes, 0) !== u32(original, 0)) {
        await log("RO worker gate: final marker readback failed; " + "reboot console");
        return;
    }
    await log("RO worker gate fully restored: two empty steps settled; " + "wait word and request marker match originals");
}
