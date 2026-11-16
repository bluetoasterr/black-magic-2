import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, call_rop: call_rop, log: log, write32: write32, write64: write64} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(b[o + i]);
    return Number(value);
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO no-cancel park: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    const event = globalThis.civRoEvent;
    const server = globalThis.civRoServerCopy;
    check(fs?.status().ready && owned?.row && event?.sourceHandle && server?.handle && typeof fs.parkRoWaitNative === "function" && typeof fs.restoreRoWaitNative === "function" && typeof fs.probeBoundedNativeRead === "function", "verified endpoint or prerequisites missing");
    const row = owned.row, park = event.sourceHandle;
    const before = await fs.read(row.address, 136);
    check(u64(before, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(before, 48) === row.wait && u32(before, 64) === 1 && owned.waiters.includes(u64(before, 40)), "owned server changed before park");
    const waitBuf = allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(server.handle));
    check(Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0 === 59905, "owned server is not idle");
    await log("RO no-cancel stage 1: writing wait word without cancellation");
    const write = fs.parkRoWaitNative(false);
    if (!write.completed || write.transport !== 0 || write.result !== 0) {
        await log("RO no-cancel park write did not verify; stop and reboot");
        return;
    }
    const verify = await fs.probeBoundedNativeRead(row.address + 48, 4, true);
    if (!verify.completed || verify.transport !== 0 || verify.result !== 0 || u32(verify.bytes, 0) !== park) {
        await log("RO no-cancel park read timed out or differed; " + "no further FS requests, reboot console");
        return;
    }
    await log("RO no-cancel stage 2: parked word read back; restoring");
    const restore = fs.restoreRoWaitNative();
    if (!restore.completed || restore.transport !== 0 || restore.result !== 0) {
        await log("RO no-cancel restore did not verify; reboot console");
        return;
    }
    const restored = await fs.probeBoundedNativeRead(row.address + 48, 4, true);
    if (!restored.completed || restored.transport !== 0 || restored.result !== 0 || u32(restored.bytes, 0) !== row.wait) {
        await log("RO no-cancel restoration read timed out or differed; " + "reboot console");
        return;
    }
    await log("RO no-cancel park/restore verified by bounded reads");
}
