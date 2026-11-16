import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, call_rop: call_rop, log: log, write32: write32, write64: write64} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const row = globalThis.civRoLoaderRow;
    const owned = globalThis.civRoOwned;
    const copy = globalThis.civRoLoaderServerCopy;
    if (!fs?.status().ready || !row || !copy?.handle || owned?.waiters?.length !== 7) throw new Error("Loader postflight prerequisites unavailable");
    const bytes = await fs.read(row.address, 136);
    const header = await fs.read(row.request, 4);
    const buf = allocPage(32);
    write64(buf, 0n);
    write32(buf + 8n, BigInt(copy.handle));
    const readiness = Number(call_rop(SVC_WaitSync, buf, buf + 8n, 1n, 0n)) >>> 0;
    await log("RO Loader postflight fields: vptr=" + (u64(bytes, 0) === fs.status().fsRoot.rootVptr - 32120) + " wait=" + u32(bytes, 48).toString(16) + " expectedWait=" + row.wait.toString(16) + " state=" + u32(bytes, 64) + " parentKnown=" + owned.waiters.includes(u64(bytes, 40)) + " header=" + u32(header, 0).toString(16) + " readiness=" + readiness.toString(16));
    if (u64(bytes, 0) !== fs.status().fsRoot.rootVptr - 32120 || u32(bytes, 48) !== row.wait || u32(bytes, 64) !== 1 || !owned.waiters.includes(u64(bytes, 40)) || u32(header, 0) === 4294967295 || readiness !== 59905) return;
    await log("RO Loader postflight passed: idle, wait handle restored, " + "request marker cleared");
}
