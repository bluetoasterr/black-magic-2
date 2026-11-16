import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, borrowThreadScheduling: borrowThreadScheduling, call_rop: call_rop, log: log, write32: write32, write64: write64} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO launch preflight: " + message);
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
    const baseline = globalThis.civRoLoaderDomainBaseline;
    check(fs?.status().ready && loader?.handle && donor?.handle && row && server?.handle && pm?.handle && owned?.waiters?.length === 7 && workers?.length === 7 && baseline?.length === 1 && baseline[0].id === 9, "live FS, Loader, donor, PM, or domain baseline missing");
    check(loader.targetDomain === row.domain && loader.targetAddress === fs.status().fsRoot.table + 8 * 48 && donor.domain !== loader.targetDomain && donor.metadata === globalThis.civRoDonorType?.metadata && donor.vptr === globalThis.civRoDonorType?.vptr, "retained object identity changed");
    const rootEntry = await fs.read(loader.targetAddress, 48);
    const donorEntry = await fs.read(donor.entry, 48);
    check(u64(rootEntry, 24) === loader.targetDomain && u64(donorEntry, 24) === donor.domain && u64(donorEntry, 32) === donor.object && u64(donorEntry, 40) === donor.metadata && u64(await fs.read(donor.object, 8), 0) === donor.vptr, "Loader or donor table entry changed");
    const serverRow = await fs.read(row.address, 136);
    check(u64(serverRow, 0) === fs.status().fsRoot.rootVptr - 32120 && u32(serverRow, 48) === row.wait && u32(serverRow, 64) === 1 && owned.waiters.includes(u64(serverRow, 40)), "Loader server no longer idle");
    const waitBuf = allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(server.handle));
    const readiness = Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0;
    check(readiness === 59905, "Loader server has pending request");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    await log("RO launch preflight passed: root=9 donor=0x" + donor.entry.toString(16) + " pm=" + pm.handle + " Loader idle; title not launched");
}
