import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

function u32(b, o) {
    return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;
}

function u64(b, o) {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
}

function check(ok, message) {
    if (!ok) throw new Error("RO gate preflight: " + message);
}

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    const event = globalThis.civRoEvent;
    const server = globalThis.civRoServerCopy;
    const workers = globalThis.civRoWorkers;
    check(fs?.status().ready && owned?.row && event?.read && event?.write && server?.handle && workers?.list?.length === 7, "retained gate prerequisites unavailable");
    const b = await fs.read(owned.row.address, 136);
    check(u64(b, 0) === fs.status().fsRoot.rootVptr - 32120 && u64(b, 112) === owned.domain && u32(b, 48) === owned.row.wait && u32(b, 72) === owned.row.receive && u64(b, 96) === owned.row.request && u64(b, 104) === 256 && u64(b, 120) === owned.row.metadata && u32(b, 64) === 1 && owned.waiters.includes(u64(b, 40)), "owned server no longer idle in verified shape");
    const req = await fs.read(owned.row.request, 4);
    check(req.length === 4, "request header unavailable");
    await log("RO gate preflight passed: owned session idle, " + "server copy present, event present, seven workers present; " + "requestHeader=0x" + u32(req, 0).toString(16));
}
