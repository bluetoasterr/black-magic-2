import coreRuntime, { waitMs } from "../src/core/runtime.mjs";

const {call_rop: call_rop, log: log, read8: read8, sdk_base: sdk_base} = coreRuntime;

function check(ok, message) {
    if (!ok) throw new Error("RO worker cancel: " + message);
}

export async function run() {
    const state = globalThis.civRoWorkers;
    const endpoint = globalThis.civFsMemory;
    check(state?.list?.length === 7 && endpoint?.status().ready, "seven worker handles or verified FS endpoint unavailable");
    const code = "210300d4c0035fd6";
    const functionAddress = sdk_base + 0x168c0cn;
    for (let i = 0; i < code.length / 2; i++) check(Number(read8(functionAddress + BigInt(i))) === parseInt(code.slice(i * 2, i * 2 + 2), 16), "CancelSynchronization wrapper bytes differ");
    const results = [];
    for (const worker of state.list) {
        const result = Number(call_rop(functionAddress, BigInt(worker.handle))) >>> 0;
        results.push(result);
    }
    check(results.every(result => result === 0), "one or more worker cancellations failed: " + results.map(result => "0x" + result.toString(16)).join(","));
    await waitMs(50);
    const root = endpoint.status().fsRoot;
    const bytes = await endpoint.read(root.object, 64);
    check(bytes.length === 64 && endpoint.status().ready, "FS endpoint did not respond after cancellation");
    await log("RO worker cancellation verified: seven results=0" + " FS endpoint responsive");
}
