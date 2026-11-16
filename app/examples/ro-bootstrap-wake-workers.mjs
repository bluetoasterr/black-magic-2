import coreRuntime from "../src/core/runtime.mjs";

const {call_rop: call_rop, log: log, read8: read8, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const run = globalThis.civRoBootstrapRun;
    const workers = globalThis.civRoWorkers?.list;
    if (run?.stage !== "running" || workers?.length !== 7) throw new Error("Bootstrap or FS worker state unavailable");
    const address = sdk_base + 0x168c0cn;
    const signature = "210300d4c0035fd6";
    for (let i = 0; i < signature.length / 2; i++) if (Number(read8(address + BigInt(i))) !== parseInt(signature.slice(i * 2, i * 2 + 2), 16)) throw new Error("CancelSynchronization wrapper differs");
    const results = workers.map(worker => Number(call_rop(address, BigInt(worker.handle))) >>> 0);
    await log("kaiHEN bootstrap worker wake: " + results.map(value => "0x" + value.toString(16)).join(","));
    if (results.some(value => value !== 0)) throw new Error("One FS worker cancellation failed");
}
