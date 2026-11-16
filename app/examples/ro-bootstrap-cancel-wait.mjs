import coreRuntime from "../src/core/runtime.mjs";

const {call_rop: call_rop, log: log, read8: read8, read32: read32, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const run = globalThis.civRoBootstrapRun;
    if (run?.stage !== "running" || !run.thread) throw new Error("No running bootstrap thread");
    const threadType = run.thread & ~7n;
    const handle = Number(read32(threadType + 0x1b0n)) >>> 0;
    if (handle < 32768 || handle >= 268435456) throw new Error("Bootstrap kernel thread handle differs");
    const address = sdk_base + 0x168c0cn;
    const signature = "210300d4c0035fd6";
    for (let i = 0; i < signature.length / 2; i++) if (Number(read8(address + BigInt(i))) !== parseInt(signature.slice(i * 2, i * 2 + 2), 16)) throw new Error("CancelSynchronization wrapper differs");
    const rc = Number(call_rop(address, BigInt(handle))) >>> 0;
    await log("kaiHEN bootstrap wait cancellation: thread=" + handle + " result=0x" + rc.toString(16));
}
