import coreRuntime from "../src/core/runtime.mjs";

const {call_rop: call_rop, log: log, read32: read32, read64: read64, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const state = globalThis.civRoBootstrapRun;
    if (!state?.thread || state.stage !== "running") throw new Error("No running kaiHEN bootstrap thread");
    const waitable = state.thread & ~7n;
    const status = Number(call_rop(sdk_base + 1274128n, waitable, 0n, 0n, 0n)) >>> 0;
    await log("kaiHEN bootstrap poll: TryWaitThread=" + status);
    if (status === 0) return;
    if (status !== 1) throw new Error("Unexpected bootstrap thread state");
    const joined = Number(call_rop(sdk_base + 1320064n, state.thread, state.slots + 8n, 0n, 0n)) >>> 0;
    if (joined !== 0) throw new Error("pthread_join=0x" + joined.toString(16));
    state.stage = "joined";
    const args = state.args;
    const operation = Number(read32(args + 408n)) >>> 0;
    const result = Number(read32(args + 412n)) >>> 0;
    const pid = read64(args + 416n);
    const gateRestore = Number(read32(args + 424n)) >>> 0;
    const channelRestore = Number(read32(args + 428n)) >>> 0;
    const returned = read64(state.slots + 8n);
    state.result = {
        operation: operation,
        result: result,
        pid: pid,
        gateRestore: gateRestore,
        channelRestore: channelRestore,
        returned: returned
    };
    await log("kaiHEN bootstrap result: operation=" + operation + " result=0x" + result.toString(16) + " pid=" + pid + " gate=0x" + gateRestore.toString(16) + " channel=0x" + channelRestore.toString(16) + " return=0x" + returned.toString(16));
    if (operation === 10 && result === 0 && returned === 0n && (gateRestore === 0 || gateRestore === 59905) && channelRestore === 0) state.stage = "verified";
}
