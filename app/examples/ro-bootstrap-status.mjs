import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, call_rop: call_rop, log: log, read32: read32, read64: read64, write32: write32, write64: write64} = coreRuntime;

export async function run() {
    const state = globalThis.civRoBootstrapRun;
    const loader = globalThis.civRoLoaderServerCopy;
    if (!state?.args || !loader?.handle) throw new Error("Bootstrap/Loader status unavailable");
    const a = state.args;
    const operation = Number(read32(a + 408n)) >>> 0;
    const result = Number(read32(a + 412n)) >>> 0;
    const pid = read64(a + 416n);
    const gateRestore = Number(read32(a + 424n)) >>> 0;
    const channelRestore = Number(read32(a + 428n)) >>> 0;
    const buf = allocPage(32);
    write64(buf, 0n);
    write32(buf + 8n, BigInt(loader.handle));
    const readiness = Number(call_rop(SVC_WaitSync, buf, buf + 8n, 1n, 0n)) >>> 0;
    await log("kaiHEN bootstrap status: stage=" + state.stage + " operation=" + operation + " result=0x" + result.toString(16) + " pid=" + pid + " gate=0x" + gateRestore.toString(16) + " channel=0x" + channelRestore.toString(16) + " LoaderReady=0x" + readiness.toString(16));
}
