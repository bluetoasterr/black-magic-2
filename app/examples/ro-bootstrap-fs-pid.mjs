import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, call_rop: call_rop, log: log, read64: read64, write64: write64} = coreRuntime;

export async function run() {
    const map = globalThis.civRoBootstrapMap;
    const process = globalThis.civRoFsProcessCopy;
    if (!map?.queryVerified || !process?.handle) throw new Error("Mapped bootstrap or FS process unavailable");
    const output = allocPage(32);
    write64(output, 0n);
    const veneer = map.entry + 0x6138n;
    const rc = Number(call_rop(veneer, output, BigInt(process.handle), 0n, 0n)) >>> 0;
    const pid = read64(output);
    await log("FS GetProcessId via mapped veneer: rc=0x" + rc.toString(16) + " pid=" + pid);
    if (rc !== 0 || pid === 0n) throw new Error("FS process ID query failed");
    globalThis.civRoFsPid = pid;
}
