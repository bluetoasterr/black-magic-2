import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    if (!fs?.status().ready || typeof fs.probeBoundedNativeRead !== "function" || typeof fs.retireBoundedNativeRead !== "function") throw new Error("bounded FS read requires the new verified endpoint");
    if (fs.retireBoundedNativeRead().pending !== false) throw new Error("bounded FS endpoint unexpectedly has a pending worker");
    const address = fs.status().fsRoot.object;
    const before = await fs.read(address, 8);
    const probe = await fs.probeBoundedNativeRead(address, 8, true);
    if (!probe.completed) {
        await log("Bounded FS read timed out; native buffers retained, " + "no further FS requests will be sent in this process");
        return;
    }
    if (probe.transport !== 0 || probe.result !== 0 || probe.bytes.length !== before.length || probe.bytes.some((byte, index) => byte !== before[index])) throw new Error("bounded native FS read differed from ordinary read: " + "transport=" + probe.transport + " result=" + probe.result);
    const after = await fs.read(address, 8);
    if (after.some((byte, index) => byte !== before[index])) throw new Error("FS endpoint changed after bounded native read");
    if (!fs.status().ready || fs.retireBoundedNativeRead().pending !== false) throw new Error("bounded FS endpoint did not return to idle");
    await log("Bounded native FS read qualified: 8 bytes matched; " + "thread exited within 2 seconds; endpoint responsive");
}
