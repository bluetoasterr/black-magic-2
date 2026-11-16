import coreRuntime from "../src/core/runtime.mjs";

export async function run() {
    const endpoint = globalThis.civFsMemory;
    if (!endpoint) {
        await coreRuntime.log("FS memory handoff is unavailable in this loader");
        return;
    }
    const status = endpoint.status();
    if (!status.ready || !Number.isSafeInteger(status.array) || status.array < 4294967296) throw new Error("Retained FS memory endpoint is not ready");
    const header = await endpoint.read(status.array, 16);
    if (!Array.isArray(header) || header.length !== 16) throw new Error("Retained FS memory read did not return 16 bytes");
    await coreRuntime.log("FS memory handoff verified: array=0x" + status.array.toString(16) + " bytes=" + header.map(byte => byte.toString(16).padStart(2, "0")).join(""));
}
