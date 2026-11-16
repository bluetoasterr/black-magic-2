import coreRuntime from "../src/core/runtime.mjs";

function u16(bytes, offset) {
    return bytes[offset] | bytes[offset + 1] << 8;
}

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("FS SM layout: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint, "FS memory handoff unavailable");
    const state = endpoint.status();
    check(state.ready && state.fsRoot, "verified FS session unavailable");
    const root = state.fsRoot;
    check(root.captureEnd - root.captureStart === 5079040, "capture size differs from kaiHEN target");
    const sdk = root.captureStart + 5242880;
    check(Number.isSafeInteger(sdk) && sdk % 4096 === 0 && sdk >= 4294967296 && sdk < 549755813888, "FS SDK page address is invalid");
    const vptrDistance = sdk - root.rootVptr;
    check(Math.abs(vptrDistance - 15961056) <= 65536, "FS root vtable does not identify the expected SDK neighborhood");
    const header = await endpoint.read(sdk + 2096, 32);
    check(u64(header, 8) === sdk + 1640 && u64(header, 0) >= 4294967296 && u64(header, 0) < 549755813888 && u32(header, 24) > 0 && u32(header, 24) <= 128, "FS SDK thread-ring header differs");
    const address = sdk + 4768;
    const bytes = await endpoint.read(address - 8, 24);
    const guard = u64(bytes, 0), handle = u32(bytes, 8);
    const initialized = guard === address && u32(bytes, 12) === 0 && u16(bytes, 16) === 257 && handle >= 32768 && handle < 33554432;
    await coreRuntime.log("FS SM candidate: " + (initialized ? "layout verified" : "layout differs") + " sdk=0x" + sdk.toString(16) + " handle=0x" + handle.toString(16) + " guardMatch=" + (guard === address) + " flag=0x" + u16(bytes, 16).toString(16));
}
