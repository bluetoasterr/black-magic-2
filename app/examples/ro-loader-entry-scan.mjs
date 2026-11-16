import coreRuntime from "../src/core/runtime.mjs";

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("RO Loader entry scan: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint, "FS memory handoff unavailable");
    const state = endpoint.status();
    check(state.ready && state.fsRoot, "verified FS session unavailable");
    const root = state.fsRoot;
    const length = Math.min(16384 * 48, Math.floor((root.captureEnd - root.table) / 48) * 48);
    check(root.table >= root.captureStart && length >= 16384 && length <= 6291456, "domain table outside verified capture");
    const bytes = await endpoint.read(root.table, length);
    const near = [], exact = [], counts = {};
    for (let offset = 0; offset + 48 <= bytes.length; offset += 48) {
        const classVptr = u64(bytes, offset + 40);
        const delta = classVptr - root.rootVptr;
        if (delta < 22272 || delta > 22784) continue;
        const id = offset / 48 + 1;
        const record = {
            id: id,
            delta: delta,
            domain: u64(bytes, offset + 24),
            object: u64(bytes, offset + 32)
        };
        counts[delta.toString(16)] = (counts[delta.toString(16)] || 0) + 1;
        if (near.length < 40) near.push(record);
        if (delta === 22656) exact.push(record);
    }
    await coreRuntime.log("RO Loader entry scan: slots=" + length / 48 + " exact5880=" + exact.length + " classes=" + JSON.stringify(counts) + " entries=" + near.map(item => item.id + ":+0x" + item.delta.toString(16) + "@0x" + item.object.toString(16)).join(","));
}
