import coreRuntime from "../src/core/runtime.mjs";

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function requireMatch(condition, message) {
    if (!condition) throw new Error("RO layout baseline: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    requireMatch(endpoint, "FS memory handoff unavailable");
    const state = endpoint.status();
    requireMatch(state.ready && state.fsRoot, "endpoint or layout unavailable");
    const root = state.fsRoot;
    requireMatch(root.captureStart >= 4294967296 && root.captureEnd > root.captureStart && root.captureEnd - root.captureStart <= 6291456, "capture bounds are invalid");
    for (const [address, length] of [ [ root.manager, 32 ], [ root.entry, 48 ], [ root.domain, 32 ], [ root.object, 64 ] ]) requireMatch(address >= root.captureStart && address + length <= root.captureEnd, "a root structure left the verified capture");
    const manager = await endpoint.read(root.manager, 32);
    requireMatch(u32(manager, 16) === 16384 && u64(manager, 24) === root.table, "domain manager changed");
    const entry = await endpoint.read(root.entry, 48);
    const entryClassVptr = u64(entry, 40);
    requireMatch(u64(entry, 24) === root.domain && u64(entry, 32) === root.object && entryClassVptr >= root.rootVptr && entryClassVptr <= root.rootVptr + 22656, "root table entry changed");
    const domain = await endpoint.read(root.domain, 32);
    requireMatch(u64(domain, 0) === root.rootVptr + 10464 && u64(domain, 8) === root.rootVptr + 10552 && u64(domain, 24) === root.manager, "root domain changed");
    const object = await endpoint.read(root.object, 64);
    requireMatch(u64(object, 0) === root.rootVptr && u64(object, 48) === 1 && u32(object, 56) > 0 && u32(object, 56) < 16777216, "promoted root object changed");
    await coreRuntime.log("RO layout baseline verified: manager=0x" + root.manager.toString(16) + " root=0x" + root.object.toString(16));
}
