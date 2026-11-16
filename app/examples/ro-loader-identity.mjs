import coreRuntime from "../src/core/runtime.mjs";

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("RO Loader identity: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint && endpoint.status().ready, "verified FS endpoint unavailable");
    const root = endpoint.status().fsRoot;
    const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    const entryAddress = root.table + 8 * 48;
    check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "Loader entry outside verified capture");
    const entry = await endpoint.read(entryAddress, 48);
    const domain = u64(entry, 24), object = u64(entry, 32);
    check(u64(entry, 40) === root.rootVptr + 22656 && canonical(domain) && canonical(object), "Loader entry class or pointers differ");
    const wrapper = await endpoint.read(domain, 32);
    check(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "Loader domain wrapper differs");
    const value = await endpoint.read(object, 64);
    check(u64(value, 0) === root.rootVptr + 7840 && u64(value, 48) === 1 && (u32(value, 56) === 1 || u32(value, 56) === 2), "Loader root object identity differs: vptrDelta=0x" + (u64(value, 0) - root.rootVptr).toString(16) + " pid=" + u64(value, 48) + " refs=" + u32(value, 56));
    await coreRuntime.log("RO Loader root verified: id=9 entry=0x" + entryAddress.toString(16) + " object=0x" + object.toString(16) + " refs=" + u32(value, 56));
}
