import coreRuntime from "../src/core/runtime.mjs";

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function requireMatch(ok, message) {
    if (!ok) throw new Error("RO Loader root: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    requireMatch(endpoint, "verified FS endpoint unavailable");
    const state = endpoint.status();
    requireMatch(state.ready && state.fsRoot, "endpoint not ready");
    const root = state.fsRoot;
    const within = (address, length) => Number.isSafeInteger(address) && address >= root.captureStart && address + length <= root.captureEnd;
    requireMatch(within(root.table, 16384) && within(root.object, 64), "domain table or owned root left verified capture");
    const owned = await endpoint.read(root.object, 64);
    requireMatch(u64(owned, 0) === root.rootVptr && u64(owned, 48) === 1 && u32(owned, 56) === 1, "owned root identity changed");
    const matches = [];
    const observed = [];
    const tableBytes = Math.min(16384 * 48, Math.floor((root.captureEnd - root.table) / 48) * 48);
    requireMatch(tableBytes >= 16384 && tableBytes <= 6291456, "table scan exceeds verified capture");
    const entries = await endpoint.read(root.table, tableBytes);
    for (let offset = 0; offset + 48 <= entries.length; offset += 48) {
        const domain = u64(entries, offset + 24);
        const object = u64(entries, offset + 32);
        const classVptr = u64(entries, offset + 40);
        if (!within(domain, 32) || !within(object, 64)) continue;
        const wrapper = await endpoint.read(domain, 32);
        if (u64(wrapper, 0) !== root.rootVptr + 10464 || u64(wrapper, 8) !== root.rootVptr + 10552 || u64(wrapper, 24) !== root.manager) continue;
        const candidate = await endpoint.read(object, 64);
        const record = {
            id: offset / 48 + 1,
            entry: root.table + offset,
            domain: domain,
            object: object,
            classDelta: classVptr - root.rootVptr,
            objectDelta: u64(candidate, 0) - root.rootVptr,
            pid: u64(candidate, 48),
            refs: u32(candidate, 56)
        };
        if (observed.length < 24 || record.pid === 1) observed.push(record);
        if (record.objectDelta === 7840 && record.pid === 1 && (record.refs === 1 || record.refs === 2)) matches.push(record);
    }
    await coreRuntime.log("RO Loader candidates (scanned " + tableBytes / 48 + " slots): " + observed.map(item => item.id + ":class=" + item.classDelta.toString(16) + ",object=" + item.objectDelta.toString(16) + ",pid=" + item.pid + ",refs=" + item.refs).join("; "));
    requireMatch(matches.length === 1, "expected one native Loader root; found " + matches.length);
    const match = matches[0];
    await coreRuntime.log("RO Loader root located read-only: id=" + match.id + " entry=0x" + match.entry.toString(16) + " object=0x" + match.object.toString(16));
}
