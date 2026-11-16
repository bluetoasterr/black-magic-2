import coreRuntime from "../src/core/runtime.mjs";

const {cloneObject: cloneObject, closeHandle: closeHandle, log: log, openDomainSession: openDomainSession} = coreRuntime;

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("RO owned domain: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint && endpoint.status().ready, "verified FS session unavailable");
    const root = endpoint.status().fsRoot;
    const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    const owned = openDomainSession();
    check(owned?.handle && owned.rootObj > 0 && owned.rootObj <= 16384, "fresh domain session failed");
    let clone = 0;
    try {
        const entryAddress = root.table + (owned.rootObj - 1) * 48;
        check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "owned entry outside verified capture");
        const entry = await endpoint.read(entryAddress, 48);
        const domain = u64(entry, 24), object = u64(entry, 32);
        check(canonical(domain) && canonical(object), "owned pointers invalid");
        const wrapper = await endpoint.read(domain, 32);
        check(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "owned domain wrapper differs");
        const before = await endpoint.read(object, 64);
        const callerPid = u64(before, 48);
        check(u64(before, 0) === root.rootVptr && callerPid > 1 && callerPid < 16777216 && u32(before, 56) === 1, "owned root type, PID, or reference count differs");
        clone = cloneObject(owned.handle, owned.rootObj);
        check(clone, "owned root clone failed");
        const during = await endpoint.read(object, 64);
        check(u32(during, 56) === 2, "clone did not raise reference count to two");
        check(Number(closeHandle(clone)) === 0, "clone close failed");
        clone = 0;
        const after = await endpoint.read(object, 64);
        check(u32(after, 56) === 1, "clone count did not restore");
        await log("RO owned domain verified: id=" + owned.rootObj + " entry=0x" + entryAddress.toString(16) + " callerPid=" + callerPid + " refs=1->2->1");
    } finally {
        if (clone) closeHandle(clone);
        closeHandle(owned.handle);
    }
}
