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

function equal(a, b) {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function check(ok, message) {
    if (!ok) throw new Error("RO Loader copy: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint && endpoint.status().ready && !globalThis.civRoLoaderRootCopy, "verified FS endpoint unavailable");
    const root = endpoint.status().fsRoot;
    const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    const targetAddress = root.table + 8 * 48;
    check(targetAddress >= root.captureStart && targetAddress + 48 <= root.captureEnd, "Loader entry outside verified capture");
    const target = await endpoint.read(targetAddress, 48);
    const targetDomain = u64(target, 24);
    const targetObject = u64(target, 32);
    check(u64(target, 40) === root.rootVptr + 22656 && canonical(targetDomain) && canonical(targetObject), "Loader entry identity differs");
    const targetBefore = await endpoint.read(targetObject, 64);
    check(u64(targetBefore, 0) === root.rootVptr + 7840 && u64(targetBefore, 48) === 1 && u32(targetBefore, 56) === 1, "Loader root PID or reference count differs");
    const owned = openDomainSession();
    check(owned?.handle && owned.rootObj > 0 && owned.rootObj <= 16384, "owned domain session failed");
    let copy = 0, restored = false, changed = false;
    let entryAddress = 0, originalPair = null;
    try {
        entryAddress = root.table + (owned.rootObj - 1) * 48;
        check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd && entryAddress !== targetAddress, "owned entry outside verified table or aliases Loader");
        const entry = await endpoint.read(entryAddress, 48);
        const ownDomain = u64(entry, 24);
        const ownObject = u64(entry, 32);
        check(canonical(ownDomain) && canonical(ownObject) && ownDomain !== targetDomain && u64(entry, 40) === root.rootVptr + 22448, "owned table entry identity differs");
        const ownBefore = await endpoint.read(ownObject, 64);
        check(u64(ownBefore, 0) === root.rootVptr && u64(ownBefore, 48) > 1 && u64(ownBefore, 48) < 16777216 && u32(ownBefore, 56) === 1, "owned root PID or reference count differs");
        check(u64(ownBefore, 8) === u64(targetBefore, 8) && u64(target, 40) - u64(entry, 40) === 208, "Loader and owned roots have incompatible layouts");
        const ownWrapper = await endpoint.read(ownDomain, 32);
        const targetWrapper = await endpoint.read(targetDomain, 32);
        for (const wrapper of [ ownWrapper, targetWrapper ]) check(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "root domain wrapper differs");
        originalPair = entry.slice(32, 48);
        const borrowedPair = target.slice(32, 48);
        changed = true;
        await endpoint.compareWrite(entryAddress + 32, originalPair, borrowedPair);
        copy = cloneObject(owned.handle, owned.rootObj);
        check(copy, "Loader root copy failed");
    } finally {
        if (changed && entryAddress && originalPair) {
            const current = await endpoint.read(entryAddress + 32, 16);
            if (!equal(current, originalPair)) await endpoint.compareWrite(entryAddress + 32, current, originalPair);
            restored = equal(await endpoint.read(entryAddress + 32, 16), originalPair);
        } else restored = true;
        if (restored) {
            closeHandle(owned.handle);
        }
    }
    check(restored, "owned table entry did not restore; handles retained");
    try {
        check(equal(await endpoint.read(targetAddress, 48), target), "Loader entry changed");
        const targetAfter = await endpoint.read(targetObject, 64);
        const expected = targetBefore.slice();
        expected[56] = 2;
        check(equal(targetAfter, expected), "Loader root reference count did not rise to two");
        globalThis.civRoLoaderRootCopy = {
            handle: copy,
            targetDomain: targetDomain,
            targetAddress: targetAddress,
            release() {
                if (globalThis.civRoLoaderRootCopy !== this) return;
                closeHandle(this.handle);
                delete globalThis.civRoLoaderRootCopy;
            }
        };
        await log("RO Loader root copy retained: handle=" + copy + " table restored; target refs=2");
    } catch (error) {
        if (copy) closeHandle(copy);
        throw error;
    }
}
