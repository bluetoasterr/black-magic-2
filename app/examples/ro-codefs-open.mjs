import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, ipcGetEntryType: ipcGetEntryType, openDomainSession: openDomainSession, prepPacket: prepPacket, read8: read8, sendIPC: sendIPC, write8: write8, write32: write32, write64: write64} = coreRuntime;

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
    check(endpoint && endpoint.status().ready, "verified FS endpoint unavailable");
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
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    const owned = openDomainSession();
    check(owned?.handle && owned.rootObj > 0 && owned.rootObj <= 16384, "owned domain session failed");
    let copy = 0, codeFs = 0, restored = false, changed = false;
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
        const swapped = await endpoint.read(entryAddress + 32, 16);
        check(equal(swapped, borrowedPair), "owned entry changed before restoration");
        await endpoint.compareWrite(entryAddress + 32, borrowedPair, originalPair);
        restored = true;
        changed = false;
        const infoSize = 420;
        const infoBuf = allocPage(8192);
        for (let i = 0; i < infoSize + 32; i++) write8(infoBuf + BigInt(i), 0x5cn);
        const packet = allocPage(8192);
        prepPacket(packet, (4 | 1 << 24) >>> 0, 12, []);
        write32(packet + 0x08n, BigInt(infoSize));
        write32(packet + 0x0cn, BigInt(Number(infoBuf & 0xffffffffn)));
        write32(packet + 0x10n, BigInt((Number(infoBuf >> 36n & 7n) << 2 | Number(infoBuf >> 32n & 15n) << 28) >>> 0));
        write32(packet + 0x20n, 0x49434653n);
        write32(packet + 0x28n, 0n);
        write8(packet + 0x30n, 1n);
        write8(packet + 0x31n, 3n);
        write64(packet + 0x38n, 0x0400000000000037n);
        const transport = Number(sendIPC(copy, packet)) >>> 0;
        const reply = cmifReply(packet);
        if (reply.moves.length === 1) codeFs = reply.moves[0];
        for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle && handle !== codeFs) closeHandle(handle);
        check(transport === 0 && reply.result === 0 && reply.moves.length === 1 && reply.copies.length === 0 && codeFs >= 32768, "OpenCodeFileSystem failed: transport=0x" + transport.toString(16) + " result=0x" + reply.result.toString(16));
        for (let i = 0; i < 32; i++) check(Number(read8(infoBuf + BigInt(infoSize + i))) === 92, "CodeFS info exceeded its output buffer");
        const npdm = ipcGetEntryType(codeFs, "/main.npdm");
        check(npdm.error === 0 && npdm.type === 1, "CodeFS main.npdm is not a readable file: result=0x" + (Number(npdm.error) >>> 0).toString(16) + " type=" + npdm.type);
    } finally {
        if (changed && entryAddress && originalPair) {
            const current = await endpoint.read(entryAddress + 32, 16);
            if (!equal(current, originalPair)) await endpoint.compareWrite(entryAddress + 32, current, originalPair);
            restored = equal(await endpoint.read(entryAddress + 32, 16), originalPair);
        } else restored = true;
        if (restored) {
            if (codeFs) closeHandle(codeFs);
            if (copy) closeHandle(copy);
            closeHandle(owned.handle);
        }
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
    check(restored, "owned table entry did not restore; handles retained");
    check(equal(await endpoint.read(targetAddress, 48), target), "Loader entry changed");
    const targetAfter = await endpoint.read(targetObject, 64);
    check(equal(targetAfter, targetBefore), "Loader root did not return to original bytes");
    await log("RO CodeFS opened read-only: title=0x0400000000000037" + " copiedLoader=" + copy + " codeFs=" + codeFs + " table restored; handles closed");
}
