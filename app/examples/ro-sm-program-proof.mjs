import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, read32: read32, readDomainObjects: readDomainObjects, sendDomainCmd: sendDomainCmd, sendIPC: sendIPC, write32: write32, write64: write64, write8: write8} = coreRuntime;

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function bytes32(value) {
    return [ value & 255, value >>> 8 & 255, value >>> 16 & 255, value >>> 24 & 255 ];
}

function equal(a, b) {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function check(ok, message) {
    if (!ok) throw new Error("RO SM export: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    check(endpoint && session && endpoint.status().ready, "verified FS session unavailable");
    const root = endpoint.status().fsRoot;
    check(root && root.captureEnd - root.captureStart === 5079040, "FS capture geometry differs");
    const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    const sdk = root.captureStart + 5242880;
    check(sdk % 4096 === 0 && Math.abs(sdk - root.rootVptr - 15961056) <= 65536, "FS SDK page differs from validated root vtable");
    const header = await endpoint.read(sdk + 2096, 32);
    check(u64(header, 8) === sdk + 1640 && u32(header, 24) > 0 && u32(header, 24) <= 128, "FS SDK thread ring differs");
    const smAddress = sdk + 4768;
    const sm = await endpoint.read(smAddress - 8, 24);
    const smHandle = u32(sm, 8);
    check(u64(sm, 0) === smAddress && u32(sm, 12) === 0 && (sm[16] | sm[17] << 8) === 257 && smHandle >= 32768 && smHandle < 33554432, "FS SM handle identity differs");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let domainId = 0, notifierHandle = 0, exportedHandle = 0;
    const returnedHandles = [];
    let handleField = 0, original = null, replacement = bytes32(smHandle);
    let replacementAttempted = false, restored = false;
    let pmResult = null, pmHandle = 0;
    try {
        const openPacket = allocPage(8192);
        const opened = sendDomainCmd(session.handle, session.rootObj, 510, openPacket, () => {}, 0);
        check(opened.ok && opened.transport === 0 && opened.result === 0 && opened.objCount === 1, "notifier open failed");
        const objects = readDomainObjects(openPacket, 1, 0);
        check(objects.length === 1 && objects[0] > 0, "notifier domain ID missing");
        domainId = objects[0];
        notifierHandle = cloneObject(session.handle, domainId);
        check(notifierHandle, "notifier clone failed");
        const entryAddress = root.table + (domainId - 1) * 48;
        check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "notifier table entry outside capture");
        const entry = await endpoint.read(entryAddress, 48);
        const domain = u64(entry, 24), object = u64(entry, 32);
        check(canonical(domain) && canonical(object), "notifier pointers invalid");
        const wrapper = await endpoint.read(domain, 32);
        check(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "notifier wrapper identity differs");
        const notifier = await endpoint.read(object, 24);
        check(u64(notifier, 0) === root.rootVptr - 5824 && u32(notifier, 16) === 2, "notifier object identity differs");
        const backendAddress = u64(notifier, 8);
        check(canonical(backendAddress), "notifier backend invalid");
        const backend = await endpoint.read(backendAddress, 72);
        check(u64(backend, 16) === backendAddress + 16 && u64(backend, 24) === backendAddress + 16, "notifier event list differs");
        const existingHandle = u32(backend, 36);
        check(existingHandle >= 32768 && existingHandle < 33554432 && existingHandle !== smHandle, "notifier event handle invalid or aliases SM");
        handleField = backendAddress + 36;
        original = bytes32(existingHandle);
        check(equal(await endpoint.read(handleField, 4), original), "notifier handle preimage changed");
        replacementAttempted = true;
        await endpoint.compareWrite(handleField, original, replacement);
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
        const transport = Number(sendIPC(notifierHandle, packet)) >>> 0;
        const reply = cmifReply(packet);
        for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle) returnedHandles.push(handle);
        if (reply.copies.length === 1) exportedHandle = reply.copies[0];
        check(transport === 0 && reply.result === 0 && reply.copies.length === 1 && reply.moves.length === 0 && exportedHandle >= 32768, "SM handle copy failed");
        const smPacket = allocPage(8192);
        prepPacket(smPacket, 17, 2, []);
        const name = "pm:shell";
        for (let i = 0; i < name.length; i++) write8(smPacket + BigInt(8 + i), BigInt(name.charCodeAt(i)));
        const smTransport = Number(sendIPC(exportedHandle, smPacket)) >>> 0;
        check(smTransport === 0, "exported SM transport failed: 0x" + smTransport.toString(16));
        const first = Number(read32(smPacket)) >>> 0;
        const second = Number(read32(smPacket + 4n)) >>> 0;
        check(first >>> 16 === 0 && (second & 1023) >= 1, "exported SM reply shape differs");
        let at = 8;
        const moves = [];
        if (second >>> 31) {
            const special = Number(read32(smPacket + BigInt(at))) >>> 0;
            at += 4;
            check(!(special & 1) && (special >>> 1 & 15) === 0, "unexpected SM reply PID or copies");
            const moveCount = special >>> 5 & 15;
            for (let i = 0; i < moveCount; i++, at += 4) {
                const handle = Number(read32(smPacket + BigInt(at))) >>> 0;
                if (handle) {
                    moves.push(handle);
                    returnedHandles.push(handle);
                }
            }
        }
        pmResult = Number(read32(smPacket + BigInt(at))) >>> 0;
        check(pmResult === 0 && moves.length === 1, "pm:shell lookup failed: result=0x" + pmResult.toString(16) + " moves=" + moves.length);
        pmHandle = moves[0];
        const programPacket = allocPage(8192);
        prepPacket(programPacket, 4, 10, [ [ 16, 1229145683 ], [ 24, 12 ] ]);
        write64(programPacket + 0x20n, 0x0100c3601518c000n);
        const programTransport = Number(sendIPC(pmHandle, programPacket)) >>> 0;
        const programReply = cmifReply(programPacket);
        check(programTransport === 0 && programReply.result === 0, "PM process-ID query failed: transport=0x" + programTransport.toString(16) + " result=0x" + programReply.result.toString(16));
    } finally {
        try {
            if (replacementAttempted && handleField && original) {
                const current = await endpoint.read(handleField, 4);
                if (!equal(current, original)) await endpoint.compareWrite(handleField, current, original);
                restored = equal(await endpoint.read(handleField, 4), original);
            }
        } finally {
            for (const handle of returnedHandles) closeHandle(handle);
            if (notifierHandle) closeHandle(notifierHandle);
            if (domainId) {
                const closePacket = allocPage(8192);
                prepPacket(closePacket, 4, 8, []);
                write8(closePacket + 0x10n, 2n);
                write32(closePacket + 0x14n, BigInt(domainId));
                sendIPC(session.handle, closePacket);
            }
            if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
        }
    }
    check(restored, "notifier handle field did not restore");
    await log("RO PM identity query verified: source=0x" + smHandle.toString(16) + " copy=" + exportedHandle + " pm:shell=" + pmHandle + " CivVII title=0x0100c3601518c000" + " notifier restored and handles closed");
}
