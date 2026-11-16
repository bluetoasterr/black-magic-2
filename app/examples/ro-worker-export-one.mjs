import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, sdk_base: sdk_base, prepPacket: prepPacket, readDomainObjects: readDomainObjects, sendDomainCmd: sendDomainCmd, sendIPC: sendIPC, write32: write32, write64: write64, write8: write8, read8: read8, read64: read64} = coreRuntime;

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
    if (!ok) throw new Error("RO worker export: " + message);
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
    const sentinel = sdk + 2096, seen = new Set, groups = new Map;
    let at = u64(header, 0), count = 0;
    while (at !== sentinel) {
        check(canonical(at) && !seen.has(at) && count < 128, "FS thread ring differs");
        seen.add(at);
        const node = await endpoint.read(at, 448);
        if (node[64] === 3 && u64(node, 88) === 49152 && u64(node, 96) === 0) {
            const entry = u64(node, 104);
            const group = groups.get(entry) || [];
            group.push({
                handle: u32(node, 432),
                id: u64(node, 440)
            });
            groups.set(entry, group);
        }
        at = u64(node, 0);
        count++;
    }
    const matches = [ ...groups.values() ].filter(rows => rows.length === 7);
    check(matches.length === 1, "seven-worker group is not unique");
    const worker = matches[0][0];
    const sourceHandle = worker.handle;
    check(sourceHandle >= 32768 && sourceHandle < 33554432 && worker.id > 0, "worker handle or ID invalid");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let domainId = 0, notifierHandle = 0, exportedHandle = 0;
    const returnedHandles = [];
    let handleField = 0, original = null, replacement = bytes32(sourceHandle);
    let replacementAttempted = false, restored = false;
    let observedId = 0;
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
        check(existingHandle >= 32768 && existingHandle < 33554432 && existingHandle !== sourceHandle, "notifier event handle invalid or aliases worker");
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
        check(transport === 0 && reply.result === 0 && reply.copies.length === 1 && reply.moves.length === 0 && exportedHandle >= 32768, "worker handle copy failed");
        const threadCode = "e00f1ff8a10400d4e20340f9410000f9ff430091c0035fd6";
        for (let i = 0; i < threadCode.length / 2; i++) check(Number(read8(sdk_base + 0x168c74n + BigInt(i))) === parseInt(threadCode.slice(i * 2, i * 2 + 2), 16), "Civ VII thread-ID wrapper bytes differ");
        const output = allocPage(16);
        write64(output, 0n);
        const result = call_rop(sdk_base + 0x168c74n, output, BigInt(exportedHandle));
        observedId = Number(read64(output));
        check(result === 0n && observedId === worker.id, "copied worker thread ID differs: result=0x" + BigInt(result).toString(16) + " expected=" + worker.id + " actual=" + observedId);
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
    await log("RO FS worker handle verified: source=0x" + sourceHandle.toString(16) + " copy=" + exportedHandle + " threadId=" + observedId + " notifier restored and handles closed");
}
