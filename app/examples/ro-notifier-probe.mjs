import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, readDomainObjects: readDomainObjects, sendDomainCmd: sendDomainCmd, sendIPC: sendIPC, write32: write32, write8: write8} = coreRuntime;

function requireMatch(ok, message) {
    if (!ok) throw new Error("RO notifier: " + message);
}

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    requireMatch(endpoint && endpoint.status().ready && session, "verified FS session unavailable");
    const root = endpoint.status().fsRoot;
    const within = (address, length) => Number.isSafeInteger(address) && address >= root.captureStart && address + length <= root.captureEnd;
    const allocations = beginAllocationTracking();
    requireMatch(allocations, "allocation tracker busy");
    let domainId = 0;
    let notifierHandle = 0;
    const events = [];
    try {
        const openPacket = allocPage(8192);
        const opened = sendDomainCmd(session.handle, session.rootObj, 510, openPacket, () => {}, 0);
        requireMatch(opened.ok && opened.transport === 0 && opened.result === 0 && opened.objCount === 1, "OpenSystemDataUpdateEventNotifier failed: transport=0x" + (Number(opened.transport) >>> 0).toString(16) + " result=0x" + (Number(opened.result) >>> 0).toString(16));
        const objects = readDomainObjects(openPacket, opened.objCount, 0);
        requireMatch(objects.length === 1 && objects[0] > 0, "notifier domain object missing");
        domainId = objects[0];
        notifierHandle = cloneObject(session.handle, domainId);
        requireMatch(notifierHandle, "notifier clone failed");
        const entryAddress = root.table + (domainId - 1) * 48;
        requireMatch(within(entryAddress, 48), "notifier entry outside verified capture");
        const entry = await endpoint.read(entryAddress, 48);
        const domain = u64(entry, 24);
        const object = u64(entry, 32);
        const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
        requireMatch(canonical(domain) && canonical(object), "notifier pointers are invalid: domain=0x" + domain.toString(16) + " object=0x" + object.toString(16));
        const wrapper = await endpoint.read(domain, 32);
        requireMatch(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "notifier domain wrapper differs");
        const notifier = await endpoint.read(object, 24);
        requireMatch(u64(notifier, 0) === root.rootVptr - 5824 && u32(notifier, 16) === 2, "notifier object identity differs: vptrOffset=0x" + (u64(notifier, 0) - root.rootVptr).toString(16) + " refs=" + u32(notifier, 16));
        const backendAddress = u64(notifier, 8);
        requireMatch(canonical(backendAddress), "notifier backend pointer invalid");
        const backend = await endpoint.read(backendAddress, 72);
        requireMatch(u64(backend, 16) === backendAddress + 16 && u64(backend, 24) === backendAddress + 16, "notifier backend event list differs");
        await log("RO notifier backend handles: read=0x" + u32(backend, 36).toString(16) + " write=0x" + u32(backend, 40).toString(16));
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
        const transport = Number(sendIPC(notifierHandle, packet)) >>> 0;
        const reply = cmifReply(packet);
        for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle) events.push(handle);
        requireMatch(transport === 0 && reply.result === 0 && reply.copies.length === 1 && reply.moves.length === 0, "GetEventHandle did not return one copied event: transport=0x" + transport.toString(16) + " result=0x" + reply.result.toString(16));
        await log("RO notifier identity verified: domainId=" + domainId + " object=0x" + object.toString(16) + " copiedEvents=" + events.length);
    } finally {
        for (const handle of events) closeHandle(handle);
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
