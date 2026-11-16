import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, readDomainObjects: readDomainObjects, sendDomainCmd: sendDomainCmd, sendIPC: sendIPC, write32: write32, write8: write8} = coreRuntime;

export async function run() {
    const session = globalThis.fspSrv;
    if (!session) {
        await log("SD mount check: no elevated fsp-srv session");
        return;
    }
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("Allocation tracker is already in use");
    let objects = [];
    try {
        const packet = allocPage(8192);
        const reply = sendDomainCmd(session.handle, session.rootObj, 18, packet, () => {}, 0);
        objects = reply.ok ? readDomainObjects(packet, reply.objCount, 0).filter(objectId => objectId !== 0) : [];
        const mounted = reply.ok && reply.transport === 0 && reply.result === 0 && reply.objCount === 1 && objects.length === 1;
        await log("OpenSdCardFileSystem: " + (mounted ? "MOUNT VERIFIED" : "FAILED") + " transport=0x" + (Number(reply.transport) >>> 0).toString(16) + " result=0x" + (Number(reply.result) >>> 0).toString(16) + " objects=" + objects.length);
    } finally {
        for (const objectId of objects) {
            const packet = allocPage(8192);
            prepPacket(packet, 4, 8, []);
            write8(packet + 0x10n, 2n);
            write32(packet + 0x14n, BigInt(objectId));
            sendIPC(session.handle, packet);
        }
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
