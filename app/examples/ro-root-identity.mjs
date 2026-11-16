import coreRuntime from "../src/core/runtime.mjs";

const {beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log} = coreRuntime;

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function requireMatch(value, message) {
    if (!value) throw new Error("RO root identity: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    requireMatch(endpoint && session, "verified FS session unavailable");
    const state = endpoint.status();
    requireMatch(state.ready && state.fsRoot, "memory endpoint unavailable");
    const root = state.fsRoot;
    requireMatch(root.object >= root.captureStart && root.object + 64 <= root.captureEnd, "root object outside verified capture");
    const allocations = beginAllocationTracking();
    requireMatch(allocations, "allocation tracker busy");
    let clone = 0;
    try {
        const before = await endpoint.read(root.object, 64);
        const refsBefore = u32(before, 56);
        requireMatch(refsBefore > 0 && refsBefore < 16777216, "implausible initial reference count");
        clone = cloneObject(session.handle, session.rootObj);
        requireMatch(clone, "root clone failed");
        const during = await endpoint.read(root.object, 64);
        const refsDuring = u32(during, 56);
        requireMatch(refsDuring === refsBefore + 1, "clone did not increase reference count by one: " + refsBefore + " -> " + refsDuring);
        for (let i = 0; i < before.length; i++) {
            if (i >= 56 && i < 60) continue;
            requireMatch(before[i] === during[i], "clone changed another root byte at 0x" + i.toString(16));
        }
        const closeResult = Number(closeHandle(clone)) >>> 0;
        clone = 0;
        requireMatch(closeResult === 0, "clone close failed");
        const after = await endpoint.read(root.object, 64);
        requireMatch(after.every((byte, index) => byte === before[index]), "root object did not return to its initial bytes");
        await log("RO root identity verified: object=0x" + root.object.toString(16) + " refs=" + refsBefore + " -> " + refsDuring + " -> " + u32(after, 56));
    } finally {
        if (clone) closeHandle(clone);
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
