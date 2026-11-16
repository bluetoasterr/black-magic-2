import coreRuntime from "../src/core/runtime.mjs";

function requireMatch(ok, message) {
    if (!ok) throw new Error("RO scratch write: " + message);
}

function equal(left, right) {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export async function run() {
    throw new Error("Disabled: scratch write froze the Switch on 2026-11-14");
    const endpoint = globalThis.civFsMemory;
    requireMatch(endpoint && endpoint.status().ready, "verified FS memory endpoint unavailable");
    const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log} = coreRuntime;
    const allocations = beginAllocationTracking();
    requireMatch(allocations, "allocation tracker busy");
    let address = 0;
    let before = null;
    let after = null;
    let changed = false;
    try {
        address = Number(allocPage(4096));
        requireMatch(Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888, "scratch allocation failed");
        before = await endpoint.read(address, 16);
        after = before.slice();
        for (let i = 0; i < 8; i++) after[i] ^= 165;
        requireMatch(!equal(before, after), "scratch mutation is empty");
        changed = true;
        await endpoint.compareWrite(address, before, after);
        requireMatch(equal(await endpoint.read(address, 16), after), "scratch readback differs");
        await endpoint.compareWrite(address, after, before);
        changed = false;
        requireMatch(equal(await endpoint.read(address, 16), before), "scratch restoration differs");
        await log("RO scratch compare-write verified and restored: address=0x" + address.toString(16) + " bytes=16");
    } finally {
        if (changed && address && before && after) {
            try {
                await endpoint.compareWrite(address, after, before);
            } catch (error) {
                await log("RO scratch restoration failed: " + error);
            }
        }
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
