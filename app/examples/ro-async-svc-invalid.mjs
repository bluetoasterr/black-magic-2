import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, read8: read8, read32: read32, sdk_base: sdk_base, write32: write32} = coreRuntime;

export async function run() {
    const entry = sdk_base + 0x168c5cn;
    const expected = "e00f1ff8610400d4e20340f9410000b9ff430091c0035fd6";
    for (let i = 0; i < expected.length / 2; i++) if (Number(read8(entry + BigInt(i))) !== parseInt(expected.slice(i * 2, i * 2 + 2), 16)) throw new Error("async IPC wrapper bytes differ");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("async IPC tracker busy");
    try {
        const packet = allocPage(4096);
        const out = allocPage(16);
        write32(out, 0n);
        const result = Number(call_rop(entry, out, packet, 0x1000n, 0n)) >>> 0;
        const handle = Number(read32(out)) >>> 0;
        await log("Async IPC invalid-handle check: result=0x" + result.toString(16) + ", returned word=0x" + handle.toString(16) + "; FS untouched");
        if (result === 0) throw new Error("invalid-handle async IPC unexpectedly succeeded");
    } finally {
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
