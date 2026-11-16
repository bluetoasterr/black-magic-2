import coreRuntime from "../src/core/runtime.mjs";

const {SM_Initialize: SM_Initialize, SM_GetService: SM_GetService, SM_Finalize: SM_Finalize, allocRawTracked: allocRawTracked, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, closeHandle: closeHandle, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, read32: read32, write64: write64, writeStr: writeStr} = coreRuntime;

export async function run() {
    if (!globalThis.civFsMemory?.status().ready) throw new Error("RO SM check requires verified FS access");
    const allocations = beginAllocationTracking();
    if (!allocations) throw new Error("RO SM allocation tracker busy");
    let handle = 0;
    try {
        const name = allocRawTracked(16);
        const output = allocRawTracked(16);
        writeStr(name, "pm:shell");
        write64(output, 0n);
        call_rop(SM_Initialize);
        let result;
        try {
            result = call_rop(SM_GetService, output, name);
        } finally {
            call_rop(SM_Finalize);
        }
        handle = Number(read32(output)) >>> 0;
        await log("RO SM direct pm:shell: result=0x" + BigInt(result).toString(16) + " handle=" + handle);
    } finally {
        if (handle) closeHandle(handle);
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
