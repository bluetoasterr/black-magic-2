import coreRuntime from "../src/core/runtime.mjs";

const {F_Sleep: F_Sleep, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, read32: read32, read64: read64, sdk_base: sdk_base, read8: read8, write8: write8, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("kaiHEN bootstrap: " + message);
};

export async function run() {
    const map = globalThis.civRoBootstrapMap;
    const input = globalThis.civRoBootstrapArgs;
    check(map?.queryVerified && map.state === "mapped" && input?.bytes?.length === 432 && !globalThis.civRoBootstrapRun, "mapped image or prepared input unavailable");
    const signatures = [ [ 1319296n, "ff4302d1fd7b04a9f92b00f9f85f06a9" ], [ 1320064n, "e803202a1f0940f261020054fd7bbea9" ], [ 1274128n, "484f00f0e10300aa084141f900c10391" ] ];
    for (const [offset, hex] of signatures) for (let i = 0; i < hex.length / 2; i++) check(Number(read8(sdk_base + offset + BigInt(i))) === parseInt(hex.slice(i * 2, i * 2 + 2), 16), "SDK pthread signature differs");
    const tracking = beginAllocationTracking();
    check(tracking, "allocation tracker busy");
    let threadStarted = false;
    try {
        const args = allocPage(4096);
        const slots = allocPage(256);
        for (let i = 0; i < 432; i++) write8(args + BigInt(i), BigInt(input.bytes[i]));
        write64(slots, 0n);
        write64(slots + 8n, 0n);
        const state = globalThis.civRoBootstrapRun = {
            args: args,
            slots: slots,
            allocations: tracking,
            entry: map.entry,
            stage: "prepared"
        };
        const create = Number(call_rop(sdk_base + 1319296n, slots, 0n, map.entry, args)) >>> 0;
        if (create !== 0) {
            delete globalThis.civRoBootstrapRun;
            throw new Error("pthread_create returned 0x" + create.toString(16));
        }
        threadStarted = true;
        const tagged = read64(slots);
        check(tagged !== 0n && (tagged & 7n) === 7n, "pthread_create returned an untagged thread");
        state.thread = tagged;
        state.stage = "running";
        await log("kaiHEN bootstrap thread started; waiting up to 60s");
        const waitable = tagged & ~7n;
        const deadline = Date.now() + 6e4;
        let finished = false;
        while (Date.now() < deadline) {
            const status = Number(call_rop(sdk_base + 1274128n, waitable, 0n, 0n, 0n)) >>> 0;
            check(status === 0 || status === 1, "TryWaitThread returned 0x" + status.toString(16));
            if (status === 1) {
                finished = true;
                break;
            }
            call_rop(F_Sleep, 10000000n, 0n, 0n, 0n);
        }
        if (!finished) {
            await log("kaiHEN bootstrap still running; image and " + "thread allocations retained");
            return;
        }
        const joined = Number(call_rop(sdk_base + 1320064n, tagged, slots + 8n, 0n, 0n)) >>> 0;
        check(joined === 0, "pthread_join returned 0x" + joined.toString(16));
        state.stage = "joined";
        const operation = Number(read32(args + 408n)) >>> 0;
        const result = Number(read32(args + 412n)) >>> 0;
        const pid = read64(args + 416n);
        const gateRestore = Number(read32(args + 424n)) >>> 0;
        const channelRestore = Number(read32(args + 428n)) >>> 0;
        const returned = read64(slots + 8n);
        state.result = {
            operation: operation,
            result: result,
            pid: pid,
            gateRestore: gateRestore,
            channelRestore: channelRestore,
            returned: returned
        };
        await log("kaiHEN bootstrap result: operation=" + operation + " result=0x" + result.toString(16) + " pid=" + pid + " gate=0x" + gateRestore.toString(16) + " channel=0x" + channelRestore.toString(16) + " return=0x" + returned.toString(16));
        check(operation === 10 && result === 0 && (gateRestore === 0 || gateRestore === 59905) && channelRestore === 0 && returned === 0n, "native startup did not complete cleanly");
        state.stage = "verified";
    } finally {
        if (endAllocationTracking(tracking) && !threadStarted) freeTrackedAllocations(tracking);
    }
}
