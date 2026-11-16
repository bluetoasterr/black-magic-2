import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, read8: read8, sendIPC: sendIPC, write32: write32, write64: write64} = coreRuntime;

function u32(b, o) {
    return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;
}

function u64(b, o) {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
}

function bytes32(n) {
    return [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];
}

function equal(a, b) {
    return a.length === b.length && a.every((x, i) => x === b[i]);
}

function check(ok, message) {
    if (!ok) throw new Error("RO Loader server copy: " + message);
}

export async function run() {
    check(!globalThis.civRoLoaderServerCopy, "Loader server handle already copied");
    const fs = globalThis.civFsMemory;
    const row = globalThis.civRoLoaderRow;
    const event = globalThis.civRoEvent;
    check(fs?.status().ready && row?.receive && event?.notifierHandle && event?.domainId, "retained RO prerequisites unavailable");
    const root = fs.status().fsRoot;
    const entryAddress = root.table + (event.domainId - 1) * 48;
    check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "notifier entry outside capture");
    const entry = await fs.read(entryAddress, 48);
    const notifier = await fs.read(u64(entry, 32), 24);
    check(u64(notifier, 0) === root.rootVptr - 5824 && u32(notifier, 16) === 2, "retained notifier identity differs");
    const backend = u64(notifier, 8);
    const handleField = backend + 36;
    const original = bytes32(u32(await fs.read(handleField, 4), 0));
    check(u32(original, 0) >= 32768 && u32(original, 0) !== row.receive, "notifier source handle differs");
    const replacement = bytes32(row.receive);
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let changed = false, copied = 0, restored = false;
    try {
        changed = true;
        await fs.compareWrite(handleField, original, replacement);
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
        const transport = Number(sendIPC(event.notifierHandle, packet)) >>> 0;
        const reply = cmifReply(packet);
        if (reply.copies.length === 1) copied = reply.copies[0];
        for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle && handle !== copied) closeHandle(handle);
        check(transport === 0 && reply.result === 0 && reply.copies.length === 1 && reply.moves.length === 0 && copied >= 32768, "server wait handle copy failed");
    } finally {
        if (changed) {
            const current = await fs.read(handleField, 4);
            if (!equal(current, original)) await fs.compareWrite(handleField, current, original);
            restored = equal(await fs.read(handleField, 4), original);
        }
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
        if (!restored && copied) {
            closeHandle(copied);
            copied = 0;
        }
    }
    check(restored && copied, "notifier field did not restore");
    const waitCode = "e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6";
    for (let i = 0; i < waitCode.length / 2; i++) check(Number(read8(SVC_WaitSync + BigInt(i))) === parseInt(waitCode.slice(i * 2, i * 2 + 2), 16), "wait wrapper bytes differ");
    const waitBuf = allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(copied));
    const waitResult = Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0;
    check(waitResult === 59905, "idle server is unexpectedly ready: 0x" + waitResult.toString(16));
    globalThis.civRoLoaderServerCopy = {
        handle: copied,
        release() {
            if (globalThis.civRoLoaderServerCopy !== this) return;
            closeHandle(this.handle);
            delete globalThis.civRoLoaderServerCopy;
        }
    };
    await log("RO Loader server readiness copy retained: handle=" + copied + " idle wait=0xea01 notifier restored");
}
