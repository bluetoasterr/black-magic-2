import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, sendIPC: sendIPC, write32: write32} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const bytes32 = n => [ n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255 ];

const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

const check = (ok, message) => {
    if (!ok) throw new Error("RO FS process export: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const event = globalThis.civRoEvent;
    check(fs?.status().ready && event?.notifierHandle && event?.domainId && !globalThis.civRoFsProcessCopy, "verified notifier or endpoint unavailable");
    const root = fs.status().fsRoot;
    const entryAddress = root.table + (event.domainId - 1) * 48;
    check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "notifier entry outside capture");
    const entry = await fs.read(entryAddress, 48);
    const notifier = await fs.read(u64(entry, 32), 24);
    check(u64(notifier, 0) === root.rootVptr - 5824 && u32(notifier, 16) === 2, "notifier identity changed");
    const backend = u64(notifier, 8);
    const field = backend + 36;
    const original = bytes32(u32(await fs.read(field, 4), 0));
    check(u32(original, 0) >= 32768 && u32(original, 0) !== 4294934529, "notifier source handle changed");
    const replacement = bytes32(4294934529);
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let changed = false, copied = 0, restored = false;
    try {
        changed = true;
        await fs.compareWrite(field, original, replacement);
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
        const transport = Number(sendIPC(event.notifierHandle, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        copied = reply?.copies.length === 1 ? reply.copies[0] : 0;
        for (const handle of [ ...reply?.copies || [], ...reply?.moves || [] ]) if (handle && handle !== copied) closeHandle(handle);
        check(transport === 0 && reply?.result === 0 && reply.copies.length === 1 && reply.moves.length === 0 && copied >= 32768, "FS process handle copy failed");
    } finally {
        if (changed) {
            const current = await fs.read(field, 4);
            if (!equal(current, original)) await fs.compareWrite(field, current, original);
            restored = equal(await fs.read(field, 4), original);
        }
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
        if (!restored && copied) {
            closeHandle(copied);
            copied = 0;
        }
    }
    check(restored && copied, "notifier source field did not restore");
    globalThis.civRoFsProcessCopy = Object.freeze({
        handle: copied,
        release() {
            if (globalThis.civRoFsProcessCopy !== this) return;
            closeHandle(this.handle);
            delete globalThis.civRoFsProcessCopy;
        }
    });
    await log("RO FS process handle copied through notifier; " + "source restored, handle=" + copied);
}
