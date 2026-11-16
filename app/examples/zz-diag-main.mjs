import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, getMountHandle: getMountHandle, ipcOpenFile: ipcOpenFile, log: log, prepPacket: prepPacket, read8: read8, read64: read64, sendIPC: sendIPC, write32: write32, write64: write64} = coreRuntime;

export async function run() {
    const mount = getMountHandle("save");
    if (!mount) throw new Error("save mount unavailable");
    const t0 = beginAllocationTracking();
    let handle = 0;
    try {
        handle = cloneObject(mount.handle, mount.objId);
        const child = ipcOpenFile(handle, "/main", 1);
        if (!child) throw new Error("open failed");
        try {
            const sp = allocPage(8192);
            prepPacket(sp, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
            const t = Number(sendIPC(child, sp)) >>> 0;
            const r = t === 0 ? cmifReply(sp) : null;
            const size = r?.result === 0 ? Number(read64(sp + BigInt(r.data))) : -1;
            const out = allocPage(8192);
            const hp = allocPage(8192);
            prepPacket(hp, (4 | 1 << 24) >>> 0, 14, []);
            write32(hp + 8n, 16n);
            write32(hp + 12n, out & 0xffffffffn);
            const flags = 1n | (out >> 36n & 7n) << 2n | (out >> 32n & 15n) << 28n;
            write32(hp + 16n, flags);
            write32(hp + 0x20n, 0x49434653n);
            write32(hp + 0x28n, 0n);
            write64(hp + 0x30n, 0n);
            write64(hp + 0x38n, 0n);
            write64(hp + 0x40n, 16n);
            const t2 = Number(sendIPC(child, hp)) >>> 0;
            const r2 = t2 === 0 ? cmifReply(hp) : null;
            let head = [];
            if (r2?.result === 0) for (let i = 0; i < 16; i++) head.push(Number(read8(out + BigInt(i))).toString(16).padStart(2, "0"));
            await log("MAIN-PROBE size=" + size + " head=" + head.join(""));
        } finally {
            closeHandle(child);
        }
    } finally {
        if (handle) closeHandle(handle);
        if (endAllocationTracking(t0)) freeTrackedAllocations(t0);
    }
}
