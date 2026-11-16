import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, cmifReply: cmifReply, freeTrackedAllocations: freeTrackedAllocations, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, launchRawWorker: launchRawWorker, log: log, read8: read8, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread, write32: write32, write64: write64} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("FS ABI probe: " + message);
};

const u32 = a => Number(read32(a)) >>> 0;

const RANGES = [ [ 309440, 44, "SD filesystem reference retain" ], [ 431296, 192, "context allocation" ], [ 431488, 184, "context free" ], [ 973664, 116, "current RomFS mount frontend" ], [ 973792, 124, "program RomFS mount frontend" ], [ 973920, 140, "data RomFS mount frontend" ], [ 981504, 164, "program-scoped CodeFS mount frontend" ], [ 1061776, 232, "filesystem release" ], [ 1062640, 44, "file retain" ], [ 1065696, 236, "namespace type" ], [ 1066416, 772, "namespace file open" ], [ 1067200, 772, "namespace directory open" ], [ 1068560, 212, "file release" ], [ 1068784, 432, "file read" ], [ 1069216, 816, "report write" ], [ 1070032, 60, "report flush" ], [ 1070096, 112, "report resize" ], [ 1070208, 148, "file size" ], [ 1070880, 212, "directory release" ], [ 1071104, 240, "directory read" ], [ 1071344, 72, "directory count" ], [ 1078416, 220, "storage release" ], [ 1078640, 16, "storage read" ], [ 1078784, 72, "storage size" ], [ 1078864, 16, "optional storage dispatch adapter" ], [ 1079216, 320, "storage read implementation" ], [ 1080256, 264, "optional storage dispatch" ], [ 1080528, 340, "batch storage dispatch" ], [ 1179344, 16, "batch storage dispatch adapter" ], [ 1180080, 92, "native notifier" ], [ 1184768, 680, "live process program registry" ], [ 1232096, 64, "program registry global reference" ], [ 2157636, 64, "native block manager global reference" ], [ 2184736, 476, "owned native block allocation" ], [ 2185216, 124, "owned native block free" ], [ 2185344, 476, "owned native block free" ], [ 2197456, 232, "SDK priority-inheriting mutex slow paths" ], [ 2402208, 84, "program registry weak reference release" ] ];

export async function run() {
    const service = globalThis.civRoService;
    const process = globalThis.civRoFsProcessCopy;
    const pid = globalThis.civRoFsPid;
    check(service?.handle && process?.handle && pid, "prerequisites unavailable (need ro-service-lookup, fs-pid)");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const tracking = beginAllocationTracking();
    check(tracking, "allocation tracker busy");
    let pending = false;
    const packet = allocPage(8192);
    const output = allocPage(4096);
    const call = build => {
        build();
        const frame = buildRawFrame([ {
            fn: IPC_SEND_DISPATCHER,
            args: [ BigInt(service.handle), packet, 0x1000n, 0n ]
        } ]);
        const worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "IPC worker did not start");
        if (waitRawThread(worker.handle, 2000000000n) !== 0) {
            globalThis.civHomePendingAbi = {
                worker: worker,
                frame: frame,
                packet: packet,
                output: output,
                tracking: tracking
            };
            pending = true;
            throw new Error("request timed out; buffers retained");
        }
        const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
        closeRawThread(worker.handle);
        check(transport === 0, "transport=0x" + transport.toString(16));
    };
    const replyData = () => {
        const r = cmifReply(packet);
        check(u32(packet + BigInt(r.at)) === 1329808979, "missing SFCO at +" + r.at.toString(16));
        return {
            result: r.result,
            d: packet + BigInt(r.data)
        };
    };
    try {
        const walk = globalThis.civHomeFsWalk;
        check(walk?.code?.length, "run zz-home-fs-walk.mjs first");
        const candidates = walk.code.filter(c => c.type === 3 && parseInt(c.perm, 16) & 4 && BigInt("0x" + c.size) >= 0x24e000n);
        check(candidates.length === 1, "ABI capture candidate not unique: " + candidates.length);
        const base = BigInt("0x" + candidates[0].base);
        await log("FS ABI: text base=0x" + base.toString(16) + " size=0x" + candidates[0].size + " (from walk, " + walk.steps + " mappings)");
        const mapSize = BigInt("0x" + candidates[0].size);
        if (mapSize < 0x24e000n) await log("FS ABI: WARNING mapping smaller than capture span; " + "high ranges may cross mappings");
        const hex8 = (at, n) => {
            let s = "";
            for (let i = 0; i < n; i++) s += Number(read8(at + BigInt(i))).toString(16).padStart(2, "0");
            return s;
        };
        for (const [offset, size, purpose] of RANGES) {
            const source = base + BigInt(offset);
            call(() => {
                write32(packet, (4 | 1 << 24) >>> 0);
                write32(packet + 4n, (14 | 2147483648) >>> 0);
                write32(packet + 8n, 2n);
                write32(packet + 12n, BigInt(process.handle));
                write32(packet + 16n, BigInt(size));
                write32(packet + 20n, output & 0xffffffffn);
                write32(packet + 24n, 1n | (output >> 36n & 7n) << 2n | (output >> 32n & 15n) << 28n);
                write32(packet + 32n, 0x49434653n);
                write32(packet + 40n, 0x524f0016n);
                write64(packet + 48n, BigInt(pid));
                write64(packet + 56n, source);
                write64(packet + 64n, BigInt(size));
                write64(packet + 72n, 0n);
            });
            const {result: result, d: d} = replyData();
            check(result === 0, "bulk read failed at +0x" + offset.toString(16) + ": 0x" + result.toString(16));
            let hex = "";
            for (let off = 0; off < size; off += 256) hex += (off ? "/" : "") + hex8(output + BigInt(off), Math.min(256, size - off));
            await log("ABI+" + offset.toString(16) + " " + size + " " + purpose + " " + hex);
        }
        globalThis.civHomeAbiBase = Object.freeze({
            base: base.toString(),
            size: mapSize.toString(),
            ranges: RANGES.length
        });
        await log("FS ABI capture COLLECTED (hashes NOT yet compared; " + "offline verification required): base=0x" + base.toString(16) + " ranges=" + RANGES.length);
    } finally {
        if (!pending && endAllocationTracking(tracking)) freeTrackedAllocations(tracking);
    }
}
