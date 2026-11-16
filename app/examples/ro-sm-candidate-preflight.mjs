import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const u16 = (b, o) => (b[o] | b[o + 1] << 8) >>> 0;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    if (!fs?.status().ready) throw new Error("verified FS endpoint unavailable");
    const root = fs.status().fsRoot;
    const sdk = root.captureStart + 5242880;
    const address = sdk + 4768;
    if (sdk % 4096 !== 0 || Math.abs(sdk - root.rootVptr - 15961056) > 65536) throw new Error("FS SDK layout differs");
    const bytes = await fs.read(address - 8, 24);
    const pointer = u64(bytes, 0);
    const handle = u32(bytes, 8);
    const zero = u32(bytes, 12);
    const guard = u16(bytes, 16);
    await log("RO SM candidate: selfPointer=" + (pointer === address) + " sourceHandle=0x" + handle.toString(16) + " zero=" + zero + " guard=0x" + guard.toString(16));
    if (pointer !== address || zero !== 0 || guard !== 257 || handle < 32768 || handle >= 33554432) throw new Error("initialized FS SM client candidate differs");
    globalThis.civRoSmCandidate = Object.freeze({
        address: address,
        handle: handle
    });
    await log("RO initialized FS SM client layout verified read-only");
}
