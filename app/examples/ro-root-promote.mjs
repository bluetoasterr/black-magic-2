import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO FS root verification: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    check(fs?.status().ready && session?.handle && session?.rootObj && !globalThis.civRoRootPromotion, "verified endpoint or owned root unavailable");
    const layout = fs.status().fsRoot;
    const root = layout.object;
    const inCapture = address => Number.isSafeInteger(address) && address >= layout.captureStart && address + 96 <= layout.captureEnd && address % 8 === 0;
    const pointer = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    check(inCapture(root), "root outside verified capture");
    const rootBytes = await fs.read(root, 64);
    check(u64(rootBytes, 0) === layout.rootVptr && u64(rootBytes, 48) === 1 && u32(rootBytes, 56) > 0 && u32(rootBytes, 56) < 16777216, "root is not already promoted to PID 1");
    const fields = [ {
        name: "root",
        address: root + 48
    } ];
    for (const [name, link, offset] of [ [ "nca", 24, 32 ], [ "save", 40, 40 ] ]) {
        const backend = u64(rootBytes, link);
        const object = backend + 24;
        check(inCapture(object), name + " backend outside capture");
        const bytes = await fs.read(object, 96);
        check(pointer(u64(bytes, 0)) && u64(bytes, offset) === 1, name + " cache is not already promoted");
        fields.push({
            name: name,
            address: object + offset
        });
    }
    check(new Set(fields.map(field => field.address)).size === 3, "PID fields alias");
    globalThis.civRoRootPromotion = Object.freeze({
        root: root,
        fields: Object.freeze(fields.map(field => Object.freeze(field)))
    });
    await log("RO FS root promotion verified read-only: " + "root/nca/save PID=1");
}
