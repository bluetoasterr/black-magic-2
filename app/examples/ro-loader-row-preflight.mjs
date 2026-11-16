import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO Loader row: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const owned = globalThis.civRoOwned;
    check(fs?.status().ready && owned?.row && !globalThis.civRoLoaderRow, "verified FS endpoint or owned row unavailable");
    const root = fs.status().fsRoot;
    const targetEntry = await fs.read(root.table + 8 * 48, 48);
    check(u64(targetEntry, 40) === root.rootVptr + 22656, "Loader root entry changed");
    const targetDomain = u64(targetEntry, 24);
    check(targetDomain && targetDomain !== owned.domain, "Loader domain aliases owned domain");
    const slots = root.manager + 3400;
    const bytes = await fs.read(slots, 65536);
    const waiters = owned.waiters;
    const rows = [];
    for (let off = 0; off + 136 <= bytes.length; off += 136) {
        const domain = u64(bytes, off + 112);
        if (u64(bytes, off) !== root.rootVptr - 32120 || domain !== targetDomain && domain !== owned.domain) continue;
        const row = {
            address: slots + off,
            domain: domain,
            parent: u64(bytes, off + 40),
            wait: u32(bytes, off + 48),
            receive: u32(bytes, off + 72),
            request: u64(bytes, off + 96),
            metadata: u64(bytes, off + 120),
            state: u32(bytes, off + 64)
        };
        check(row.wait === row.receive && u64(bytes, off + 56) === 1 && row.state === 1 && u64(bytes, off + 104) === 256 && waiters.includes(row.parent), "server row is not idle on a known waiter");
        rows.push(row);
    }
    check(rows.length === 2 && new Set(rows.map(row => row.domain)).size === 2, "Loader/owned row pair is not unique");
    const row = rows.find(item => item.domain === targetDomain);
    check(row && row.receive >= 32768 && row.request >= root.captureStart && row.request + 256 <= root.captureEnd, "Loader server row has unexpected handles/buffer");
    globalThis.civRoLoaderRow = Object.freeze({
        ...row
    });
    await log("RO Loader server row bound read-only: address=0x" + row.address.toString(16) + " wait=0x" + row.wait.toString(16) + " request=0x" + row.request.toString(16) + " ownedDistinct=true");
}
