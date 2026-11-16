import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const loader = globalThis.civRoLoaderRootCopy;
    if (!fs?.status().ready || !loader?.handle) throw new Error("RO Loader domain list prerequisites unavailable");
    const root = fs.status().fsRoot;
    const sentinel = loader.targetDomain + 32;
    let at = u64(await fs.read(sentinel, 8), 0);
    const seen = new Set, rows = [];
    while (at !== sentinel) {
        if (at < root.table || at + 48 > root.captureEnd || (at - root.table) % 48 !== 0 || seen.has(at) || rows.length >= 128) throw new Error("RO Loader domain list left verified table");
        seen.add(at);
        const row = await fs.read(at, 48);
        if (u64(row, 24) !== loader.targetDomain) throw new Error("RO Loader domain entry owner differs");
        rows.push({
            id: (at - root.table) / 48 + 1,
            object: u64(row, 32),
            metadata: u64(row, 40)
        });
        at = u64(row, 0);
    }
    globalThis.civRoLoaderDomainBaseline = Object.freeze(rows.map(row => Object.freeze(row)));
    await log("RO Loader domain baseline: count=" + rows.length + " ids=" + rows.map(row => row.id).join(","));
}
