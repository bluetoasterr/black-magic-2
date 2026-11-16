import coreRuntime from "../src/core/runtime.mjs";

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("RO worker ring: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint && endpoint.status().ready, "verified FS endpoint unavailable");
    const root = endpoint.status().fsRoot;
    check(root.captureEnd - root.captureStart === 5079040, "FS capture geometry differs");
    const sdk = root.captureStart + 5242880;
    check(sdk % 4096 === 0 && Math.abs(sdk - root.rootVptr - 15961056) <= 65536, "FS SDK page differs");
    const header = await endpoint.read(sdk + 2096, 32);
    const sentinel = sdk + 2096;
    check(u64(header, 8) === sdk + 1640 && u32(header, 24) > 0 && u32(header, 24) <= 128, "thread-ring header differs");
    const seen = new Set, groups = new Map;
    let at = u64(header, 0), count = 0;
    while (at !== sentinel) {
        check(at >= 4294967296 && at < 549755813888 && at % 8 === 0 && !seen.has(at) && count < 128, "thread ring is invalid or cyclical");
        seen.add(at);
        const node = await endpoint.read(at, 448);
        if (node[64] === 3 && u64(node, 88) === 49152 && u64(node, 96) === 0) {
            const entry = u64(node, 104);
            const group = groups.get(entry) || [];
            group.push({
                address: at,
                handle: u32(node, 432),
                id: u64(node, 440)
            });
            groups.set(entry, group);
        }
        at = u64(node, 0);
        count++;
    }
    const matches = [ ...groups.entries() ].filter(([, rows]) => rows.length === 7);
    check(matches.length === 1, "expected one seven-worker group; found " + matches.length + " among " + count + " threads");
    const [entry, workers] = matches[0];
    check(workers.every(worker => worker.handle >= 32768 && worker.handle < 33554432 && worker.id > 0), "worker IDs or handles differ");
    await coreRuntime.log("RO FS API workers verified: count=7" + " entry=0x" + entry.toString(16) + " handles=" + workers.map(worker => "0x" + worker.handle.toString(16)).join(","));
}
