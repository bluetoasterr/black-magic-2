import coreRuntime from "../src/core/runtime.mjs";

const {closeHandle: closeHandle, log: log, openDomainSession: openDomainSession} = coreRuntime;

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function check(ok, message) {
    if (!ok) throw new Error("RO session bindings: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint && endpoint.status().ready, "verified FS endpoint unavailable");
    const root = endpoint.status().fsRoot;
    const tableEntry = async id => {
        const address = root.table + (id - 1) * 48;
        check(address >= root.captureStart && address + 48 <= root.captureEnd, "domain table entry outside verified capture");
        return endpoint.read(address, 48);
    };
    const targetEntry = await tableEntry(9);
    check(u64(targetEntry, 40) === root.rootVptr + 22656, "Loader entry changed");
    const targetDomain = u64(targetEntry, 24);
    const owned = openDomainSession();
    check(owned?.handle && owned.rootObj > 0 && owned.rootObj <= 16384, "owned domain open failed");
    try {
        const ownEntry = await tableEntry(owned.rootObj);
        check(u64(ownEntry, 40) === root.rootVptr + 22448, "owned root entry changed");
        const ownDomain = u64(ownEntry, 24);
        check(ownDomain !== targetDomain, "owned domain aliases Loader");
        const slots = root.manager + 3400;
        check(slots >= root.captureStart && slots + 65536 <= root.captureEnd, "native session pool outside verified capture");
        const bytes = await endpoint.read(slots, 65536);
        const waiters = Array.from({
            length: 7
        }, (_, i) => root.manager + 1040 + i * 272);
        const rows = [];
        for (let offset = 0; offset + 136 <= bytes.length; offset += 136) {
            const domain = u64(bytes, offset + 112);
            if (u64(bytes, offset) !== root.rootVptr - 32120 || domain !== ownDomain && domain !== targetDomain) continue;
            const wait = u32(bytes, offset + 48);
            const receive = u32(bytes, offset + 72);
            const parent = u64(bytes, offset + 40);
            check(wait === receive && u64(bytes, offset + 56) === 1 && u32(bytes, offset + 64) === 1 && u64(bytes, offset + 104) === 256 && waiters.includes(parent), "native server-session shape differs");
            rows.push({
                address: slots + offset,
                domain: domain,
                wait: wait,
                parent: parent
            });
        }
        check(rows.length === 2 && new Set(rows.map(row => row.domain)).size === 2, "expected one owned and one Loader session, found " + rows.length);
        const loader = rows.find(row => row.domain === targetDomain);
        const mine = rows.find(row => row.domain === ownDomain);
        await log("RO native sessions verified: Loader=0x" + loader.address.toString(16) + " wait=0x" + loader.wait.toString(16) + " owned=0x" + mine.address.toString(16) + " ownedId=" + owned.rootObj);
    } finally {
        closeHandle(owned.handle);
    }
}
