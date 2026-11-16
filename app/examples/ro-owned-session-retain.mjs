import coreRuntime from "../src/core/runtime.mjs";

const {closeHandle: closeHandle, log: log, openDomainSession: openDomainSession} = coreRuntime;

function u32(b, o) {
    return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;
}

function u64(b, o) {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
}

function check(ok, message) {
    if (!ok) throw new Error("RO owned session: " + message);
}

export async function run() {
    check(!globalThis.civRoOwned, "owned session already retained");
    const fs = globalThis.civFsMemory;
    check(fs?.status().ready && globalThis.civRoWorkers?.list?.length === 7 && globalThis.civRoEvent?.read, "RO prerequisites unavailable");
    const root = fs.status().fsRoot;
    const targetEntry = await fs.read(root.table + 8 * 48, 48);
    check(u64(targetEntry, 40) === root.rootVptr + 22656, "Loader root entry changed");
    const targetDomain = u64(targetEntry, 24);
    const owned = openDomainSession();
    check(owned?.handle && owned.rootObj > 0 && owned.rootObj <= 16384, "owned domain open failed");
    let retained = false;
    try {
        const entryAddress = root.table + (owned.rootObj - 1) * 48;
        check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "owned table entry outside capture");
        const entry = await fs.read(entryAddress, 48);
        check(u64(entry, 40) === root.rootVptr + 22448, "owned entry type changed");
        const ownDomain = u64(entry, 24);
        check(ownDomain !== targetDomain, "owned domain aliases Loader");
        const slots = root.manager + 3400;
        check(slots >= root.captureStart && slots + 65536 <= root.captureEnd, "native session pool outside capture");
        const bytes = await fs.read(slots, 65536);
        const waiters = Array.from({
            length: 7
        }, (_, i) => root.manager + 1040 + i * 272);
        const rows = [];
        for (let off = 0; off + 136 <= bytes.length; off += 136) {
            const domain = u64(bytes, off + 112);
            if (u64(bytes, off) !== root.rootVptr - 32120 || domain !== ownDomain && domain !== targetDomain) continue;
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
            check(row.wait === row.receive && u64(bytes, off + 56) === 1 && row.state === 1 && u64(bytes, off + 104) === 256 && waiters.includes(row.parent), "server session is not idle on expected waiter");
            rows.push(row);
        }
        check(rows.length === 2 && new Set(rows.map(row => row.domain)).size === 2, "Loader and owned session pair is not unique");
        const row = rows.find(item => item.domain === ownDomain);
        check(row && row.receive >= 32768 && row.request >= root.captureStart && row.request + 256 <= root.captureEnd, "owned session receive handle or buffer invalid");
        globalThis.civRoOwned = {
            handle: owned.handle,
            rootObj: owned.rootObj,
            domain: ownDomain,
            row: row,
            waiters: waiters,
            release() {
                if (globalThis.civRoOwned !== this) return;
                closeHandle(this.handle);
                delete globalThis.civRoOwned;
            }
        };
        retained = true;
        await log("RO owned server session retained: address=0x" + row.address.toString(16) + " wait=0x" + row.wait.toString(16) + " domainId=" + owned.rootObj);
    } finally {
        if (!retained) closeHandle(owned.handle);
    }
}
