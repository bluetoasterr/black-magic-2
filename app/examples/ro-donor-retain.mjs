import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, getMountHandle: getMountHandle, ipcGetEntryType: ipcGetEntryType, log: log, prepPacket: prepPacket, read32: read32, sendIPC: sendIPC, write32: write32} = coreRuntime;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return Number(n);
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO donor retain: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const type = globalThis.civRoDonorType;
    const loader = globalThis.civRoLoaderRootCopy;
    check(fs?.status().ready && type?.compatible && loader?.handle && globalThis.civRoDonorStaged?.files?.length === 2 && !globalThis.civRoDonor, "verified donor and Loader root unavailable");
    const mount = getMountHandle("save");
    check(mount, "save mount unavailable");
    const handle = cloneObject(mount.handle, mount.objId);
    check(handle, "donor filesystem clone failed");
    let retained = false;
    try {
        for (const path of [ "/main.npdm", "/main" ]) {
            const entry = ipcGetEntryType(handle, path);
            check(entry.error === 0 && entry.type === 1, path + " donor file missing");
        }
        const packet = allocPage(8192);
        prepPacket(packet, 5, 8, []);
        write32(packet + 0x10n, 0x49434653n);
        write32(packet + 0x18n, 0n);
        const transport = Number(sendIPC(handle, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        const rootObj = reply?.result === 0 ? Number(read32(packet + BigInt(reply.data))) >>> 0 : 0;
        check(transport === 0 && reply?.result === 0 && rootObj > 0 && rootObj <= 16384, "donor ConvertToDomain failed");
        const layout = fs.status().fsRoot;
        const address = layout.table + (rootObj - 1) * 48;
        check(address >= layout.captureStart && address + 48 <= layout.captureEnd, "donor entry outside capture");
        const entry = await fs.read(address, 48);
        const domain = u64(entry, 24);
        const object = u64(entry, 32);
        const metadata = u64(entry, 40);
        check(domain >= 4294967296 && domain !== loader.targetDomain && object >= 4294967296 && metadata === type.metadata, "donor entry identity differs");
        const header = await fs.read(object, 64);
        check(u64(header, 0) === type.vptr, "donor concrete filesystem type changed");
        globalThis.civRoDonor = {
            handle: handle,
            rootObj: rootObj,
            entry: address,
            domain: domain,
            object: object,
            metadata: metadata,
            vptr: type.vptr,
            release() {
                if (globalThis.civRoDonor !== this) return;
                closeHandle(this.handle);
                delete globalThis.civRoDonor;
            }
        };
        retained = true;
        await log("RO donor filesystem retained: handle=" + handle + " root=" + rootObj + " entry=0x" + address.toString(16) + " type verified");
    } finally {
        if (!retained) closeHandle(handle);
    }
}
