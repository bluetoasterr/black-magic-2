import runtime from "../src/core/runtime.mjs";

const {allocPage: allocPage, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, log: log, prepPacket: prepPacket, sendIPC: sendIPC, ipcStorageGetSize: ipcStorageGetSize, ipcStorageRead: ipcStorageRead, read8: read8, read32: read32} = runtime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    if (!fs?.status().ready || !session?.handle || !session?.rootObj) throw new Error("HOME preflight requires verified FS access");
    const root = cloneObject(session.handle, session.rootObj);
    if (!root) throw new Error("HOME preflight could not clone FS root");
    let storage = 0;
    try {
        const packet = allocPage(8192);
        prepPacket(packet, 4, 10, [ [ 16, 1229145683 ], [ 24, 201 ] ]);
        const id = 0x0100000000001000n;
        runtime.write64(packet + 32n, id);
        const transport = Number(sendIPC(root, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        await log("HOME storage open: transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16) + " handles=" + (reply?.moves.length ?? 0));
        if (transport || reply?.result || reply.moves.length !== 1) return;
        storage = reply.moves[0];
        const size = ipcStorageGetSize(storage);
        await log("HOME storage size: error=0x" + size.error.toString(16) + " bytes=" + size.size);
        if (size.error || size.size < 512) return;
        const buf = allocPage(4096);
        const read = ipcStorageRead(storage, 0, 256, buf);
        let hex = "";
        if (!read.error) for (let i = 0; i < 64; i++) hex += Number(read8(buf + BigInt(i))).toString(16).padStart(2, "0");
        await log("HOME storage header: read=0x" + read.error.toString(16) + " first64=" + hex);
    } finally {
        if (storage) closeHandle(storage);
        closeHandle(root);
    }
}
