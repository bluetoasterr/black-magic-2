import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, ipcGetEntryType: ipcGetEntryType, log: log, prepPacket: prepPacket, sendIPC: sendIPC} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO SD preflight: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const promotion = globalThis.civRoRootPromotion;
    const session = globalThis.fspSrv;
    check(fs?.status().ready && promotion?.root === fs.status().fsRoot.object && session?.handle && session?.rootObj, "verified promoted root unavailable");
    const root = cloneObject(session.handle, session.rootObj);
    check(root, "dedicated root clone failed");
    let sd = 0;
    try {
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 18 ] ]);
        const transport = Number(sendIPC(root, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        check(transport === 0 && reply?.result === 0 && reply.moves.length === 1, "OpenSdCardFileSystem failed: transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16));
        sd = reply.moves[0];
        const entry = ipcGetEntryType(sd, "/");
        check(entry.error === 0 && entry.type === 0, "SD root is not a directory");
        await log("RO promoted FS root opened SD read-only; " + "root directory verified");
    } finally {
        if (sd) closeHandle(sd);
        closeHandle(root);
    }
}
