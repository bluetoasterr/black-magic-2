import core from "../src/core/runtime.mjs";

const {allocPage: allocPage, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, ipcCommitChecked: ipcCommitChecked, ipcCreateFile: ipcCreateFile, ipcGetEntryType: ipcGetEntryType, ipcOpenFile: ipcOpenFile, log: log, prepPacket: prepPacket, read8: read8, read64: read64, sendIPC: sendIPC, write8: write8, write32: write32, write64: write64, writeStr: writeStr, writeXDesc: writeXDesc} = core;

const fail = message => {
    throw new Error("hbmenu SD transfer: " + message);
};

const requireOk = (ok, message) => {
    if (!ok) fail(message);
};

function descriptor(packet, buffer, length, direction) {
    prepPacket(packet, (4 | 1 << direction) >>> 0, 14, []);
    write32(packet + 8n, BigInt(length));
    write32(packet + 12n, buffer & 0xffffffffn);
    write32(packet + 16n, 1n | (buffer >> 36n & 7n) << 2n | (buffer >> 32n & 15n) << 28n);
}

function fileSize(file) {
    const packet = allocPage(8192);
    prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
    const transport = Number(sendIPC(file, packet)) >>> 0;
    const reply = transport === 0 ? cmifReply(packet) : null;
    requireOk(transport === 0 && reply?.result === 0, "size query failed");
    return Number(read64(packet + BigInt(reply.data)));
}

function createDirectory(sd, path) {
    const pathBuf = allocPage(4096);
    writeStr(pathBuf, path);
    const packet = allocPage(8192);
    prepPacket(packet, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(packet, 8, pathBuf, path.length + 1);
    write32(packet + 16n, 0x49434653n);
    write32(packet + 24n, 2n);
    const transport = Number(sendIPC(sd, packet)) >>> 0;
    const reply = transport === 0 ? cmifReply(packet) : null;
    requireOk(transport === 0 && reply?.result === 0, "directory creation failed: " + path);
}

export async function stageChunk(target, offset, hex, total, expectedHash) {
    const fs = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    requireOk(fs?.status().ready && session?.handle && session?.rootObj, "verified FS session unavailable");
    requireOk((target === "/hbmenu.nro" || target === "/switch/ounceshell.nro") && Number.isInteger(offset) && offset >= 0 && Number.isInteger(total) && total > 0 && /^[0-9a-f]{64}$/.test(expectedHash) && /^[0-9a-f]*$/.test(hex) && hex.length % 2 === 0 && offset + hex.length / 2 <= total && hex.length <= 262144, "invalid chunk metadata");
    const transfers = globalThis.civSdTransfers ||= {};
    const prior = transfers[target];
    if (prior) requireOk(prior.total === total && prior.hash === expectedHash && prior.next === offset, "unexpected chunk order"); else requireOk(offset === 0, "first chunk must start at zero");
    const root = cloneObject(session.handle, session.rootObj);
    requireOk(root, "root clone failed");
    let sd = 0, file = 0;
    try {
        const mount = allocPage(8192);
        prepPacket(mount, 4, 8, [ [ 16, 1229145683 ], [ 24, 18 ] ]);
        const transport = Number(sendIPC(root, mount)) >>> 0;
        const reply = transport === 0 ? cmifReply(mount) : null;
        requireOk(transport === 0 && reply?.result === 0 && reply.moves.length === 1, "SD mount failed");
        sd = reply.moves[0];
        if (target.startsWith("/switch/")) {
            const directory = ipcGetEntryType(sd, "/switch");
            if (directory.error === 514) createDirectory(sd, "/switch"); else requireOk(directory.error === 0 && directory.type === 0, "/switch is not a directory");
        }
        const existing = ipcGetEntryType(sd, target);
        let verifyOnly = !!prior?.verifyOnly;
        if (!prior) {
            if (existing.error === 514) {
                requireOk(ipcCreateFile(sd, target, total) === 0, "file creation failed");
            } else {
                requireOk(existing.error === 0 && existing.type === 1, "existing target is not a file");
                verifyOnly = true;
            }
        } else requireOk(existing.error === 0 && existing.type === 1, "staged file missing");
        file = ipcOpenFile(sd, target, verifyOnly ? 1 : 3);
        requireOk(file && fileSize(file) === total, "file size mismatch");
        const length = hex.length / 2;
        const input = allocPage(length + 4096);
        const output = allocPage(length + 4096);
        for (let i = 0; i < length; i++) write8(input + BigInt(i), BigInt(parseInt(hex.slice(i * 2, i * 2 + 2), 16)));
        if (!verifyOnly) {
            const write = allocPage(8192);
            descriptor(write, input, length, 20);
            write32(write + 0x20n, 0x49434653n);
            write32(write + 0x28n, 1n);
            write32(write + 0x30n, 1n);
            write64(write + 0x38n, BigInt(offset));
            write64(write + 0x40n, BigInt(length));
            const wt = Number(sendIPC(file, write)) >>> 0;
            const wr = wt === 0 ? cmifReply(write) : null;
            requireOk(wt === 0 && wr?.result === 0, "write failed at " + offset);
        }
        const read = allocPage(8192);
        descriptor(read, output, length, 24);
        write32(read + 0x20n, 0x49434653n);
        write32(read + 0x28n, 0n);
        write64(read + 0x30n, 0n);
        write64(read + 0x38n, BigInt(offset));
        write64(read + 0x40n, BigInt(length));
        const rt = Number(sendIPC(file, read)) >>> 0;
        const rr = rt === 0 ? cmifReply(read) : null;
        const count = rr?.result === 0 ? Number(read64(read + BigInt(rr.data))) : -1;
        requireOk(rt === 0 && rr?.result === 0 && count === length, "readback failed at " + offset);
        for (let i = 0; i < length; i++) if (Number(read8(output + BigInt(i))) !== parseInt(hex.slice(i * 2, i * 2 + 2), 16)) fail("byte mismatch at " + (offset + i));
        if (!verifyOnly) {
            const commit = ipcCommitChecked(sd);
            requireOk(commit.transport === 0 && commit.result === 0, "SD commit failed at " + offset);
        }
        transfers[target] = {
            total: total,
            hash: expectedHash,
            next: offset + length,
            verifyOnly: verifyOnly
        };
        await log("hbmenu SD verified " + (offset + length) + "/" + total);
    } finally {
        if (file) closeHandle(file);
        if (sd) closeHandle(sd);
        closeHandle(root);
    }
}
