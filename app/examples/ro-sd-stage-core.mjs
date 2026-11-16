import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, ipcCommitChecked: ipcCommitChecked, ipcCreateFile: ipcCreateFile, ipcGetEntryType: ipcGetEntryType, ipcOpenFile: ipcOpenFile, log: log, prepPacket: prepPacket, read8: read8, read64: read64, sendIPC: sendIPC, write8: write8, write32: write32, write64: write64, writeStr: writeStr, writeXDesc: writeXDesc} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO SD stage: " + message);
};

const descriptor = (packet, buffer, length, direction) => {
    prepPacket(packet, (4 | 1 << direction) >>> 0, 14, []);
    write32(packet + 8n, BigInt(length));
    write32(packet + 12n, buffer & 0xffffffffn);
    const flags = 1n | (buffer >> 36n & 7n) << 2n | (buffer >> 32n & 15n) << 28n;
    write32(packet + 16n, flags);
};

const fromHex = hex => {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    return bytes;
};

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
    check(transport === 0 && reply?.result === 0, "CreateDirectory " + path + " failed");
}

function verifyFile(sd, path, bytes, output) {
    const child = ipcOpenFile(sd, path, 1);
    check(child, "OpenFile " + path + " failed");
    try {
        const sizePacket = allocPage(8192);
        prepPacket(sizePacket, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
        const sizeTransport = Number(sendIPC(child, sizePacket)) >>> 0;
        const sizeReply = sizeTransport === 0 ? cmifReply(sizePacket) : null;
        const size = sizeReply?.result === 0 ? Number(read64(sizePacket + BigInt(sizeReply.data))) : -1;
        check(sizeTransport === 0 && sizeReply?.result === 0 && size === bytes.length, path + " size differs");
        for (let offset = 0; offset < size; offset += 4096) {
            const length = Math.min(4096, size - offset);
            const packet = allocPage(8192);
            descriptor(packet, output, length, 24);
            write32(packet + 0x20n, 0x49434653n);
            write32(packet + 0x28n, 0n);
            write64(packet + 0x30n, 0n);
            write64(packet + 0x38n, BigInt(offset));
            write64(packet + 0x40n, BigInt(length));
            const transport = Number(sendIPC(child, packet)) >>> 0;
            const reply = transport === 0 ? cmifReply(packet) : null;
            const count = reply?.result === 0 ? Number(read64(packet + BigInt(reply.data))) : 0;
            check(transport === 0 && reply?.result === 0 && count === length, path + " readback failed at " + offset);
            for (let i = 0; i < length; i++) check(Number(read8(output + BigInt(i))) === bytes[offset + i], path + " differs at " + (offset + i) + " expected=" + bytes[offset + i] + " actual=" + Number(read8(output + BigInt(i))));
        }
    } finally {
        closeHandle(child);
    }
}

function writeFile(sd, path, bytes, input) {
    check(ipcCreateFile(sd, path, bytes.length) === 0, path + " creation failed");
    const child = ipcOpenFile(sd, path, 3);
    check(child, path + " open for write failed");
    try {
        for (let offset = 0; offset < bytes.length; offset += 4096) {
            const length = Math.min(4096, bytes.length - offset);
            for (let i = 0; i < length; i++) write8(input + BigInt(i), BigInt(bytes[offset + i]));
            const packet = allocPage(8192);
            descriptor(packet, input, length, 20);
            write32(packet + 0x20n, 0x49434653n);
            write32(packet + 0x28n, 1n);
            write32(packet + 0x30n, 1n);
            write64(packet + 0x38n, BigInt(offset));
            write64(packet + 0x40n, BigInt(length));
            const transport = Number(sendIPC(child, packet)) >>> 0;
            const reply = transport === 0 ? cmifReply(packet) : null;
            check(transport === 0 && reply?.result === 0, path + " write failed at " + offset);
        }
    } finally {
        closeHandle(child);
    }
}

export async function stage(path, hex, sha256, expectedLength) {
    const fs = globalThis.civFsMemory;
    const promotion = globalThis.civRoRootPromotion;
    const session = globalThis.fspSrv;
    check(fs?.status().ready && promotion?.root === fs.status().fsRoot.object && session?.handle && session?.rootObj && path.startsWith("/kaihen/") && !path.includes(".."), "verified promoted root or SD target unavailable");
    const bytes = fromHex(hex);
    check(bytes.length === expectedLength && /^[0-9a-f]{64}$/.test(sha256), "local kaiHEN asset differs");
    const root = cloneObject(session.handle, session.rootObj);
    check(root, "dedicated root clone failed");
    let sd = 0;
    try {
        const packet = allocPage(8192);
        prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 18 ] ]);
        const transport = Number(sendIPC(root, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        check(transport === 0 && reply?.result === 0 && reply.moves.length === 1, "OpenSdCardFileSystem failed");
        sd = reply.moves[0];
        const segments = path.split("/").slice(1, -1);
        let directory = "";
        for (const segment of segments) {
            directory += "/" + segment;
            const entry = ipcGetEntryType(sd, directory);
            if (entry.error === 514) createDirectory(sd, directory); else check(entry.error === 0 && entry.type === 0, directory + " is not a directory");
        }
        const output = allocPage(8192);
        const input = allocPage(8192);
        const existing = ipcGetEntryType(sd, path);
        if (existing.error === 0) {
            check(existing.type === 1, path + " existing entry is not a file");
            verifyFile(sd, path, bytes, output);
        } else {
            check(existing.error === 514, path + " lookup failed");
            writeFile(sd, path, bytes, input);
            verifyFile(sd, path, bytes, output);
            const commit = ipcCommitChecked(sd);
            check(commit.transport === 0 && commit.result === 0, path + " SD commit failed");
        }
        verifyFile(sd, path, bytes, output);
        (globalThis.civRoSdStaged ||= {})[path] = {
            bytes: bytes.length,
            sha256: sha256
        };
        await log("kaiHEN SD file staged and verified: " + path + " (" + bytes.length + " bytes)");
    } finally {
        if (sd) closeHandle(sd);
        closeHandle(root);
    }
}
