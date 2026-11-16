function ipcFreeSpace(handle, path) {
    path = path || "/";
    const pathBuf = allocPage(4096);
    writeStr(pathBuf, path);
    const buf = allocPage(8192);
    prepPacket(buf, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(buf, 8, pathBuf, path.length + 1);
    write32(buf + 0x10n, 0x49434653n);
    write32(buf + 0x18n, 11n);
    sendIPC(handle, buf);
    const reply = cmifReply(buf);
    if (reply.result !== 0) return {
        error: reply.result,
        bytes: -1
    };
    const lo = Number(read32(buf + BigInt(reply.data))) >>> 0;
    const hi = Number(read32(buf + BigInt(reply.data + 4))) >>> 0;
    return {
        error: 0,
        bytes: lo + hi * 4294967296
    };
}

function ipcGetEntryType(handle, path) {
    const pathBuf = allocPage(4096);
    writeStr(pathBuf, path);
    const buf = allocPage(8192);
    prepPacket(buf, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(buf, 8, pathBuf, path.length + 1);
    write32(buf + 0x10n, 0x49434653n);
    write32(buf + 0x18n, 7n);
    sendIPC(handle, buf);
    const reply = cmifReply(buf);
    if (reply.result !== 0) return {
        error: reply.result,
        type: -1
    };
    return {
        error: 0,
        type: Number(read32(buf + BigInt(reply.data))) >>> 0
    };
}

function ipcListDirectory(handle, path, mode, onDirectoryClose) {
    const IFS_CMD_OPEN_DIRECTORY = 9;
    const IDIRECTORY_CMD_READ = 0;
    mode = mode || 3;
    const pathBuf = allocPage(4096);
    writeStr(pathBuf, path);
    const buf = allocPage(8192);
    prepPacket(buf, (4 | 1 << 16) >>> 0, 12, []);
    writeXDesc(buf, 8, pathBuf, 769);
    write32(buf + 0x10n, 0x49434653n);
    write32(buf + 0x18n, BigInt(IFS_CMD_OPEN_DIRECTORY));
    write32(buf + 0x20n, BigInt(mode));
    sendIPC(handle, buf);
    const openReply = cmifReply(buf);
    if (openReply.result !== 0 || openReply.moves.length === 0) return {
        error: openReply.result || 65535,
        openResult: openReply.result,
        openOk: false,
        readResult: null,
        entries: []
    };
    const dirHandle = openReply.moves[0];
    var result = null;
    try {
        var ENTRY_SIZE = 784;
        var MAX_ENTRIES = 64;
        var outSize = ENTRY_SIZE * MAX_ENTRIES;
        var outBuf = allocPage(outSize + 4096);
        for (var i = 0n; i < BigInt(outSize); i += 8n) write64(outBuf + i, 0n);
        var readBuf = allocPage(8192);
        for (var j = 0n; j < 0x200n; j += 8n) write64(readBuf + j, 0n);
        write32(readBuf, BigInt((4 | 1 << 24) >>> 0));
        write32(readBuf + 4n, 8n);
        var addrLow = Number(outBuf & 0xFFFFFFFFn);
        var bDescriptorMode = 0;
        var bWord2 = (bDescriptorMode | Number(outBuf >> 36n & 0x7n) << 2 | Number(BigInt(outSize) >> 32n & 0xFn) << 24 | Number(outBuf >> 32n & 0xFn) << 28) >>> 0;
        write32(readBuf + 0x08n, BigInt(outSize));
        write32(readBuf + 0x0Cn, BigInt(addrLow >>> 0));
        write32(readBuf + 0x10n, BigInt(bWord2));
        write32(readBuf + 0x20n, 0x49434653n);
        write32(readBuf + 0x28n, BigInt(IDIRECTORY_CMD_READ));
        var readTransport = Number(sendIPC(dirHandle, readBuf)) >>> 0;
        var readReply = null;
        var readProtocolError = null;
        if (readTransport === 0) {
            readReply = cmifReply(readBuf);
            var sfcoMagic = Number(read32(readBuf + BigInt(readReply.at))) >>> 0;
            if (sfcoMagic !== 1329808979) readProtocolError = "response did not contain SFCO";
        }
        var entries = [];
        var entriesRead = null;
        if (readTransport === 0 && !readProtocolError && readReply.result === 0) {
            var entriesReadRaw = read64(readBuf + BigInt(readReply.data));
            entriesRead = entriesReadRaw.toString();
            var count = entriesReadRaw > BigInt(MAX_ENTRIES) ? MAX_ENTRIES : Number(entriesReadRaw);
            for (var e = 0; e < count; e++) {
                var base = outBuf + BigInt(e * ENTRY_SIZE);
                var name = "";
                for (var c = 0; c < 769; c++) {
                    var ch = Number(read8(base + BigInt(c)));
                    if (ch === 0) break;
                    name += String.fromCharCode(ch);
                }
                var entryType = Number(read8(base + 0x304n));
                var sizeLo = Number(read32(base + 0x308n)) >>> 0;
                var sizeHi = Number(read32(base + 0x30Cn)) >>> 0;
                entries.push({
                    name: name,
                    type: entryType,
                    size: sizeLo + sizeHi * 4294967296
                });
            }
        }
        var readError;
        if (readTransport !== 0) {
            readError = readTransport;
        } else if (readProtocolError) {
            readError = 4294967295;
        } else {
            readError = readReply.result;
        }
        result = {
            error: readError,
            openResult: openReply.result,
            openOk: true,
            readTransport: readTransport,
            readProtocolError: readProtocolError,
            readResult: readReply && !readProtocolError ? readReply.result : null,
            entriesRead: entriesRead,
            truncated: entriesRead !== null && BigInt(entriesRead) >= BigInt(MAX_ENTRIES),
            entries: entries
        };
        return result;
    } finally {
        var closeResult = null;
        var closeError = null;
        try {
            closeResult = Number(closeHandle(dirHandle)) >>> 0;
            if (result) result.directoryCloseResult = closeResult;
        } catch (error) {
            closeError = error;
            if (result) result.directoryCloseError = error.message;
        }
        if (onDirectoryClose) onDirectoryClose(closeResult, closeError);
        if (closeError) throw closeError;
    }
}

function ipcSimpleCmd(handle, cmdId) {
    const buf = allocPage(8192);
    prepPacket(buf, 4, 8, [ [ 16, 1229145683 ], [ 24, cmdId ] ]);
    sendIPC(handle, buf);
    return cmifReply(buf);
}

function ipcPathCmd(handle, cmdId, path) {
    const pathBuf = allocPage(4096);
    writeStr(pathBuf, path);
    const buf = allocPage(8192);
    prepPacket(buf, (4 | 1 << 16) >>> 0, 12, []);
    writeXDesc(buf, 8, pathBuf, 768);
    write32(buf + 0x10n, 0x49434653n);
    write32(buf + 0x18n, BigInt(cmdId));
    sendIPC(handle, buf);
    const reply = cmifReply(buf);
    reply.buf = buf;
    return reply;
}

function armGetEntryType(pkt, pathBuf, pathSize) {
    pathSize = pathSize || 768;
    prepPacket(pkt, (4 | 1 << 16) >>> 0, 8, [ [ 16, 1229145683 ], [ 24, 7 ] ]);
    writeXDesc(pkt, 8, pathBuf, pathSize);
}

function ipcCreateDirectory(handle, path) {
    var pathBuf = allocPage(4096);
    var pkt = allocPage(8192);
    writeStr(pathBuf, path);
    prepPacket(pkt, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(pkt, 8, pathBuf, path.length + 1);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 2n);
    sendIPC(handle, pkt);
    return cmifReply(pkt).result;
}

function ipcCreateFile(handle, path, size) {
    var pathBuf = allocPage(4096);
    var pkt = allocPage(8192);
    writeStr(pathBuf, path);
    prepPacket(pkt, (4 | 1 << 16) >>> 0, 12, []);
    writeXDesc(pkt, 8, pathBuf, path.length + 1);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 0n);
    write32(pkt + 0x20n, 0n);
    write32(pkt + 0x24n, 0n);
    write64(pkt + 0x28n, BigInt(size || 0));
    sendIPC(handle, pkt);
    return cmifReply(pkt).result;
}

function ipcOpenFile(handle, path, mode) {
    var pathBuf = allocPage(4096);
    var pkt = allocPage(8192);
    writeStr(pathBuf, path);
    prepPacket(pkt, (4 | 1 << 16) >>> 0, 9, []);
    writeXDesc(pkt, 8, pathBuf, path.length + 1);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 8n);
    write32(pkt + 0x20n, BigInt(mode));
    sendIPC(handle, pkt);
    var reply = cmifReply(pkt);
    return reply.result === 0 && reply.moves.length ? reply.moves[0] : 0;
}

function ipcDeleteDirectoryRecursivelyChecked(handle, path) {
    var pathBuf = allocPage(4096);
    var pkt = allocPage(8192);
    writeStr(pathBuf, path);
    prepPacket(pkt, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(pkt, 8, pathBuf, path.length + 1);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 4n);
    var transport = Number(sendIPC(handle, pkt)) >>> 0;
    if (transport !== 0) return {
        transport: transport,
        result: null
    };
    return {
        transport: transport,
        result: cmifReply(pkt).result
    };
}

function ipcDeleteDirectoryRecursively(handle, path) {
    var checked = ipcDeleteDirectoryRecursivelyChecked(handle, path);
    return checked.transport === 0 ? checked.result : 4294967295;
}

function ipcCommitChecked(handle) {
    var pkt = allocPage(8192);
    prepPacket(pkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 10 ] ]);
    var transport = Number(sendIPC(handle, pkt)) >>> 0;
    if (transport !== 0) return {
        transport: transport,
        result: null
    };
    return {
        transport: transport,
        result: cmifReply(pkt).result
    };
}

function ipcCommit(handle) {
    var checked = ipcCommitChecked(handle);
    return checked.transport === 0 ? checked.result : 4294967295;
}
