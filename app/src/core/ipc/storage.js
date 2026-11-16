function openContentStorage(rootSession) {
    var pkt = allocPage(8192);
    prepPacket(pkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 200 ] ]);
    sendIPC(rootSession, pkt);
    var reply = cmifReply(pkt);
    if (reply.result !== 0 || reply.moves.length !== 1) {
        for (var i = 0; i < reply.moves.length; i++) closeHandle(reply.moves[i]);
        for (var i = 0; i < reply.copies.length; i++) closeHandle(reply.copies[i]);
        return 0;
    }
    return reply.moves[0];
}

function ipcStorageGetSize(storageHandle) {
    var pkt = allocPage(8192);
    prepPacket(pkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
    sendIPC(storageHandle, pkt);
    var reply = cmifReply(pkt);
    if (reply.result !== 0) return {
        error: reply.result,
        size: 0
    };
    var lo = Number(read32(pkt + BigInt(reply.data))) >>> 0;
    var hi = Number(read32(pkt + BigInt(reply.data + 4))) >>> 0;
    return {
        error: 0,
        size: lo + hi * 4294967296
    };
}

function ipcStorageRead(storageHandle, offset, size, outputBuf) {
    var pkt = allocPage(8192);
    prepPacket(pkt, (4 | 1 << 24) >>> 0, 12, []);
    write32(pkt + 8n, BigInt(size));
    write32(pkt + 12n, BigInt(Number(outputBuf & 0xFFFFFFFFn)));
    write32(pkt + 16n, BigInt((1 | Number(outputBuf >> 36n & 7n) << 2 | Number(outputBuf >> 32n & 15n) << 28) >>> 0));
    write32(pkt + 0x20n, 0x49434653n);
    write32(pkt + 0x28n, 0n);
    write64(pkt + 0x30n, BigInt(offset));
    write64(pkt + 0x38n, BigInt(size));
    var transport = Number(sendIPC(storageHandle, pkt)) >>> 0;
    if (transport !== 0) {
        return {
            error: transport,
            canonicalError: null,
            transport: transport,
            cmifError: null
        };
    }
    var reply = cmifReply(pkt);
    return {
        error: reply.result,
        canonicalError: reply.result & 4194303,
        transport: transport,
        cmifError: reply.result
    };
}

function ipcStorageWrite(storageHandle, offset, inputBuf, size) {
    var writeOffset = BigInt(offset);
    var inputAddress = BigInt(inputBuf);
    var writeSize = BigInt(size);
    if (writeOffset < 0n || writeOffset >= 1n << 63n || inputAddress < 0n || inputAddress >= 1n << 39n || writeSize <= 0n || writeSize > 0xFFFFFFFFFn) {
        return {
            error: 4294967295,
            canonicalError: 4294967295
        };
    }
    var pkt = allocPage(8192);
    prepPacket(pkt, (4 | 1 << 20) >>> 0, 12, []);
    var descriptorFlags = 1n | inputAddress >> 36n << 2n | writeSize >> 32n << 24n | (inputAddress >> 32n & 0xFn) << 28n;
    write32(pkt + 0x08n, writeSize & 0xFFFFFFFFn);
    write32(pkt + 0x0Cn, inputAddress & 0xFFFFFFFFn);
    write32(pkt + 0x10n, descriptorFlags & 0xFFFFFFFFn);
    write32(pkt + 0x20n, 0x49434653n);
    write32(pkt + 0x28n, 1n);
    write64(pkt + 0x30n, writeOffset);
    write64(pkt + 0x38n, writeSize);
    var transport = Number(sendIPC(storageHandle, pkt)) >>> 0;
    var reply = cmifReply(pkt);
    return {
        error: reply.result,
        canonicalError: reply.result & 4194303,
        transport: transport
    };
}

function ipcStorageInvalidate(storageHandle, offset, size) {
    var pkt = allocPage(8192);
    prepPacket(pkt, 4, 12, []);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 5n);
    write32(pkt + 0x20n, 2n);
    write64(pkt + 0x28n, BigInt(offset));
    write64(pkt + 0x30n, BigInt(size));
    sendIPC(storageHandle, pkt);
    return cmifReply(pkt).result;
}

function cloneFsSession(sourceHandle) {
    var pkt = allocPage(8192);
    prepPacket(pkt, 5, 8, [ [ 16, 1229145683 ], [ 24, 2 ], [ 32, 0 ] ]);
    sendIPC(sourceHandle, pkt);
    var reply = cmifReply(pkt);
    if (reply.result !== 0 || reply.moves.length === 0) return 0;
    return reply.moves[0];
}
