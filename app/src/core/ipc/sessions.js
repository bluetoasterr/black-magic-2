function openFspSession() {
    call_rop(SM_Initialize);
    var name = allocRawTracked(16);
    writeStr(name, "fsp-srv");
    var out = allocRawTracked(16);
    write64(out, 0n);
    var rc = call_rop(SM_GetService, out, name);
    call_rop(SM_Finalize);
    if (rc !== 0n) return 0;
    var handle = Number(read32(out)) >>> 0;
    if (!handle) return 0;
    var buf = allocPage(8192);
    prepPacket(buf, 4, (10 | 2147483648) >>> 0, []);
    write32(buf + 0x08n, 1n);
    write64(buf + 0x0Cn, 0n);
    write32(buf + 0x20n, 0x49434653n);
    write32(buf + 0x28n, 1n);
    sendIPC(handle, buf);
    var reply = cmifReply(buf);
    if (reply.result !== 0) {
        closeHandle(handle);
        return 0;
    }
    return handle;
}

function cloneObject(sessionHandle, domainObjId) {
    const buf = allocPage(8192);
    prepPacket(buf, 5, 9, [ [ 16, 1229145683 ], [ 24, 1 ], [ 32, domainObjId ] ]);
    sendIPC(sessionHandle, buf);
    const reply = cmifReply(buf);
    if (reply.result !== 0 || reply.moves.length === 0) return 0;
    return reply.moves[0];
}

function openDomainSession() {
    var h = openFspSession();
    if (!h) return null;
    var buf = allocPage(8192);
    prepPacket(buf, 5, 8, []);
    write32(buf + 0x10n, 0x49434653n);
    write32(buf + 0x18n, 0n);
    sendIPC(h, buf);
    var magic = Number(read32(buf + 0x10n)) >>> 0;
    if (magic !== 1329808979) {
        closeHandle(h);
        return null;
    }
    var reply = cmifReply(buf);
    if (reply.result !== 0) {
        closeHandle(h);
        return null;
    }
    var root = Number(read32(buf + BigInt(reply.data))) >>> 0;
    return {
        handle: h,
        rootObj: root
    };
}
