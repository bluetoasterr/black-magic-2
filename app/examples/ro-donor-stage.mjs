import coreRuntime from "../src/core/runtime.mjs";

import { policyHex, payloadHex } from "./ro-donor-bytes.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, getMountHandle: getMountHandle, ipcCommitChecked: ipcCommitChecked, ipcCreateFile: ipcCreateFile, ipcGetEntryType: ipcGetEntryType, ipcOpenFile: ipcOpenFile, log: log, prepPacket: prepPacket, read8: read8, read64: read64, sendIPC: sendIPC, write8: write8, write32: write32, write64: write64} = coreRuntime;

const fromHex = hex => {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    return bytes;
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO donor stage: " + message);
};

const descriptor = (packet, buffer, length, direction) => {
    prepPacket(packet, (4 | 1 << direction) >>> 0, 14, []);
    write32(packet + 8n, BigInt(length));
    write32(packet + 12n, buffer & 0xffffffffn);
    const flags = 1n | (buffer >> 36n & 7n) << 2n | (buffer >> 32n & 15n) << 28n;
    write32(packet + 16n, flags);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    check(fs?.status().ready && globalThis.civRoRootPromotion?.root === fs.status().fsRoot.object, "verified FS root unavailable");
    const files = [ {
        path: "/main.npdm",
        bytes: fromHex(policyHex)
    }, {
        path: "/main",
        bytes: fromHex(payloadHex)
    } ];
    check(files[0].bytes.length === 1264 && files[0].bytes.slice(0, 4).every((b, i) => b === [ 77, 69, 84, 65 ][i]) && files[1].bytes.length === 4757, "donor assets differ from verified manifest");
    const mount = getMountHandle("save");
    check(mount, "save mount unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let handle = 0, committed = false;
    try {
        handle = cloneObject(mount.handle, mount.objId);
        check(handle, "save mount clone failed");
        const before = files.map(file => ipcGetEntryType(handle, file.path));
        if (before.every(entry => entry.error === 0 && entry.type === 1)) {
            committed = true;
            await log("RO donor files already present; frontend stage will " + "verify their exact contents");
            return;
        }
        check(before.every(entry => entry.error === 514), "donor files are partially present or lookup failed");
        for (const file of files) {
            const created = ipcCreateFile(handle, file.path, file.bytes.length);
            check(created === 0, file.path + " creation result=0x" + (Number(created) >>> 0).toString(16));
            let child = 0;
            try {
                child = ipcOpenFile(handle, file.path, 3);
                check(child, file.path + " open failed");
                const input = allocPage(8192);
                const output = allocPage(8192);
                for (let i = 0; i < file.bytes.length; i++) write8(input + BigInt(i), BigInt(file.bytes[i]));
                const writePacket = allocPage(8192);
                descriptor(writePacket, input, file.bytes.length, 20);
                write32(writePacket + 0x20n, 0x49434653n);
                write32(writePacket + 0x28n, 1n);
                write32(writePacket + 0x30n, 1n);
                write64(writePacket + 0x38n, 0n);
                write64(writePacket + 0x40n, BigInt(file.bytes.length));
                const writeTransport = Number(sendIPC(child, writePacket)) >>> 0;
                const writeReply = writeTransport === 0 ? cmifReply(writePacket) : null;
                check(writeTransport === 0 && writeReply?.result === 0, file.path + " write transport/result failed");
                const readPacket = allocPage(8192);
                descriptor(readPacket, output, file.bytes.length, 24);
                write32(readPacket + 0x20n, 0x49434653n);
                write32(readPacket + 0x28n, 0n);
                write64(readPacket + 0x30n, 0n);
                write64(readPacket + 0x38n, 0n);
                write64(readPacket + 0x40n, BigInt(file.bytes.length));
                const readTransport = Number(sendIPC(child, readPacket)) >>> 0;
                const readReply = readTransport === 0 ? cmifReply(readPacket) : null;
                const count = readReply?.result === 0 ? Number(read64(readPacket + BigInt(readReply.data))) : 0;
                check(readTransport === 0 && readReply?.result === 0 && count === file.bytes.length, file.path + " readback was short or failed");
                for (let i = 0; i < file.bytes.length; i++) check(Number(read8(output + BigInt(i))) === file.bytes[i], file.path + " readback differs at byte " + i);
                await log("RO donor " + file.path + " verified: " + file.bytes.length + " bytes");
            } finally {
                if (child) closeHandle(child);
            }
        }
        const commit = ipcCommitChecked(handle);
        check(commit.transport === 0 && commit.result === 0, "save commit failed");
        committed = true;
        for (const file of files) {
            const entry = ipcGetEntryType(handle, file.path);
            check(entry.error === 0 && entry.type === 1, file.path + " missing after commit");
        }
        globalThis.civRoDonorStaged = Object.freeze({
            files: Object.freeze(files.map(file => Object.freeze({
                path: file.path,
                length: file.bytes.length
            })))
        });
        await log("RO donor files committed and verified in save mount");
    } finally {
        if (handle) closeHandle(handle);
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
        if (!committed) await log("RO donor stage did not commit; inspect save " + "before retrying");
    }
}
