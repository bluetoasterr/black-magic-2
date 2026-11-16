import coreRuntime from "../src/core/runtime.mjs";

import { payloadHex as demoHex, policyHex } from "./ro-donor-bytes.mjs";

import { frontendHex, frontendSha256 } from "./ro-frontend-bytes.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, getMountHandle: getMountHandle, ipcCommitChecked: ipcCommitChecked, ipcCreateFile: ipcCreateFile, ipcGetEntryType: ipcGetEntryType, ipcOpenFile: ipcOpenFile, log: log, prepPacket: prepPacket, read8: read8, read64: read64, sendIPC: sendIPC, write8: write8, write32: write32, write64: write64, writeStr: writeStr, writeXDesc: writeXDesc} = coreRuntime;

const fromHex = hex => {
    const out = [];
    for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
    return out;
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO frontend stage: " + message);
};

const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

const descriptor = (packet, buffer, length, direction) => {
    prepPacket(packet, (4 | 1 << direction) >>> 0, 14, []);
    write32(packet + 8n, BigInt(length));
    write32(packet + 12n, buffer & 0xffffffffn);
    const flags = 1n | (buffer >> 36n & 7n) << 2n | (buffer >> 32n & 15n) << 28n;
    write32(packet + 16n, flags);
};

export async function run() {
    check(globalThis.civFsMemory?.status().ready, "verified FS endpoint unavailable");
    const demo = fromHex(demoHex);
    const frontend = fromHex(frontendHex);
    const policy = fromHex(policyHex);
    check(demo.length === 4757 && frontend.length === 26367 && policy.length === 1264 && frontendSha256 === "5945fa6b7e32f6e9e5e25e0b578beff7d3d33739d9a0d1100f4a81b00be5e585", "local donor asset lengths or release digest changed");
    const mount = getMountHandle("save");
    check(mount, "save mount unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let handle = 0;
    const output = allocPage(8192);
    const input = allocPage(8192);
    const readFile = (path, expected) => {
        const child = ipcOpenFile(handle, path, 1);
        check(child, path + " open for verification failed");
        try {
            const sizePacket = allocPage(8192);
            prepPacket(sizePacket, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
            const sizeTransport = Number(sendIPC(child, sizePacket)) >>> 0;
            const sizeReply = sizeTransport === 0 ? cmifReply(sizePacket) : null;
            const size = sizeReply?.result === 0 ? Number(read64(sizePacket + BigInt(sizeReply.data))) : -1;
            check(sizeTransport === 0 && sizeReply?.result === 0 && size === expected.length, path + " size differs from expected donor");
            const seen = [];
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
                check(transport === 0 && reply?.result === 0 && count === length, path + " readback failed");
                for (let i = 0; i < length; i++) seen.push(Number(read8(output + BigInt(i))));
            }
            check(equal(seen, expected), path + " contents differ from verified donor");
        } finally {
            closeHandle(child);
        }
    };
    const sizeOf = path => {
        const child = ipcOpenFile(handle, path, 1);
        check(child, path + " open for size check failed");
        try {
            const packet = allocPage(8192);
            prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 4 ] ]);
            const transport = Number(sendIPC(child, packet)) >>> 0;
            const reply = transport === 0 ? cmifReply(packet) : null;
            check(transport === 0 && reply?.result === 0, path + " size query failed");
            return Number(read64(packet + BigInt(reply.data)));
        } finally {
            closeHandle(child);
        }
    };
    const deleteFile = path => {
        const pathBuf = allocPage(4096);
        writeStr(pathBuf, path);
        const packet = allocPage(8192);
        prepPacket(packet, (4 | 1 << 16) >>> 0, 8, []);
        writeXDesc(packet, 8, pathBuf, path.length + 1);
        write32(packet + 16n, 0x49434653n);
        write32(packet + 24n, 1n);
        const transport = Number(sendIPC(handle, packet)) >>> 0;
        const reply = transport === 0 ? cmifReply(packet) : null;
        check(transport === 0 && reply?.result === 0, path + " deletion failed");
    };
    const writeFile = (path, bytes) => {
        check(ipcCreateFile(handle, path, bytes.length) === 0, path + " creation failed");
        const child = ipcOpenFile(handle, path, 3);
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
    };
    try {
        handle = cloneObject(mount.handle, mount.objId);
        check(handle, "save mount clone failed");
        check(ipcGetEntryType(handle, "/main.npdm").type === 1 && ipcGetEntryType(handle, "/main").type === 1, "expected donor files are missing");
        readFile("/main.npdm", policy);
        let alreadyFrontend = false;
        try {
            readFile("/main", frontend);
            alreadyFrontend = true;
        } catch (error) {
            check(error.message.includes("size differs") || error.message.includes("contents differ"), "current /main verification failed unexpectedly");
        }
        if (!alreadyFrontend) {
            const current = sizeOf("/main");
            check(current === demo.length || current === 24299, "current /main is not a known donor build");
            deleteFile("/main");
            const deleted = ipcCommitChecked(handle);
            check(deleted.transport === 0 && deleted.result === 0 && ipcGetEntryType(handle, "/main").error === 514, "old demo donor did not delete cleanly");
            writeFile("/main", frontend);
            readFile("/main", frontend);
            const committed = ipcCommitChecked(handle);
            check(committed.transport === 0 && committed.result === 0, "frontend donor commit failed");
        }
        readFile("/main", frontend);
        readFile("/main.npdm", policy);
        globalThis.civRoFrontendStaged = Object.freeze({
            bytes: frontend.length,
            sha256: frontendSha256,
            policyBytes: policy.length
        });
        globalThis.civRoDonorStaged = Object.freeze({
            files: Object.freeze([ Object.freeze({
                path: "/main.npdm",
                length: policy.length
            }), Object.freeze({
                path: "/main",
                length: frontend.length
            }) ])
        });
        await log("RO frontend staged and verified in save mount: " + frontend.length + " bytes");
    } finally {
        if (handle) closeHandle(handle);
        if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
    }
}
