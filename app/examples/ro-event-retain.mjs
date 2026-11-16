import coreRuntime from "../src/core/runtime.mjs";

const {SVC_WaitSync: SVC_WaitSync, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, call_rop: call_rop, cloneObject: cloneObject, closeHandle: closeHandle, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, log: log, prepPacket: prepPacket, read8: read8, readDomainObjects: readDomainObjects, sdk_base: sdk_base, sendDomainCmd: sendDomainCmd, sendIPC: sendIPC, write32: write32, write64: write64, write8: write8} = coreRuntime;

function u32(bytes, offset) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}

function u64(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = value << 8n | BigInt(bytes[offset + i]);
    return Number(value);
}

function bytes32(value) {
    return [ value & 255, value >>> 8 & 255, value >>> 16 & 255, value >>> 24 & 255 ];
}

function equal(a, b) {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function check(ok, message) {
    if (!ok) throw new Error("RO event gate: " + message);
}

export async function run() {
    check(!globalThis.civRoEvent, "event already retained");
    const endpoint = globalThis.civFsMemory;
    const session = globalThis.fspSrv;
    check(endpoint && session && endpoint.status().ready, "verified FS session unavailable");
    const root = endpoint.status().fsRoot;
    check(root && root.captureEnd - root.captureStart === 5079040, "FS capture geometry differs");
    const canonical = address => Number.isSafeInteger(address) && address >= 4294967296 && address < 549755813888 && address % 8 === 0;
    const sdk = root.captureStart + 5242880;
    check(sdk % 4096 === 0 && Math.abs(sdk - root.rootVptr - 15961056) <= 65536, "FS SDK page differs from validated root vtable");
    const header = await endpoint.read(sdk + 2096, 32);
    check(u64(header, 8) === sdk + 1640 && u32(header, 24) > 0 && u32(header, 24) <= 128, "FS SDK thread ring differs");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let domainId = 0, notifierHandle = 0;
    let readHandle = 0, writeHandle = 0, sourceHandle = 0;
    const returnedHandles = [];
    let handleField = 0, original = null, replacement = null;
    let replacementAttempted = false, restored = false;
    let committed = false, qualified = false;
    try {
        const openPacket = allocPage(8192);
        const opened = sendDomainCmd(session.handle, session.rootObj, 510, openPacket, () => {}, 0);
        check(opened.ok && opened.transport === 0 && opened.result === 0 && opened.objCount === 1, "notifier open failed");
        const objects = readDomainObjects(openPacket, 1, 0);
        check(objects.length === 1 && objects[0] > 0, "notifier domain ID missing");
        domainId = objects[0];
        notifierHandle = cloneObject(session.handle, domainId);
        check(notifierHandle, "notifier clone failed");
        const entryAddress = root.table + (domainId - 1) * 48;
        check(entryAddress >= root.captureStart && entryAddress + 48 <= root.captureEnd, "notifier table entry outside capture");
        const entry = await endpoint.read(entryAddress, 48);
        const domain = u64(entry, 24), object = u64(entry, 32);
        check(canonical(domain) && canonical(object), "notifier pointers invalid");
        const wrapper = await endpoint.read(domain, 32);
        check(u64(wrapper, 0) === root.rootVptr + 10464 && u64(wrapper, 8) === root.rootVptr + 10552 && u64(wrapper, 24) === root.manager, "notifier wrapper identity differs");
        const notifier = await endpoint.read(object, 24);
        check(u64(notifier, 0) === root.rootVptr - 5824 && u32(notifier, 16) === 2, "notifier object identity differs");
        const backendAddress = u64(notifier, 8);
        check(canonical(backendAddress), "notifier backend invalid");
        const backend = await endpoint.read(backendAddress, 72);
        check(u64(backend, 16) === backendAddress + 16 && u64(backend, 24) === backendAddress + 16, "notifier event list differs");
        const existingHandle = u32(backend, 36);
        sourceHandle = u32(backend, 40);
        check(existingHandle >= 32768 && existingHandle < 268435456 && sourceHandle >= 32768 && sourceHandle < 268435456 && existingHandle !== sourceHandle, "notifier read/write handles differ");
        handleField = backendAddress + 36;
        original = bytes32(existingHandle);
        replacement = bytes32(sourceHandle);
        check(equal(await endpoint.read(handleField, 4), original), "notifier handle preimage changed");
        const getEventHandle = () => {
            const packet = allocPage(8192);
            prepPacket(packet, 4, 8, [ [ 16, 1229145683 ], [ 24, 0 ] ]);
            const transport = Number(sendIPC(notifierHandle, packet)) >>> 0;
            const reply = cmifReply(packet);
            for (const handle of [ ...reply.copies, ...reply.moves ]) if (handle) returnedHandles.push(handle);
            check(transport === 0 && reply.result === 0 && reply.copies.length === 1 && reply.moves.length === 0 && reply.copies[0] >= 32768, "notifier GetEventHandle failed");
            return reply.copies[0];
        };
        readHandle = getEventHandle();
        replacementAttempted = true;
        await endpoint.compareWrite(handleField, original, replacement);
        writeHandle = getEventHandle();
        check(writeHandle !== readHandle, "notifier read and write copies alias");
        const findSyscall = hex => {
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
            let found = 0n, count = 0;
            for (let off = 0; off + bytes.length <= 288; off += 4) {
                const address = sdk_base + 0x168b00n + BigInt(off);
                if (bytes.every((byte, i) => Number(read8(address + BigInt(i))) === byte)) {
                    found = address;
                    count++;
                }
            }
            check(count === 1, "event syscall wrapper is not unique");
            return found;
        };
        const signal = findSyscall("210200d4c0035fd6");
        const clear = findSyscall("410200d4c0035fd6");
        const waitCode = "e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6";
        for (let i = 0; i < waitCode.length / 2; i++) check(Number(read8(SVC_WaitSync + BigInt(i))) === parseInt(waitCode.slice(i * 2, i * 2 + 2), 16), "wait-synchronization wrapper differs");
        const waitBuf = allocPage(32);
        const wait = () => {
            write64(waitBuf, 0n);
            write32(waitBuf + 8n, BigInt(readHandle));
            return Number(call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, 0n)) >>> 0;
        };
        check(Number(call_rop(clear, BigInt(readHandle))) === 0 && wait() === 59905 && Number(call_rop(signal, BigInt(writeHandle))) === 0 && wait() === 0 && Number(call_rop(clear, BigInt(readHandle))) === 0 && wait() === 59905, "event signal/wait/clear sequence differs");
        qualified = true;
    } finally {
        try {
            if (replacementAttempted && handleField && original) {
                const current = await endpoint.read(handleField, 4);
                if (!equal(current, original)) await endpoint.compareWrite(handleField, current, original);
                restored = equal(await endpoint.read(handleField, 4), original);
            }
            committed = qualified && restored;
        } finally {
            if (!committed) for (const handle of returnedHandles) closeHandle(handle);
            if (!committed && notifierHandle) closeHandle(notifierHandle);
            if (!committed && domainId) {
                const closePacket = allocPage(8192);
                prepPacket(closePacket, 4, 8, []);
                write8(closePacket + 0x10n, 2n);
                write32(closePacket + 0x14n, BigInt(domainId));
                sendIPC(session.handle, closePacket);
            }
            if (endAllocationTracking(allocations)) freeTrackedAllocations(allocations);
        }
    }
    check(restored, "notifier handle field did not restore");
    check(committed && restored && readHandle && writeHandle && notifierHandle && domainId, "event retention incomplete");
    globalThis.civRoEvent = {
        read: readHandle,
        write: writeHandle,
        sourceHandle: sourceHandle,
        notifierHandle: notifierHandle,
        domainId: domainId,
        release() {
            if (globalThis.civRoEvent !== this) return;
            closeHandle(this.read);
            closeHandle(this.write);
            closeHandle(this.notifierHandle);
            const closePacket = allocPage(8192);
            prepPacket(closePacket, 4, 8, []);
            write8(closePacket + 0x10n, 2n);
            write32(closePacket + 0x14n, BigInt(this.domainId));
            sendIPC(session.handle, closePacket);
            delete globalThis.civRoEvent;
        }
    };
    await log("RO notifier event retained: read=" + readHandle + " write=" + writeHandle + " source=0x" + sourceHandle.toString(16) + " signal/wait/clear passed; notifier field restored");
}
