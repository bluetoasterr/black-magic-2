import { buffersEqual, checkAddressHeaderEncoding, cleanup, hasByteDifferent, hasByteDifferentFast, ipcGetEntryTypeRawBytes, pad2, padRight, formatWaveSummaryLine, readFsAddressBytes, readHexBytes, bytesToHex, scanPointerWords } from "./util.mjs";

import { inspectFspIdentityTargetsReadOnly as _inspectFspIdentityTargetsReadOnly, scanNativeLinkBuffer, scanRootDomainChunk, scanRootDomainChunkPrefiltered, captureDomainTail, recordRootDomainCandidate, inspectRootBackend } from "./scan.mjs";

import { resolvePoolCandidates, discoverMetadataAnchors, qualifyMetadataPage, verifyAddressCandidate } from "./discovery.mjs";

import { installAddressHeader, qualifyCacheBucketPeriod, retireCandidateCache } from "./cache.mjs";

import { buildPlans, configureProfile, configurePayload, writeIntoPayload, checkPathPairQuiet, queryCanaryHealth, nulWrites, analyzeWave } from "./wave.mjs";

export function createFspIdentityHelpers(options = {}) {
    const optimizeRootCandidateScan = options.optimizeRootCandidateScan === true;
    const collectRootScanTiming = options.collectRootScanTiming === true;
    return {
        inspectFspIdentityTargetsReadOnly: input => _inspectFspIdentityTargetsReadOnly({
            ...input,
            optimizeRootCandidateScan: optimizeRootCandidateScan,
            collectRootScanTiming: collectRootScanTiming
        }),
        scanNativeLinkBuffer: scanNativeLinkBuffer,
        resolvePoolCandidates: resolvePoolCandidates,
        discoverMetadataAnchors: discoverMetadataAnchors,
        qualifyMetadataPage: qualifyMetadataPage,
        verifyAddressCandidate: verifyAddressCandidate,
        scanRootDomainChunk: scanRootDomainChunk,
        scanRootDomainChunkPrefiltered: scanRootDomainChunkPrefiltered,
        captureDomainTail: captureDomainTail,
        recordRootDomainCandidate: recordRootDomainCandidate,
        readFsAddressBytes: readFsAddressBytes,
        inspectRootBackend: inspectRootBackend,
        pad2: pad2,
        padRight: padRight,
        formatWaveSummaryLine: formatWaveSummaryLine,
        readHexBytes: readHexBytes,
        bytesToHex: bytesToHex,
        ipcGetEntryTypeRawBytes: ipcGetEntryTypeRawBytes,
        checkAddressHeaderEncoding: checkAddressHeaderEncoding,
        buffersEqual: buffersEqual,
        hasByteDifferent: hasByteDifferent,
        hasByteDifferentFast: hasByteDifferentFast,
        scanPointerWords: scanPointerWords,
        cleanup: cleanup,
        installAddressHeader: installAddressHeader,
        qualifyCacheBucketPeriod: qualifyCacheBucketPeriod,
        retireCandidateCache: retireCandidateCache,
        buildPlans: buildPlans,
        configureProfile: configureProfile,
        configurePayload: configurePayload,
        writeIntoPayload: writeIntoPayload,
        checkPathPairQuiet: checkPathPairQuiet,
        queryCanaryHealth: queryCanaryHealth,
        nulWrites: nulWrites,
        analyzeWave: analyzeWave
    };
}
