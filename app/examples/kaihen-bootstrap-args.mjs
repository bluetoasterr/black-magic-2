const put32 = (bytes, at, value) => {
    const n = Number(value) >>> 0;
    for (let i = 0; i < 4; i++) bytes[at + i] = n >>> 8 * i & 255;
};

const put64 = (bytes, at, value) => {
    let n = BigInt(value);
    for (let i = 0; i < 8; i++) {
        bytes[at + i] = Number(n & 255n);
        n >>= 8n;
    }
};

export function buildBootstrapArgs(input) {
    if (!input || input.workers?.length !== 7 || input.waiters?.length !== 7) throw new Error("kaiHEN bootstrap workers/waiters differ");
    const bytes = new Uint8Array(432);
    put32(bytes, 0, input.candidateHandle);
    put64(bytes, 8, input.dataOffset);
    put64(bytes, 16, input.dataEntryOffset + 32);
    const gate = [ input.row.address, input.row.vptr, input.row.domain, input.row.metadata, input.row.request, ...input.waiters ];
    gate.forEach((value, i) => put64(bytes, 24 + i * 8, value));
    input.workers.forEach((handle, i) => put32(bytes, 120 + i * 4, handle));
    [ input.row.receive, input.row.wait, input.event.sourceHandle, input.loaderServerCopy, input.event.read, input.event.write ].forEach((value, i) => put32(bytes, 148 + i * 4, value));
    [ input.root.table, input.loader.targetDomain, input.rootId, input.donor.entry, input.donor.object, input.donor.metadata, input.donor.vptr, 0x040000000000003an ].forEach((value, i) => put64(bytes, 176 + i * 8, value));
    put32(bytes, 240, input.pmShell);
    put32(bytes, 244, input.pmMonitor);
    put64(bytes, 248, 0x040000000000003an);
    put32(bytes, 256, 20);
    bytes[260] = 3;
    put64(bytes, 264, input.sdkBase + 1319296n);
    put64(bytes, 272, input.tryWaitAdapter);
    put64(bytes, 280, input.sdkBase + 1320064n);
    put32(bytes, 288, input.smHandle);
    put32(bytes, 292, input.roHandle);
    put32(bytes, 296, input.promotedRootHandle);
    const path = "@Sdcard:/kaihen/bin/hen/exefs.nsp";
    for (let i = 0; i < path.length; i++) bytes[300 + i] = path.charCodeAt(i);
    put32(bytes, 396, input.fsProcessHandle);
    put32(bytes, 400, input.notifierHandle);
    put32(bytes, 404, input.loaderRootHandle);
    return bytes;
}
