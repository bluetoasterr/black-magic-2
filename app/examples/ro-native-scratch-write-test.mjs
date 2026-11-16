import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

export async function run() {
    const fs = globalThis.civFsMemory;
    if (!fs?.status().ready || typeof fs.probeBoundedNativeScratchWrite !== "function") throw new Error("native scratch endpoint unavailable");
    const state = fs.status();
    const address = state.array + 1416;
    if (address < state.fsRoot.captureStart || address + 16 > state.fsRoot.captureEnd) throw new Error("scratch slot outside verified FS capture");
    const before = await fs.read(address, 16);
    const marker = [ 78, 65, 84, 73, 86, 69, 45, 70, 83, 45, 87, 82, 73, 84, 69, 49 ];
    if (equal(before, marker)) throw new Error("scratch already equals native marker");
    const selected = await fs.read(address - 48, 64);
    if (selected.length !== 64) throw new Error("scratch offset preselection failed");
    const cancel = globalThis.civRoWorkers?.list?.length === 7;
    const result = fs.probeBoundedNativeScratchWrite(marker, cancel);
    if (!result.completed) {
        await log("Native scratch write timed out; no FS cleanup request sent");
        return;
    }
    try {
        if (result.transport !== 0 || result.result !== 0 || cancel && (result.cancellations.length !== 7 || result.cancellations.some(code => code !== 0))) throw new Error("native scratch write/cancel failed: " + result.transport + "/" + result.result);
        if (!equal(await fs.read(address, 16), marker)) throw new Error("native scratch marker readback differs");
    } finally {
        const current = await fs.read(address, 16);
        if (!equal(current, before)) await fs.compareWrite(address, current, before);
    }
    if (!equal(await fs.read(address, 16), before)) throw new Error("native scratch slot did not restore");
    await log("Native scratch write verified and restored; " + "worker cancellations=" + (cancel ? 7 : 0));
}
