import coreRuntime from "../src/core/runtime.mjs";

function equal(left, right) {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function check(ok, message) {
    if (!ok) throw new Error("FS scratch write: " + message);
}

export async function run() {
    const endpoint = globalThis.civFsMemory;
    check(endpoint, "FS memory handoff unavailable");
    const state = endpoint.status();
    check(state.ready && state.fsRoot, "verified FS session unavailable");
    const address = state.array + 1416;
    check(Number.isSafeInteger(state.array) && state.array % 8 === 0 && address >= state.fsRoot.captureStart && address + 16 <= state.fsRoot.captureEnd, "owned scratch slot left verified FS capture");
    const before = await endpoint.read(address, 16);
    const marker = [ 82, 79, 45, 70, 83, 45, 80, 82, 79, 79, 70, 45, 49, 52, 0, 1 ];
    check(!equal(before, marker), "scratch already contains marker");
    let attempted = false;
    try {
        attempted = true;
        await endpoint.compareWrite(address, before, marker);
        check(equal(await endpoint.read(address, 16), marker), "marker readback differs");
    } finally {
        if (attempted) {
            const current = await endpoint.read(address, 16);
            if (!equal(current, before)) await endpoint.compareWrite(address, current, before);
        }
    }
    check(equal(await endpoint.read(address, 16), before), "scratch did not restore exactly");
    await coreRuntime.log("FS-owned scratch compare-write verified and restored: 0x" + address.toString(16));
}
