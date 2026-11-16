import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

const check = (ok, message) => {
    if (!ok) throw new Error("RO bounded pointer: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    check(fs?.status().ready && typeof fs.selectPointerBounded === "function" && typeof fs.probeBoundedNativeRead === "function", "verified endpoint unavailable");
    const array = fs.status().array;
    const addresses = [ array, array + 1416 ];
    const expected = [];
    for (const address of addresses) expected.push(await fs.read(address, 8));
    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        const selected = await fs.selectPointerBounded(address);
        if (!selected.completed || !selected.verified) {
            await log("RO bounded pointer selection failed at " + selected.stage + "; stop and reboot");
            return;
        }
        const observed = await fs.probeBoundedNativeRead(address, 8, true);
        if (!observed.completed || observed.transport !== 0 || observed.result !== 0 || !equal(observed.bytes, expected[i])) {
            await log("RO bounded pointer readback failed; stop and reboot");
            return;
        }
    }
    await log("RO bounded pointer retarget verified on two owned addresses");
}
