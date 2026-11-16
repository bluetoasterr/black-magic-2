import coreRuntime from "../src/core/runtime.mjs";

const {log: log, read8: read8, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    let hex = "";
    for (let off = 1477704; off < 1477748; off++) hex += Number(read8(sdk_base + BigInt(off))).toString(16).padStart(2, "0");
    await log("Async IPC wrapper sdk+0x168c48: " + hex);
}
