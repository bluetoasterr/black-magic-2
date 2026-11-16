import coreRuntime from "../src/core/runtime.mjs";

const {log: log, read32: read32, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const matches = [];
    for (let off = 1470464; off < 1482752; off += 4) {
        if (Number(read32(sdk_base + BigInt(off))) === 3556770913) matches.push(off);
    }
    await log("Async IPC svc #0x23 wrapper scan: " + (matches.length ? matches.map(off => "sdk+0x" + off.toString(16)).join(", ") : "none in SDK syscall-wrapper window"));
}
