import coreRuntime from "../src/core/runtime.mjs";

const {log: log, read32: read32, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const hits = [];
    for (let offset = 1470464; offset < 1482752; offset += 4) {
        if (Number(read32(sdk_base + BigInt(offset))) >>> 0 === 3556770945) hits.push(offset);
    }
    await log("SDK svcGetProcessId instruction offsets: " + hits.map(value => "0x" + value.toString(16)).join(","));
}
