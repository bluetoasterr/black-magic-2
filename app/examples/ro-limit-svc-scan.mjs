import coreRuntime from "../src/core/runtime.mjs";

const {log: log, read32: read32, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const targets = [ 41, 48, 49 ];
    for (const id of targets) {
        const opcode = 3556769793 | id << 5;
        const matches = [];
        for (let off = 1470464; off < 1482752; off += 4) if (Number(read32(sdk_base + BigInt(off))) === opcode) matches.push(off);
        await log("Resource query svc #0x" + id.toString(16) + ": " + (matches.length ? matches.map(off => "sdk+0x" + off.toString(16)).join(", ") : "absent"));
    }
}
