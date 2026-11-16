import coreRuntime from "../src/core/runtime.mjs";

const {SM_Initialize: SM_Initialize, SM_Finalize: SM_Finalize, call_rop: call_rop, log: log, read32: read32, read64: read64, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    throw new Error("Disabled: this inspects Civ VII, not the FS process");
    const sdk = Number(sdk_base);
    if (!Number.isSafeInteger(sdk) || sdk < 4294967296 || sdk >= 549755813888 || sdk % 4096 !== 0) throw new Error("RO SM candidate has invalid SDK base");
    const matches = [];
    const initResult = call_rop(SM_Initialize);
    try {
        for (let offset = 16; offset < 131072; offset += 8) {
            const address = sdk + offset;
            const guard = Number(read64(BigInt(address - 8)));
            if (guard !== address) continue;
            const handle = Number(read32(BigInt(address))) >>> 0;
            const reserved = Number(read32(BigInt(address + 4))) >>> 0;
            const flag = Number(read32(BigInt(address + 8))) & 65535;
            if (reserved === 0 && flag === 257 && handle >= 32768 && handle < 33554432) matches.push({
                offset: offset,
                handle: handle
            });
        }
    } finally {
        call_rop(SM_Finalize);
    }
    await log("RO SM guarded candidates while initialized (result=0x" + BigInt(initResult).toString(16) + "): " + (matches.length ? matches.map(item => "offset=0x" + item.offset.toString(16) + " handle=0x" + item.handle.toString(16)).join(", ") : "none"));
}
