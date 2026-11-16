import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, call_rop: call_rop, log: log, read32: read32, read64: read64, sdk_base: sdk_base} = coreRuntime;

export async function run() {
    const map = globalThis.civRoBootstrapMap;
    if (!map?.destination || map.state !== "mapped") throw new Error("No mapped bootstrap destination");
    const query = sdk_base + 0x168b0cn;
    const out = allocPage(256);
    const offsets = [ 0, 65536, 69632, 73728 ];
    for (const offset of offsets) {
        const at = map.destination + BigInt(offset);
        const rc = Number(call_rop(query, out, out + 0x40n, at)) >>> 0;
        if (rc !== 0) throw new Error("QueryMemory failed: 0x" + rc.toString(16));
        const address = read64(out);
        const size = read64(out + 8n);
        const type = Number(read32(out + 16n)) >>> 0;
        const permission = Number(read32(out + 24n)) >>> 0;
        await log("NRO region +0x" + offset.toString(16) + " base=0x" + address.toString(16) + " size=0x" + size.toString(16) + " type=" + type + " perm=" + permission);
        if (at < address || at >= address + size || permission !== [ 5, 1, 3, 3 ][offsets.indexOf(offset)]) throw new Error("NRO mapped permission differs");
    }
    globalThis.civRoBootstrapMap.queryVerified = true;
}
