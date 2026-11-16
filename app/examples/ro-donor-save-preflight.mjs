import coreRuntime from "../src/core/runtime.mjs";

const {cloneObject: cloneObject, closeHandle: closeHandle, getMountHandle: getMountHandle, ipcFreeSpace: ipcFreeSpace, ipcGetEntryType: ipcGetEntryType, log: log} = coreRuntime;

export async function run() {
    if (!globalThis.civFsMemory?.status().ready) throw new Error("RO donor preflight: verified FS unavailable");
    const mount = getMountHandle("save");
    if (!mount) throw new Error("RO donor preflight: save mount missing");
    const handle = cloneObject(mount.handle, mount.objId);
    if (!handle) throw new Error("RO donor preflight: save clone failed");
    try {
        const names = [ "main.npdm", "main", "rtld", "sdk", ...Array.from({
            length: 10
        }, (_, i) => "subsdk" + i) ];
        const entries = [];
        for (const name of names) {
            const result = ipcGetEntryType(handle, "/" + name);
            entries.push(name + "=0x" + (Number(result.error) >>> 0).toString(16) + "/" + result.type);
        }
        const free = ipcFreeSpace(handle, "/");
        await log("RO donor save paths: " + entries.join(" "));
        await log("RO donor save free-space result: " + JSON.stringify(free));
        if (free.error !== 0 || free.bytes < 65536) throw new Error("RO donor preflight: insufficient save space");
        if (entries.some(item => !item.includes("=0x202/"))) throw new Error("RO donor preflight: a donor path exists or " + "returned another result");
    } finally {
        closeHandle(handle);
    }
}
