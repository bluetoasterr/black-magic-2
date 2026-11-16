import coreRuntime from "../src/core/runtime.mjs";

export async function run() {
    const fs = globalThis.civFsMemory;
    if (!fs?.status().ready) throw new Error("FS endpoint unavailable");
    for (const name of [ "civRoServerCopy", "civRoOwned", "civRoEvent", "civRoWorkers" ]) {
        const state = globalThis[name];
        if (state?.release) state.release();
    }
    const root = fs.status().fsRoot;
    const bytes = await fs.read(root.object, 64);
    if (bytes.length !== 64 || !fs.status().ready) throw new Error("FS endpoint did not respond after gate-handle release");
    await coreRuntime.log("RO gate handles released; FS endpoint responsive");
}
