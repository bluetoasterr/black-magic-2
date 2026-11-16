import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const status = fs?.status?.();
    await log("RO port status: FS=" + !!status?.ready + " workers=" + (globalThis.civRoWorkers?.list?.length || 0) + " frontendStaged=" + !!globalThis.civRoFrontendStaged + " promoted=" + !!globalThis.civRoRootPromotion + " frontendReady=" + !!globalThis.civRoFrontendReady);
    if (status?.ready) {
        const root = status.fsRoot;
        const bytes = await fs.read(root.object, 64);
        await log("RO port endpoint read: " + bytes.length + " bytes, root=0x" + root.object.toString(16));
    }
}
