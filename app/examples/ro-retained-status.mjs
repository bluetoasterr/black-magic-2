import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    const workers = globalThis.civRoWorkers;
    const event = globalThis.civRoEvent;
    if (!fs?.status().ready || workers?.list?.length !== 7 || !event?.read || !event?.write || !event?.notifierHandle) throw new Error("RO retained state unavailable");
    const root = fs.status().fsRoot;
    const bytes = await fs.read(root.object, 64);
    if (bytes.length !== 64 || !fs.status().ready) throw new Error("RO FS endpoint became unresponsive");
    await log("RO retained state healthy: FS read, seven workers, " + "read/write event and notifier handle");
}
