import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const get32 = (bytes, at) => (bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24) >>> 0;

export async function run() {
    const input = globalThis.civRoBootstrapArgs;
    const event = globalThis.civRoEvent;
    const workers = globalThis.civRoWorkers?.list;
    if (!input?.bytes || !event || workers?.length !== 7 || get32(input.bytes, 156) !== event.sourceHandle) throw new Error("Original kaiHEN park handle differs");
    const worker = workers[0].source;
    if (worker < 32768 || worker === event.sourceHandle) throw new Error("Worker park source invalid");
    for (let i = 0; i < 4; i++) input.bytes[156 + i] = worker >>> i * 8 & 255;
    input.parkMode = "worker";
    await log("kaiHEN bootstrap input park handle changed to verified " + "FS worker source=0x" + worker.toString(16));
}
