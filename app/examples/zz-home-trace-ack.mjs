import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

const HOST = {
    base: null,
    entry: null,
    cave: null
};

export async function run() {
    const o = globalThis.civHomeOriginals;
    if (!o?.base || !o.entry || !o.cave) throw new Error("trace-ack: run zz-home-trace-read.mjs first");
    if (!HOST.base || !HOST.entry || !HOST.cave) throw new Error("trace-ack: host constants not filled from a " + "durably saved file; refusing to open the install gate");
    if (o.base !== HOST.base || o.entry !== HOST.entry || o.cave !== HOST.cave) throw new Error("trace-ack: session originals differ from the " + "host-saved file (session=" + JSON.stringify(o) + " host=" + JSON.stringify(HOST) + "); NOT opening the install gate");
    globalThis.civHomeTraceAck = Object.freeze({
        ...HOST,
        saved: true
    });
    await log("trace-ack: host-saved originals verified against the " + "session for base=" + HOST.base + "; install gate open");
}
