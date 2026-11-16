import coreRuntime from "../src/core/runtime.mjs";

const {closeRawThread: closeRawThread, cmifReply: cmifReply, log: log, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const map = globalThis.civRoBootstrapMap;
    if (!map?.worker?.handle || map.state !== "pending") throw new Error("No pending bootstrap map to recover");
    if (waitRawThread(map.worker.handle, 0n) !== 0) throw new Error("LoadNro worker still running");
    const transport = Number(readFrameResult(map.frame.frame, 0)) >>> 0;
    const reply = transport === 0 ? cmifReply(map.packet) : null;
    const destination = reply?.result === 0 ? read64(map.packet + BigInt(reply.data)) : 0n;
    if (transport !== 0 || reply?.result !== 0 || destination < 0x1000000n || destination >= 0x8000000000n || destination % 0x1000n !== 0n) throw new Error("LoadNro reply is not a valid mapped address");
    closeRawThread(map.worker.handle);
    map.worker = null;
    map.destination = destination;
    map.entry = destination + BigInt(map.entryOffset);
    map.tryWaitAdapter = map.entry + BigInt(map.adapterOffset);
    map.state = "mapped";
    await log("kaiHEN bootstrap LoadNro returned a mapped address 0x" + destination.toString(16));
}
