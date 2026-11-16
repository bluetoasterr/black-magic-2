import coreRuntime from "../src/core/runtime.mjs";

const {cmifReply: cmifReply, log: log, read32: read32, read64: read64, readFrameResult: readFrameResult, waitRawThread: waitRawThread} = coreRuntime;

export async function run() {
    const map = globalThis.civRoBootstrapMap;
    if (!map?.worker?.handle || !map.frame || !map.packet) throw new Error("retained LoadNro attempt unavailable");
    const finished = waitRawThread(map.worker.handle, 0n) === 0;
    const transport = Number(readFrameResult(map.frame.frame, 0)) >>> 0;
    const reply = finished && transport === 0 ? cmifReply(map.packet) : null;
    const destination = reply?.result === 0 ? read64(map.packet + BigInt(reply.data)) : 0n;
    await log("RO LoadNro diagnostic: finished=" + finished + " transport=0x" + transport.toString(16) + " result=0x" + (reply?.result ?? 4294967295).toString(16) + " source=0x" + map.source.toString(16) + " bss=0x" + map.bss.toString(16) + " destination=0x" + destination.toString(16) + " header=0x" + (Number(read32(map.packet)) >>> 0).toString(16));
}
