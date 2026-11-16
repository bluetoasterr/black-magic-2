import coreRuntime from "../src/core/runtime.mjs";

const {log: log} = coreRuntime;

export async function run() {
    const fs = globalThis.civFsMemory;
    if (typeof fs?.retireBoundedNativeRead !== "function") throw new Error("bounded FS endpoint unavailable");
    const result = fs.retireBoundedNativeRead();
    if (result.pending) {
        await log("Native FS read still pending; buffers retained. " + "No FS cleanup writes attempted.");
    } else if (result.completed) {
        await log("Native FS read exited; thread handle and buffers freed. " + "RO gate state remains unverified; restart Civ VII.");
    } else {
        await log("No bounded native FS read is pending.");
    }
}
