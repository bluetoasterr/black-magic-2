import coreRuntime, { waitMs } from "./runtime.mjs";

const {log: log} = coreRuntime;

const STAGE_LOG_MARKER = "stage:";

const LOG_PAUSE_MS = 30;

let verboseLogging = false;

export function setVerboseLogging(enabled) {
    const previous = verboseLogging;
    verboseLogging = enabled === true;
    return previous;
}

export function stageOnlyLog(message) {
    if (typeof message === "string" && message.startsWith(STAGE_LOG_MARKER)) return message.slice(STAGE_LOG_MARKER.length);
    if (verboseLogging && typeof message === "string") return message;
    return null;
}

export async function emitFastStage(message) {
    await log(STAGE_LOG_MARKER + message);
}

export async function emitVerboseStage(message) {
    if (verboseLogging && message) await emitFastStage(message);
}

export async function emitStage(message) {
    await emitFastStage(message);
    await waitMs(LOG_PAUSE_MS);
}
