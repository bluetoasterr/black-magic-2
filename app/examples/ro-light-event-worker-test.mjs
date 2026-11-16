import coreRuntime from "../src/core/runtime.mjs";

const {allocPage: allocPage, beginAllocationTracking: beginAllocationTracking, borrowThreadScheduling: borrowThreadScheduling, buildRawFrame: buildRawFrame, call_rop: call_rop, closeRawThread: closeRawThread, endAllocationTracking: endAllocationTracking, freeTrackedAllocations: freeTrackedAllocations, F_Sleep: F_Sleep, launchRawWorker: launchRawWorker, log: log, read8: read8, sdk_base: sdk_base, waitRawThread: waitRawThread} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO light event worker: " + message);
};

const verify = (address, hex) => {
    for (let i = 0; i < hex.length / 2; i++) check(Number(read8(address + BigInt(i))) === parseInt(hex.slice(i * 2, i * 2 + 2), 16), "SDK event code differs");
};

export async function run() {
    const init = sdk_base + 1254624n;
    const finalize = sdk_base + 1254672n;
    const signal = sdk_base + 1254688n;
    const wait = sdk_base + 1255040n;
    verify(init, "280080525f04007108040039e8179f1a3f000072080000394800805208119f1a080400b9c0035fd6");
    verify(finalize, "1f040039c0035fd6");
    verify(signal, "ff0301d1fd7b01a9f65702a9f44f03a9fd430091f30300aa68464038e802003454008052");
    verify(wait, "ff0301d1fd7b01a9f65702a9f44f03a9fd430091f30300aa684640384805003435008052");
    const schedule = borrowThreadScheduling();
    check(schedule && schedule.priority > 0 && schedule.priority < 64 && schedule.core <= 7, "native worker schedule unavailable");
    const allocations = beginAllocationTracking();
    check(allocations, "allocation tracker busy");
    let worker = null, exited = false, initialized = false;
    try {
        const gate = allocPage(16);
        call_rop(init, gate, 0n, 0n, 0n);
        initialized = true;
        check(Number(read8(gate)) === 0 && Number(read8(gate + 1n)) === 1 && [ 4, 5, 6, 7 ].every(i => Number(read8(gate + BigInt(i))) === 0), "event did not initialize unsignaled");
        const frame = buildRawFrame([ {
            fn: wait,
            args: [ gate, 0n, 0n, 0n ]
        }, {
            fn: F_Sleep,
            args: [ 1000000n, 0n, 0n, 0n ]
        } ]);
        worker = launchRawWorker(frame.frame, schedule);
        check(worker?.handle && worker.rc === 0 && worker.started, "native worker did not start");
        const early = waitRawThread(worker.handle, 1000000n);
        if (early === 0) {
            exited = true;
            closeRawThread(worker.handle);
            call_rop(finalize, gate, 0n, 0n, 0n);
            initialized = false;
            throw new Error("worker passed the unsignaled gate");
        }
        call_rop(signal, gate, 0n, 0n, 0n);
        const after = waitRawThread(worker.handle, 2000000000n);
        if (after !== 0) {
            globalThis.civRoPendingLightEvent = {
                worker: worker,
                frame: frame,
                allocations: allocations,
                gate: gate
            };
            await log("RO light event worker did not exit after signal; " + "buffers retained");
            return;
        }
        exited = true;
        closeRawThread(worker.handle);
        call_rop(finalize, gate, 0n, 0n, 0n);
        initialized = false;
        await log("RO light event start gate qualified: worker blocked " + "before signal and exited afterward");
    } finally {
        if (endAllocationTracking(allocations) && (exited || !worker?.started)) freeTrackedAllocations(allocations);
    }
}
