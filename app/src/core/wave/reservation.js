function readAllocationCounters(session, pktBuf) {
    var latest = null;
    for (var pass = 0; pass < 2; pass++) {
        prepPacket(pktBuf, 4, 8, [ [ 16, 1229145683 ], [ 24, 1009 ] ]);
        sendIPC(session, pktBuf);
        var reply = cmifReply(pktBuf);
        if (reply.result !== 0) return null;
        latest = [];
        for (var i = 0; i < 16; i++) latest.push(Number(read64(pktBuf + BigInt(reply.data + i * 8))));
    }
    return latest;
}

function closeDomainObjectNow(sessionHandle, objectId, pktBuf) {
    if (!sessionHandle || !objectId) return 4294967295;
    prepPacket(pktBuf, 4, 8, []);
    write8(pktBuf + 0x10n, 2n);
    write32(pktBuf + 0x14n, BigInt(objectId));
    write32(pktBuf + 0x1Cn, 0n);
    return Number(sendIPC(sessionHandle, pktBuf)) >>> 0;
}

function closeUnwrappedReservationGroup(sessionHandle, rootCopy, reservationObjectIds, pktBuf) {
    for (var i = reservationObjectIds.length - 1; i >= 0; i--) closeDomainObjectNow(sessionHandle, reservationObjectIds[i], pktBuf);
    if (rootCopy) closeHandle(rootCopy);
    if (sessionHandle) closeHandle(sessionHandle);
}

function openReservationGroup(readerSession, pktBuf, count) {
    count = count || 59;
    var expectedAllocation = count * 208;
    var maxGroupAttempts = 3;
    for (var attempt = 1; attempt <= maxGroupAttempts; attempt++) {
        var sessionHandle = openFspSession();
        if (!sessionHandle) return {
            ok: false,
            error: "open fsp-srv"
        };
        prepPacket(pktBuf, 5, 8, [ [ 16, 1229145683 ], [ 24, 0 ], [ 32, 0 ] ]);
        sendIPC(sessionHandle, pktBuf);
        var converted = cmifReply(pktBuf);
        var rootObj = converted.result === 0 ? Number(read32(pktBuf + BigInt(converted.data))) >>> 0 : 0;
        if (!rootObj) {
            closeHandle(sessionHandle);
            return {
                ok: false,
                error: "ConvertToDomain SFCO=" + hex32(converted.result)
            };
        }
        prepPacket(pktBuf, 5, 9, [ [ 16, 1229145683 ], [ 24, 1 ], [ 32, rootObj ] ]);
        sendIPC(sessionHandle, pktBuf);
        var copiedRoot = cmifReply(pktBuf);
        var rootCopy = copiedRoot.result === 0 && copiedRoot.moves.length ? copiedRoot.moves[0] : 0;
        if (!rootCopy) {
            closeHandle(sessionHandle);
            return {
                ok: false,
                error: "CopyFromCurrentDomain SFCO=" + hex32(copiedRoot.result)
            };
        }
        var before = readAllocationCounters(readerSession, pktBuf);
        if (before === null) {
            closeHandle(rootCopy);
            closeHandle(sessionHandle);
            return {
                ok: false,
                error: "allocation counters unavailable before reservations",
                attempts: attempt
            };
        }
        var reservationObjectIds = [];
        var reservationSuccessCount = 0;
        var reservationFailures = [];
        var reservationFailureCount = 0;
        for (var i = 0; i < count; i++) {
            prepPacket(pktBuf, 4, 12, [ [ 16, 1 ], [ 18, 16 ], [ 20, rootObj ], [ 32, 1229145683 ], [ 40, 1200 ] ]);
            write16(pktBuf + 0x12n, 16n);
            var transport = Number(sendIPC(sessionHandle, pktBuf)) >>> 0;
            if (transport !== 0) {
                reservationFailureCount++;
                if (reservationFailures.length < 4) reservationFailures.push("#" + i + ":transport=" + hex32(transport));
                continue;
            }
            var result = Number(read32(pktBuf + 0x28n)) >>> 0;
            var objectCount = Number(read32(pktBuf + 0x10n)) >>> 0;
            var objectId = Number(read32(pktBuf + 0x30n)) >>> 0;
            if (result === 0 && objectCount === 1 && objectId !== 0) {
                reservationSuccessCount++;
                reservationObjectIds.push(objectId);
            } else {
                reservationFailureCount++;
                if (reservationFailures.length < 4) reservationFailures.push("#" + i + ":sfco=" + hex32(result) + ",objects=" + objectCount + ",id=" + hex32(objectId));
            }
        }
        var held = readAllocationCounters(readerSession, pktBuf);
        var allocationDelta = before && held ? before[5] - held[5] : null;
        var reservationsComplete = reservationSuccessCount === count && reservationObjectIds.length === count && reservationFailureCount === 0;
        var countersAvailable = before !== null && held !== null;
        if (!reservationsComplete || !countersAvailable) {
            closeUnwrappedReservationGroup(sessionHandle, rootCopy, reservationObjectIds, pktBuf);
            if (!reservationsComplete && attempt < maxGroupAttempts) continue;
            return {
                ok: false,
                error: !reservationsComplete ? "cmd-1200 reservations=" + reservationSuccessCount + "/" + count + " failures=" + reservationFailureCount + " after " + attempt + " attempts" : "allocation counters unavailable",
                reserved: reservationSuccessCount,
                failures: reservationFailures,
                before: before,
                held: held,
                allocationDelta: allocationDelta,
                attempts: attempt
            };
        }
        if (allocationDelta !== expectedAllocation) {
            var allocationError = "allocation delta=0x" + Number(allocationDelta).toString(16) + " expected=0x" + expectedAllocation.toString(16);
            closeUnwrappedReservationGroup(sessionHandle, rootCopy, reservationObjectIds, pktBuf);
            if (attempt < maxGroupAttempts) continue;
            return {
                ok: false,
                error: allocationError + " after " + attempt + " attempts",
                reserved: reservationSuccessCount,
                failures: reservationFailures,
                before: before,
                held: held,
                allocationDelta: allocationDelta,
                attempts: attempt
            };
        }
        prepPacket(pktBuf, 5, 8, [ [ 16, 1229145683 ], [ 24, 0 ], [ 32, 0 ] ]);
        sendIPC(sessionHandle, pktBuf);
        var wrapped = cmifReply(pktBuf);
        var outer = wrapped.result === 0 ? Number(read32(pktBuf + BigInt(wrapped.data))) >>> 0 : 0;
        if (!outer) {
            closeUnwrappedReservationGroup(sessionHandle, rootCopy, reservationObjectIds, pktBuf);
            return {
                ok: false,
                error: "group wrap SFCO=" + hex32(wrapped.result),
                reserved: reservationSuccessCount,
                failures: reservationFailures,
                before: before,
                held: held,
                allocationDelta: allocationDelta,
                attempts: attempt
            };
        }
        return {
            ok: true,
            session: sessionHandle,
            root: rootObj,
            rootCopy: rootCopy,
            outer: outer,
            reserved: reservationSuccessCount,
            failures: reservationFailures,
            before: before,
            held: held,
            allocationDelta: allocationDelta,
            attempts: attempt
        };
    }
    return {
        ok: false,
        error: "reservation accounting retries exhausted"
    };
}

function closeReservationGroup(group, outerStillOpen, pktBuf) {
    if (!group) return;
    if (group.session && outerStillOpen && group.outer) closeDomainObjectNow(group.session, group.outer, pktBuf);
    if (group.rootCopy) closeHandle(group.rootCopy);
    if (group.session) closeHandle(group.session);
}
