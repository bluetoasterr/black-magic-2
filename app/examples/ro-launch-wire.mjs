const u16 = (b, o) => b[o] | b[o + 1] << 8;

const u32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

const u64 = (b, o) => {
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = n << 8n | BigInt(b[o + i]);
    return n;
};

const check = (ok, message) => {
    if (!ok) throw new Error("RO Loader request: " + message);
};

export function dataStart(bytes) {
    check(bytes.length >= 8, "short IPC header");
    const first = u32(bytes, 0), second = u32(bytes, 4);
    let at = 8;
    if (second >>> 31) {
        check(bytes.length >= at + 4, "short special header");
        const special = u32(bytes, at);
        at += 4 + (special & 1 ? 8 : 0);
        at += 4 * ((special >>> 1 & 15) + (special >>> 5 & 15));
    }
    at += (first >>> 16 & 15) * 8;
    at += ((first >>> 20 & 15) + (first >>> 24 & 15) + (first >>> 28 & 15)) * 12;
    at = at + 15 & ~15;
    check(at + 16 <= bytes.length, "descriptors exceed capture");
    return at;
}

export function requestInfo(bytes) {
    const at = dataStart(bytes);
    const type = u32(bytes, 0) & 65535;
    if (type === 5 || type === 7) return {
        kind: "control",
        command: u32(bytes, at + 8)
    };
    check(type === 4 || type === 6, "unexpected request type");
    const object = u32(bytes, at + 4);
    check(object > 0, "zero domain object");
    if (bytes[at] === 2) return {
        kind: "close",
        object: object
    };
    check(bytes[at] === 1 && String.fromCharCode(...bytes.slice(at + 16, at + 20)) === "SFCI", "malformed domain request");
    const extent = u16(bytes, at + 2);
    check(extent >= 16 && at + 16 + extent <= bytes.length, "domain request extent exceeds capture");
    return {
        kind: "request",
        object: object,
        command: u32(bytes, at + 24),
        input: bytes.slice(at + 32, at + 16 + extent)
    };
}

export function targetCodeFsRequest(info, rootId, title) {
    if (info.kind !== "request" || info.object !== rootId || info.command !== 0) return false;
    const input = info.input;
    check(input.length >= 16 && input[0] === 1 && input[1] === 3 && u64(input, 8) === BigInt(title), "CodeFS mount does not match selected native target");
    return true;
}
