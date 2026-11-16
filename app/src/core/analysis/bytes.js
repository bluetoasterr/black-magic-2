var AnalysisBytes = function() {
    function checkRange(bytes, offset, count) {
        if (!bytes || typeof bytes.length !== "number" || !Number.isSafeInteger(offset) || !Number.isSafeInteger(count) || offset < 0 || count < 0 || offset + count > bytes.length) {
            throw new RangeError("byte range is outside the supplied buffer");
        }
    }
    function readU32LE(bytes, offset) {
        checkRange(bytes, offset, 4);
        return (Number(bytes[offset]) | Number(bytes[offset + 1]) << 8 | Number(bytes[offset + 2]) << 16 | Number(bytes[offset + 3]) << 24) >>> 0;
    }
    function writeU32LE(bytes, offset, value) {
        checkRange(bytes, offset, 4);
        var word = Number(value) >>> 0;
        bytes[offset] = word & 255;
        bytes[offset + 1] = word >>> 8 & 255;
        bytes[offset + 2] = word >>> 16 & 255;
        bytes[offset + 3] = word >>> 24 & 255;
    }
    function readU64LE(bytes, offset) {
        checkRange(bytes, offset, 8);
        var word = 0n;
        for (var i = 7; i >= 0; i--) word = word << 8n | BigInt(bytes[offset + i]);
        return word;
    }
    function writeU64LE(bytes, offset, value) {
        checkRange(bytes, offset, 8);
        var word = BigInt.asUintN(64, BigInt(value));
        for (var i = 0; i < 8; i++) {
            bytes[offset + i] = Number(word & 0xFFn);
            word >>= 8n;
        }
    }
    function equal(left, right) {
        if (!left || !right || left.length !== right.length) return false;
        for (var i = 0; i < left.length; i++) if (Number(left[i]) !== Number(right[i])) return false;
        return true;
    }
    function toHex(bytes, start, end) {
        start = start === undefined ? 0 : start;
        end = end === undefined ? bytes.length : end;
        checkRange(bytes, start, end - start);
        var out = "";
        for (var i = start; i < end; i++) out += ("0" + Number(bytes[i]).toString(16)).slice(-2);
        return out;
    }
    function utf8Step(state, byte) {
        var remaining = state[0], low = state[1], high = state[2];
        if (remaining) {
            if (byte < low || byte > high) return null;
            return remaining > 1 ? [ remaining - 1, 128, 191 ] : [ 0, 0, 0 ];
        }
        if (byte >= 1 && byte <= 127) return [ 0, 0, 0 ];
        if (byte >= 194 && byte <= 223) return [ 1, 128, 191 ];
        if (byte === 224) return [ 2, 160, 191 ];
        if (byte >= 225 && byte <= 239) return [ 2, 128, byte === 237 ? 159 : 191 ];
        if (byte === 240) return [ 3, 144, 191 ];
        if (byte >= 241 && byte <= 244) return [ 3, 128, byte === 244 ? 143 : 191 ];
        return null;
    }
    return {
        readU32LE: readU32LE,
        writeU32LE: writeU32LE,
        readU64LE: readU64LE,
        writeU64LE: writeU64LE,
        equal: equal,
        toHex: toHex,
        utf8Step: utf8Step
    };
}();
