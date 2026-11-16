import { bytesHex, sha256 } from "./kaihen-bootstrap-bytes.mjs";

const fromHex = hex => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
};

const put32 = (bytes, offset, value) => {
    const n = Number(value) >>> 0;
    for (let i = 0; i < 4; i++) bytes[offset + i] = n >>> 8 * i & 255;
};

const put64 = (bytes, offset, value) => {
    let n = BigInt(value);
    for (let i = 0; i < 8; i++) {
        bytes[offset + i] = Number(n & 255n);
        n >>= 8n;
    }
};

export function buildBootstrapImage(sdkBase) {
    const text = fromHex(bytesHex);
    if (text.length !== 28012 || sha256 !== "c7a00d324ef1a13f43596b9806539b027761ffb2dd7ab6d4d8cf5fd1327b0be1") throw new Error("kaiHEN bootstrap asset differs");
    const adapterOffset = text.length + 15 & ~15;
    if (adapterOffset + 24 > 65408) throw new Error("kaiHEN bootstrap exceeds NRO text");
    const image = new Uint8Array(73728);
    image.set(text, 128);
    const words = [ 2457726976, 1476395120, 3592356352, 3573751839 ];
    words.forEach((word, i) => put32(image, 128 + adapterOffset + i * 4, word));
    put64(image, 128 + adapterOffset + 16, BigInt(sdkBase) + 1274128n);
    image.set([ 78, 82, 79, 48 ], 16);
    put32(image, 24, image.length);
    put32(image, 36, 65536);
    put32(image, 40, 65536);
    put32(image, 44, 4096);
    put32(image, 48, 69632);
    put32(image, 52, 4096);
    put32(image, 56, 4096);
    return {
        image: image,
        adapterOffset: adapterOffset,
        entryOffset: 128
    };
}
