import fs from "node:fs/promises";

import path from "node:path";

import crypto from "node:crypto";

import net from "node:net";

import { fileURLToPath } from "node:url";

import { buildPayload } from "./bundle.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

const root = path.resolve(here, "..");

const ounceShell = process.argv.includes("--ounceshell");

const target = ounceShell ? "/switch/ounceshell.nro" : "/hbmenu.nro";

const file = path.resolve(root, ounceShell ? "assets/ounceshell.nro" : "assets/hbmenu.nro");

const generated = path.join(root, "examples/.generated-hbmenu-chunk.mjs");

const host = process.argv[2];

const maxChunks = process.argv.includes("--one") ? 1 : Infinity;

const resumeAt = Number(process.argv.find(arg => arg.startsWith("--resume="))?.split("=")[1] || 0);

if (!host) throw new Error("usage: node tools/stage-hbmenu.mjs <Switch IP> [--one]");

const bytes = await fs.readFile(file);

const hash = crypto.createHash("sha256").update(bytes).digest("hex");

const expected = ounceShell ? {
    length: 22249803,
    hash: "675b492a1922b3dafa7a69fe3afe37cda117ecdc406ae5fc964d093fc761c9ba"
} : {
    length: 11782782,
    hash: "bbb2de170be91749ae186bcae9853897dc4ec1e01790ef507b3504a9ea2c628a"
};

if (bytes.length !== expected.length || hash !== expected.hash) throw new Error("native asset differs from reviewed build");

async function send(payload) {
    return new Promise((resolve, reject) => {
        let result = "";
        const socket = net.createConnection({
            host: host,
            port: 9026
        }, () => {
            socket.write(payload, () => socket.end());
        });
        socket.setTimeout(24e4);
        socket.on("data", chunk => {
            result += chunk.toString();
        });
        socket.on("end", () => resolve(result));
        socket.on("error", reject);
        socket.on("timeout", () => {
            socket.destroy();
            reject(new Error("Switch loader timeout"));
        });
    });
}

let sent = 0;

try {
    for (let offset = resumeAt; offset < bytes.length && sent < maxChunks; ) {
        const length = Math.min(offset === 0 ? 32768 : 131072, bytes.length - offset);
        const hex = bytes.subarray(offset, offset + length).toString("hex");
        await fs.writeFile(generated, `import {stageChunk} from "./ro-sd-stage-large-core.mjs";\n` + `export async function run(){await stageChunk(${JSON.stringify(target)},${offset},` + `${JSON.stringify(hex)},${bytes.length},${JSON.stringify(hash)});}\n`);
        const built = await buildPayload({
            entry: generated
        });
        const result = await send(built.payload);
        process.stdout.write(result);
        if (!result.includes("hbmenu SD verified " + (offset + length) + "/" + bytes.length) || result.includes("PAYLOAD ERROR")) throw new Error("Switch did not verify chunk at " + offset);
        offset += length;
        sent++;
        console.log(`host progress ${offset}/${bytes.length} (${sent} chunks)`);
    }
} finally {
    await fs.rm(generated, {
        force: true
    });
}
