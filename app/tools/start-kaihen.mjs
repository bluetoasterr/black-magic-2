import { spawn } from "node:child_process";

import path from "node:path";

import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const host = process.argv[2];

if (!host) process.exit(1);

const verbose = process.env.KAIHEN_VERBOSE === "1";

let fsReached = false;

function run(args, onOutput) {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, args, {
            cwd: root,
            stdio: [ "inherit", "pipe", "pipe" ]
        });
        let output = "";
        for (const stream of [ child.stdout, child.stderr ]) stream.on("data", chunk => {
            const part = chunk.toString();
            output += part;
            if (verbose) process.stdout.write(part);
            onOutput?.(output);
        });
        child.on("error", reject);
        child.on("close", code => resolve({
            code: code,
            output: output
        }));
    });
}

function good(result, marker) {
    return result.code === 0 && result.output.includes(marker) && !/PAYLOAD ERROR|connection error|receive timeout/.test(result.output);
}

function failed(stage) {
    console.error(`failed on ${stage}/4 — please restart your Switch and ` + "try again. This takes some time.");
    process.exit(1);
}

const replay = await run([ "tools/replay-kaihen-port.mjs", host, "--worker-park", "--hbmenu", "--ounceshell" ], output => {
    if (!fsReached && output.includes("USER STORAGE ACCESS VERIFIED")) {
        fsReached = true;
        console.log("1/4 reached");
    }
});

if (!good(replay, "HEN input prepared. Native bootstrap not started.")) failed(fsReached ? 2 : 1);

console.log("2/4 reached");

const start = await run([ "tools/send.mjs", "--entry", "examples/ro-bootstrap-start.mjs", host ]);

if (!good(start, "Executed successfully")) failed(3);

let outcome = start.output;

for (let attempt = 0; attempt < 24 && !outcome.includes("kaiHEN bootstrap result:"); attempt++) {
    await new Promise(resolve => setTimeout(resolve, 5e3));
    const poll = await run([ "tools/send.mjs", "--entry", "examples/ro-bootstrap-poll.mjs", host ]);
    if (!good(poll, "Executed successfully")) failed(3);
    outcome += poll.output;
}

if (!/kaiHEN bootstrap result: operation=10 result=0x0 pid=[1-9]\d*/.test(outcome)) failed(3);

console.log("3/4 reached");

const postflight = await run([ "tools/send.mjs", "--entry", "examples/ro-loader-postflight.mjs", host ]);

if (!good(postflight, "RO Loader postflight passed")) failed(4);

console.log("4/4 reached");
