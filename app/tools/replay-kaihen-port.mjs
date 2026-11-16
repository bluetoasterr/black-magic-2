import { spawnSync } from "node:child_process";

import path from "node:path";

import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const host = process.argv[2];

if (!host) {
    console.error("Usage: node tools/replay-kaihen-port.mjs <switch-ip>");
    process.exit(1);
}

const stages = [ "src/core.js", "examples/ro-root-promote.mjs", "examples/ro-sd-open-preflight.mjs", "examples/ro-sd-stage-hen.mjs", "examples/ro-sd-stage-game.mjs", "examples/ro-donor-stage.mjs", "examples/ro-frontend-stage.mjs", "examples/ro-worker-retain.mjs", "examples/ro-event-retain.mjs", "examples/ro-owned-session-retain.mjs", "examples/ro-server-handle-retain.mjs", "examples/ro-loader-row-preflight.mjs", "examples/ro-loader-server-handle-retain.mjs", "examples/ro-donor-type-compare.mjs", "examples/ro-loader-root-retain.mjs", "examples/ro-donor-retain.mjs", "examples/ro-loader-domain-list.mjs", "examples/ro-sm-candidate-preflight.mjs", "examples/ro-sm-handle-retain.mjs", "examples/ro-pm-shell-lookup.mjs", "examples/ro-pm-identity-probe.mjs", "examples/ro-pm-monitor-lookup.mjs", "examples/ro-launch-preflight.mjs", "examples/ro-launch-intercept.mjs", "examples/ro-loader-postflight.mjs", "examples/ro-pm-process-verify.mjs", "examples/ro-activate.mjs", "examples/ro-frontend-lookup.mjs", "examples/ro-frontend-ready.mjs", "examples/ro-fs-process-export.mjs", "examples/ro-bootstrap-map.mjs", "examples/ro-bootstrap-map-query.mjs", "examples/ro-bootstrap-args-preflight.mjs" ];

if (process.argv.includes("--worker-park")) stages.push("examples/ro-bootstrap-park-worker.mjs");

if (process.argv.includes("--hbmenu")) stages.splice(3, 0, "@stage-hbmenu");

if (process.argv.includes("--ounceshell")) stages.splice(process.argv.includes("--hbmenu") ? 4 : 3, 0, "@stage-ounceshell");

if (process.argv.includes("--start-hen")) {
    stages.push("examples/ro-bootstrap-start.mjs");
    stages.push("examples/ro-loader-postflight.mjs");
}

const resumeArg = process.argv.find(arg => arg.startsWith("--resume-after="));

const resumeAfter = resumeArg?.slice("--resume-after=".length);

const startIndex = resumeAfter ? stages.indexOf(resumeAfter) + 1 : 0;

if (resumeAfter && startIndex === 0) {
    console.error("Unknown resume stage: " + resumeAfter);
    process.exit(1);
}

if (resumeAfter) console.log("Resuming only in the existing verified loader session after " + resumeAfter);

for (let i = startIndex; i < stages.length; i++) {
    const stage = stages[i];
    process.stdout.write(`\n[${i + 1}/${stages.length}] ${stage}\n`);
    const isAsset = stage === "@stage-ounceshell" || stage === "@stage-hbmenu";
    const run = spawnSync(process.execPath, isAsset ? [ "tools/stage-hbmenu.mjs", host, ...stage === "@stage-ounceshell" ? [ "--ounceshell" ] : [] ] : [ "tools/send.mjs", "--entry", stage, host ], {
        cwd: root,
        encoding: "utf8",
        maxBuffer: 2 * 1024 * 1024
    });
    const output = (run.stdout || "") + (run.stderr || "");
    process.stdout.write(output);
    if (run.status !== 0 || run.error || /user storage access was not verified|root identity not verified/.test(output) || !(isAsset ? output.includes(stage === "@stage-ounceshell" ? "host progress 22249803/22249803" : "host progress 11782782/11782782") : output.includes("Executed successfully")) || /PAYLOAD ERROR|connection error|receive timeout/.test(output)) {
        process.stderr.write(`Stopped after ${stage}; no further stage sent.\n`);
        process.exit(1);
    }
}

process.stdout.write("\nHEN input prepared. Native bootstrap not started.\n");
