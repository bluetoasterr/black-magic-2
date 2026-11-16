import { stage } from "./ro-sd-stage-core.mjs";

import { bytesHex, sha256 } from "./kaihen-game-bytes.mjs";

export async function run() {
    await stage("/kaihen/bin/game/main", bytesHex, sha256, 62943);
}
