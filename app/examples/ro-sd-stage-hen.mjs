import { stage } from "./ro-sd-stage-core.mjs";

import { bytesHex, sha256 } from "./kaihen-hen-bytes.mjs";

export async function run() {
    await stage("/kaihen/bin/hen/main", bytesHex, sha256, 78761);
}
