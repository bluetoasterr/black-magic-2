export const VERBOSE_LOGGING = false;

export function createFspIdentityConfig() {
    var SLOT_SIZE = 2048;
    var WAVE_READ_SIZE = 65536;
    var DIRTY_FILE_SIZE = 8388608;
    var MAX_CONTROL_WAVES = 20;
    var MAX_COPY_ATTEMPTS = 30;
    var COPY_BATCHES = 3;
    var MAX_ADDRESS_CANDIDATES = 5;
    var MAX_POOL_REFINEMENT_READS = 16;
    var MAX_POOL_ANCHOR_CANDIDATES = 4;
    var MAX_METADATA_ANCHOR_CHECKS = 16;
    var MAX_METADATA_PAGE_PROBES = 16;
    var MAX_ROOT_LAYOUT_SCANS = 4;
    var CANARY_LENGTH = 1440;
    var EXTENT_SIZE = 9280;
    var POSITIVE_FILL_SEGMENT = 200;
    var PINNING_ALLOCATION_BYTES = 6960;
    var HEAP_JITTER_BYTES = 192;
    var ALIAS_OFFSET = 20971520;
    var MARKER_OFFSET = 9024;
    var WINDOW_MINIMUM_CACHE_HELD = 9728;
    var FIELD_MINIMUM_CACHE_HELD = 9728;
    var CACHE_READ_SIZE = 2097152;
    var CONTROL_SIZE = 16384;
    var ROOT_CAPTURE_SIZE = 5079040;
    var ROOT_CAPTURE_BACK = 5242880;
    var ROOT_CAPTURE_GAP = 163840;
    var ROOT_CAPTURE_CHUNK = 163840;
    var ROOT_CAPTURE_CHUNKS = ROOT_CAPTURE_SIZE / ROOT_CAPTURE_CHUNK;
    var CACHE_ALIAS_PREFIX = [ 0, 0, 64, 1, 0, 0, 0, 0, 65, 65, 65, 65, 65, 65, 65, 65, 1, 0 ];
    var roleDelays = [ 0, 3e5, 35e4, 45e4, 55e4, 65e4, 1e6, 12e5, 13e5, 17e5 ];
    var guardDelays = [ 15e4, 3e5 ];
    var roleLabels = [ "commit", "bottleneck", "frag0", "frag1", "frag2", "frag3", "canary", "filler0", "filler1", "release", "guard0", "guard1", "trigger" ];
    var roleShort = [ "C", "B", "F0", "F1", "F2", "F3", "Y", "X0", "X1", "R", "G0", "G1", "T" ];
    var throughRoles = [ "commit", "frag0", "frag1", "frag2", "frag3" ];
    var heldRoles = [ "canary", "filler0", "filler1", "guard0", "guard1" ];
    var overlapRoles = throughRoles.concat(heldRoles);
    return {
        SLOT_SIZE: SLOT_SIZE,
        WAVE_READ_SIZE: WAVE_READ_SIZE,
        DIRTY_FILE_SIZE: DIRTY_FILE_SIZE,
        MAX_CONTROL_WAVES: MAX_CONTROL_WAVES,
        MAX_COPY_ATTEMPTS: MAX_COPY_ATTEMPTS,
        COPY_BATCHES: COPY_BATCHES,
        MAX_ADDRESS_CANDIDATES: MAX_ADDRESS_CANDIDATES,
        MAX_POOL_REFINEMENT_READS: MAX_POOL_REFINEMENT_READS,
        MAX_POOL_ANCHOR_CANDIDATES: MAX_POOL_ANCHOR_CANDIDATES,
        MAX_METADATA_ANCHOR_CHECKS: MAX_METADATA_ANCHOR_CHECKS,
        MAX_METADATA_PAGE_PROBES: MAX_METADATA_PAGE_PROBES,
        MAX_ROOT_LAYOUT_SCANS: MAX_ROOT_LAYOUT_SCANS,
        CANARY_LENGTH: CANARY_LENGTH,
        EXTENT_SIZE: EXTENT_SIZE,
        POSITIVE_FILL_SEGMENT: POSITIVE_FILL_SEGMENT,
        PINNING_ALLOCATION_BYTES: PINNING_ALLOCATION_BYTES,
        HEAP_JITTER_BYTES: HEAP_JITTER_BYTES,
        ALIAS_OFFSET: ALIAS_OFFSET,
        MARKER_OFFSET: MARKER_OFFSET,
        WINDOW_MINIMUM_CACHE_HELD: WINDOW_MINIMUM_CACHE_HELD,
        FIELD_MINIMUM_CACHE_HELD: FIELD_MINIMUM_CACHE_HELD,
        CACHE_READ_SIZE: CACHE_READ_SIZE,
        CONTROL_SIZE: CONTROL_SIZE,
        ROOT_CAPTURE_SIZE: ROOT_CAPTURE_SIZE,
        ROOT_CAPTURE_BACK: ROOT_CAPTURE_BACK,
        ROOT_CAPTURE_GAP: ROOT_CAPTURE_GAP,
        ROOT_CAPTURE_CHUNK: ROOT_CAPTURE_CHUNK,
        ROOT_CAPTURE_CHUNKS: ROOT_CAPTURE_CHUNKS,
        CACHE_ALIAS_PREFIX: CACHE_ALIAS_PREFIX,
        roleDelays: roleDelays,
        guardDelays: guardDelays,
        roleLabels: roleLabels,
        roleShort: roleShort,
        throughRoles: throughRoles,
        heldRoles: heldRoles,
        overlapRoles: overlapRoles
    };
}
