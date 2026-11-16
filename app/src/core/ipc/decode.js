function arr_read32(arr, offset) {
    return arr[offset] | arr[offset + 1] << 8 | arr[offset + 2] << 16 | arr[offset + 3] << 24;
}

function decode_ipc_response(buf) {
    const u32 = off => arr_read32(buf, off) >>> 0;
    const w0 = u32(0);
    const w1 = u32(4);
    const hipc = {
        type: w0 & 65535,
        ptr_bufs: w0 >> 16 & 15,
        send_bufs: w0 >> 20 & 15,
        recv_bufs: w0 >> 24 & 15,
        exch_bufs: w0 >> 28 & 15,
        raw_words: w1 & 1023,
        recv_list: w1 >> 10 & 15,
        has_special: w1 >> 31 & 1
    };
    let pos = 8;
    if (hipc.has_special) {
        const special_w = u32(pos);
        const has_pid = special_w & 1;
        const num_copy = special_w >> 1 & 15;
        const num_move = special_w >> 5 & 15;
        pos += 4;
        if (has_pid) pos += 8;
        pos += (num_copy + num_move) * 4;
    }
    pos += hipc.ptr_bufs * 8;
    pos += hipc.send_bufs * 12;
    pos += hipc.recv_bufs * 12;
    pos += hipc.exch_bufs * 12;
    const raw_start = pos;
    const raw_end = raw_start + hipc.raw_words * 4;
    let sfci = null;
    let sfco = null;
    let domain = null;
    for (let off = raw_start; off + 16 <= buf.length; off += 4) {
        const magic = u32(off);
        if (magic === 1229145683) {
            sfci = {
                offset: off,
                magic: "SFCI",
                version: u32(off + 4),
                command_id: u32(off + 8),
                token: u32(off + 12)
            };
            break;
        }
        if (magic === 1329808979) {
            sfco = {
                offset: off,
                magic: "SFCO",
                version: u32(off + 4),
                result: u32(off + 8),
                token: u32(off + 12)
            };
            break;
        }
    }
    const aligned_start = Math.ceil(raw_start / 16) * 16;
    let cmif_offset = -1;
    if (sfci) {
        cmif_offset = sfci.offset;
    } else if (sfco) {
        cmif_offset = sfco.offset;
    }
    if (cmif_offset > aligned_start) {
        const first_word = u32(aligned_start);
        if (sfco && first_word < 256) {
            domain = {
                num_output_objects: first_word
            };
        } else if (sfci) {
            domain = {
                type: buf[aligned_start],
                num_input_objects: buf[aligned_start + 1],
                data_len: buf[aligned_start + 2] | buf[aligned_start + 3] << 8,
                object_id: u32(aligned_start + 4)
            };
        }
    }
    if (!sfci && !sfco && aligned_start + 8 <= buf.length) {
        const dom_type = buf[aligned_start];
        if (dom_type === 2) {
            domain = {
                type: 2,
                num_input_objects: buf[aligned_start + 1],
                data_len: buf[aligned_start + 2] | buf[aligned_start + 3] << 8,
                object_id: u32(aligned_start + 4),
                is_close: true
            };
        }
    }
    return {
        hipc: hipc,
        domain: domain,
        sfci: sfci,
        sfco: sfco,
        raw_start: raw_start,
        raw_end: raw_end
    };
}

function log_ipc_message(msg) {
    const hipc_types = {
        0: "Response",
        2: "Close",
        4: "Request",
        5: "Control",
        6: "RequestWithContext",
        7: "ControlWithContext"
    };
    const type_name = hipc_types[msg.hipc.type] || "Unknown(" + msg.hipc.type + ")";
    log("HIPC: type=" + msg.hipc.type + " (" + type_name + ")" + " raw=" + msg.hipc.raw_words + "w" + " ptr=" + msg.hipc.ptr_bufs + " send=" + msg.hipc.send_bufs + " recv=" + msg.hipc.recv_bufs + " special=" + msg.hipc.has_special);
    if (msg.domain) {
        if (msg.domain.is_close) {
            log("Domain CLOSE: object_id=" + msg.domain.object_id + " (destroying domain sub-object)");
        } else if (msg.domain.object_id !== undefined) {
            log("Domain request: target_object=" + msg.domain.object_id + " type=" + msg.domain.type + " input_objects=" + msg.domain.num_input_objects);
        } else {
            log("Domain response: output_objects=" + msg.domain.num_output_objects);
        }
    }
    if (msg.sfci) {
        log("SFCI at +" + msg.sfci.offset.toString(16) + ": cmd=" + msg.sfci.command_id + " token=0x" + msg.sfci.token.toString(16));
    }
    if (msg.sfco) {
        log("SFCO at +" + msg.sfco.offset.toString(16) + ": result=0x" + msg.sfco.result.toString(16) + (msg.sfco.result === 0 ? " (OK)" : " (ERROR)") + " token=0x" + msg.sfco.token.toString(16));
    }
    if (!msg.sfci && !msg.sfco && !(msg.domain && msg.domain.is_close)) {
        log("No SFCI/SFCO found in raw data section");
    }
}

function cmifReply(buf) {
    const U32 = o => Number(read32(buf + BigInt(o))) >>> 0;
    const t0 = U32(0), t1 = U32(4);
    let at = 8;
    const copies = [], moves = [];
    if (t1 >>> 31 !== 0) {
        const sp = U32(8);
        at = 12;
        if (sp & 1) at += 8;
        let n = sp >>> 1 & 15;
        for (let i = 0; i < n; i++) copies.push(U32(at + 4 * i));
        at += n * 4;
        n = sp >>> 5 & 15;
        for (let i = 0; i < n; i++) moves.push(U32(at + 4 * i));
        at += n * 4;
    }
    at += (t0 >>> 16 & 15) * 8;
    at += ((t0 >>> 20 & 15) + (t0 >>> 24 & 15) + (t0 >>> 28 & 15)) * 12;
    at = at + 15 & ~15;
    return {
        at: at,
        result: U32(at + 8),
        data: at + 16,
        copies: copies,
        moves: moves
    };
}
