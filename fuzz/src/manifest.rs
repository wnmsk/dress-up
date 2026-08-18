use crate::{
    cbor::cbor_bstr_header,
    consts::{
        self,
        labels::{commands as cmd, common_elements, parameters as param},
    },
    reader::Reader,
    suit::{encode_head, encode_tstr, encode_uint},
};

/// A manifest element: (label, already-encoded value bytes)
pub type Element = (u8, Vec<u8>);

pub fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut v = cbor_bstr_header(payload.len());
    v.extend_from_slice(payload);
    v
}

pub fn build_img_digest(img_hash: &[u8]) -> Vec<u8> {
    let mut img_digest = vec![];

    img_digest.push(consts::cbor::array(2));
    img_digest.push(consts::cose::HashAlg::Sha256.val());
    img_digest.extend(cbor_bstr_header(img_hash.len()));
    img_digest.extend(img_hash);

    img_digest
}

pub fn build_common_data(
    comps: &[u8],
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
    comp_count: usize,
    reader: &mut Reader,
) -> Vec<u8> {
    let common_seq =
        build_common_com_seq(vendor_id, class_id, img_hash, img_size, comp_count, reader);

    let mut entries: Vec<(u8, Vec<u8>)> = vec![];

    if reader.flag() {
        entries.push((common_elements::COMPONENT_IDENTIFIERS, comps.to_vec()));
    }

    if reader.flag() || entries.is_empty() {
        entries.push((common_elements::COMMON_COMMAND_SEQUENCE, bstr(&common_seq)));
    }

    let mut out = encode_head(consts::cbor::MAP_MAJOR_BASE, entries.len() as u64);

    for (k, v) in entries {
        out.push(k);
        out.extend(v);
    }

    out
}

pub fn build_common_com_seq(
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
    comp_count: usize,
    reader: &mut Reader,
) -> Vec<u8> {
    build_shared_seq(
        reader, 3, comp_count, vendor_id, class_id, img_hash, img_size,
    )
}

pub fn build_shared_seq(
    reader: &mut Reader,
    depth: u8,
    comp_count: usize,
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> Vec<u8> {
    let n = (reader.u8() % 8 + 1) as usize;

    let mut items = Vec::new();
    let mut count = 0u64;

    //
    // #6
    // Emit per-component parameter blocks first.
    //

    if reader.flag() {
        for idx in 0..comp_count {
            items.push(cmd::SET_COMPONENT_INDEX);
            items.extend(encode_uint(idx as u64));
            count += 2;

            items.push(cmd::OVERRIDE_PARAMETERS);

            items.extend(build_shared_params(
                reader, vendor_id, class_id, img_hash, img_size,
            ));

            count += 2;
        }
    }

    //
    // Additional fuzzed shared commands.
    //

    for _ in 0..n {
        if reader.is_empty() {
            break;
        }

        let (label, arg) = build_shared_command(
            reader, depth, comp_count, vendor_id, class_id, img_hash, img_size,
        );

        items.push(label);
        items.extend(arg);

        count += 2;
    }

    let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, count);

    out.extend(items);
    out
}

pub fn build_shared_command(
    reader: &mut Reader,
    depth: u8,
    comp_count: usize,
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> (u8, Vec<u8>) {
    match reader.choice(10) {
        0 => (cmd::VENDOR_IDENTIFIER, encode_uint(reader.u8() as u64)),

        1 => (cmd::CLASS_IDENTIFIER, encode_uint(reader.u8() as u64)),

        2 => (cmd::IMAGE_MATCH, encode_uint(reader.u8() as u64)),

        3 => (cmd::ABORT, encode_uint(0)),

        4 => (cmd::COMPONENT_SLOT, encode_uint(reader.u8() as u64)),

        5 => (cmd::DEVICE_IDENTIFIER, bstr(&reader.bytes(16))),

        6 => (
            cmd::OVERRIDE_PARAMETERS,
            build_shared_params(reader, vendor_id, class_id, img_hash, img_size),
        ),

        7 => (
            cmd::SET_COMPONENT_INDEX,
            build_set_component_index_arg(reader, comp_count),
        ),

        8 => {
            if depth == 0 {
                (cmd::ABORT, encode_uint(0))
            } else {
                let inner = build_shared_seq(
                    reader,
                    depth - 1,
                    comp_count,
                    vendor_id,
                    class_id,
                    img_hash,
                    img_size,
                );

                (cmd::RUN_SEQUENCE, bstr(&inner))
            }
        }

        9 => {
            if depth == 0 {
                (cmd::ABORT, encode_uint(0))
            } else {
                let k = (reader.u8() % 4 + 1) as usize;

                let mut arms = encode_head(consts::cbor::ARRAY_MAJOR_BASE, k as u64);

                for _ in 0..k {
                    let inner = build_shared_seq(
                        reader,
                        depth - 1,
                        comp_count,
                        vendor_id,
                        class_id,
                        img_hash,
                        img_size,
                    );

                    arms.extend(bstr(&inner));
                }

                (cmd::TRY_EACH, arms)
            }
        }

        _ => unreachable!(),
    }
}

pub fn build_shared_params(
    reader: &mut Reader,
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> Vec<u8> {
    let mut items = Vec::new();
    let mut count = 0;

    let digest = build_img_digest(img_hash);

    if reader.flag() {
        items.push(param::VENDOR_ID);
        items.extend(bstr(vendor_id));
        count += 1;
    }

    if reader.flag() {
        items.push(param::CLASS_ID);
        items.extend(bstr(class_id));
        count += 1;
    }

    if reader.flag() {
        items.push(param::IMAGE_DIGEST);
        items.extend(bstr(&digest));
        count += 1;
    }

    if reader.flag() {
        items.push(param::IMAGE_SIZE);
        items.extend(img_size.iter().copied());
        count += 1;
    }

    if reader.flag() {
        items.push(param::DEVICE_ID);
        items.extend(bstr(&reader.bytes(16)));
        count += 1;
    }

    if reader.flag() {
        items.push(param::COMPONENT_SLOT);
        items.extend(encode_uint(reader.u8() as u64));
        count += 1;
    }

    if reader.flag() {
        items.push(param::STRICT_ORDER);
        items.push(if reader.flag() { 0xf5 } else { 0xf4 });
        count += 1;
    }

    // Avoid empty map
    if count == 0 {
        items.push(param::IMAGE_DIGEST);
        items.extend(bstr(&digest));
        count = 1;
    }

    let mut out = encode_head(consts::cbor::MAP_MAJOR_BASE, count);

    out.extend(items);
    out
}

pub fn build_command_seq_fuzzed(reader: &mut Reader, comp_count: usize) -> Vec<u8> {
    build_seq(reader, 3, comp_count)
}

pub fn build_seq(reader: &mut Reader, depth: u8, comp_count: usize) -> Vec<u8> {
    // 1..=8 command/argument pairs
    let n = (reader.u8() % 8 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u8;

    if comp_count > 1 {
        let sci = build_set_component_index(reader, comp_count);

        items.extend_from_slice(&sci);
        count += 2;
    }

    for _ in 0..n {
        if reader.is_empty() {
            break;
        }
        let (label, arg) = build_command(reader, depth, comp_count);
        items.push(label);
        items.extend_from_slice(&arg);
        count += 2; // command sequences are flat arrays of [label, arg, label, arg, ...]
    }

    let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, count as u64);
    out.extend_from_slice(&items);
    out
}

pub fn build_command(reader: &mut Reader, depth: u8, comp_count: usize) -> (u8, Vec<u8>) {
    match reader.choice(17) {
        0 => (cmd::VENDOR_IDENTIFIER, encode_uint(reader.u8() as u64)),
        1 => (cmd::CLASS_IDENTIFIER, encode_uint(reader.u8() as u64)),
        2 => (cmd::IMAGE_MATCH, encode_uint(reader.u8() as u64)),
        3 => (cmd::ABORT, encode_uint(reader.u8() as u64)),
        4 => (cmd::COMPONENT_SLOT, encode_uint(reader.u8() as u64)),
        5 => (cmd::CHECK_CONTENT, encode_uint(reader.u8() as u64)),
        6 => (cmd::OVERRIDE_PARAMETERS, build_params(reader)),
        7 => (cmd::FETCH, encode_uint(reader.u8() as u64)),
        8 => (cmd::COPY, encode_uint(reader.u8() as u64)),
        9 => (cmd::INVOKE, encode_uint(reader.u8() as u64)),
        10 => {
            let len = (reader.u8() % 16) as usize;
            (cmd::WRITE_CONTENT, bstr(&reader.bytes(len)))
        }
        11 => (cmd::DEVICE_IDENTIFIER, bstr(&reader.bytes(16))),
        12 => {
            if depth == 0 {
                (cmd::ABORT, encode_uint(0))
            } else if reader.flag() {
                // try-each: array of bstr-wrapped sequences
                let k = (reader.u8() % 5 + 1) as usize;
                let mut arms: Vec<u8> = encode_head(consts::cbor::ARRAY_MAJOR_BASE, k as u64);
                for _ in 0..k {
                    let inner = build_seq(reader, depth - 1, comp_count);
                    arms.extend_from_slice(&bstr(&inner));
                }
                (cmd::TRY_EACH, arms)
            } else {
                let inner = build_seq(reader, depth - 1, comp_count);
                (cmd::RUN_SEQUENCE, bstr(&inner))
            }
        }
        13 => (cmd::SWAP, encode_uint(reader.u8() as u64)),
        14 => {
            // CUSTOM command with negative number
            let val = reader.u8();
            (((val as i8) as u8), encode_uint(reader.u8() as u64))
        }
        15 => {
            let len = (reader.u8() % 16) as usize;
            (cmd::IMAGE_MATCH, bstr(&reader.bytes(len)))
        }
        16 => {
            let len = (reader.u8() % 32) as usize;
            (cmd::FETCH, bstr(&reader.bytes(len)))
        }
        _ => unreachable!(),
    }
}

pub fn build_params(reader: &mut Reader) -> Vec<u8> {
    let n = (reader.u8() % 8 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u64;

    for _ in 0..n {
        match reader.choice(12) {
            0 => {
                items.push(param::VENDOR_ID);
                items.extend(bstr(&reader.bytes(16)));
            }
            1 => {
                items.push(param::CLASS_ID);
                items.extend(bstr(&reader.bytes(16)));
            }
            2 => {
                items.push(param::IMAGE_DIGEST);
                items.extend(bstr(&build_img_digest(&reader.bytes(32))));
            }
            3 => {
                items.push(param::IMAGE_SIZE);
                items.extend(encode_uint(reader.u16() as u64));
            }
            4 => {
                items.push(param::URI);
                items.extend(encode_tstr(&format!(
                    "coap://[{}::{}]/f",
                    reader.u8(),
                    reader.u8()
                )));
            }
            5 => {
                items.push(param::CONTENT);
                items.extend(bstr(&reader.bytes(8)));
            }
            6 => {
                items.push(param::STRICT_ORDER);
                items.push(if reader.flag() { 0xf5 } else { 0xf4 });
            }
            7 => {
                items.push(param::SOFT_FAILURE);
                items.push(if reader.flag() { 0xf5 } else { 0xf4 });
            }
            8 => {
                items.push(param::SOURCE_COMPONENT);
                items.extend(encode_uint(reader.u8() as u64));
            }
            9 => {
                items.push(param::COMPONENT_SLOT);
                items.extend(encode_uint(reader.u8() as u64));
            }
            10 => {
                items.push(param::DEVICE_ID);
                items.extend(bstr(&reader.bytes(16)));
            }
            11 => {
                let len = (reader.u8() % 16) as usize;
                items.push(param::INVOKE_ARGS);
                items.extend(bstr(&reader.bytes(len)));
            }
            _ => unreachable!(),
        }
        count += 1;
    }

    let mut out = encode_head(consts::cbor::MAP_MAJOR_BASE, count);
    out.extend_from_slice(&items);
    out
}

pub fn build_set_component_index_arg(reader: &mut Reader, comp_count: usize) -> Vec<u8> {
    match reader.choice(3) {
        0 => {
            // uint form: single component index
            let idx = reader.u8() as usize % comp_count;
            encode_uint(idx as u64)
        }
        1 => {
            // array form: [idx1, idx2, ...] multiple component indices
            let num = (reader.u8() % (comp_count as u8 + 1)) as usize;

            let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, num as u64);

            for _ in 0..num {
                let idx = reader.u8() as usize % comp_count;

                out.extend(encode_uint(idx as u64));
            }

            out
        }
        // boolean form: true (select all components)
        _ => vec![0xf5],
    }
}

pub fn build_set_component_index(reader: &mut Reader, comp_count: usize) -> Vec<u8> {
    let mut out = vec![cmd::SET_COMPONENT_INDEX];
    out.extend(build_set_component_index_arg(reader, comp_count));
    out
}

pub fn build_components(reader: &mut Reader) -> (Vec<u8>, usize) {
    let n = (reader.u8() % 4 + 1) as usize; // 1..=4 components TODO: maybe even add more?
    let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, n as u64);
    for _ in 0..n {
        // each component-id is an array of bstr
        let parts = (reader.u8() % 3 + 1) as usize;
        let mut c = encode_head(consts::cbor::ARRAY_MAJOR_BASE, parts as u64);
        for _ in 0..parts {
            let len = (reader.u8() % 8) as usize;
            c.extend(bstr(&reader.bytes(len)));
        }
        out.extend_from_slice(&c);
    }
    (out, n)
}
