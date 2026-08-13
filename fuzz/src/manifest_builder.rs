use sha2::{Digest, Sha256};

use crate::{
    cbor::cbor_bstr_header,
    consts::{self, cbor::map, labels},
    reader::Reader,
};

// BIG TODO:
// - use dynamic vendor & class id
// - make common data block dynamic
// - add additional bytes as payload (maybe also depending on bitmap)
// - [DONE] add additional component count
//      --> DO add set component index!!
// - generate REAL hash for payload ("hello world!")


fn build_img_digest(img_hash: &[u8]) -> Vec<u8> {
    let mut img_digest = vec![];

    img_digest.push(consts::cbor::array(2));
    img_digest.push(consts::cose::HashAlg::Sha256.val());
    img_digest.extend(cbor_bstr_header(img_hash.len()));
    img_digest.extend(img_hash);

    img_digest
}

fn build_common_com_seq(
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> Vec<u8> {
    let img_digest = build_img_digest(img_hash);
    let mut com_seq: Vec<u8> = vec![];

    com_seq.push(consts::cbor::array(6)); // use array of static length 6 for now

    // --- override parameters ---
    com_seq.push(labels::commands::OVERRIDE_PARAMETERS);
    com_seq.push(map(4)); // map with static length of 4 for now: Vendor ID, Class ID, Image Digest, Image Size

    // vendor id
    com_seq.push(labels::parameters::VENDOR_ID);
    com_seq.extend(cbor_bstr_header(vendor_id.len()));
    com_seq.extend(vendor_id);

    // class id
    com_seq.push(labels::parameters::CLASS_ID);
    com_seq.extend(cbor_bstr_header(class_id.len()));
    com_seq.extend(class_id);

    // image digest
    com_seq.push(labels::parameters::IMAGE_DIGEST);
    com_seq.extend(cbor_bstr_header(img_digest.len()));
    com_seq.extend(img_digest);

    // image size
    com_seq.push(labels::parameters::IMAGE_SIZE);
    com_seq.push(0x19); // header for "next two bytes uint" TODO: write function to variably calc uint header
    com_seq.extend(img_size);

    // --- vendor identifier ---
    com_seq.push(labels::commands::VENDOR_IDENTIFIER);
    com_seq.push(0b1111); // Reporting Policy 15 TODO: maybe make RP-builder function?

    // --- class identifier ---
    com_seq.push(labels::commands::CLASS_IDENTIFIER);
    com_seq.push(0b1111); // Reporting Policy 15 TODO: maybe make RP-builder function?

    com_seq
}

fn build_common_data(
    comps: &[u8],
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> Vec<u8> {
    // TODO: make more dynamic
    // build common command sequence
    let common_com_seq = build_common_com_seq(vendor_id, class_id, img_hash, img_size);

    // build common data block
    let mut common_data: Vec<u8> = vec![];
    common_data.push(consts::cbor::map(2)); // map containing component identifiers and common command sequence

    // --- component identifiers ---
    // TODO: maybe push multiple components
    common_data.push(labels::common_elements::COMPONENT_IDENTIFIERS);

    // generated components
    common_data.extend(comps);

    // --- common command sequence ---
    common_data.push(labels::common_elements::COMMON_COMMAND_SEQUENCE);
    common_data.extend(cbor_bstr_header(common_com_seq.len()));
    common_data.extend(common_com_seq);

    common_data
}

use crate::consts::labels::manifest_elements as me;
use crate::suit::{encode_head, encode_uint, encode_tstr};

/// A manifest element: (label, already-encoded value bytes)
type Element = (u8, Vec<u8>);

fn emit_map(entries: &[Element]) -> Vec<u8> {
    let mut out = vec![consts::cbor::map(entries.len() as u8)];
    for (label, value) in entries {
        out.push(*label);
        out.extend_from_slice(value);
    }
    out
}

fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut v = cbor_bstr_header(payload.len());
    v.extend_from_slice(payload);
    v
}

pub fn build_manifest(mut reader: Reader, payload: &[u8]) -> Vec<u8> {
    // let mut r = Reader::new(data);

    let version = reader.u8();
    let seq_nr = reader.u16();
    // let comp_ident = reader.u8();
    // let vendor_id = reader.bytes(16);
    // let class_id = reader.bytes(16);
    // TODO: try again with input from data
    let class_id: &[u8] = &[0x01, 0x9c, 0x9a, 0x96, 0x34, 0x7b, 0x7d, 0x98, 0xac, 0xc9, 0xb9, 0x01, 0x17, 0xf4, 0xa6, 0x65];
    let vendor_id: &[u8] = &[0x01, 0x9c, 0x9a, 0x95, 0xf6, 0xcb, 0x71, 0xa7, 0xa0, 0xa6, 0xaa, 0xc1, 0x48, 0xfc, 0x47, 0x43];
    // let img_hash = reader.bytes(32);
    let img_hash: [u8; 32] = Sha256::digest(payload).into();
    // let img_size = reader.u16();
    // let img_size = [reader.u8(), reader.u8()];
    let img_size = encode_uint(img_hash.len() as u64);

    // one selector byte gates the optional elements
    let sel = reader.u8();

    let mut entries: Vec<Element> = Vec::new();

    // --- mandatory-ish elements, but still optional so the parser's
    //     "missing field" error paths get covered ---
    if sel & 0b0000_0001 != 0 {
        entries.push((me::ENCODING_VERSION, encode_uint(version as u64)));
    }
    if sel & 0b0000_0010 != 0 {
        entries.push((me::SEQUENCE_NUMBER, encode_uint(seq_nr as u64)));
    }

    let comps = build_components(&mut reader);

    let common = build_common_data(&comps, &vendor_id, &class_id, &img_hash, &img_size);
    entries.push((me::COMMON_DATA, bstr(&common)));

    if sel & 0b0000_0100 != 0 {
        // reference-uri is a tstr
        entries.push((me::REFERENCE_URI, encode_tstr("http://example.com/file1.bin")));
    }

    // --- command sequences, each independently switchable ---
    for (bit, label) in [
        (0b0000_1000u8, me::PAYLOAD_FETCH),
        (0b0001_0000, me::PAYLOAD_INSTALLATION),
        (0b0010_0000, me::IMAGE_VALIDATION),
        (0b0100_0000, me::IMAGE_LOADING),
        (0b1000_0000, me::IMAGE_INVOCATION),
    ] {
        if sel & bit != 0 {
            let seq = build_command_seq_fuzzed(&mut reader);
            entries.push((label, bstr(&seq)));
        }
    }

    emit_map(&entries)
}


// =================================================

use crate::consts::labels::{commands as cmd, parameters as param};

fn build_command_seq_fuzzed(reader: &mut Reader) -> Vec<u8> {
    build_seq(reader, 3)
}

fn build_seq(reader: &mut Reader, depth: u8) -> Vec<u8> {
    // 1..=8 command/argument pairs
    let n = (reader.u8() % 8 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u8;

    for _ in 0..n {
        if reader.is_empty() {
            break;
        }
        let (label, arg) = build_command(reader, depth);
        items.push(label);
        items.extend_from_slice(&arg);
        count += 2; // command sequences are flat arrays of [label, arg, label, arg, ...]
    }

    let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, count as u64);
    out.extend_from_slice(&items);
    out
}

fn build_command(reader: &mut Reader, depth: u8) -> (u8, Vec<u8>) {
    match reader.choice(12) {
        0 => (cmd::VENDOR_IDENTIFIER, encode_uint(15)),      // rep-policy style arg
        1 => (cmd::CLASS_IDENTIFIER, encode_uint(15)),
        2 => (cmd::IMAGE_MATCH, encode_uint(15)),
        3 => (cmd::SET_COMPONENT_INDEX, encode_uint(reader.u8() as u64)),
        4 => (cmd::ABORT, encode_uint(0)),
        5 => (cmd::COMPONENT_SLOT, encode_uint(reader.u8() as u64)),
        6 => (cmd::CHECK_CONTENT, encode_uint(15)),
        7 => (cmd::OVERRIDE_PARAMETERS, build_params(reader)),
        8 => (cmd::FETCH, encode_uint(15)),
        9 => (cmd::COPY, encode_uint(15)),
        10 => (cmd::INVOKE, encode_uint(15)),
        11 => {
            if depth == 0 {
                // bottom out with something harmless
                (cmd::ABORT, encode_uint(0))
            } else if reader.flag() {
                // try-each: array of bstr-wrapped sequences
                let k = (reader.u8() % 3 + 1) as usize;
                let mut arms: Vec<u8> = encode_head(consts::cbor::ARRAY_MAJOR_BASE, k as u64);
                for _ in 0..k {
                    let inner = build_seq(reader, depth - 1);
                    arms.extend_from_slice(&bstr(&inner));
                }
                (cmd::TRY_EACH, arms)
            } else {
                let inner = build_seq(reader, depth - 1);
                (cmd::RUN_SEQUENCE, bstr(&inner))
            }
        }
        _ => unreachable!(),
    }
}

fn build_params(reader: &mut Reader) -> Vec<u8> {
    let n = (reader.u8() % 6 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u64;

    for _ in 0..n {
        match reader.choice(9) {
            0 => { items.push(param::VENDOR_ID);        items.extend(bstr(&reader.bytes(16))); }
            1 => { items.push(param::CLASS_ID);         items.extend(bstr(&reader.bytes(16))); }
            2 => { items.push(param::IMAGE_DIGEST);     items.extend(bstr(&build_img_digest(&reader.bytes(32)))); }
            3 => { items.push(param::IMAGE_SIZE);       items.extend(encode_uint(reader.u16() as u64)); }
            4 => { items.push(param::URI);              items.extend(encode_tstr("coap://[::1]/f")); }
            5 => { items.push(param::CONTENT);          items.extend(bstr(&reader.bytes(8))); }
            6 => { items.push(param::STRICT_ORDER);     items.push(if reader.flag() { 0xf5 } else { 0xf4 }); }
            7 => { items.push(param::SOFT_FAILURE);     items.push(if reader.flag() { 0xf5 } else { 0xf4 }); }
            8 => { items.push(param::SOURCE_COMPONENT); items.extend(encode_uint(reader.u8() as u64)); }
            _ => unreachable!(),
        }
        count += 1;
    }

    let mut out = encode_head(consts::cbor::MAP_MAJOR_BASE, count);
    out.extend_from_slice(&items);
    out
}

// ===================================================================


fn build_components(reader: &mut Reader) -> Vec<u8> {
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
    out
}
