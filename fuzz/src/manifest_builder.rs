use crate::{
    cbor::cbor_bstr_header,
    consts::{self, cbor::map, labels},
    reader::Reader,
};

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
    comp_ident: u8,
    vendor_id: &[u8],
    class_id: &[u8],
    img_hash: &[u8],
    img_size: &[u8],
) -> Vec<u8> {
    // build common command sequence
    let common_com_seq = build_common_com_seq(vendor_id, class_id, img_hash, img_size);

    // build common data block
    let mut common_data: Vec<u8> = vec![];
    common_data.push(consts::cbor::map(2)); // map containing component identifiers and common command sequence

    // --- component identifiers ---
    // TODO: maybe push multiple components
    common_data.push(labels::common_elements::COMPONENT_IDENTIFIERS);
    common_data.push(consts::cbor::array(1));
    common_data.push(consts::cbor::array(1));
    common_data.extend(cbor_bstr_header(1));
    common_data.push(comp_ident);

    // --- common command sequence ---
    common_data.push(labels::common_elements::COMMON_COMMAND_SEQUENCE);
    common_data.extend(cbor_bstr_header(common_com_seq.len()));
    common_data.extend(common_com_seq);

    common_data
}

fn build_command_seq(label: u8) -> Vec<u8> {
    match label {
        consts::labels::manifest_elements::PAYLOAD_FETCH => {
            todo!()
        }
        consts::labels::manifest_elements::PAYLOAD_INSTALLATION => {
            todo!()
        }
        consts::labels::manifest_elements::IMAGE_VALIDATION => {
            vec![
                consts::cbor::array(2),
                labels::commands::IMAGE_MATCH,
                0b1111, // Reporting Policy 15 TODO: maybe make RP-builder function?
            ]
        }
        consts::labels::manifest_elements::IMAGE_LOADING => {
            todo!()
        }
        consts::labels::manifest_elements::IMAGE_INVOCATION => {
            vec![
                consts::cbor::array(2),
                labels::commands::INVOKE,
                0b0010, // Reporting Policy 02 TODO: maybe make RP-builder function?
            ]
        }
        _ => panic!("unsupported command sequence label"),
    }
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

pub fn build_manifest(data: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(data);

    let version = r.u8();
    let seq_nr = r.u16();
    let comp_ident = r.u8();
    let vendor_id = r.bytes(16);
    let class_id = r.bytes(16);
    let img_hash = r.bytes(32);
    // let img_size = r.u16();
    let img_size = [r.u8(), r.u8()];

    // one selector byte gates the optional elements
    let sel = r.u8();

    let mut entries: Vec<Element> = Vec::new();

    // --- mandatory-ish elements, but still optional so the parser's
    //     "missing field" error paths get covered ---
    if sel & 0b0000_0001 != 0 {
        entries.push((me::ENCODING_VERSION, encode_uint(version as u64)));
    }
    if sel & 0b0000_0010 != 0 {
        entries.push((me::SEQUENCE_NUMBER, encode_uint(seq_nr as u64)));
    }

    let common = build_common_data(comp_ident, &vendor_id, &class_id, &img_hash, &img_size);
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
            let seq = build_command_seq_fuzzed(&mut r);
            entries.push((label, bstr(&seq)));
        }
    }

    emit_map(&entries)
}


// =================================================

use crate::consts::labels::{commands as cmd, parameters as param};

fn build_command_seq_fuzzed(r: &mut Reader) -> Vec<u8> {
    build_seq(r, 3)
}

fn build_seq(r: &mut Reader, depth: u8) -> Vec<u8> {
    // 1..=8 command/argument pairs
    let n = (r.u8() % 8 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u8;

    for _ in 0..n {
        if r.is_empty() {
            break;
        }
        let (label, arg) = build_command(r, depth);
        items.push(label);
        items.extend_from_slice(&arg);
        count += 2; // command sequences are flat arrays of [label, arg, label, arg, ...]
    }

    let mut out = encode_head(consts::cbor::ARRAY_MAJOR_BASE, count as u64);
    out.extend_from_slice(&items);
    out
}

fn build_command(r: &mut Reader, depth: u8) -> (u8, Vec<u8>) {
    match r.choice(12) {
        0 => (cmd::VENDOR_IDENTIFIER, encode_uint(15)),      // rep-policy style arg
        1 => (cmd::CLASS_IDENTIFIER, encode_uint(15)),
        2 => (cmd::IMAGE_MATCH, encode_uint(15)),
        3 => (cmd::SET_COMPONENT_INDEX, encode_uint(r.u8() as u64)),
        4 => (cmd::ABORT, encode_uint(0)),
        5 => (cmd::COMPONENT_SLOT, encode_uint(r.u8() as u64)),
        6 => (cmd::CHECK_CONTENT, encode_uint(15)),
        7 => (cmd::OVERRIDE_PARAMETERS, build_params(r)),
        8 => (cmd::FETCH, encode_uint(15)),
        9 => (cmd::COPY, encode_uint(15)),
        10 => (cmd::INVOKE, encode_uint(15)),
        11 => {
            if depth == 0 {
                // bottom out with something harmless
                (cmd::ABORT, encode_uint(0))
            } else if r.flag() {
                // try-each: array of bstr-wrapped sequences
                let k = (r.u8() % 3 + 1) as usize;
                let mut arms: Vec<u8> = encode_head(consts::cbor::ARRAY_MAJOR_BASE, k as u64);
                for _ in 0..k {
                    let inner = build_seq(r, depth - 1);
                    arms.extend_from_slice(&bstr(&inner));
                }
                (cmd::TRY_EACH, arms)
            } else {
                let inner = build_seq(r, depth - 1);
                (cmd::RUN_SEQUENCE, bstr(&inner))
            }
        }
        _ => unreachable!(),
    }
}

fn build_params(r: &mut Reader) -> Vec<u8> {
    let n = (r.u8() % 6 + 1) as usize;
    let mut items: Vec<u8> = Vec::new();
    let mut count = 0u64;

    for _ in 0..n {
        match r.choice(9) {
            0 => { items.push(param::VENDOR_ID);        items.extend(bstr(&r.bytes(16))); }
            1 => { items.push(param::CLASS_ID);         items.extend(bstr(&r.bytes(16))); }
            2 => { items.push(param::IMAGE_DIGEST);     items.extend(bstr(&build_img_digest(&r.bytes(32)))); }
            3 => { items.push(param::IMAGE_SIZE);       items.extend(encode_uint(r.u16() as u64)); }
            4 => { items.push(param::URI);              items.extend(encode_tstr("coap://[::1]/f")); }
            5 => { items.push(param::CONTENT);          items.extend(bstr(&r.bytes(8))); }
            6 => { items.push(param::STRICT_ORDER);     items.push(if r.flag() { 0xf5 } else { 0xf4 }); }
            7 => { items.push(param::SOFT_FAILURE);     items.push(if r.flag() { 0xf5 } else { 0xf4 }); }
            8 => { items.push(param::SOURCE_COMPONENT); items.extend(encode_uint(r.u8() as u64)); }
            _ => unreachable!(),
        }
        count += 1;
    }

    let mut out = encode_head(consts::cbor::MAP_MAJOR_BASE, count);
    out.extend_from_slice(&items);
    out
}
