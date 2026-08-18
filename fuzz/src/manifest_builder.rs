use sha2::{Digest, Sha256};

use crate::{
    consts::{cbor, labels::manifest_elements as me},
    manifest::{self, Element},
    reader::Reader,
    suit::{encode_tstr, encode_uint},
};

fn emit_map(entries: &[Element]) -> Vec<u8> {
    let mut out = vec![cbor::map(entries.len() as u8)];
    for (label, value) in entries {
        out.push(*label);
        out.extend_from_slice(value);
    }
    out
}

pub fn build_manifest(
    mut reader: Reader,
    payload: &[u8],
    class_id: &[u8],
    vendor_id: &[u8],
) -> Vec<u8> {
    let version = reader.u8();
    let seq_nr = reader.u16();
    let img_hash: [u8; 32] = Sha256::digest(payload).into();
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

    let (comps, comp_count) = manifest::build_components(&mut reader);

    let common = manifest::build_common_data(
        &comps,
        &vendor_id,
        &class_id,
        &img_hash,
        &img_size,
        comp_count,
        &mut reader,
    );
    entries.push((me::COMMON_DATA, manifest::bstr(&common)));

    if sel & 0b0000_0100 != 0 {
        // reference-uri is a tstr
        entries.push((
            me::REFERENCE_URI,
            encode_tstr("http://example.com/file1.bin"),
        ));
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
            let seq = manifest::build_command_seq_fuzzed(&mut reader, comp_count);
            entries.push((label, manifest::bstr(&seq)));
        }
    }

    emit_map(&entries)
}
