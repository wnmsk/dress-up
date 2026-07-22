use crate::{
    cbor::cbor_bstr_header,
    consts::{self, cbor::map, labels},
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

pub fn build_manifest(data: &[u8]) -> Vec<u8> {
    let mut use_payload_installation = false;

    if data.len() > 100 {
        // TODO: maybe adjust threshold here
        use_payload_installation = true; // TODO: use flag to determine if "Payload Installation" block will be included with additional bytes
    }

    // specify content of the different fields from arbitrary bytes
    let version = data[0];
    // let version = 1;
    let seq_nr = [data[1], data[2]];
    let comp_ident = data[3];
    // let vendor_id = &data[4..20]; // TODO: maybe just use constant id
    // let class_id = &data[20..36]; // TODO: maybe just use constant id
    let img_hash = &data[36..68]; // TODO: maybe rather calculate hash here
    let img_size = [data[68], data[69]];

    // use same class_id as declared in manifest_gen
    let class_id: &[u8] = &[
        0x01, 0x9c, 0x9a, 0x96, 0x34, 0x7b, 0x7d, 0x98, 0xac, 0xc9, 0xb9, 0x01, 0x17, 0xf4, 0xa6,
        0x65,
    ];

    // use same vendor_id as declared in manifest_gen
    let vendor_id: &[u8] = &[
        0x01, 0x9c, 0x9a, 0x95, 0xf6, 0xcb, 0x71, 0xa7, 0xa0, 0xa6, 0xaa, 0xc1, 0x48, 0xfc, 0x47,
        0x43,
    ];

    // create common data block
    let common_data = build_common_data(comp_ident, vendor_id, class_id, img_hash, &img_size);

    // create command sequences
    let com_seq_val = build_command_seq(labels::manifest_elements::IMAGE_VALIDATION);
    let com_seq_inv = build_command_seq(labels::manifest_elements::IMAGE_INVOCATION);

    // build manifest structure
    let mut manifest: Vec<u8> = vec![];
    manifest.push(consts::cbor::map(5)); // map containing all of the manifest

    // --- suit-manifest-version ---
    manifest.push(labels::manifest_elements::ENCODING_VERSION);
    manifest.push(version);

    // --- suit-manifest-sequence-number ---
    manifest.push(labels::manifest_elements::SEQUENCE_NUMBER);
    manifest.push(0x19); // header for "next two bytes uint" TODO: write function to variably calc uint header
    manifest.extend(seq_nr);

    // --- suit-common ---
    manifest.push(labels::manifest_elements::COMMON_DATA);
    manifest.extend(cbor_bstr_header(common_data.len()));
    manifest.extend(common_data);

    // command sequences; TODO: randomly select command sequences (maybe based on selector bytes again?)
    // manually adding image validation and image invocation for the moment

    // --- suit-validate ---
    manifest.push(consts::labels::manifest_elements::IMAGE_VALIDATION);
    manifest.extend(cbor_bstr_header(com_seq_val.len()));
    manifest.extend(com_seq_val);

    // --- suit-validate ---
    manifest.push(consts::labels::manifest_elements::IMAGE_INVOCATION);
    manifest.extend(cbor_bstr_header(com_seq_inv.len()));
    manifest.extend(com_seq_inv);

    manifest
}
