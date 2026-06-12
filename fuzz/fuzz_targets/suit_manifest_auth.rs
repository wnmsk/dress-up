#![no_main]

use libfuzzer_sys::fuzz_target;

use sha2::{Digest, Sha256};
use std::cell::Cell;
use uuid::{uuid, Uuid};

use dress_up::{error::Error, OperatingHooks, SuitManifest};
use fuzz::consts::CborConsts;

// OsHooks copied from examples/minimal/main.rs
struct OsHooks<'a> {
    payload: &'a [u8],
    storage: Cell<Vec<u8>>,
    capacity: usize,
    vendor_id: Uuid,
    class_id: Uuid,
}

impl<'a> OsHooks<'a> {
    fn new(capacity: usize, vendor_id: Uuid, class_id: Uuid, payload: &'a [u8]) -> Self {
        Self {
            payload,
            storage: Cell::new(Vec::with_capacity(capacity)),
            capacity,
            vendor_id,
            class_id,
        }
    }
}

impl<'a> OperatingHooks for OsHooks<'a> {
    type ReadWriteBufferSize = generic_array::typenum::U64;

    fn match_vendor_id(
        &self,
        uuid: Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.vendor_id == uuid)
    }

    fn match_class_id(
        &self,
        uuid: Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.class_id == uuid)
    }

    fn component_read(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), dress_up::error::Error> {
        let storage = self.storage.take();
        if bytes.len() + offset > storage.len() {
            self.storage.set(storage);
            return Err(Error::InvalidCommandSequence { position: 0 });
        }
        bytes.copy_from_slice(&storage[offset..offset + bytes.len()]);
        self.storage.set(storage);
        Ok(())
    }

    fn component_write(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _offset: usize,
        _bytes: &[u8],
    ) -> Result<(), dress_up::error::Error> {
        todo!()
    }

    fn component_size(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        let storage = self.storage.take();
        let len = storage.len();
        self.storage.set(storage);
        Ok(len)
    }

    fn component_capacity(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        Ok(self.capacity)
    }

    fn fetch(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _uri: &str,
    ) -> Result<(), Error> {
        let mut storage = self.storage.take();
        storage.clear();
        storage.extend_from_slice(self.payload);
        self.storage.set(storage);
        Ok(())
    }
}

fn cbor_bstr_header(len: usize) -> Vec<u8> {
    // Major type 2 (byte string): initial byte is 0b010_aaaaa == 0x40 + additional info
    if len <= 23 {
        // additional info = len
        vec![CborConsts::bstr_len_small(len as u8)]
    } else if len <= 0xff {
        // additional info = 24, followed by 1-byte length
        vec![CborConsts::BSTR_LEN_U8, len as u8]
    } else if len <= 0xffff {
        // additional info = 25, followed by 2-byte length (big-endian)
        vec![
            CborConsts::BSTR_LEN_U16,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    } else if len <= 0xffff_ffff {
        // additional info = 26, followed by 4-byte length (big-endian)
        let n = len as u32;
        vec![
            CborConsts::BSTR_LEN_U32,
            ((n >> 24) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            (n & 0xff) as u8,
        ]
    } else if (len as u128) <= 0xffff_ffff_ffff_ffffu128 {
        // additional info = 27, followed by 8-byte length (big-endian)
        let n = len as u64;
        vec![
            CborConsts::BSTR_LEN_U64,
            ((n >> 56) & 0xff) as u8,
            ((n >> 48) & 0xff) as u8,
            ((n >> 40) & 0xff) as u8,
            ((n >> 32) & 0xff) as u8,
            ((n >> 24) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            (n & 0xff) as u8,
        ]
    } else {
        panic!("byte string too large for CBOR definite-length encoding");
    }
}

fn gen_auth(manifest: &[u8]) -> Vec<u8> {
    // --- manifest hash ---
    let mut man: Vec<u8> = vec![];
    man.extend(cbor_bstr_header(manifest.len())); // add length header of manifest
    man.extend(manifest); // manifest itself

    // hash the manifest TODO: implement oher hash algs
    let man_hash = Sha256::digest(man);

    // --- digest container ---
    let mut digest_cont: Vec<u8> = vec![];
    digest_cont.push(CborConsts::array(2)); // Array with 2 fields
    digest_cont.push(CborConsts::ALG_SHA_256); // digest algorithm (here Sha256) TODO: implement other hash algs
    digest_cont.extend(cbor_bstr_header(man_hash.len())); // length header for manifest hash
    digest_cont.extend(man_hash); // actual hash from manifest

    // --- auth block ---
    let mut auth_block: Vec<u8> = vec![];
    auth_block.push(CborConsts::array(2)); // Array with 2 fields
    auth_block.extend(cbor_bstr_header(digest_cont.len())); // length of digest
    auth_block.extend(digest_cont); // digest block

    // --- COSE ---
    auth_block.push(CborConsts::BSTR_MAJOR_BASE); // empty bstr (placeholder for COSE block)

    auth_block
}

fn build_envelope(auth_block: &[u8], manifest: &[u8]) -> Vec<u8> {
    // --- envelope header ---
    let mut envlp: Vec<u8> = vec![];
    envlp.extend(CborConsts::MANIFEST_TAG); // Tag for SUIT Manifest
    envlp.push(CborConsts::map(2)); // map with 2 entries

    // --- auth block header ---
    envlp.push(CborConsts::ENVLP_AUTHENTICATION); // envelop key "Authentication"
    envlp.extend(cbor_bstr_header(auth_block.len())); // auth block length

    // --- auth block ---
    envlp.extend_from_slice(auth_block);

    // --- manifest header ---
    envlp.push(CborConsts::ENVLP_MANIFEST); // envelop key "Manifest"
    envlp.extend(cbor_bstr_header(manifest.len())); // manifest length

    // --- inner manifest ---
    envlp.extend_from_slice(manifest);

    envlp
}

fuzz_target!(|data: &[u8]| {
    let selector = data.get(0).copied().unwrap_or(0);
    let manifest = data.get(1..).unwrap_or(data);
    let payload = "hello world!";

    // minimal structure-awareness by appending "valid" auth block at beginning of input
    let auth_block = gen_auth(manifest);
    let input = build_envelope(&auth_block, manifest);

    // class_id and vendor_id taken from minimal example
    // TODO: check if this makes any difference
    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");

    let hooks = OsHooks::new(4096, vendor_id, class_id, payload.as_bytes());

    let suit = SuitManifest::from_bytes(&input);

    // circumvent authentication by just returning true
    if let Ok(suit) = suit.authenticate(|_cose, _payload| Ok(true)) {
        if let Ok(envelope) = suit.envelope() {
            if let Ok(manifest) = envelope.manifest() {
                // randomly select which function is called based on first byte of data
                match selector % 10 {
                    0 => {
                        let _ = manifest.has_payload_fetch();
                    }
                    1 => {
                        let _ = manifest.has_payload_installation();
                    }
                    2 => {
                        let _ = manifest.has_image_validation();
                    }
                    3 => {
                        let _ = manifest.has_image_loading();
                    }
                    4 => {
                        let _ = manifest.has_invoke();
                    }
                    5 => {
                        let _ = manifest.execute_payload_fetch(&hooks);
                    }
                    6 => {
                        let _ = manifest.execute_payload_installation(&hooks);
                    }
                    7 => {
                        let _ = manifest.execute_image_validation(&hooks);
                    }
                    8 => {
                        let _ = manifest.execute_image_loading(&hooks);
                    }
                    9 => {
                        let _ = manifest.execute_invoke(&hooks);
                    }
                    _ => {
                        let _ = manifest.execute_full(&hooks);
                    }
                }
            }
        }
    }
});
