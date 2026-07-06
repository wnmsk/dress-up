#![no_main]

use libfuzzer_sys::fuzz_target;

use uuid::uuid;

use dress_up::SuitManifest;
use fuzz::{envelope_builder::build_envelope, os_hooks::OsHooks};

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let manifest = data.get(1..).unwrap_or(data);
    let payload = "hello world!";

    // certain structure-awareness by wrapping inner manifest in valid SUIT envelope with valid auth block
    let input = build_envelope(manifest);

    // class_id and vendor_id taken from minimal example
    // TODO: check if this also needs to be fuzzed
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
