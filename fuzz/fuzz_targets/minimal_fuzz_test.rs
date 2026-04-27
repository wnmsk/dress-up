#![no_main]

use libfuzzer_sys::fuzz_target;

use dress_up::SuitManifest;

const MAX_INPUT_LEN: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let suit = SuitManifest::from_bytes(&data);

    if let Ok(envelope) = suit.envelope() {
        let _ = envelope.manifest();
    }
});