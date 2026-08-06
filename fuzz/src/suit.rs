use crate::consts::cbor;

pub fn encode_uint(v: u64) -> Vec<u8> {
    encode_head(cbor::UINT_MAJOR_BASE, v)
}

pub fn encode_head(major: u8, v: u64) -> Vec<u8> {
    if v <= 23 {
        vec![major | v as u8]
    } else if v <= u8::MAX as u64 {
        vec![major | cbor::AI_ONE_BYTE, v as u8]
    } else if v <= u16::MAX as u64 {
        let mut o = vec![major | cbor::AI_TWO_BYTES];
        o.extend_from_slice(&(v as u16).to_be_bytes());
        o
    } else if v <= u32::MAX as u64 {
        let mut o = vec![major | cbor::AI_FOUR_BYTES];
        o.extend_from_slice(&(v as u32).to_be_bytes());
        o
    } else {
        let mut o = vec![major | cbor::AI_EIGHT_BYTES];
        o.extend_from_slice(&v.to_be_bytes());
        o
    }
}

pub fn encode_tstr(s: &str) -> Vec<u8> {
    let mut o = encode_head(cbor::TSTR_MAJOR_BASE, s.len() as u64);
    o.extend_from_slice(s.as_bytes());
    o
}
