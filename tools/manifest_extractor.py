#!/usr/bin/env python3
import sys
import cbor2

SUIT_ENVELOPE_MANIFEST_KEY = 3  # SuitEnvelope::Manifest [1]
SUIT_TAG = 107                  # suit manifest tag

def extract_inner_manifest(envelope_bytes: bytes) -> bytes:
    obj = cbor2.loads(envelope_bytes)

    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != SUIT_TAG:
            raise ValueError(f"Unexpected CBOR tag {obj.tag}, expected {SUIT_TAG}")
        obj = obj.value

    # if not isinstance(obj, dict):
    #     raise ValueError(f"Expected top-level CBOR map (dict), got {type(obj).__name__}")

    if SUIT_ENVELOPE_MANIFEST_KEY not in obj:
        # Sometimes keys could be encoded differently; dump keys for debugging
        raise KeyError(f"Manifest key {SUIT_ENVELOPE_MANIFEST_KEY} not found. Keys: {list(obj.keys())}")

    manifest_item = obj[SUIT_ENVELOPE_MANIFEST_KEY]

    # Common pattern: manifest is wrapped as a bstr containing CBOR of the manifest.
    if isinstance(manifest_item, (bytes, bytearray)):
        return bytes(manifest_item)

    # Fallback: if the manifest is embedded directly as a CBOR map/array,
    # return its CBOR encoding so it can still be fuzzed as "inner bytes".
    return cbor2.dumps(manifest_item)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <suit-envelope.cbor> <out-inner-manifest.cbor>", file=sys.stderr)
        sys.exit(2)

    in_path, out_path = sys.argv[1], sys.argv[2]
    envelope = open(in_path, "rb").read()
    inner = extract_inner_manifest(envelope)
    open(out_path, "wb").write(inner)
    print(f"Wrote {len(inner)} bytes to {out_path}")

if __name__ == "__main__":
    main()
