#!/usr/bin/env python3

import cbor2
import json
import sys
from pathlib import Path


MANIFEST = {
    1: "encoding_version",
    2: "sequence_number",
    3: "common",
    4: "reference_uri",
    7: "image_validation",
    8: "image_loading",
    9: "image_invocation",
    16: "payload_fetch",
    20: "payload_install",
    23: "text",
}

COMMON = {
    2: "component_identifiers",
    4: "common_command_sequence",
}

PARAMETERS = {
    1: "vendor_id",
    2: "class_id",
    3: "image_digest",
    5: "component_slot",
    12: "strict_order",
    13: "soft_failure",
    14: "image_size",
    18: "content",
    21: "uri",
    22: "source_component",
    23: "invoke_args",
    24: "device_id",
}

COMMANDS = {
    1: "vendor_identifier",
    2: "class_identifier",
    3: "image_match",
    5: "component_slot",
    6: "check_content",
    12: "set_component_index",
    14: "abort",
    15: "try_each",
    18: "write_content",
    20: "override_parameters",
    21: "fetch",
    22: "copy",
    23: "invoke",
    24: "device_identifier",
    31: "swap",
    32: "run_sequence",
}


def normalize(obj):
    if isinstance(obj, bytes):
        return obj.hex()

    if isinstance(obj, list):
        return [normalize(x) for x in obj]

    if isinstance(obj, dict):
        return {str(k): normalize(v) for k, v in obj.items()}

    return obj


def decode_override_parameters(m):
    result = {}

    for k, v in m.items():
        name = PARAMETERS.get(k, f"unknown_param_{k}")

        if k == 3:
            try:
                digest = cbor2.loads(v)

                result[name] = {
                    "algorithm": digest[0],
                    "hash": digest[1].hex(),
                }
            except Exception:
                result[name] = normalize(v)

        else:
            result[name] = normalize(v)

    return result


def decode_command_sequence(bstr):
    seq = cbor2.loads(bstr)

    result = []
    i = 0

    while i < len(seq):
        cmd = seq[i]
        cmd_name = COMMANDS.get(cmd, f"unknown_cmd_{cmd}")

        entry = {"command": cmd_name}

        if i + 1 < len(seq):
            arg = seq[i + 1]

            if cmd == 20 and isinstance(arg, dict):
                entry["parameters"] = decode_override_parameters(arg)
            else:
                entry["argument"] = normalize(arg)

        result.append(entry)
        i += 2

    return result


def decode_common(common_bstr):
    common = cbor2.loads(common_bstr)

    result = {}

    for k, v in common.items():
        name = COMMON.get(k, f"unknown_common_{k}")

        if k == 4:
            result[name] = decode_command_sequence(v)
        else:
            result[name] = normalize(v)

    return result


def decode_manifest(data):
    manifest = cbor2.loads(data)

    result = {}

    for k, v in manifest.items():
        name = MANIFEST.get(k, f"unknown_manifest_{k}")

        if k == 3:
            result[name] = decode_common(v)

        elif k in (7, 8, 9, 16, 20):
            try:
                result[name] = decode_command_sequence(v)
            except Exception:
                result[name] = normalize(v)

        else:
            result[name] = normalize(v)

    return result


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} manifest.suit")
        sys.exit(1)

    path = Path(sys.argv[1])

    with open(path, "rb") as f:
        data = f.read()

    manifest = decode_manifest(data)

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
