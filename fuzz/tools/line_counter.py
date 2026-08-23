#!/usr/bin/env python3
import sys

def count_code_lines(filename):
    count = 0
    in_block_comment = False

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            i = 0
            code_on_line = False

            while i < len(line):
                if in_block_comment:
                    end = line.find("*/", i)
                    if end == -1:
                        break
                    in_block_comment = False
                    i = end + 2
                elif line.startswith("/*", i):
                    in_block_comment = True
                    i += 2
                elif line.startswith("//", i):
                    break
                else:
                    code_on_line = True
                    i += 1

            if code_on_line:
                count += 1

    return count


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <rust_file>")
        sys.exit(1)

    print(count_code_lines(sys.argv[1]))
