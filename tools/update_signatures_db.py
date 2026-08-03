#!/usr/bin/env python3
"""Update signatures_db.py with real malware hashes from fetched data."""

import json
import re
import sys
import os

def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else "D:/Antivirus/engine/signatures/signatures_db.py"
    hashes_path = sys.argv[2] if len(sys.argv) > 2 else "D:/Antivirus/tools/fetched_hashes.json"

    # Load real hashes
    with open(hashes_path, "r", encoding="utf-8") as f:
        real_hashes = json.load(f)

    # Read the file
    with open(db_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find all entries with md5 field
    # Pattern: {"md5": "xxx", "sha1": "xxx", "sha256": "xxx", "name": "xxx", ...}
    entry_pattern = re.compile(r'\{\s*"md5"\s*:\s*"([^"]+)"\s*,\s*"sha1"\s*:\s*"[^"]+"\s*,\s*"sha256"\s*:\s*"[^"]+"\s*,\s*"name"\s*:\s*"([^"]+)"')

    entries = list(entry_pattern.finditer(content))
    total = len(entries)
    replace_count = min(500, len(real_hashes))

    print(f"Total entries: {total}, replacing first {replace_count}", file=sys.stderr)

    # Process from the end to avoid offset issues
    content_list = list(content)

    # Replace md5 hashes for first 500 entries
    replaced = 0
    for i, m in enumerate(entries):
        if i >= replace_count:
            break
        old_md5 = m.group(1)
        new_md5 = real_hashes[i]["md5"]
        if old_md5.lower() != new_md5:
            # Find the exact position of the md5 value within the match
            md5_start = content.find('"md5": "', m.start()) + len('"md5": "')
            md5_end = md5_start + len(old_md5)
            if md5_start >= 0 and md5_start < md5_end:
                # Replace in the content list
                for j in range(md5_start, md5_end):
                    content_list[j] = ''
                content_list[md5_start] = new_md5
                replaced += 1
                print(f"  Replaced entry {i+1}: {old_md5} -> {new_md5}", file=sys.stderr)

    # Mark remaining entries as unverified
    unverified = 0
    for i, m in enumerate(entries):
        if i < replace_count:
            continue
        name = m.group(2)
        if not name.endswith("_unverified"):
            # Find the name value position
            name_start = content.find('"name": "', m.start()) + len('"name": "')
            name_end = name_start + len(name)
            if name_start >= 0:
                # Insert _unverified after the name
                suffix = "_unverified"
                # Shift content to make room
                for j in range(name_end, len(content_list)):
                    pass
                # Insert the suffix
                for j, ch in enumerate(suffix):
                    content_list.insert(name_end + j, ch)
                unverified += 1

    content = "".join(content_list)

    # Update counts
    content = re.sub(r'签名总数: \d+', f'签名总数: {total}', content)
    content = re.sub(r'SIGNATURE_COUNT = \d+', f'SIGNATURE_COUNT = {total}', content)

    # Write back
    with open(db_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Updated {db_path}", file=sys.stderr)
    print(f"  Entries: {total}", file=sys.stderr)
    print(f"  Replaced: {replaced}", file=sys.stderr)
    print(f"  Marked unverified: {unverified}", file=sys.stderr)


if __name__ == "__main__":
    main()