#!/usr/bin/env python3
"""Update signatures.py with real malware hashes from fetched data."""

import json
import re
import sys
import os

def main():
    sig_path = sys.argv[1] if len(sys.argv) > 1 else "D:/Antivirus/engine/signatures/signatures.py"
    hashes_path = sys.argv[2] if len(sys.argv) > 2 else "D:/Antivirus/tools/fetched_hashes.json"
    
    # Load real hashes
    with open(hashes_path, "r", encoding="utf-8") as f:
        real_hashes = json.load(f)
    
    # Read the file
    with open(sig_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    # Find all hash entries and their line numbers
    hash_pattern = re.compile(r'^\s+"([0-9a-f]{32})":\s*\{')
    entries = []
    for i, line in enumerate(lines):
        m = hash_pattern.match(line)
        if m:
            entries.append((i, m.group(1)))
    
    total = len(entries)
    replace_count = min(2000, len(real_hashes))
    print(f"Total entries: {total}, replacing first {replace_count}", file=sys.stderr)
    
    # Replace md5 hashes (first 2000)
    replaced = 0
    for idx, (line_num, old_hash) in enumerate(entries):
        if idx >= replace_count:
            break
        new_hash = real_hashes[idx]["md5"]
        if old_hash != new_hash:
            lines[line_num] = lines[line_num].replace('"' + old_hash + '"', '"' + new_hash + '"', 1)
            replaced += 1
    
    # Mark unverified (remaining entries)
    unverified = 0
    for idx, (line_num, old_hash) in enumerate(entries):
        if idx < replace_count:
            continue
        # Find the name field in this entry
        j = line_num + 1
        while j < len(lines):
            name_match = re.match(r'^(\s*"name":\s*")([^"]+)(")', lines[j])
            if name_match:
                if not name_match.group(2).endswith("_unverified"):
                    lines[j] = name_match.group(1) + name_match.group(2) + "_unverified" + lines[j][name_match.start(3):]
                    unverified += 1
                break
            # Stop if we hit the next hash entry or end of dict
            if re.match(r'^\s+"[0-9a-f]{32}":\s*\{', lines[j]):
                break
            if lines[j].strip() in ("}", "},"):
                break
            j += 1
    
    # Fix EICAR entry if it got marked unverified
    eicar_fixed = 0
    for i, line in enumerate(lines):
        if '44d88612fea8a8f36de82e1278abb02f' in line:
            # Check if next line has unverified
            if i+1 < len(lines):
                name_m = re.match(r'^(\s*"name":\s*")([^"]+_unverified)(")', lines[i+1])
                if name_m:
                    lines[i+1] = name_m.group(1) + "EICAR.Test.File" + lines[i+1][name_m.start(3):]
                    eicar_fixed += 1
            break
    
    # Update header
    output = "".join(lines)
    output = re.sub(r'# 签名总数: \d+', f'# 签名总数: {total}', output)
    output = re.sub(r'SIGNATURE_COUNT = \d+', f'SIGNATURE_COUNT = {total}', output)
    
    # Write back
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(output)
    
    print(f"Updated {sig_path}", file=sys.stderr)
    print(f"  Entries: {total}", file=sys.stderr)
    print(f"  Replaced: {replaced}", file=sys.stderr)
    print(f"  Marked unverified: {unverified}", file=sys.stderr)
    if eicar_fixed:
        print(f"  Fixed EICAR: {eicar_fixed}", file=sys.stderr)

if __name__ == "__main__":
    main()
