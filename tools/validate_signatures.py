#!/usr/bin/env python3
"""
Signature Validation Tool
Validates MD5 hashes in signature files, checks format,
and optionally verifies against MalwareBazaar API.

Usage:
    python validate_signatures.py
    python validate_signatures.py --verify-api
    python validate_signatures.py --file signatures.py
"""

import json
import re
import sys
import os
import urllib.request
import urllib.error
import ssl

def validate_md5(hash_str):
    """Check if a string is a valid MD5 hash (32 hex characters)."""
    return bool(re.match(r'^[0-9a-f]{32}$', hash_str))

def validate_md5_ignore_case(hash_str):
    """Check if a string is a valid MD5 hash (case-insensitive)."""
    return bool(re.match(r'^[0-9a-f]{32}$', hash_str, re.IGNORECASE))

def find_md5_hashes_in_file(filepath):
    """Find all MD5 hash strings in a Python file."""
    hashes = []
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern for signatures.py format: "32hexchars": {
    pattern1 = re.findall(r'"([0-9a-f]{32})"\s*:\s*\{', content, re.IGNORECASE)
    hashes.extend(pattern1)
    
    # Pattern for signatures_db.py format: "md5": "32hexchars"
    pattern2 = re.findall(r'"md5"\s*:\s*"([0-9a-f]{32})"', content, re.IGNORECASE)
    hashes.extend(pattern2)
    
    # Pattern for ALL_SIGNATURES["32hexchars"]
    pattern3 = re.findall(r'ALL_SIGNATURES\["([0-9a-f]{32})"\]', content)
    hashes.extend(pattern3)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_hashes = []
    for h in hashes:
        h_lower = h.lower()
        if h_lower not in seen:
            seen.add(h_lower)
            unique_hashes.append(h)
    
    return unique_hashes

def check_hash_via_malwarebazaar(md5_hash):
    """Check if a hash is known to MalwareBazaar API."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = f"query=get_siginfo&hash={md5_hash}"
    headers = {"API-KEY": ""}
    
    try:
        req = urllib.request.Request(url, data=data.encode(), headers=headers, method="POST")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        result = json.loads(resp.read().decode())
        return result.get("query_status") == "ok"
    except Exception:
        return None  # Unknown / error

def validate_file(filepath, verify_api=False):
    """Validate all hashes in a signature file."""
    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        return
    
    hashes = find_md5_hashes_in_file(filepath)
    total = len(hashes)
    
    print(f"File: {filepath}")
    print(f"Total hashes found: {total}")
    print()
    
    # Check format validity
    valid_format = 0
    invalid_format = 0
    invalid_hashes = []
    
    for h in hashes:
        if validate_md5(h):
            valid_format += 1
        elif validate_md5_ignore_case(h):
            invalid_hashes.append(h)
            invalid_format += 1
        else:
            invalid_hashes.append(h)
            invalid_format += 1
    
    print(f"Format valid (lowercase 32 hex): {valid_format}")
    print(f"Format invalid (non-lowercase or bad length): {invalid_format}")
    if invalid_hashes:
        print(f"  Invalid hashes: {invalid_hashes[:10]}")
        if len(invalid_hashes) > 10:
            print(f"  ... and {len(invalid_hashes) - 10} more")
    
    # Check for unverified markers
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    unverified_count = len(re.findall(r'_unverified', content))
    if unverified_count > 0:
        print(f"Unverified entries: {unverified_count}")
    
    # Check for duplicates
    hash_list = [h.lower() for h in hashes]
    dupes = set(h for h in hash_list if hash_list.count(h) > 1)
    if dupes:
        print(f"Duplicate hashes: {len(dupes)}")
        for d in list(dupes)[:5]:
            print(f"  {d}")
    else:
        print("Duplicate hashes: 0")
    
    # Check for EICAR test hash
    eicar = "44d88612fea8a8f36de82e1278abb02f"
    if eicar in hash_list:
        print(f"EICAR test signature: PRESENT")
    else:
        print(f"EICAR test signature: MISSING!")
    
    # Verify against MalwareBazaar API (optional)
    if verify_api:
        print()
        print("Verifying against MalwareBazaar API...")
        verified = 0
        not_found = 0
        error = 0
        
        # Sample first 50 hashes for verification
        sample = hashes[:50]
        for i, h in enumerate(sample):
            result = check_hash_via_malwarebazaar(h)
            if result is True:
                verified += 1
            elif result is False:
                not_found += 1
            else:
                error += 1
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{len(sample)}")
        
        print(f"API check results (sample of {len(sample)}):")
        print(f"  Verified in MalwareBazaar: {verified}")
        print(f"  Not found: {not_found}")
        print(f"  API error: {error}")
    
    print()
    
    # Summary
    file_type = "signatures.py" if "signatures.py" in filepath else "signatures_db.py"
    print(f"=== {file_type} Validation Summary ===")
    print(f"Status: {'PASS' if invalid_format == 0 else 'WARN'}")
    if invalid_format > 0:
        print(f"  {invalid_format} hashes have non-standard format")
    if unverified_count > 0:
        print(f"  {unverified_count} entries marked as unverified")
    print(f"  EICAR test: {'OK' if eicar in hash_list else 'MISSING'}")
    print(f"  Duplicates: {'None' if not dupes else str(len(dupes))}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate signature file hashes")
    parser.add_argument("--file", "-f", default=None,
                        help="Path to signature file (default: checks both signatures.py and signatures_db.py)")
    parser.add_argument("--verify-api", "-a", action="store_true",
                        help="Verify hashes against MalwareBazaar API")
    args = parser.parse_args()
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sig_dir = os.path.join(base_dir, "engine", "signatures")
    
    if args.file:
        validate_file(args.file, args.verify_api)
    else:
        sig_file = os.path.join(sig_dir, "signatures.py")
        db_file = os.path.join(sig_dir, "signatures_db.py")
        
        print("=" * 60)
        validate_file(sig_file, args.verify_api)
        print()
        print("=" * 60)
        validate_file(db_file, args.verify_api)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
