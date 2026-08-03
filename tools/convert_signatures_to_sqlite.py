#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert Existing Python Signature Files to SQLite Database
===========================================================
Reads all existing Python signature files (signatures.py, signatures_ext.py,
signatures_ext2.py, and signatures_db.py) and creates/updates the SQLite database.

Handles deduplication: same hash across multiple files is stored only once.

Usage:
    python tools/convert_signatures_to_sqlite.py
    python tools/convert_signatures_to_sqlite.py --db-path /path/to/signatures.db
"""

import os
import sys
import time
import argparse

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.signatures.signature_db_manager import SignatureDBManager


def convert_signatures_py(db: SignatureDBManager) -> int:
    """Convert signatures from signatures.py (ALL_SIGNATURES dict).

    The signatures.py module has ALL_SIGNATURES as a dict of:
        {md5_hash: {name, type, level, family, desc}}
    """
    from engine.signatures import signatures as sig_module

    entries = []
    # ALL_SIGNATURES is the main MD5 dict
    if hasattr(sig_module, 'ALL_SIGNATURES'):
        for md5_hash, info in sig_module.ALL_SIGNATURES.items():
            if len(md5_hash) == 32:
                entries.append({
                    'md5': md5_hash,
                    'name': info.get('name', ''),
                    'threat_type': info.get('type', 'unknown'),
                    'level': info.get('level', 3),
                    'family': info.get('family', ''),
                    'description': info.get('desc', ''),
                    'source': 'signatures.py',
                    'is_verified': 0,
                })

    # SHA1_SIGNATURES
    if hasattr(sig_module, 'SHA1_SIGNATURES'):
        for sha1_hash, info in sig_module.SHA1_SIGNATURES.items():
            if len(sha1_hash) == 40:
                entries.append({
                    'sha1': sha1_hash,
                    'name': info.get('name', ''),
                    'threat_type': info.get('type', 'unknown'),
                    'level': info.get('level', 3),
                    'family': info.get('family', ''),
                    'description': info.get('desc', ''),
                    'source': 'signatures.py',
                    'is_verified': 0,
                })

    # SHA256_SIGNATURES
    if hasattr(sig_module, 'SHA256_SIGNATURES'):
        for sha256_hash, info in sig_module.SHA256_SIGNATURES.items():
            if len(sha256_hash) == 64:
                entries.append({
                    'sha256': sha256_hash,
                    'name': info.get('name', ''),
                    'threat_type': info.get('type', 'unknown'),
                    'level': info.get('level', 3),
                    'family': info.get('family', ''),
                    'description': info.get('desc', ''),
                    'source': 'signatures.py',
                    'is_verified': 0,
                })

    if not entries:
        # Fallback: try to extract from individual type dicts
        for attr_name in dir(sig_module):
            if attr_name.endswith('_SIGNATURES') and attr_name not in ('ALL_SIGNATURES', 'SHA1_SIGNATURES', 'SHA256_SIGNATURES'):
                try:
                    sig_dict = getattr(sig_module, attr_name)
                    if isinstance(sig_dict, dict):
                        for md5_hash, info in sig_dict.items():
                            if len(md5_hash) == 32:
                                entries.append({
                                    'md5': md5_hash,
                                    'name': info.get('name', ''),
                                    'threat_type': info.get('type', attr_name.replace('_SIGNATURES', '').lower()),
                                    'level': info.get('level', 3),
                                    'family': info.get('family', ''),
                                    'description': info.get('desc', ''),
                                    'source': 'signatures.py',
                                    'is_verified': 0,
                                })
                except Exception:
                    pass

    if entries:
        count = db.insert_batch(entries)
        print(f"  signatures.py: {count} entries imported (from {len(entries)} total)")
    else:
        print(f"  signatures.py: 0 entries imported (no recognizable format)")
    return len(entries)


def convert_signatures_ext(db: SignatureDBManager) -> int:
    """Convert signatures from signatures_ext.py (EXTENDED_SIGNATURES list)."""
    try:
        from engine.signatures import signatures_ext as ext_module
    except ImportError:
        print("  signatures_ext.py: module not found, skipping")
        return 0

    if not hasattr(ext_module, 'EXTENDED_SIGNATURES'):
        print("  signatures_ext.py: no EXTENDED_SIGNATURES found")
        return 0

    entries = []
    for entry in ext_module.EXTENDED_SIGNATURES:
        entries.append({
            'md5': entry.get('md5', ''),
            'sha1': entry.get('sha1', ''),
            'sha256': entry.get('sha256', ''),
            'name': entry.get('name', ''),
            'threat_type': entry.get('type', 'unknown'),
            'level': entry.get('level', 3),
            'family': entry.get('family', ''),
            'description': entry.get('desc', ''),
            'source': 'signatures_ext.py',
            'is_verified': 0,
        })

    count = db.insert_batch(entries)
    print(f"  signatures_ext.py: {count} entries imported (from {len(entries)} total)")
    return count


def convert_signatures_ext2(db: SignatureDBManager) -> int:
    """Convert signatures from signatures_ext2.py (SIGNATURES_PART3 list)."""
    try:
        from engine.signatures import signatures_ext2 as ext2_module
    except ImportError:
        print("  signatures_ext2.py: module not found, skipping")
        return 0

    if not hasattr(ext2_module, 'SIGNATURES_PART3'):
        print("  signatures_ext2.py: no SIGNATURES_PART3 found")
        return 0

    entries = []
    for entry in ext2_module.SIGNATURES_PART3:
        entries.append({
            'md5': entry.get('md5', ''),
            'sha1': entry.get('sha1', ''),
            'sha256': entry.get('sha256', ''),
            'name': entry.get('name', ''),
            'threat_type': entry.get('type', 'unknown'),
            'level': entry.get('level', 3),
            'family': entry.get('family', ''),
            'description': entry.get('desc', ''),
            'source': 'signatures_ext2.py',
            'is_verified': 0,
        })

    count = db.insert_batch(entries)
    print(f"  signatures_ext2.py: {count} entries imported (from {len(entries)} total)")
    return count


def convert_signatures_db(db: SignatureDBManager) -> int:
    """Convert signatures from signatures_db.py (SIGNATURE_DB list)."""
    try:
        from engine.signatures import signatures_db as sdb_module
    except ImportError:
        print("  signatures_db.py: module not found, skipping")
        return 0

    if not hasattr(sdb_module, 'SIGNATURE_DB'):
        print("  signatures_db.py: no SIGNATURE_DB found")
        return 0

    entries = []
    for entry in sdb_module.SIGNATURE_DB:
        entries.append({
            'md5': entry.get('md5', ''),
            'sha1': entry.get('sha1', ''),
            'sha256': entry.get('sha256', ''),
            'name': entry.get('name', ''),
            'threat_type': entry.get('type', 'unknown'),
            'level': entry.get('level', 3),
            'family': entry.get('family', ''),
            'description': entry.get('desc', ''),
            'source': 'signatures_db.py',
            'is_verified': 0,
        })

    count = db.insert_batch(entries)
    print(f"  signatures_db.py: {count} entries imported (from {len(entries)} total)")
    return count


def main():
    parser = argparse.ArgumentParser(
        description='Convert existing Python signature files to SQLite database'
    )
    parser.add_argument(
        '--db-path', type=str, default=None,
        help='Path to SQLite database file (default: engine/signatures/signatures.db)'
    )
    parser.add_argument(
        '--force', action='store_true',
        help='Recreate the database from scratch'
    )
    args = parser.parse_args()

    db_path = args.db_path
    if db_path and os.path.exists(db_path):
        if args.force:
            os.remove(db_path)
            print(f"Removed existing database: {db_path}")
        else:
            print(f"Database already exists at: {db_path}")
            print("Use --force to recreate it from scratch.")
            # Still update stats
            db = SignatureDBManager(db_path)
            db.initialize()
            stats = db.get_stats()
            print(f"Current stats: {stats}")
            db.close()
            return

    db = SignatureDBManager(db_path)
    db.initialize()

    print("=" * 60)
    print("Converting signature files to SQLite database")
    print(f"Database: {db.db_path}")
    print("=" * 60)

    start_time = time.time()

    total = 0
    total += convert_signatures_py(db)
    total += convert_signatures_ext(db)
    total += convert_signatures_ext2(db)
    total += convert_signatures_db(db)

    elapsed = time.time() - start_time

    db.vacuum()

    stats = db.get_stats()
    print("=" * 60)
    print(f"Conversion complete!")
    print(f"  Total entries processed: {total}")
    print(f"  Total unique signatures in DB: {stats['total_signatures']}")
    print(f"  Verified signatures: {stats['verified_count']}")
    print(f"  Time: {elapsed:.2f}s")
    print(f"  Database: {db.db_path}")

    # Show type distribution
    type_counts = db.count_by_type()
    if type_counts:
        print(f"\nType distribution:")
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {t}: {c}")

    db.close()


if __name__ == '__main__':
    main()