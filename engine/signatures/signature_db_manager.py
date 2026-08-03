#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLite-backed Signature Database Manager
=========================================
Provides lazy-loading signature storage using SQLite.
Only queries what's needed, instead of loading all signatures into memory.

Features:
  - Thread-safe with RLock
  - WAL mode for concurrent read performance
  - Indexed hash columns for fast lookup
  - Lazy loading: only fetch what you need
  - Batch inserts for initialization
  - Fallback to in-memory dict for small, frequently-used sets

Usage:
    db = SignatureDBManager()
    db.initialize()
    threat = db.lookup_by_md5('44d88612fea8a8f36de82e1278abb02f')
    if threat:
        print(f"Found: {threat['name']}")
"""

import os
import sqlite3
import threading
import time
from typing import Optional, Dict, List, Tuple, Any
from pathlib import Path


# Path to the SQLite database file
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'signatures.db'
)


class SignatureDBManager:
    """SQLite-backed signature database manager with lazy loading.

    Attributes:
        db_path: Path to the SQLite database file
        _lock: Thread safety lock
        _conn: SQLite connection (per-thread via threading.local)
        _initialized: Whether the database has been initialized
    """

    # Schema version for migration support
    SCHEMA_VERSION = 1

    CREATE_TABLE_SQL = '''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            name TEXT NOT NULL DEFAULT '',
            threat_type TEXT NOT NULL DEFAULT 'unknown',
            level INTEGER NOT NULL DEFAULT 3,
            family TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            is_verified INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
            updated_at REAL NOT NULL DEFAULT (strftime('%s','now'))
        )
    '''

    CREATE_INDEXES_SQL = [
        'CREATE INDEX IF NOT EXISTS idx_md5 ON signatures(md5)',
        'CREATE INDEX IF NOT EXISTS idx_sha1 ON signatures(sha1)',
        'CREATE INDEX IF NOT EXISTS idx_sha256 ON signatures(sha256)',
        'CREATE INDEX IF NOT EXISTS idx_family ON signatures(family)',
        'CREATE INDEX IF NOT EXISTS idx_threat_type ON signatures(threat_type)',
        'CREATE INDEX IF NOT EXISTS idx_name ON signatures(name)',
        'CREATE INDEX IF NOT EXISTS idx_is_verified ON signatures(is_verified)',
    ]

    def __init__(self, db_path: Optional[str] = None):
        """Initialize the signature database manager.

        Args:
            db_path: Path to the SQLite database file. If None, uses default.
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self._local = threading.local()
        self._initialized = False
        self._stats = {
            'total_signatures': 0,
            'verified_count': 0,
            'last_updated': 0,
        }

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrent reads
            self._local.conn.execute('PRAGMA journal_mode=WAL')
            # Performance pragmas
            self._local.conn.execute('PRAGMA synchronous=NORMAL')
            self._local.conn.execute('PRAGMA cache_size=-8000')  # 8MB cache
            self._local.conn.execute('PRAGMA busy_timeout=5000')
            self._local.conn.execute('PRAGMA temp_store=MEMORY')
            self._local.conn.execute('PRAGMA mmap_size=268435456')  # 256MB mmap
        return self._local.conn

    def initialize(self) -> bool:
        """Create the database and tables if they don't exist.

        Returns:
            True if successful, False otherwise.
        """
        with self._lock:
            try:
                conn = self._get_conn()
                conn.execute(self.CREATE_TABLE_SQL)
                for idx_sql in self.CREATE_INDEXES_SQL:
                    conn.execute(idx_sql)
                conn.commit()
                self._initialized = True
                self._refresh_stats()
                return True
            except sqlite3.Error as e:
                print(f"[SignatureDB] Failed to initialize database: {e}")
                return False

    @property
    def is_available(self) -> bool:
        """Check if the database is initialized and has data."""
        if not self._initialized:
            return False
        return self._stats['total_signatures'] > 0

    # ----------------------------------------------------------
    # Lookup Methods (Lazy Loading)
    # ----------------------------------------------------------

    def lookup_by_md5(self, md5: str) -> Optional[Dict[str, Any]]:
        """Look up a signature by MD5 hash.

        Args:
            md5: MD5 hash string (32 hex chars)

        Returns:
            Signature dict or None if not found
        """
        if not md5 or len(md5) != 32:
            return None
        return self._lookup('md5', md5.lower())

    def lookup_by_sha1(self, sha1: str) -> Optional[Dict[str, Any]]:
        """Look up a signature by SHA1 hash.

        Args:
            sha1: SHA1 hash string (40 hex chars)

        Returns:
            Signature dict or None if not found
        """
        if not sha1 or len(sha1) != 40:
            return None
        return self._lookup('sha1', sha1.lower())

    def lookup_by_sha256(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Look up a signature by SHA256 hash.

        Args:
            sha256: SHA256 hash string (64 hex chars)

        Returns:
            Signature dict or None if not found
        """
        if not sha256 or len(sha256) != 64:
            return None
        return self._lookup('sha256', sha256.lower())

    def lookup_any(self, md5: str = '', sha1: str = '', sha256: str = '') -> Optional[Dict[str, Any]]:
        """Look up by any hash, trying MD5 first, then SHA1, then SHA256.

        Args:
            md5: MD5 hash
            sha1: SHA1 hash
            sha256: SHA256 hash

        Returns:
            Signature dict or None
        """
        if md5:
            result = self.lookup_by_md5(md5)
            if result:
                return result
        if sha1:
            result = self.lookup_by_sha1(sha1)
            if result:
                return result
        if sha256:
            result = self.lookup_by_sha256(sha256)
            if result:
                return result
        return None

    def _lookup(self, column: str, value: str) -> Optional[Dict[str, Any]]:
        """Internal lookup method."""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                f'SELECT * FROM signatures WHERE {column} = ? LIMIT 1',
                (value,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except sqlite3.Error:
            return None

    # ----------------------------------------------------------
    # Batch Operations
    # ----------------------------------------------------------

    def insert_batch(self, entries: List[Dict[str, Any]]) -> int:
        """Insert multiple signatures in a batch transaction.

        Args:
            entries: List of signature dicts with keys:
                     md5, sha1, sha256, name, threat_type, level,
                     family, description, source, is_verified

        Returns:
            Number of rows inserted
        """
        if not entries:
            return 0

        sql = '''
            INSERT OR IGNORE INTO signatures
                (md5, sha1, sha256, name, threat_type, level, family,
                 description, source, is_verified, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))
        '''

        count = 0
        with self._lock:
            try:
                conn = self._get_conn()
                now = time.time()
                batch = []
                for entry in entries:
                    batch.append((
                        (entry.get('md5') or '')[:32].lower(),
                        (entry.get('sha1') or '')[:40].lower(),
                        (entry.get('sha256') or '')[:64].lower(),
                        entry.get('name', ''),
                        entry.get('threat_type', entry.get('type', 'unknown')),
                        int(entry.get('level', 3)),
                        entry.get('family', ''),
                        entry.get('description', entry.get('desc', '')),
                        entry.get('source', ''),
                        int(entry.get('is_verified', 0)),
                    ))

                conn.executemany(sql, batch)
                conn.commit()
                count = len(batch)
                self._refresh_stats()
            except sqlite3.Error as e:
                print(f"[SignatureDB] Batch insert error: {e}")
                conn.rollback()
        return count

    def insert_or_update(self, entry: Dict[str, Any]) -> bool:
        """Insert a single signature, or update if exists (matched by any hash).

        Args:
            entry: Signature dict

        Returns:
            True if successful
        """
        with self._lock:
            try:
                conn = self._get_conn()
                md5 = (entry.get('md5') or '')[:32].lower()
                sha1 = (entry.get('sha1') or '')[:40].lower()
                sha256 = (entry.get('sha256') or '')[:64].lower()

                # Try to find existing record
                existing = None
                if md5 and len(md5) == 32:
                    existing = self._lookup('md5', md5)
                if not existing and sha1 and len(sha1) == 40:
                    existing = self._lookup('sha1', sha1)
                if not existing and sha256 and len(sha256) == 64:
                    existing = self._lookup('sha256', sha256)

                if existing:
                    # Update
                    conn.execute('''
                        UPDATE signatures SET
                            md5 = ?, sha1 = ?, sha256 = ?, name = ?,
                            threat_type = ?, level = ?, family = ?,
                            description = ?, source = ?, is_verified = ?,
                            updated_at = strftime('%s','now')
                        WHERE id = ?
                    ''', (
                        md5, sha1, sha256,
                        entry.get('name', ''),
                        entry.get('threat_type', entry.get('type', 'unknown')),
                        int(entry.get('level', 3)),
                        entry.get('family', ''),
                        entry.get('description', entry.get('desc', '')),
                        entry.get('source', ''),
                        int(entry.get('is_verified', 0)),
                        existing['id']
                    ))
                else:
                    # Insert
                    conn.execute('''
                        INSERT INTO signatures
                            (md5, sha1, sha256, name, threat_type, level, family,
                             description, source, is_verified, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))
                    ''', (
                        md5, sha1, sha256,
                        entry.get('name', ''),
                        entry.get('threat_type', entry.get('type', 'unknown')),
                        int(entry.get('level', 3)),
                        entry.get('family', ''),
                        entry.get('description', entry.get('desc', '')),
                        entry.get('source', ''),
                        int(entry.get('is_verified', 0)),
                    ))
                conn.commit()
                self._refresh_stats()
                return True
            except sqlite3.Error as e:
                print(f"[SignatureDB] Insert/update error: {e}")
                return False

    # ----------------------------------------------------------
    # Query Methods
    # ----------------------------------------------------------

    def query_by_name(self, name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query signatures by name (partial match).

        Args:
            name: Threat name to search for
            limit: Maximum results

        Returns:
            List of matching signature dicts
        """
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT * FROM signatures WHERE name LIKE ? LIMIT ?',
                (f'%{name}%', limit)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []

    def query_by_family(self, family: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query signatures by malware family."""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT * FROM signatures WHERE family = ? LIMIT ?',
                (family, limit)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []

    def query_by_type(self, threat_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query signatures by threat type."""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT * FROM signatures WHERE threat_type = ? LIMIT ?',
                (threat_type, limit)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []

    def get_verified(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get verified (real) signatures.

        Args:
            limit: Maximum results

        Returns:
            List of verified signature dicts
        """
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT * FROM signatures WHERE is_verified = 1 LIMIT ?',
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []

    def get_unverified(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get unverified (generated) signatures that need replacement."""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT * FROM signatures WHERE is_verified = 0 LIMIT ?',
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []

    def count_by_type(self) -> Dict[str, int]:
        """Get count of signatures by threat type."""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                'SELECT threat_type, COUNT(*) as cnt FROM signatures GROUP BY threat_type'
            )
            return {row['threat_type']: row['cnt'] for row in cursor.fetchall()}
        except sqlite3.Error:
            return {}

    def count_verified(self) -> int:
        """Get count of verified signatures."""
        try:
            conn = self._get_conn()
            cursor = conn.execute('SELECT COUNT(*) as cnt FROM signatures WHERE is_verified = 1')
            return cursor.fetchone()['cnt']
        except sqlite3.Error:
            return 0

    # ----------------------------------------------------------
    # Statistics & Maintenance
    # ----------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        self._refresh_stats()
        return dict(self._stats)

    def _refresh_stats(self):
        """Refresh cached statistics."""
        try:
            conn = self._get_conn()
            cursor = conn.execute('SELECT COUNT(*) as cnt FROM signatures')
            self._stats['total_signatures'] = cursor.fetchone()['cnt']

            cursor = conn.execute('SELECT COUNT(*) as cnt FROM signatures WHERE is_verified = 1')
            self._stats['verified_count'] = cursor.fetchone()['cnt']

            cursor = conn.execute('SELECT MAX(updated_at) as max_ts FROM signatures')
            row = cursor.fetchone()
            self._stats['last_updated'] = row['max_ts'] if row['max_ts'] else 0
        except sqlite3.Error:
            pass

    def vacuum(self) -> bool:
        """Reclaim disk space by rebuilding the database."""
        try:
            conn = self._get_conn()
            conn.execute('VACUUM')
            return True
        except sqlite3.Error:
            return False

    def get_total_count(self) -> int:
        """Get total number of signatures."""
        self._refresh_stats()
        return self._stats['total_signatures']

    # ----------------------------------------------------------
    # Connection Management
    # ----------------------------------------------------------

    def close(self):
        """Close all database connections."""
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            try:
                self._local.conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()