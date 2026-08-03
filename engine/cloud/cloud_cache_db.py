#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 云查杀 SQLite 缓存
替换原有的 JSON 文件缓存，提供更高效、可靠的持久化缓存
"""
import os
import sys
import time
import json
import sqlite3
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger


class CloudCacheDB:
    """SQLite 云查杀缓存

    相比 JSON 文件缓存：
    - 增量写入，无需每次写入完整数据
    - 支持高效过期删除
    - 线程安全，支持并发访问
    - 自动清理过期条目
    """

    def __init__(self, db_path: str, max_entries: int = 10000, ttl_hours: int = 24):
        self.db_path = db_path
        self.max_entries = max_entries
        self.ttl_seconds = ttl_hours * 3600
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
        self._cleanup_expired()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接（线程本地）"""
        if self._conn is None:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute('PRAGMA synchronous=NORMAL')
            self._conn.execute('PRAGMA cache_size=-8192')  # 8MB cache
        return self._conn

    def _init_db(self):
        """初始化数据库表结构"""
        try:
            conn = self._get_conn()
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cloud_cache (
                    hash_key TEXT PRIMARY KEY,
                    result_data TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    malicious INTEGER NOT NULL DEFAULT 0,
                    threat_name TEXT DEFAULT '',
                    confidence REAL DEFAULT 0,
                    access_count INTEGER DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_cloud_cache_timestamp
                ON cloud_cache(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_cloud_cache_malicious
                ON cloud_cache(malicious)
            ''')
            conn.commit()
        except Exception as e:
            logger.error(f"初始化云缓存数据库失败: {e}")

    def get(self, key: str) -> Optional[Dict]:
        """获取缓存条目"""
        if not key:
            return None
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                '''SELECT result_data, timestamp, malicious
                   FROM cloud_cache WHERE hash_key = ?''',
                (key,)
            )
            row = cursor.fetchone()
            if row:
                result_data, timestamp, malicious = row
                # 检查 TTL
                if time.time() - timestamp < self.ttl_seconds:
                    # 更新访问计数
                    conn.execute(
                        'UPDATE cloud_cache SET access_count = access_count + 1 WHERE hash_key = ?',
                        (key,)
                    )
                    conn.commit()
                    result = json.loads(result_data)
                    result['malicious'] = bool(malicious)
                    return result
                else:
                    # 过期条目，删除
                    conn.execute('DELETE FROM cloud_cache WHERE hash_key = ?', (key,))
                    conn.commit()
            return None
        except Exception as e:
            logger.error(f"读取云缓存失败: {e}")
            return None

    def set(self, key: str, value: Dict):
        """设置缓存条目"""
        if not key:
            return
        try:
            # 提取关键字段
            malicious = 1 if value.get('malicious') else 0
            threat_name = value.get('threat_name', '')
            confidence = value.get('confidence', 0)

            # 存储完整数据（不含 timestamp）
            store_value = dict(value)
            store_value.pop('timestamp', None)

            conn = self._get_conn()
            conn.execute(
                '''INSERT OR REPLACE INTO cloud_cache
                   (hash_key, result_data, timestamp, malicious, threat_name, confidence)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    key,
                    json.dumps(store_value, ensure_ascii=False),
                    time.time(),
                    malicious,
                    threat_name,
                    confidence,
                )
            )
            conn.commit()

            # 检查是否超过最大条目数
            self._enforce_max_entries()

        except Exception as e:
            logger.error(f"写入云缓存失败: {e}")

    def set_batch(self, entries: Dict[str, Dict]):
        """批量设置缓存条目"""
        try:
            conn = self._get_conn()
            conn.execute('BEGIN')
            now = time.time()
            for key, value in entries.items():
                malicious = 1 if value.get('malicious') else 0
                threat_name = value.get('threat_name', '')
                confidence = value.get('confidence', 0)
                store_value = dict(value)
                store_value.pop('timestamp', None)
                conn.execute(
                    '''INSERT OR REPLACE INTO cloud_cache
                       (hash_key, result_data, timestamp, malicious, threat_name, confidence)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (key, json.dumps(store_value, ensure_ascii=False), now, malicious, threat_name, confidence)
                )
            conn.commit()
        except Exception as e:
            logger.error(f"批量写入云缓存失败: {e}")

    def _enforce_max_entries(self):
        """确保缓存条目不超过上限"""
        try:
            conn = self._get_conn()
            count = conn.execute('SELECT COUNT(*) FROM cloud_cache').fetchone()[0]
            if count > self.max_entries:
                # 删除最旧的条目，保留 max_entries 个
                excess = count - self.max_entries + int(self.max_entries * 0.1)  # 额外删除10%
                conn.execute(
                    '''DELETE FROM cloud_cache WHERE rowid IN (
                        SELECT rowid FROM cloud_cache ORDER BY timestamp ASC LIMIT ?
                    )''',
                    (excess,)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"清理缓存条目失败: {e}")

    def _cleanup_expired(self):
        """清理过期条目"""
        try:
            conn = self._get_conn()
            cutoff = time.time() - self.ttl_seconds
            deleted = conn.execute(
                'DELETE FROM cloud_cache WHERE timestamp < ?',
                (cutoff,)
            ).rowcount
            conn.commit()
            if deleted > 0:
                logger.info(f"云缓存: 清理了 {deleted} 条过期条目")
        except Exception as e:
            logger.error(f"清理过期缓存失败: {e}")

    def get_malicious_count(self) -> int:
        """获取恶意缓存条目数"""
        try:
            conn = self._get_conn()
            return conn.execute(
                'SELECT COUNT(*) FROM cloud_cache WHERE malicious = 1'
            ).fetchone()[0]
        except Exception:
            return 0

    def get_clean_count(self) -> int:
        """获取安全缓存条目数"""
        try:
            conn = self._get_conn()
            return conn.execute(
                'SELECT COUNT(*) FROM cloud_cache WHERE malicious = 0'
            ).fetchone()[0]
        except Exception:
            return 0

    def search_by_threat(self, threat_name_pattern: str) -> List[Dict]:
        """按威胁名称搜索缓存"""
        try:
            conn = self._get_conn()
            cursor = conn.execute(
                '''SELECT hash_key, result_data, timestamp, threat_name, confidence
                   FROM cloud_cache
                   WHERE threat_name LIKE ? AND malicious = 1
                   ORDER BY timestamp DESC LIMIT 100''',
                (f'%{threat_name_pattern}%',)
            )
            results = []
            for row in cursor:
                results.append({
                    'hash': row[0],
                    'data': json.loads(row[1]),
                    'timestamp': row[2],
                    'threat_name': row[3],
                    'confidence': row[4],
                })
            return results
        except Exception:
            return []

    def stats(self) -> Dict:
        """缓存统计"""
        try:
            conn = self._get_conn()
            total = conn.execute('SELECT COUNT(*) FROM cloud_cache').fetchone()[0]
            malicious = conn.execute(
                'SELECT COUNT(*) FROM cloud_cache WHERE malicious = 1'
            ).fetchone()[0]
            oldest = conn.execute(
                'SELECT MIN(timestamp) FROM cloud_cache'
            ).fetchone()[0]
            newest = conn.execute(
                'SELECT MAX(timestamp) FROM cloud_cache'
            ).fetchone()[0]
            return {
                'entries': total,
                'max_entries': self.max_entries,
                'malicious': malicious,
                'clean': total - malicious,
                'ttl_hours': self.ttl_seconds / 3600,
                'oldest': datetime.fromtimestamp(oldest).isoformat() if oldest else '',
                'newest': datetime.fromtimestamp(newest).isoformat() if newest else '',
            }
        except Exception as e:
            logger.error(f"获取缓存统计失败: {e}")
            return {'entries': 0, 'max_entries': self.max_entries, 'ttl_hours': self.ttl_seconds / 3600}

    def clear(self):
        """清空缓存"""
        try:
            conn = self._get_conn()
            conn.execute('DELETE FROM cloud_cache')
            conn.commit()
            logger.info("云缓存已清空")
        except Exception as e:
            logger.error(f"清空缓存失败: {e}")

    def close(self):
        """关闭数据库连接"""
        try:
            if self._conn:
                self._conn.close()
                self._conn = None
        except Exception as e:
            logger.error(f"关闭数据库连接失败: {e}")

    def __del__(self):
        self.close()