#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
签名数据库管理 - SignatureDatabase
===================================

提供签名数据库的加载、保存、版本管理和增量更新功能。
签名数据以 JSON 格式存储，支持多级目录结构。

特性:
  - 加载/保存签名数据（JSON 格式）
  - 签名版本管理（版本号、发布时间、签名数量）
  - 增量更新支持（基于时间戳的差异更新）
  - 签名校验和验证
  - 签名分类统计
  - 签名导入/导出
  - 签名压缩存储

用法示例:
    db = SignatureDatabase()
    db.load('D:/Antivirus/data/signatures/latest.json')
    stats = db.get_statistics()
    print(f'总签名数: {stats["total"]}')
"""

import os
import json
import time
import gzip
import hashlib
import shutil
import threading
from typing import List, Dict, Optional, Tuple, Set, Any, Callable
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

from .. import ThreatType, ThreatLevel, ScanResult, SIGNATURE_VERSION


class SignatureDatabase:
    """签名数据库管理器

    管理签名数据的完整生命周期：加载、保存、版本控制、增量更新。

    属性:
        signatures: Dict[str, Dict] - 主签名数据 {hash: info}
        sha1_signatures: Dict[str, Dict] - SHA1 签名
        sha256_signatures: Dict[str, Dict] - SHA256 签名
        byte_patterns: List[Dict] - 字节序列特征
        yara_rules: List[Dict] - YARA 规则
        metadata: Dict - 数据库元信息
        version: str - 当前版本号
        _lock: threading.RLock - 线程安全锁
        _dirty: bool - 是否有未保存的修改
    """

    # 支持的签名格式版本
    FORMAT_VERSION = 2

    # 默认存路径
    DEFAULT_STORAGE = Path('D:/Antivirus/data/signatures')
    INDEX_FILE = 'signature_index.json'

    def __init__(self, storage_dir: Optional[str] = None):
        """初始化签名数据库

        Args:
            storage_dir: 签名数据存储目录，默认使用 D:/Antivirus/data/signatures
        """
        self.storage_dir = Path(storage_dir) if storage_dir else self.DEFAULT_STORAGE

        # 签名数据
        self.signatures: Dict[str, Dict] = {}          # MD5 签名
        self.sha1_signatures: Dict[str, Dict] = {}     # SHA1 签名
        self.sha256_signatures: Dict[str, Dict] = {}   # SHA256 签名
        self.byte_patterns: List[Dict] = []             # 字节序列
        self.yara_rules: List[Dict] = []                # YARA 规则

        # 元数据
        self.metadata: Dict[str, Any] = {
            'format_version': self.FORMAT_VERSION,
            'created_at': time.time(),
            'updated_at': time.time(),
            'version': SIGNATURE_VERSION,
            'signature_count': 0,
            'sha1_count': 0,
            'sha256_count': 0,
            'byte_pattern_count': 0,
            'yara_rule_count': 0,
            'checksum': '',
            'description': '天盾 Antivirus 签名数据库',
            'author': 'TianDun Security',
            'source': 'internal'
        }

        self.version = SIGNATURE_VERSION
        self._lock = threading.RLock()
        self._dirty = False

        # 更新历史
        self.update_history: List[Dict] = []

        # 确保存储目录存在
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    # ----------------------------------------------------------
    # 加载 / 保存
    # ----------------------------------------------------------

    def load(self, filepath: Optional[str] = None, merge: bool = False) -> int:
        """从 JSON 文件加载签名数据

        Args:
            filepath: JSON 文件路径，None 则从默认路径加载
            merge: 是否合并到现有数据（True）或替换（False）

        Returns:
            加载的签名总数
        """
        if filepath is None:
            # 从默认路径加载
            candidates = [
                self.storage_dir / 'signatures.json',
                self.storage_dir / 'signatures.json.gz',
                self.storage_dir / self.INDEX_FILE,
                self.storage_dir / 'latest.json',
            ]
            for cand in candidates:
                if cand.exists():
                    filepath = str(cand)
                    break

        if not filepath or not os.path.exists(filepath):
            raise FileNotFoundError(f'签名数据库文件不存在: {filepath}')

        with self._lock:
            # 读取数据
            raw_data = self._read_file(filepath)

            if not merge:
                # 替换模式
                self.signatures.clear()
                self.sha1_signatures.clear()
                self.sha256_signatures.clear()
                self.byte_patterns.clear()
                self.yara_rules.clear()

            # 解析数据
            count = 0
            if isinstance(raw_data, dict):
                # 新版格式（带元数据）
                if 'metadata' in raw_data:
                    self.metadata.update(raw_data['metadata'])
                    self.version = self.metadata.get('version', SIGNATURE_VERSION)

                if 'signatures' in raw_data:
                    self.signatures.update(raw_data['signatures'])
                    count += len(raw_data['signatures'])

                if 'sha1_signatures' in raw_data:
                    self.sha1_signatures.update(raw_data['sha1_signatures'])
                    count += len(raw_data['sha1_signatures'])

                if 'sha256_signatures' in raw_data:
                    self.sha256_signatures.update(raw_data['sha256_signatures'])
                    count += len(raw_data['sha256_signatures'])

                if 'byte_patterns' in raw_data:
                    self.byte_patterns.extend(raw_data['byte_patterns'])
                    count += len(raw_data['byte_patterns'])

                if 'yara_rules' in raw_data:
                    self.yara_rules.extend(raw_data['yara_rules'])
                    count += len(raw_data['yara_rules'])

            elif isinstance(raw_data, list):
                # 旧版格式（纯签名列表）
                for item in raw_data:
                    if isinstance(item, dict) and 'hash' in item:
                        self.signatures[item['hash']] = item
                        count += 1

            # 更新统计
            self._update_stats()
            self._dirty = False

            return count

    def save(self, filepath: Optional[str] = None, compress: bool = False) -> str:
        """保存签名数据到 JSON 文件

        Args:
            filepath: 保存路径，None 则使用默认路径
            compress: 是否 gzip 压缩

        Returns:
            保存的文件路径
        """
        if filepath is None:
            filename = 'signatures.json.gz' if compress else 'signatures.json'
            filepath = str(self.storage_dir / filename)

        with self._lock:
            self._update_stats()
            self.metadata['updated_at'] = time.time()
            self.metadata['checksum'] = self._compute_checksum()

            data = {
                'metadata': dict(self.metadata),
                'signatures': dict(self.signatures),
                'sha1_signatures': dict(self.sha1_signatures),
                'sha256_signatures': dict(self.sha256_signatures),
                'byte_patterns': list(self.byte_patterns),
                'yara_rules': list(self.yara_rules),
            }

            # 确保目录存在
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            # 写入文件
            if compress or filepath.endswith('.gz'):
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

            self._dirty = False
            return filepath

    def export_to_csv(self, filepath: str, hash_type: str = 'md5') -> int:
        """导出签名到 CSV 文件

        Args:
            filepath: 导出路径
            hash_type: hash 类型（md5, sha1, sha256）

        Returns:
            导出的行数
        """
        import csv

        db = self.signatures
        if hash_type == 'sha1':
            db = self.sha1_signatures
        elif hash_type == 'sha256':
            db = self.sha256_signatures

        fieldnames = ['hash', 'name', 'type', 'level', 'family', 'desc']

        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for hash_val, info in db.items():
                row = {
                    'hash': hash_val,
                    'name': info.get('name', ''),
                    'type': info.get('type', ''),
                    'level': info.get('level', ''),
                    'family': info.get('family', ''),
                    'desc': info.get('desc', ''),
                }
                writer.writerow(row)

        return len(db)

    def import_from_csv(self, filepath: str, hash_type: str = 'md5') -> int:
        """从 CSV 文件导入签名

        Args:
            filepath: CSV 文件路径
            hash_type: hash 类型

        Returns:
            导入的签名数
        """
        import csv

        count = 0
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                hash_val = row.get('hash', '').strip().lower()
                if not hash_val or len(hash_val) < 32:
                    continue

                info = {
                    'name': row.get('name', ''),
                    'type': row.get('type', ThreatType.UNKNOWN),
                    'level': int(row.get('level', ThreatLevel.MEDIUM)),
                    'family': row.get('family', ''),
                    'desc': row.get('desc', ''),
                }

                with self._lock:
                    if hash_type == 'sha1':
                        self.sha1_signatures[hash_val] = info
                    elif hash_type == 'sha256':
                        self.sha256_signatures[hash_val] = info
                    else:
                        self.signatures[hash_val] = info
                count += 1

        self._dirty = True
        self._update_stats()
        return count

    # ----------------------------------------------------------
    # 版本管理
    # ----------------------------------------------------------

    def set_version(self, version: str):
        """设置签名数据库版本号"""
        self.version = version
        self.metadata['version'] = version
        self._dirty = True

    def get_version(self) -> str:
        """获取当前版本号"""
        return self.version

    def compare_version(self, other_version: str) -> int:
        """比较版本号

        Args:
            other_version: 要比较的版本号

        Returns:
            1: 当前版本更新，0: 相同，-1: 当前版本更旧
        """
        parts_self = self.version.split('.')
        parts_other = other_version.split('.')

        for a, b in zip(parts_self, parts_other):
            try:
                if int(a) > int(b):
                    return 1
                elif int(a) < int(b):
                    return -1
            except ValueError:
                if a > b:
                    return 1
                elif a < b:
                    return -1

        if len(parts_self) > len(parts_other):
            return 1
        elif len(parts_self) < len(parts_other):
            return -1
        return 0

    # ----------------------------------------------------------
    # 增量更新
    # ----------------------------------------------------------

    def compute_diff(self, other: 'SignatureDatabase') -> Dict[str, Any]:
        """计算当前数据库与另一个数据库的差异

        Args:
            other: 另一个签名数据库实例

        Returns:
            {added: {...}, removed: {...}, modified: {...}}
        """
        diff = {
            'added': {},
            'removed': {},
            'modified': {},
        }

        # 找新增和修改的签名
        for hash_val, info in self.signatures.items():
            if hash_val not in other.signatures:
                diff['added'][hash_val] = info
            elif info != other.signatures[hash_val]:
                diff['modified'][hash_val] = {'old': other.signatures[hash_val], 'new': info}

        # 找删除的签名
        for hash_val in other.signatures:
            if hash_val not in self.signatures:
                diff['removed'][hash_val] = other.signatures[hash_val]

        return diff

    def apply_update(self, update_data: Dict[str, Any]) -> int:
        """应用增量更新

        Args:
            update_data: 更新数据，格式同 compute_diff 返回值

        Returns:
            更新的签名数量
        """
        count = 0
        with self._lock:
            # 新增签名
            for hash_val, info in update_data.get('added', {}).items():
                self.signatures[hash_val] = info
                count += 1

            # 删除签名
            for hash_val in update_data.get('removed', {}):
                if hash_val in self.signatures:
                    del self.signatures[hash_val]
                    count += 1

            # 修改签名
            for hash_val, change in update_data.get('modified', {}).items():
                if 'new' in change:
                    self.signatures[hash_val] = change['new']
                    count += 1

        self._dirty = True
        self._update_stats()
        return count

    def create_update_package(self, base_version: str, output_path: str) -> str:
        """创建增量更新包

        Args:
            base_version: 基础版本号
            output_path: 输出文件路径

        Returns:
            输出文件路径
        """
        # 加载基础版本数据库
        base_db = SignatureDatabase()
        base_path = self.storage_dir / f'signatures_{base_version}.json'
        if base_path.exists():
            base_db.load(str(base_path))
        else:
            raise FileNotFoundError(f'基础版本数据库未找到: {base_path}')

        # 计算差异
        diff = self.compute_diff(base_db)

        # 写入更新包
        update_package = {
            'base_version': base_version,
            'target_version': self.version,
            'created_at': time.time(),
            'diff': diff,
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(update_package, f, ensure_ascii=False, indent=2)

        return output_path

    # ----------------------------------------------------------
    # 查询 / 统计
    # ----------------------------------------------------------

    def query(self, hash_val: str) -> Optional[Dict]:
        """按哈希值查询签名

        Args:
            hash_val: MD5/SHA1/SHA256 哈希值

        Returns:
            签名信息字典，未找到返回 None
        """
        hash_val = hash_val.lower()
        # 按长度判断哈希类型
        return (
            self.signatures.get(hash_val) or
            self.sha1_signatures.get(hash_val) or
            self.sha256_signatures.get(hash_val)
        )

    def query_by_name(self, name: str, exact: bool = False) -> List[Tuple[str, Dict]]:
        """按名称查询签名

        Args:
            name: 病毒名称或关键词
            exact: 是否精确匹配

        Returns:
            [(hash, info), ...]
        """
        results = []
        name_lower = name.lower()

        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for hash_val, info in db.items():
                sig_name = info.get('name', '').lower()
                if exact:
                    if sig_name == name_lower:
                        results.append((hash_val, info))
                else:
                    if name_lower in sig_name:
                        results.append((hash_val, info))

        return results

    def query_by_family(self, family: str) -> List[Tuple[str, Dict]]:
        """按病毒家族查询签名"""
        results = []
        family_lower = family.lower()
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for hash_val, info in db.items():
                if info.get('family', '').lower() == family_lower:
                    results.append((hash_val, info))
        return results

    def query_by_type(self, threat_type: str) -> List[Tuple[str, Dict]]:
        """按威胁类型查询签名"""
        results = []
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for hash_val, info in db.items():
                if info.get('type', '') == threat_type:
                    results.append((hash_val, info))
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取签名统计信息"""
        self._update_stats()
        return {
            'version': self.version,
            'total_signatures': len(self.signatures),
            'sha1_count': len(self.sha1_signatures),
            'sha256_count': len(self.sha256_signatures),
            'byte_pattern_count': len(self.byte_patterns),
            'yara_rule_count': len(self.yara_rules),
            'total': (len(self.signatures) + len(self.sha1_signatures) +
                      len(self.sha256_signatures) + len(self.byte_patterns) +
                      len(self.yara_rules)),
            'type_distribution': self._get_type_distribution(),
            'level_distribution': self._get_level_distribution(),
            'family_distribution': self._get_family_distribution(),
            'last_updated': self.metadata.get('updated_at', 0),
            'checksum': self.metadata.get('checksum', ''),
        }

    def _get_type_distribution(self) -> Dict[str, int]:
        """获取按威胁类型的分布统计"""
        dist = defaultdict(int)
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for info in db.values():
                t = info.get('type', ThreatType.UNKNOWN)
                dist[t] += 1
        return dict(dist)

    def _get_level_distribution(self) -> Dict[str, int]:
        """获取按威胁等级的分布统计"""
        dist = defaultdict(int)
        level_names = {5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info', 0: 'none'}
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for info in db.values():
                lvl = info.get('level', ThreatLevel.MEDIUM)
                key = level_names.get(lvl, 'unknown')
                dist[key] += 1
        return dict(dist)

    def _get_family_distribution(self) -> Dict[str, int]:
        """获取按病毒家族的分布统计（Top 50）"""
        dist = defaultdict(int)
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for info in db.values():
                family = info.get('family', 'unknown')
                dist[family] += 1
        # 返回 Top 50
        return dict(sorted(dist.items(), key=lambda x: -x[1])[:50])

    # ----------------------------------------------------------
    # 签名管理
    # ----------------------------------------------------------

    def add_signature(self, hash_val: str, info: Dict, hash_type: str = 'md5') -> bool:
        """添加单条签名

        Args:
            hash_val: 哈希值
            info: 签名信息
            hash_type: 哈希类型（md5, sha1, sha256）

        Returns:
            是否成功添加
        """
        hash_val = hash_val.lower()
        with self._lock:
            if hash_type == 'sha1':
                self.sha1_signatures[hash_val] = info
            elif hash_type == 'sha256':
                self.sha256_signatures[hash_val] = info
            else:
                self.signatures[hash_val] = info
            self._dirty = True
        return True

    def remove_signature(self, hash_val: str) -> bool:
        """删除单条签名"""
        hash_val = hash_val.lower()
        with self._lock:
            removed = (
                self.signatures.pop(hash_val, None) or
                self.sha1_signatures.pop(hash_val, None) or
                self.sha256_signatures.pop(hash_val, None)
            )
            self._dirty = removed is not None
            return removed is not None

    def add_byte_pattern(self, pattern: Dict) -> bool:
        """添加字节序列特征"""
        with self._lock:
            self.byte_patterns.append(pattern)
            self._dirty = True
        return True

    def add_yara_rule(self, rule: Dict) -> bool:
        """添加 YARA 规则"""
        with self._lock:
            self.yara_rules.append(rule)
            self._dirty = True
        return True

    def merge(self, other: 'SignatureDatabase') -> int:
        """合并另一个签名数据库

        Args:
            other: 另一个数据库实例

        Returns:
            合并后的签名总数
        """
        count = 0
        with self._lock:
            # 合并 MD5
            for h, info in other.signatures.items():
                if h not in self.signatures:
                    self.signatures[h] = info
                    count += 1

            # 合并 SHA1
            for h, info in other.sha1_signatures.items():
                if h not in self.sha1_signatures:
                    self.sha1_signatures[h] = info
                    count += 1

            # 合并 SHA256
            for h, info in other.sha256_signatures.items():
                if h not in self.sha256_signatures:
                    self.sha256_signatures[h] = info
                    count += 1

            # 合并字节序列
            existing_patterns = {json.dumps(p, sort_keys=True) for p in self.byte_patterns}
            for p in other.byte_patterns:
                key = json.dumps(p, sort_keys=True)
                if key not in existing_patterns:
                    self.byte_patterns.append(p)
                    existing_patterns.add(key)
                    count += 1

            self._dirty = True
            self._update_stats()

        return count

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _update_stats(self):
        """更新统计信息"""
        self.metadata['signature_count'] = len(self.signatures)
        self.metadata['sha1_count'] = len(self.sha1_signatures)
        self.metadata['sha256_count'] = len(self.sha256_signatures)
        self.metadata['byte_pattern_count'] = len(self.byte_patterns)
        self.metadata['yara_rule_count'] = len(self.yara_rules)

    def _compute_checksum(self) -> str:
        """计算数据库校验和"""
        data = []
        for db in (self.signatures, self.sha1_signatures, self.sha256_signatures):
            for h in sorted(db.keys()):
                data.append(f'{h}:{json.dumps(db[h], sort_keys=True)}')

        combined = '|'.join(data)
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    def _read_file(self, filepath: str) -> Any:
        """读取文件（支持普通 JSON 和 gzip JSON）"""
        if filepath.endswith('.gz'):
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)

    def is_dirty(self) -> bool:
        """检查是否有未保存的修改"""
        return self._dirty

    def __len__(self) -> int:
        return (len(self.signatures) + len(self.sha1_signatures) +
                len(self.sha256_signatures) + len(self.byte_patterns) +
                len(self.yara_rules))

    def __repr__(self) -> str:
        return (f'SignatureDatabase(version={self.version}, '
                f'total={len(self)})')


# ============================================================
# 便捷函数
# ============================================================

def load_default_database() -> SignatureDatabase:
    """加载默认签名数据库"""
    db = SignatureDatabase()
    try:
        db.load()
    except FileNotFoundError:
        pass
    return db


def create_database_from_module(sig_module) -> SignatureDatabase:
    """从 signatures 模块创建签名数据库"""
    db = SignatureDatabase()

    if hasattr(sig_module, 'ALL_SIGNATURES'):
        db.signatures = dict(sig_module.ALL_SIGNATURES)

    if hasattr(sig_module, 'SHA1_SIGNATURES'):
        db.sha1_signatures = dict(sig_module.SHA1_SIGNATURES)

    if hasattr(sig_module, 'SHA256_SIGNATURES'):
        db.sha256_signatures = dict(sig_module.SHA256_SIGNATURES)

    if hasattr(sig_module, 'BYTE_PATTERNS'):
        db.byte_patterns = list(sig_module.BYTE_PATTERNS)

    if hasattr(sig_module, 'YARA_RULES'):
        db.yara_rules = list(sig_module.YARA_RULES)

    db._update_stats()
    return db