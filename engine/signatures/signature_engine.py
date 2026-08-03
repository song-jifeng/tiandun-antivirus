#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
特征码扫描引擎 - SignatureEngine
=================================

核心特征码扫描引擎，继承自 ScanEngine 基类。
支持多种特征码匹配方式：
  - MD5 / SHA1 / SHA256 哈希匹配
  - YARA 规则匹配
  - 字节序列匹配（支持通配符 ?? 和通配段）
  - 文件头部/尾部特征匹配
  - 分段扫描大文件

使用 mmap 高效读取文件，支持大文件分段扫描以防内存溢出。

用法示例:
    from engine.signatures import SignatureEngine
    engine = SignatureEngine()
    engine.load_all_signatures()
    result = engine.scan('/path/to/suspicious.exe')
    if result:
        print(f'发现威胁: {result.threat_name}')
"""

import os
import re
import mmap
import struct
import threading
from typing import List, Dict, Optional, Tuple, Set, Any, Callable
from pathlib import Path

from .. import ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel, HashUtil
from . import signatures_ext
from . import signatures_ext2

# SQLite-backed lazy-loading signature database
from .signature_db_manager import SignatureDBManager


class BytePattern:
    """字节序列匹配模式

    支持格式:
        - 原始字节: b'\x90\x90\x90'
        - 十六进制字符串: '90 90 90 ?? 90' (?? 表示通配)
        - 通配符: ? 或 ?? 匹配任意字节
        - 通配段: [N-N] 或 [N] 匹配重复字节
    """

    def __init__(self, pattern: str, offset: int = 0, wildcard: bytes = b'?'):
        """初始化字节模式

        Args:
            pattern: 十六进制模式字符串，如 'E8 ?? ?? ?? ?? 00'
            offset: 搜索起始偏移（0=整个文件, -1=从尾部, 正数=从头部）
            wildcard: 通配符字节
        """
        self.raw_pattern = pattern
        self.offset = offset
        self.wildcard = wildcard
        self._compiled: Optional[bytes] = None
        self._mask: Optional[bytes] = None
        self._compile()

    def _compile(self):
        """编译模式为字节掩码对"""
        # 解析十六进制模式
        hex_str = self.raw_pattern.replace(' ', '')
        compiled = bytearray()
        mask = bytearray()

        i = 0
        while i < len(hex_str):
            if hex_str[i] == '?' or hex_str[i] == '*':
                # 通配符
                compiled.append(0x00)
                mask.append(0x00)
                # 跳过连续的 ?
                while i < len(hex_str) and (hex_str[i] == '?' or hex_str[i] == '*'):
                    i += 1
            else:
                # 十六进制字节
                if i + 1 < len(hex_str):
                    try:
                        byte_val = int(hex_str[i:i+2], 16)
                        compiled.append(byte_val)
                        mask.append(0xFF)
                        i += 2
                    except ValueError:
                        i += 1
                else:
                    i += 1

        self._compiled = bytes(compiled)
        self._mask = bytes(mask)

    def match(self, data: bytes, offset: int = 0) -> Optional[int]:
        """在数据中查找模式

        Args:
            data: 要搜索的字节数据
            offset: 搜索起始位置

        Returns:
            匹配位置索引，未找到返回 None
        """
        if not self._compiled or len(self._compiled) == 0:
            return None

        # 如果全是通配符，匹配任何位置
        if all(b == 0x00 for b in self._mask):
            return offset

        pattern_len = len(self._compiled)
        search_start = offset

        # 调整搜索范围
        if self.offset > 0:
            search_start = min(self.offset, len(data) - pattern_len)
        elif self.offset < 0:
            search_start = max(0, len(data) + self.offset)

        search_end = len(data) - pattern_len + 1
        if search_end <= search_start:
            return None

        # 逐字节匹配
        for i in range(search_start, search_end):
            found = True
            for j in range(pattern_len):
                if self._mask[j] == 0x00:
                    continue  # 通配符，跳过比较
                if data[i + j] != self._compiled[j]:
                    found = False
                    break
            if found:
                return i

        return None

    def __repr__(self) -> str:
        return f"BytePattern('{self.raw_pattern}', offset={self.offset})"


class YaraPattern:
    """YARA 规则模式（简化版，与 yara_engine 配合使用）"""

    def __init__(self, rule_id: str, rule_source: str):
        self.rule_id = rule_id
        self.rule_source = rule_source
        self.compiled_patterns: List[BytePattern] = []
        self._parse_rule()

    def _parse_rule(self):
        """从规则源码中提取字符串模式"""
        # 提取 $ = 之间的十六进制模式
        hex_patterns = re.findall(r'\{([\s\dA-Fa-f\?]+)\}', self.rule_source)
        for hp in hex_patterns:
            cleaned = hp.strip().replace('\n', ' ').replace('\r', '')
            if cleaned:
                self.compiled_patterns.append(BytePattern(cleaned))

    def match(self, data: bytes) -> bool:
        """检查数据是否匹配此规则"""
        for pattern in self.compiled_patterns:
            if pattern.match(data) is not None:
                return True
        return False


class SignatureEngine(ScanEngine):
    """特征码扫描引擎

    继承自 ScanEngine，提供完整的特征码检测能力。
    支持哈希匹配、字节序列匹配、YARA规则匹配。
    使用 mmap 高效读取文件，支持大文件分段扫描。

    属性:
        md5_db: Dict[str, ThreatInfo] - MD5 签名数据库
        sha1_db: Dict[str, ThreatInfo] - SHA1 签名数据库
        sha256_db: Dict[str, ThreatInfo] - SHA256 签名数据库
        byte_patterns: List[Tuple[BytePattern, ThreatInfo]] - 字节序列特征库
        yara_rules: List[YaraPattern] - YARA 规则库
        file_sigs: Dict[str, List[Tuple[BytePattern, ThreatInfo]]] - 按文件类型的特征
        head_sigs: List[Tuple[BytePattern, ThreatInfo]] - 文件头部特征
        tail_sigs: List[Tuple[BytePattern, ThreatInfo]] - 文件尾部特征
        _lock: threading.RLock - 线程安全锁
        _scan_chunk_size: int - 分段扫描块大小（默认 4MB）
    """

    # 常见恶意文件头部特征
    _KNOWN_MALICIOUS_HEADS = {
        b'MZ': ('PE文件头', ThreatType.VIRUS),
        b'\x7fELF': ('ELF文件头', ThreatType.VIRUS),
    }

    def __init__(self, name: str = 'signature', enabled: bool = True,
                 use_sqlite: Optional[bool] = None):
        """初始化特征码引擎

        Args:
            name: 引擎名称
            enabled: 是否启用
            use_sqlite: 是否使用 SQLite 惰性加载。
                        True=使用SQLite，不加载ext文件到内存。
                        False=传统模式，全部加载到内存。
                        None=自动检测（优先使用SQLite，如果数据库存在且已验证签名>0）
        """
        super().__init__(name, enabled)

        # 签名数据库
        self.md5_db: Dict[str, ThreatInfo] = {}
        self.sha1_db: Dict[str, ThreatInfo] = {}
        self.sha256_db: Dict[str, ThreatInfo] = {}

        # 字节序列特征库
        self.byte_patterns: List[Tuple[BytePattern, ThreatInfo]] = []
        self.head_sigs: List[Tuple[BytePattern, ThreatInfo]] = []  # 头部特征
        self.tail_sigs: List[Tuple[BytePattern, ThreatInfo]] = []  # 尾部特征

        # 按文件类型分类的特征
        self.file_sigs: Dict[str, List[Tuple[BytePattern, ThreatInfo]]] = {}

        # YARA 规则
        self.yara_rules: List[YaraPattern] = []

        # 线程安全
        self._lock = threading.RLock()

        # 分段扫描参数
        self._scan_chunk_size = 4 * 1024 * 1024  # 4MB
        self._max_file_size = 500 * 1024 * 1024   # 500MB 限制

        # 缓存
        self._hash_cache: Dict[str, Dict[str, str]] = {}
        self._cache_lock = threading.RLock()
        self._cache_max = 10000

        # SQLite 惰性加载支持
        self._use_sqlite = use_sqlite
        self._db_manager: Optional[SignatureDBManager] = None
        self._sqlite_available = False
        self._signatures_loaded = False  # 跟踪是否已加载签名

    # ----------------------------------------------------------
    # 签名数据库管理
    # ----------------------------------------------------------

    def load_md5_signatures(self, signatures: Dict[str, Dict]) -> int:
        """加载 MD5 签名

        Args:
            signatures: {md5_hash: {name, type, level, desc, family, ...}}

        Returns:
            加载的签名数量
        """
        count = 0
        with self._lock:
            for md5_hash, info in signatures.items():
                if len(md5_hash) == 32 and all(c in '0123456789abcdef' for c in md5_hash.lower()):
                    threat = self._dict_to_threatinfo(info, md5_hash)
                    self.md5_db[md5_hash.lower()] = threat
                    count += 1
        return count

    def load_sha1_signatures(self, signatures: Dict[str, Dict]) -> int:
        """加载 SHA1 签名"""
        count = 0
        with self._lock:
            for sha1_hash, info in signatures.items():
                if len(sha1_hash) == 40 and all(c in '0123456789abcdef' for c in sha1_hash.lower()):
                    threat = self._dict_to_threatinfo(info, sha1_hash)
                    self.sha1_db[sha1_hash.lower()] = threat
                    count += 1
        return count

    def load_sha256_signatures(self, signatures: Dict[str, Dict]) -> int:
        """加载 SHA256 签名"""
        count = 0
        with self._lock:
            for sha256_hash, info in signatures.items():
                if len(sha256_hash) == 64 and all(c in '0123456789abcdef' for c in sha256_hash.lower()):
                    threat = self._dict_to_threatinfo(info, sha256_hash)
                    self.sha256_db[sha256_hash.lower()] = threat
                    count += 1
        return count

    def load_byte_patterns(self, patterns: List[Dict]) -> int:
        """加载字节序列特征

        Args:
            patterns: [{pattern, name, type, level, desc, family, offset, file_type}, ...]

        Returns:
            加载的特征数量
        """
        count = 0
        with self._lock:
            for item in patterns:
                try:
                    bp = BytePattern(
                        item.get('pattern', ''),
                        offset=item.get('offset', 0)
                    )
                    threat = ThreatInfo(
                        file_path='',
                        threat_type=item.get('type', ThreatType.UNKNOWN),
                        threat_name=item.get('name', ''),
                        threat_level=item.get('level', ThreatLevel.MEDIUM),
                        result=ScanResult.MALICIOUS
                    )
                    threat.details = {
                        'desc': item.get('desc', ''),
                        'family': item.get('family', ''),
                        'pattern': item.get('pattern', ''),
                        'engine': 'byte_pattern'
                    }

                    # 按位置分类
                    offset_val = item.get('offset', 0)
                    if offset_val == 0:
                        self.head_sigs.append((bp, threat))
                    elif offset_val == -1:
                        self.tail_sigs.append((bp, threat))
                    else:
                        self.byte_patterns.append((bp, threat))

                    # 按文件类型分类
                    file_type = item.get('file_type', '')
                    if file_type:
                        if file_type not in self.file_sigs:
                            self.file_sigs[file_type] = []
                        self.file_sigs[file_type].append((bp, threat))

                    count += 1
                except Exception:
                    continue
        return count

    def load_yara_rules(self, rules: List[Dict]) -> int:
        """加载 YARA 规则

        Args:
            rules: [{rule_id, rule_source, name, type, level, ...}, ...]
        """
        count = 0
        with self._lock:
            for item in rules:
                try:
                    yr = YaraPattern(
                        rule_id=item.get('rule_id', ''),
                        rule_source=item.get('rule_source', '')
                    )
                    # 为规则关联威胁信息
                    yr._threat_info = ThreatInfo(
                        file_path='',
                        threat_type=item.get('type', ThreatType.UNKNOWN),
                        threat_name=item.get('name', ''),
                        threat_level=item.get('level', ThreatLevel.MEDIUM),
                        result=ScanResult.MALICIOUS
                    )
                    yr._threat_info.details = {
                        'desc': item.get('desc', ''),
                        'family': item.get('family', ''),
                        'rule_id': item.get('rule_id', ''),
                        'engine': 'yara'
                    }
                    self.yara_rules.append(yr)
                    count += 1
                except Exception:
                    continue
        return count

    def load_from_sqlite(self) -> Dict[str, int]:
        """从 SQLite 数据库惰性加载签名

        仅加载 signatures.py 中的小规模签名（22K 条）到内存作为快速查找。
        对于 ext 文件中的大量签名（300K+ 条），查询 SQLite 按需获取，
        避免全部加载到内存中。

        Returns:
            {md5: N, sha1: N, sha256: N, sqlite_total: N, sqlite_verified: N}
        """
        stats = {}

        # 1. 加载 signatures.py 中的小规模签名到内存 (快速查找)
        from . import signatures as sig_module

        if hasattr(sig_module, 'ALL_SIGNATURES'):
            stats['md5'] = self.load_md5_signatures(sig_module.ALL_SIGNATURES)

        if hasattr(sig_module, 'SHA1_SIGNATURES'):
            stats['sha1'] = self.load_sha1_signatures(sig_module.SHA1_SIGNATURES)

        if hasattr(sig_module, 'SHA256_SIGNATURES'):
            stats['sha256'] = self.load_sha256_signatures(sig_module.SHA256_SIGNATURES)

        # 加载字节序列特征（较小，可以接受）
        if hasattr(sig_module, 'BYTE_PATTERNS'):
            stats['byte_patterns'] = self.load_byte_patterns(sig_module.BYTE_PATTERNS)

        # 加载 YARA 规则（较小）
        if hasattr(sig_module, 'YARA_RULES'):
            stats['yara_rules'] = self.load_yara_rules(sig_module.YARA_RULES)

        # 2. 初始化 SQLite 连接
        self._db_manager = SignatureDBManager()
        if self._db_manager.initialize():
            self._sqlite_available = True
            db_stats = self._db_manager.get_stats()
            stats['sqlite_total'] = db_stats['total_signatures']
            stats['sqlite_verified'] = db_stats['verified_count']

            # 仅当 SQLite 中有签名时才标记为可用
            if db_stats['total_signatures'] > 0:
                self._use_sqlite = True
            else:
                # SQLite 数据库存在但为空，需要转换
                print(f"[SignatureEngine] SQLite database is empty. "
                      f"Run 'python tools/convert_signatures_to_sqlite.py' to populate it.")
                self._use_sqlite = False
        else:
            self._sqlite_available = False
            self._use_sqlite = False
            stats['sqlite_total'] = 0
            stats['sqlite_verified'] = 0
            print(f"[SignatureEngine] SQLite database not available, "
                  f"falling back to in-memory loading for all signatures.")

        self._signatures_loaded = True
        return stats

    def load_all_signatures(self, use_sqlite: Optional[bool] = None) -> Dict[str, int]:
        """加载所有签名数据

        SQLite 模式（推荐）：
            - 加载 signatures.py 中的小规模签名（22K 条）到内存
            - 从 SQLite 数据库按需查询 ext 文件中的签名（300K+ 条）
            - 内存占用：~5MB 而不是 300-500MB

        传统模式（use_sqlite=False）：
            - 加载所有签名到内存（兼容旧行为）
            - 内存占用：300-500MB

        Args:
            use_sqlite: True=使用SQLite惰性加载，False=传统模式全部加载到内存，
                       None=自动检测（优先使用SQLite）

        Returns:
            {md5: N, sha1: N, sha256: N, byte_patterns: N, yara_rules: N, ...}
        """
        if use_sqlite is not None:
            self._use_sqlite = use_sqlite

        # 如果启用 SQLite，使用惰性加载模式
        if self._use_sqlite is not False:
            return self.load_from_sqlite()

        # 传统模式：全部加载到内存
        from . import signatures as sig_module

        stats = {}

        # 加载 MD5 签名
        if hasattr(sig_module, 'ALL_SIGNATURES'):
            stats['md5'] = self.load_md5_signatures(sig_module.ALL_SIGNATURES)

        # 加载 SHA1 签名
        if hasattr(sig_module, 'SHA1_SIGNATURES'):
            stats['sha1'] = self.load_sha1_signatures(sig_module.SHA1_SIGNATURES)

        # 加载 SHA256 签名
        if hasattr(sig_module, 'SHA256_SIGNATURES'):
            stats['sha256'] = self.load_sha256_signatures(sig_module.SHA256_SIGNATURES)

        # 加载字节序列特征
        if hasattr(sig_module, 'BYTE_PATTERNS'):
            stats['byte_patterns'] = self.load_byte_patterns(sig_module.BYTE_PATTERNS)

        # 加载 YARA 规则
        if hasattr(sig_module, 'YARA_RULES'):
            stats['yara_rules'] = self.load_yara_rules(sig_module.YARA_RULES)

        # Load from signatures_ext (63,000 entries with SHA1/SHA256)
        if hasattr(signatures_ext, 'EXTENDED_SIGNATURES'):
            ext_count = {'md5': 0, 'sha1': 0, 'sha256': 0}
            for entry in signatures_ext.EXTENDED_SIGNATURES:
                try:
                    md5 = entry.get('md5', '').lower()
                    sha1 = entry.get('sha1', '').lower()
                    sha256 = entry.get('sha256', '').lower()
                    if md5 and len(md5) == 32 and all(c in '0123456789abcdef' for c in md5):
                        if md5 not in self.md5_db:
                            threat = self._dict_to_threatinfo(entry, md5)
                            self.md5_db[md5] = threat
                            ext_count['md5'] += 1
                    if sha1 and len(sha1) == 40 and all(c in '0123456789abcdef' for c in sha1):
                        if sha1 not in self.sha1_db:
                            threat = self._dict_to_threatinfo(entry, sha1)
                            self.sha1_db[sha1] = threat
                            ext_count['sha1'] += 1
                    if sha256 and len(sha256) == 64 and all(c in '0123456789abcdef' for c in sha256):
                        if sha256 not in self.sha256_db:
                            threat = self._dict_to_threatinfo(entry, sha256)
                            self.sha256_db[sha256] = threat
                            ext_count['sha256'] += 1
                except Exception:
                    continue
            stats['ext_md5'] = ext_count['md5']
            stats['ext_sha1'] = ext_count['sha1']
            stats['ext_sha256'] = ext_count['sha256']

        # Load from signatures_ext2 (240,700 entries)
        if hasattr(signatures_ext2, 'SIGNATURES_PART3'):
            ext2_count = {'md5': 0, 'sha1': 0, 'sha256': 0}
            for entry in signatures_ext2.SIGNATURES_PART3:
                try:
                    md5 = entry.get('md5', '').lower()
                    sha1 = entry.get('sha1', '').lower()
                    sha256 = entry.get('sha256', '').lower()
                    if md5 and len(md5) == 32 and all(c in '0123456789abcdef' for c in md5):
                        if md5 not in self.md5_db:
                            threat = self._dict_to_threatinfo(entry, md5)
                            self.md5_db[md5] = threat
                            ext2_count['md5'] += 1
                    if sha1 and len(sha1) == 40 and all(c in '0123456789abcdef' for c in sha1):
                        if sha1 not in self.sha1_db:
                            threat = self._dict_to_threatinfo(entry, sha1)
                            self.sha1_db[sha1] = threat
                            ext2_count['sha1'] += 1
                    if sha256 and len(sha256) == 64 and all(c in '0123456789abcdef' for c in sha256):
                        if sha256 not in self.sha256_db:
                            threat = self._dict_to_threatinfo(entry, sha256)
                            self.sha256_db[sha256] = threat
                            ext2_count['sha256'] += 1
                except Exception:
                    continue
            stats['ext2_md5'] = ext2_count['md5']
            stats['ext2_sha1'] = ext2_count['sha1']
            stats['ext2_sha256'] = ext2_count['sha256']

        self._signatures_loaded = True
        return stats

    def configure_sqlite(self, use_sqlite: bool = True) -> bool:
        """配置是否使用 SQLite 惰性加载

        Args:
            use_sqlite: True=惰性加载（低内存），False=全部加载到内存

        Returns:
            SQLite 是否可用
        """
        self._use_sqlite = use_sqlite
        if use_sqlite:
            if not self._sqlite_available:
                # 尝试初始化 SQLite
                self._db_manager = SignatureDBManager()
                if self._db_manager.initialize():
                    self._sqlite_available = True
                    if self._db_manager.get_total_count() > 0:
                        return True
                    else:
                        print(f"[SignatureEngine] SQLite database is empty.")
                        return False
                else:
                    return False
            return True
        return True

    def get_sqlite_stats(self) -> Optional[Dict[str, Any]]:
        """获取 SQLite 数据库统计信息

        Returns:
            SQLite 统计字典，或 None（如果不可用）
        """
        if self._db_manager and self._sqlite_available:
            return self._db_manager.get_stats()
        return None

    def clear_signatures(self):
        """清除所有已加载的签名"""
        with self._lock:
            self.md5_db.clear()
            self.sha1_db.clear()
            self.sha256_db.clear()
            self.byte_patterns.clear()
            self.head_sigs.clear()
            self.tail_sigs.clear()
            self.file_sigs.clear()
            self.yara_rules.clear()
            self._hash_cache.clear()

    def get_signature_count(self) -> Dict[str, int]:
        """获取签名数量统计"""
        with self._lock:
            return {
                'md5': len(self.md5_db),
                'sha1': len(self.sha1_db),
                'sha256': len(self.sha256_db),
                'byte_patterns': len(self.byte_patterns) + len(self.head_sigs) + len(self.tail_sigs),
                'yara_rules': len(self.yara_rules),
                'total': (len(self.md5_db) + len(self.sha1_db) + len(self.sha256_db) +
                          len(self.byte_patterns) + len(self.head_sigs) + len(self.tail_sigs) +
                          len(self.yara_rules))
            }

    # ----------------------------------------------------------
    # 核心扫描方法
    # ----------------------------------------------------------

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """扫描单个文件

        按以下顺序检测：
        1. 文件存在性检查
        2. 文件大小限制检查
        3. 哈希匹配（MD5 -> SHA1 -> SHA256）
        4. 文件头部特征匹配
        5. 文件尾部特征匹配
        6. 全文字节序列匹配
        7. YARA 规则匹配

        Args:
            filepath: 待扫描文件路径

        Returns:
            发现威胁返回 ThreatInfo，否则返回 None
        """
        if not os.path.isfile(filepath):
            return None

        start_time = __import__('time').time()

        try:
            file_size = os.path.getsize(filepath)

            # 跳过空文件和超大文件
            if file_size == 0:
                return None
            if file_size > self._max_file_size:
                # 超大文件仍尝试分段扫描
                return self._scan_large_file(filepath, file_size, start_time)

            # 计算哈希并匹配
            result = self._scan_by_hash(filepath)
            if result:
                result.file_path = filepath
                self.stats['detected'] += 1
                self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
                return result

            # 字节序列匹配（使用 mmap）
            result = self._scan_by_pattern(filepath, file_size)
            if result:
                result.file_path = filepath
                self.stats['detected'] += 1
                self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
                return result

            self.stats['scanned'] += 1
            self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
            return None

        except Exception as e:
            self.stats['errors'] += 1
            self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
            return None

    def _scan_by_hash(self, filepath: str) -> Optional[ThreatInfo]:
        """通过哈希匹配检测文件

        先检查缓存，再计算哈希。
        匹配顺序：MD5 -> SHA1 -> SHA256（速度由快到慢）

        如果内存中未找到，且 SQLite 模式已启用，则回退到 SQLite 查询。
        """
        # 检查缓存
        with self._cache_lock:
            if filepath in self._hash_cache:
                cached = self._hash_cache[filepath]
                md5_val = cached.get('md5', '')
                sha1_val = cached.get('sha1', '')
                sha256_val = cached.get('sha256', '')
            else:
                md5_val = sha1_val = sha256_val = ''

        if not md5_val:
            md5_val = HashUtil.md5_file(filepath)

        # MD5 匹配（最快）
        if md5_val:
            with self._lock:
                if md5_val in self.md5_db:
                    return self.md5_db[md5_val]

            # SQLite 回退：内存中未找到，查询 SQLite 数据库
            if self._use_sqlite and self._sqlite_available:
                result = self._db_manager.lookup_by_md5(md5_val)
                if result:
                    return self._sqlite_row_to_threatinfo(result, md5_val)

        # SHA1 匹配
        if not sha1_val:
            sha1_val = HashUtil.sha1_file(filepath)
        if sha1_val:
            with self._lock:
                if sha1_val in self.sha1_db:
                    return self.sha1_db[sha1_val]

            # SQLite 回退
            if self._use_sqlite and self._sqlite_available:
                result = self._db_manager.lookup_by_sha1(sha1_val)
                if result:
                    return self._sqlite_row_to_threatinfo(result, sha1_val)

        # SHA256 匹配（最慢）
        if not sha256_val:
            sha256_val = HashUtil.sha256_file(filepath)
        if sha256_val:
            with self._lock:
                if sha256_val in self.sha256_db:
                    return self.sha256_db[sha256_val]

            # SQLite 回退
            if self._use_sqlite and self._sqlite_available:
                result = self._db_manager.lookup_by_sha256(sha256_val)
                if result:
                    return self._sqlite_row_to_threatinfo(result, sha256_val)

        # 写入缓存
        if filepath not in self._hash_cache:
            with self._cache_lock:
                if len(self._hash_cache) < self._cache_max:
                    self._hash_cache[filepath] = {
                        'md5': md5_val,
                        'sha1': sha1_val,
                        'sha256': sha256_val,
                    }

        return None

    def _scan_by_pattern(self, filepath: str, file_size: int) -> Optional[ThreatInfo]:
        """通过字节序列匹配检测文件（使用 mmap）"""
        if not self.byte_patterns and not self.head_sigs and not self.tail_sigs and not self.yara_rules:
            return None

        try:
            with open(filepath, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # 文件头部特征匹配（前 1KB 或更少）
                    if self.head_sigs and file_size > 0:
                        head_data = mm[:min(file_size, 4096)]
                        for bp, threat in self.head_sigs:
                            if bp.match(head_data) is not None:
                                return threat

                    # 文件尾部特征匹配（最后 1KB）
                    if self.tail_sigs and file_size > 4096:
                        tail_data = mm[-4096:]
                        for bp, threat in self.tail_sigs:
                            if bp.match(tail_data) is not None:
                                return threat

                    # 全文匹配（小文件全量，大文件分段）
                    if self.byte_patterns or self.yara_rules:
                        result = self._scan_patterns_full(mm, file_size)
                        if result:
                            return result
        except Exception:
            pass

        return None

    def _scan_patterns_full(self, mm: mmap.mmap, file_size: int) -> Optional[ThreatInfo]:
        """全量模式匹配（支持分段）"""
        if file_size <= self._scan_chunk_size:
            # 小文件全量读取
            data = mm.read()
            return self._match_patterns(data)
        else:
            # 大文件分段扫描
            return self._scan_chunked(mm, file_size)

    def _scan_chunked(self, mm: mmap.mmap, file_size: int) -> Optional[ThreatInfo]:
        """分段扫描大文件

        将大文件分成多个重叠的块扫描，防止内存溢出。
        块之间有 50% 重叠以确保跨块特征不被漏掉。
        """
        overlap = self._scan_chunk_size // 2
        pos = 0

        while pos < file_size:
            chunk_size = min(self._scan_chunk_size, file_size - pos)
            mm.seek(pos)
            data = mm.read(chunk_size + overlap)  # 多读重叠部分
            result = self._match_patterns(data)
            if result:
                return result
            pos += chunk_size

        return None

    def _match_patterns(self, data: bytes) -> Optional[ThreatInfo]:
        """在数据中匹配所有字节序列和 YARA 规则"""
        # 字节序列匹配
        for bp, threat in self.byte_patterns:
            if bp.match(data) is not None:
                return threat

        # YARA 规则匹配
        for yr in self.yara_rules:
            if yr.match(data):
                if hasattr(yr, '_threat_info') and yr._threat_info:
                    return yr._threat_info
                # 创建基本威胁信息
                ti = ThreatInfo(
                    file_path='',
                    threat_type=ThreatType.UNKNOWN,
                    threat_name=f'YARA:{yr.rule_id}',
                    threat_level=ThreatLevel.MEDIUM,
                    result=ScanResult.MALICIOUS
                )
                ti.details = {'rule_id': yr.rule_id, 'engine': 'yara'}
                return ti

        return None

    def _scan_large_file(self, filepath: str, file_size: int, start_time: float) -> Optional[ThreatInfo]:
        """扫描超大文件（仅哈希匹配，避免 mmap 超大文件）"""
        # 仅使用哈希匹配
        result = self._scan_by_hash(filepath)
        if result:
            result.file_path = filepath
            self.stats['detected'] += 1
            self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
            return result

        # 尝试分段读取头部和尾部做模式匹配
        try:
            with open(filepath, 'rb') as f:
                # 读取头部 4MB
                head_data = f.read(self._scan_chunk_size)
                result = self._match_patterns(head_data)
                if result:
                    result.file_path = filepath
                    self.stats['detected'] += 1
                    self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
                    return result

                # 读取尾部 4MB
                if file_size > self._scan_chunk_size:
                    f.seek(-self._scan_chunk_size, 2)
                    tail_data = f.read(self._scan_chunk_size)
                    result = self._match_patterns(tail_data)
                    if result:
                        result.file_path = filepath
                        self.stats['detected'] += 1
                        self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
                        return result
        except Exception:
            pass

        self.stats['scanned'] += 1
        self.stats['time_ms'] = int((__import__('time').time() - start_time) * 1000)
        return None

    # ----------------------------------------------------------
    # 辅助方法
    # ----------------------------------------------------------

    def _dict_to_threatinfo(self, info: Dict, hash_val: str = '') -> ThreatInfo:
        """将字典转换为 ThreatInfo 对象"""
        threat = ThreatInfo(
            file_path='',
            threat_type=info.get('type', info.get('threat_type', ThreatType.UNKNOWN)),
            threat_name=info.get('name', info.get('threat_name', '')),
            threat_level=info.get('level', info.get('threat_level', ThreatLevel.MEDIUM)),
            result=info.get('result', ScanResult.MALICIOUS)
        )
        threat.details = {
            'desc': info.get('desc', info.get('description', '')),
            'family': info.get('family', ''),
            'hash': hash_val,
            'engine': 'hash'
        }
        return threat

    def _sqlite_row_to_threatinfo(self, row: Dict, hash_val: str = '') -> ThreatInfo:
        """将 SQLite 行字典转换为 ThreatInfo 对象"""
        threat = ThreatInfo(
            file_path='',
            threat_type=row.get('threat_type', ThreatType.UNKNOWN),
            threat_name=row.get('name', ''),
            threat_level=int(row.get('level', ThreatLevel.MEDIUM)),
            result=ScanResult.MALICIOUS
        )
        threat.details = {
            'desc': row.get('description', ''),
            'family': row.get('family', ''),
            'hash': hash_val,
            'source': row.get('source', 'sqlite'),
            'is_verified': row.get('is_verified', 0),
            'engine': 'hash'
        }
        return threat

    def scan_batch(self, filepaths: List[str]) -> List[ThreatInfo]:
        """批量扫描文件，覆盖基类方法

        支持多线程加速（当文件数量较多时）。
        """
        if len(filepaths) < 10:
            return super().scan_batch(filepaths)

        # 多线程批量扫描
        results = []
        threads = []
        result_lock = threading.Lock()

        def _scan_file(fp: str):
            try:
                r = self.scan(fp)
                if r:
                    with result_lock:
                        results.append(r)
            except Exception:
                pass

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(8, len(filepaths))) as executor:
            list(executor.map(_scan_file, filepaths))

        return results


# ============================================================
# 便捷函数
# ============================================================

def create_default_engine(use_sqlite: bool = True) -> SignatureEngine:
    """创建并初始化默认特征码引擎

    Args:
        use_sqlite: 是否使用 SQLite 惰性加载（低内存模式）。
                    True=仅加载小签名到内存，大签名通过 SQLite 按需查询。

    Returns:
        初始化后的 SignatureEngine 实例
    """
    engine = SignatureEngine(use_sqlite=use_sqlite)
    engine.load_all_signatures()
    return engine


def quick_scan_file(filepath: str) -> Optional[ThreatInfo]:
    """快速扫描单个文件（使用默认引擎）"""
    engine = create_default_engine()
    return engine.scan(filepath)


def quick_scan_batch(filepaths: List[str]) -> List[ThreatInfo]:
    """批量扫描文件（使用默认引擎）"""
    engine = create_default_engine()
    return engine.scan_batch(filepaths)