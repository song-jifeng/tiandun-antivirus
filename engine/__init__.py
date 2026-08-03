#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 核心引擎包
五大核心能力：特征码查杀、启发式分析、行为检测、云查杀、主动防御(HIPS)
"""
__version__ = '1.0.0'
__author__ = 'TianDun Security'
__build__ = '2026.08.03'

import os
import sys
import time
import json
import hashlib
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Callable, Any

# ============================================================
# 全局常量
# ============================================================
PROJECT_ROOT = Path(os.environ.get('TIANDUN_ROOT', 'D:/Antivirus'))
ENGINE_VERSION = '1.0.0.20260803'
SIGNATURE_VERSION = '2026.08.03'
QUARANTINE_DIR = PROJECT_ROOT / 'quarantine'
LOGS_DIR = PROJECT_ROOT / 'logs'
SIGNATURES_DIR = PROJECT_ROOT / 'engine' / 'signatures'

# ============================================================
# 扫描结果枚举
# ============================================================
class ScanResult:
    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    ERROR = -1
    UNKNOWN = -2

    NAMES = {
        CLEAN: '安全',
        SUSPICIOUS: '可疑',
        MALICIOUS: '恶意',
        ERROR: '错误',
        UNKNOWN: '未知'
    }

# ============================================================
# 威胁类型分类
# ============================================================
class ThreatType:
    VIRUS = 'virus'             # 传统病毒
    WORM = 'worm'               # 蠕虫
    TROJAN = 'trojan'           # 木马
    RANSOMWARE = 'ransomware'   # 勒索病毒
    SPYWARE = 'spyware'         # 间谍软件
    ADWARE = 'adware'           # 广告软件
    ROOTKIT = 'rootkit'         # Rootkit
    KEYLOGGER = 'keylogger'     # 键盘记录器
    MINER = 'miner'             # 挖矿病毒
    DOWNLOADER = 'downloader'   # 下载器
    BACKDOOR = 'backdoor'       # 后门
    WORMMACRO = 'worm_macro'    # 宏病毒
    PUP = 'pup'                 # 潜在不受欢迎程序
    HEURISTIC = 'heuristic'     # 启发式检测
    BEHAVIOR = 'behavior'       # 行为检测
    UNKNOWN = 'unknown'

    NAMES = {
        VIRUS: '传统病毒', WORM: '蠕虫', TROJAN: '木马',
        RANSOMWARE: '勒索病毒', SPYWARE: '间谍软件', ADWARE: '广告软件',
        ROOTKIT: 'Rootkit', KEYLOGGER: '键盘记录器', MINER: '挖矿病毒',
        DOWNLOADER: '下载器', BACKDOOR: '后门', WORMMACRO: '宏病毒',
        PUP: '潜在不受欢迎程序', HEURISTIC: '启发式检测',
        BEHAVIOR: '行为检测', UNKNOWN: '未知'
    }

# ============================================================
# 威胁等级
# ============================================================
class ThreatLevel:
    CRITICAL = 5    # 严重 - 勒索病毒、Rootkit
    HIGH = 4        # 高危 - 木马、后门
    MEDIUM = 3      # 中等 - 广告软件、PUP
    LOW = 2         # 低危 - 潜在风险
    INFO = 1        # 信息 - 仅通知
    NONE = 0        # 无害

    NAMES = {
        CRITICAL: '严重', HIGH: '高危', MEDIUM: '中等',
        LOW: '低危', INFO: '信息', NONE: '无害'
    }

# ============================================================
# 威胁信息结构
# ============================================================
class ThreatInfo:
    """完整的威胁信息"""
    def __init__(self, file_path: str, threat_type: str = ThreatType.UNKNOWN,
                 threat_name: str = '', scan_engine: str = 'unknown',
                 threat_level: int = ThreatLevel.MEDIUM,
                 result: int = ScanResult.MALICIOUS):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path) if file_path else ''
        self.file_size = os.path.getsize(file_path) if file_path and os.path.exists(file_path) else 0
        self.md5 = ''
        self.sha1 = ''
        self.sha256 = ''
        self.threat_type = threat_type
        self.threat_name = threat_name
        self.scan_engine = scan_engine
        self.threat_level = threat_level
        self.result = result
        self.timestamp = time.time()
        self.details = {}
        self.processed = False

    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'threat_type': self.threat_type,
            'threat_name': self.threat_name,
            'scan_engine': self.scan_engine,
            'threat_level': self.threat_level,
            'result': self.result,
            'timestamp': self.timestamp,
            'details': self.details
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatInfo':
        t = cls(data.get('file_path', ''))
        t.file_name = data.get('file_name', '')
        t.file_size = data.get('file_size', 0)
        t.md5 = data.get('md5', '')
        t.sha1 = data.get('sha1', '')
        t.sha256 = data.get('sha256', '')
        t.threat_type = data.get('threat_type', ThreatType.UNKNOWN)
        t.threat_name = data.get('threat_name', '')
        t.scan_engine = data.get('scan_engine', 'unknown')
        t.threat_level = data.get('threat_level', ThreatLevel.MEDIUM)
        t.result = data.get('result', ScanResult.MALICIOUS)
        t.timestamp = data.get('timestamp', time.time())
        t.details = data.get('details', {})
        return t

# ============================================================
# 哈希工具
# ============================================================
class HashUtil:
    @staticmethod
    def md5_file(filepath: str, blocksize: int = 65536) -> str:
        h = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(blocksize), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    @staticmethod
    def sha1_file(filepath: str, blocksize: int = 65536) -> str:
        h = hashlib.sha1()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(blocksize), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    @staticmethod
    def sha256_file(filepath: str, blocksize: int = 65536) -> str:
        h = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(blocksize), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    @staticmethod
    def compute_all(filepath: str) -> Tuple[str, str, str]:
        return (HashUtil.md5_file(filepath),
                HashUtil.sha1_file(filepath),
                HashUtil.sha256_file(filepath))

# ============================================================
# 文件类型检测
# ============================================================
class FileTypeDetector:
    """通过魔数检测文件真实类型"""
    MAGIC_SIGNATURES = {
        b'MZ': 'exe/dll',                    # PE 文件
        b'\x7fELF': 'elf',                   # ELF 文件
        b'\x89PNG': 'png',                   # PNG 图片
        b'\xff\xd8\xff': 'jpg',              # JPEG 图片
        b'GIF8': 'gif',                      # GIF 图片
        b'%PDF': 'pdf',                      # PDF 文档
        b'PK\x03\x04': 'zip/docx/xlsx',      # ZIP 压缩包 / Office 文档
        b'PK\x05\x06': 'zip',                # ZIP 空压缩包
        b'Rar!\x1a\x07': 'rar',              # RAR 压缩包
        b'\x1f\x8b': 'gz',                   # GZIP 压缩包
        b'BZh': 'bz2',                       # BZ2 压缩包
        b'\xfd7zXZ': '7z',                   # 7Z 压缩包
        b'RIFF': 'avi/wav',                  # RIFF 格式
        b'DICM': 'dicom',                    # DICOM 医学图像
        b'\x00\x01\x00\x00': 'ico',          # ICO 图标
        b'BM': 'bmp',                        # BMP 位图
        b'%!PS': 'ps',                       # PostScript
        b'\xca\xfe\xba\xbe': 'class',        # Java Class
        b'\x1a\x45\xdf\xa3': 'webm/mkv',     # Matroska 媒体
        b'{\rtf': 'rtf',                     # RTF 文档
        b'<!DOCTYPE': 'html',                # HTML 文档
        b'<html': 'html',                    # HTML 文档
        b'<svg': 'svg',                      # SVG 矢量图
        b'SCE': 'psp',                       # PSP 游戏
    }

    @staticmethod
    def detect(filepath: str) -> str:
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(8)
            for sig, ftype in FileTypeDetector.MAGIC_SIGNATURES.items():
                if magic.startswith(sig):
                    return ftype
            # 尝试文本检测
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    f.read(1024)
                return 'text'
            except Exception:
                return 'binary'
        except Exception:
            return 'unknown'

# ============================================================
# 扫描引擎基类
# ============================================================
class ScanEngine:
    """所有扫描引擎的基类"""
    def __init__(self, name: str = 'base', enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.stats = {'scanned': 0, 'detected': 0, 'errors': 0, 'time_ms': 0}
        self._stats_lock = threading.RLock()

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """扫描单个文件，返回威胁信息或None"""
        raise NotImplementedError

    def scan_batch(self, filepaths: List[str]) -> List[ThreatInfo]:
        """批量扫描文件"""
        results = []
        for fp in filepaths:
            try:
                result = self.scan(fp)
                if result:
                    results.append(result)
                    self.stats['detected'] += 1
                self.stats['scanned'] += 1
            except Exception:
                self.stats['errors'] += 1
        return results

    def get_stats(self) -> Dict:
        with self._stats_lock:
            return dict(self.stats)

    def reset_stats(self):
        with self._stats_lock:
            self.stats = {'scanned': 0, 'detected': 0, 'errors': 0, 'time_ms': 0}

    def _inc_stat(self, key: str, value: int = 1):
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + value

# ============================================================
# 扫描回调
# ============================================================
class ScanCallback:
    def __init__(self):
        self.on_file_start: Optional[Callable[[str], None]] = None
        self.on_file_complete: Optional[Callable[[str, Optional[ThreatInfo]], None]] = None
        self.on_threat_found: Optional[Callable[[ThreatInfo], None]] = None
        self.on_progress: Optional[Callable[[int, int], None]] = None  # current, total
        self.on_error: Optional[Callable[[str, str], None]] = None     # filepath, error
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

# ============================================================
# 扫描模式
# ============================================================
class ScanMode:
    QUICK = 'quick'         # 快速扫描 - 仅系统关键路径
    FULL = 'full'           # 全盘扫描 - 所有文件
    CUSTOM = 'custom'       # 自定义扫描 - 指定路径
    MEMORY = 'memory'       # 内存扫描
    BOOT = 'boot'           # 启动扫描

    NAMES = {
        QUICK: '快速扫描', FULL: '全盘扫描',
        CUSTOM: '自定义扫描', MEMORY: '内存扫描', BOOT: '启动扫描'
    }