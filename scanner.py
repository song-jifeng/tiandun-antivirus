#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 扫描管理器
整合所有扫描引擎，实现多引擎并行扫描
"""
import os
import sys
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime

# 导入引擎模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import (
    ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel,
    HashUtil, FileTypeDetector, ScanCallback, ScanMode, ENGINE_VERSION
)
from engine.logger import logger
from engine.config import config

# ============================================================
# 扫描报告
# ============================================================
class ScanReport:
    """扫描报告"""
    def __init__(self, scan_mode: str = ScanMode.CUSTOM):
        self.scan_mode = scan_mode
        self.start_time = time.time()
        self.end_time = 0.0
        self.total_files = 0
        self.scanned_files = 0
        self.threats_found: List[ThreatInfo] = []
        self.errors: List[Dict[str, str]] = []
        self.scanned_paths: List[str] = []
        self.engine_stats: Dict[str, Dict] = {}

    def add_threat(self, threat: ThreatInfo):
        self.threats_found.append(threat)

    def add_error(self, filepath: str, error: str):
        self.errors.append({'file': filepath, 'error': error})

    def finish(self):
        self.end_time = time.time()

    @property
    def duration(self) -> float:
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time

    @property
    def threat_count(self) -> int:
        return len(self.threats_found)

    @property
    def clean_files(self) -> int:
        return self.scanned_files - self.threat_count

    def to_dict(self) -> Dict:
        return {
            'scan_mode': self.scan_mode,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else '',
            'duration_seconds': self.duration,
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'threats_found': self.threat_count,
            'errors': len(self.errors),
            'threats': [t.to_dict() for t in self.threats_found],
            'engine_stats': self.engine_stats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "天盾 Antivirus - 扫描报告",
            "=" * 60,
            f"扫描模式: {ScanMode.NAMES.get(self.scan_mode, self.scan_mode)}",
            f"扫描时间: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}",
            f"耗时: {self.duration:.1f}秒",
            f"扫描文件: {self.scanned_files}/{self.total_files}",
            f"发现威胁: {self.threat_count}",
            f"错误: {len(self.errors)}",
            "-" * 60,
        ]
        if self.threats_found:
            lines.append("威胁列表:")
            for t in self.threats_found:
                level_name = ThreatLevel.NAMES.get(t.threat_level, '未知')
                lines.append(f"  [{level_name}] {t.file_name} - {t.threat_name}")
        lines.append("=" * 60)
        return '\n'.join(lines)


# ============================================================
# 文件发现器
# ============================================================
class FileDiscoverer:
    """文件发现器 - 递归查找文件"""

    SCAN_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.cpl',
        '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.mst',
        '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
        '.ppt', '.pptx', '.pptm', '.pdf',
        '.zip', '.rar', '.7z', '.cab', '.gz', '.bz2', '.tar',
        '.py', '.pyw', '.jar', '.class', '.swf', '.hta',
        '.php', '.asp', '.aspx', '.jsp', '.pl',
        '.txt', '.json', '.md', '.log', '.csv',
        '.xml', '.yaml', '.yml', '.cfg', '.ini',
        '.conf', '.dat', '.tmp', '.db', '.sqlite',
        '.reg', '.inf',
    }

    def __init__(self, max_size_mb: int = 200):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def discover(self, paths: List[str], recursive: bool = True,
                 extensions: Optional[set] = None) -> List[str]:
        """发现文件"""
        files = []
        exts = extensions or self.SCAN_EXTENSIONS
        for path in paths:
            if self._cancel.is_set():
                break
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                if self._should_scan(path, exts):
                    files.append(path)
            elif os.path.isdir(path):
                try:
                    for root, dirs, filenames in os.walk(path):
                        if self._cancel.is_set():
                            break
                        # 跳过系统保护目录
                        dirs[:] = [d for d in dirs if not d.startswith('$')]
                        for f in filenames:
                            fpath = os.path.join(root, f)
                            if self._should_scan(fpath, exts):
                                files.append(fpath)
                except PermissionError:
                    continue
                except Exception:
                    continue
        return files

    def _should_scan(self, filepath: str, extensions: set) -> bool:
        """判断是否应该扫描该文件"""
        try:
            # 检查扩展名
            ext = os.path.splitext(filepath)[1].lower()
            if ext not in extensions:
                # 检查无扩展名文件
                if not ext:
                    # 检查是否有执行权限
                    return True
                return False
            # 检查文件大小
            size = os.path.getsize(filepath)
            if size > self.max_size_bytes:
                return False
            if size == 0:
                return False
            return True
        except Exception:
            return False


# ============================================================
# 扫描器
# ============================================================
class Scanner:
    """扫描管理器 - 整合所有引擎"""

    def __init__(self):
        self.engines: List[ScanEngine] = []
        self._lock = threading.Lock()
        self._load_engines()

    def _load_engines(self):
        """加载所有可用的扫描引擎"""
        try:
            from engine.signatures.signature_engine import SignatureEngine
            se = SignatureEngine()
            se.enabled = True
            self.engines.append(se)
            logger.info(f"加载签名引擎: {se.name}")
        except Exception as e:
            logger.error(f"加载签名引擎失败: {e}")

        try:
            from engine.heuristic.heuristic_engine import HeuristicEngine
            he = HeuristicEngine()
            he.enabled = True
            self.engines.append(he)
            logger.info(f"加载启发式引擎: {he.name}")
        except Exception as e:
            logger.error(f"加载启发式引擎失败: {e}")

        try:
            from engine.behavior.behavior_engine import BehaviorEngine
            be = BehaviorEngine()
            be.enabled = False  # 行为引擎在扫描时不做主动扫描
            self.engines.append(be)
            logger.info(f"加载行为引擎: {be.name}")
        except Exception as e:
            logger.error(f"加载行为引擎失败: {e}")

        try:
            from engine.cloud.cloud_engine import CloudEngine
            ce = CloudEngine()
            ce.enabled = config.get('cloud.enabled', True)
            self.engines.append(ce)
            logger.info(f"加载云查杀引擎: {ce.name}")
        except Exception as e:
            logger.error(f"加载云查杀引擎失败: {e}")

        logger.info(f"共加载 {len(self.engines)} 个扫描引擎")

    def scan_file(self, filepath: str, callback: Optional[ScanCallback] = None) -> List[ThreatInfo]:
        """使用所有引擎扫描单个文件"""
        threats = []
        if callback and callback.is_cancelled():
            return threats

        for engine in self.engines:
            if not engine.enabled:
                continue
            try:
                start = time.time()
                result = engine.scan(filepath)
                elapsed = (time.time() - start) * 1000
                engine.stats['time_ms'] += elapsed

                if result:
                    threat = result
                    if not threat.md5:
                        threat.md5 = HashUtil.md5_file(filepath)
                    if not threat.sha1:
                        threat.sha1 = HashUtil.sha1_file(filepath)
                    if not threat.sha256:
                        threat.sha256 = HashUtil.sha256_file(filepath)
                    threats.append(threat)
                    logger.log_scan_result(filepath, 'MALICIOUS', engine.name,
                                         threat.threat_name, elapsed)
                    if callback and callback.on_threat_found:
                        callback.on_threat_found(threat)
                else:
                    logger.log_scan_result(filepath, 'CLEAN', engine.name, '', elapsed)
            except Exception as e:
                logger.error(f"扫描引擎 {engine.name} 扫描 {filepath} 失败: {e}")
                if callback and callback.on_error:
                    callback.on_error(filepath, str(e))

        return threats

    def scan(self, paths: List[str], mode: str = ScanMode.QUICK,
             callback: Optional[ScanCallback] = None) -> ScanReport:
        """扫描指定路径"""
        report = ScanReport(mode)
        logger.info(f"开始{ScanMode.NAMES.get(mode, mode)}: {paths}")

        # 发现文件
        discoverer = FileDiscoverer(
            max_size_mb=config.get('scan.max_file_size_mb', 200)
        )
        files = discoverer.discover(paths)
        report.total_files = len(files)
        logger.info(f"发现 {len(files)} 个文件待扫描")

        # 并行扫描
        max_workers = config.get('scan.thread_count', 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, filepath in enumerate(files):
                if callback:
                    if callback.is_cancelled():
                        logger.info("扫描被用户取消")
                        break
                    if callback.on_file_start:
                        callback.on_file_start(filepath)
                    if callback.on_progress:
                        callback.on_progress(i, len(files))

                future = executor.submit(self.scan_file, filepath, callback)
                futures[future] = filepath

            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    threats = future.result(timeout=300)
                    report.scanned_files += 1
                    for threat in threats:
                        report.add_threat(threat)
                    if callback and callback.on_file_complete:
                        callback.on_file_complete(filepath, threats[0] if threats else None)
                except Exception as e:
                    report.add_error(filepath, str(e))
                    logger.error(f"扫描文件失败 {filepath}: {e}")
                    if callback and callback.on_error:
                        callback.on_error(filepath, str(e))

        report.finish()

        # 收集引擎统计
        for engine in self.engines:
            report.engine_stats[engine.name] = engine.get_stats()

        # 记录扫描报告
        logger.info(f"扫描完成: {report.scanned_files}/{report.total_files} 文件, "
                    f"{report.threat_count} 威胁, {len(report.errors)} 错误")
        logger.log_scan_result('SUMMARY', 'COMPLETE', 'ALL',
                              f"{report.threat_count} threats", report.duration * 1000)

        return report

    def quick_scan(self, callback: Optional[ScanCallback] = None) -> ScanReport:
        """快速扫描 - 系统关键路径"""
        paths = config.get('scan.quick_paths', [])
        # 过滤存在的路径
        valid_paths = [p for p in paths if os.path.exists(p)]
        return self.scan(valid_paths, ScanMode.QUICK, callback)

    def full_scan(self, callback: Optional[ScanCallback] = None) -> ScanReport:
        """全盘扫描 - 所有驱动器"""
        drives = []
        try:
            import string
            from ctypes import windll
            bitmask = windll.kernel32.GetLogicalDrives()
            for i, letter in enumerate(string.ascii_uppercase):
                if bitmask & (1 << i):
                    drives.append(f'{letter}:\\')
        except Exception:
            drives = ['C:\\']
        return self.scan(drives, ScanMode.FULL, callback)

    def custom_scan(self, paths: List[str],
                    callback: Optional[ScanCallback] = None) -> ScanReport:
        """自定义扫描"""
        return self.scan(paths, ScanMode.CUSTOM, callback)

    def get_engine_stats(self) -> List[Dict]:
        """获取所有引擎的统计信息"""
        stats = []
        for engine in self.engines:
            stats.append({
                'name': engine.name,
                'enabled': engine.enabled,
                'stats': engine.get_stats(),
            })
        return stats


# ============================================================
# 全局扫描器实例
# ============================================================
scanner = Scanner()