#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 扫描管理器
整合所有扫描引擎，实现多引擎并行扫描

架构特点:
  - 生产者-消费者模式: FileDiscoverer 发现文件的同时 Scanner 开始扫描
  - 实时进度报告: 通过回调报告扫描进度
  - 结构化异常处理: 所有异常都有详细日志
  - 支持取消操作
"""
import os
import sys
import time
import json
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable, Iterator, Set
from datetime import datetime
from queue import Queue

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
# 文件发现器 (生产者-消费者模式)
# ============================================================
class FileDiscoverer:
    """文件发现器 - 生产者-消费者模式，发现文件时实时产出

    使用回调机制，发现文件时立即通知消费者，无需等待全部发现完成。
    """

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

    # 系统保护目录前缀（跳过）
    SKIP_DIR_PREFIXES = {
        '$', 'System Volume Information', 'Windows.old',
        'Recovery', '$Recycle.Bin', 'Config.Msi',
    }

    def __init__(self, max_size_mb: int = 200):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._cancel = threading.Event()
        self._discovered_count = 0

    def cancel(self):
        self._cancel.set()

    @property
    def discovered_count(self) -> int:
        return self._discovered_count

    def discover(self, paths: List[str], recursive: bool = True,
                 extensions: Optional[set] = None,
                 file_callback: Optional[Callable[[str], None]] = None) -> List[str]:
        """发现文件 - 收集所有文件（传统模式，向后兼容）

        Args:
            paths: 要扫描的路径列表
            recursive: 是否递归子目录
            extensions: 要扫描的扩展名集合
            file_callback: 发现文件时的回调（可选）

        Returns:
            文件路径列表
        """
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
                    self._discovered_count += 1
                    if file_callback:
                        file_callback(path)
            elif os.path.isdir(path):
                try:
                    if recursive:
                        walk_iter = os.walk(path)
                    else:
                        # 非递归：只获取顶层文件和目录
                        try:
                            entries = os.listdir(path)
                        except PermissionError:
                            entries = []
                        walk_iter = [(path,
                                      [d for d in entries if os.path.isdir(os.path.join(path, d))],
                                      [f for f in entries if os.path.isfile(os.path.join(path, f))])]
                    for root, dirs, filenames in walk_iter:
                        if self._cancel.is_set():
                            break
                        # 跳过系统保护目录
                        dirs[:] = [d for d in dirs
                                   if not any(d.startswith(prefix) for prefix in self.SKIP_DIR_PREFIXES)]
                        for f in filenames:
                            fpath = os.path.join(root, f)
                            if self._should_scan(fpath, exts):
                                files.append(fpath)
                                self._discovered_count += 1
                                if file_callback:
                                    file_callback(fpath)
                except PermissionError as e:
                    logger.warning(f"权限不足，跳过目录 {path}: {e}")
                except OSError as e:
                    logger.warning(f"访问目录 {path} 失败: {e}")
                except Exception as e:
                    logger.error(f"扫描目录 {path} 时发生异常: {e}")
                    logger.debug(traceback.format_exc())
        return files

    def discover_iter(self, paths: List[str], recursive: bool = True,
                      extensions: Optional[set] = None) -> Iterator[str]:
        """发现文件 - 迭代器模式，实时产出文件

        使用 yield 逐个产出发现的文件，消费者可以立即开始处理。
        配合 Scanner 的生产者-消费者模式使用。

        Args:
            paths: 要扫描的路径列表
            recursive: 是否递归子目录
            extensions: 要扫描的扩展名集合

        Yields:
            逐个文件路径
        """
        exts = extensions or self.SCAN_EXTENSIONS
        for path in paths:
            if self._cancel.is_set():
                break
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                if self._should_scan(path, exts):
                    self._discovered_count += 1
                    yield path
            elif os.path.isdir(path):
                try:
                    if recursive:
                        walk_iter = os.walk(path)
                    else:
                        # 非递归：只获取顶层文件和目录
                        try:
                            entries = os.listdir(path)
                        except PermissionError:
                            entries = []
                        walk_iter = [(path,
                                      [d for d in entries if os.path.isdir(os.path.join(path, d))],
                                      [f for f in entries if os.path.isfile(os.path.join(path, f))])]
                    for root, dirs, filenames in walk_iter:
                        if self._cancel.is_set():
                            break
                        # 跳过系统保护目录
                        dirs[:] = [d for d in dirs
                                   if not any(d.startswith(prefix) for prefix in self.SKIP_DIR_PREFIXES)]
                        for f in filenames:
                            if self._cancel.is_set():
                                break
                            fpath = os.path.join(root, f)
                            if self._should_scan(fpath, exts):
                                self._discovered_count += 1
                                yield fpath
                except PermissionError as e:
                    logger.warning(f"权限不足，跳过目录 {path}: {e}")
                except OSError as e:
                    logger.warning(f"访问目录 {path} 失败: {e}")
                except Exception as e:
                    logger.error(f"扫描目录 {path} 时发生异常: {e}")
                    logger.debug(traceback.format_exc())

    def _should_scan(self, filepath: str, extensions: set) -> bool:
        """判断是否应该扫描该文件"""
        try:
            # 检查扩展名
            ext = os.path.splitext(filepath)[1].lower()
            if ext not in extensions:
                # 检查无扩展名文件
                if not ext:
                    return True
                return False
            # 检查文件大小
            size = os.path.getsize(filepath)
            if size > self.max_size_bytes:
                return False
            if size == 0:
                return False
            return True
        except OSError as e:
            logger.debug(f"检查文件 {filepath} 时出错: {e}")
            return False
        except Exception as e:
            logger.debug(f"检查文件 {filepath} 时出现未知错误: {e}")
            return False


# ============================================================
# 扫描器
# ============================================================
class Scanner:
    """扫描管理器 - 整合所有引擎，使用生产者-消费者模式"""

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
        except ImportError as e:
            logger.error(f"加载签名引擎失败: 模块未找到 - {e}")
        except Exception as e:
            logger.error(f"加载签名引擎失败: {e}")
            logger.debug(traceback.format_exc())

        try:
            from engine.heuristic.heuristic_engine import HeuristicEngine
            he = HeuristicEngine()
            he.enabled = True
            self.engines.append(he)
            logger.info(f"加载启发式引擎: {he.name}")
        except ImportError as e:
            logger.error(f"加载启发式引擎失败: 模块未找到 - {e}")
        except Exception as e:
            logger.error(f"加载启发式引擎失败: {e}")
            logger.debug(traceback.format_exc())

        try:
            from engine.behavior.behavior_engine import BehaviorEngine
            be = BehaviorEngine()
            be.enabled = False  # 行为引擎在扫描时不做主动扫描
            self.engines.append(be)
            logger.info(f"加载行为引擎: {be.name}")
        except ImportError as e:
            logger.error(f"加载行为引擎失败: 模块未找到 - {e}")
        except Exception as e:
            logger.error(f"加载行为引擎失败: {e}")
            logger.debug(traceback.format_exc())

        try:
            from engine.cloud.cloud_engine import CloudEngine
            ce = CloudEngine()
            ce.enabled = config.get('cloud.enabled', True)
            self.engines.append(ce)
            logger.info(f"加载云查杀引擎: {ce.name}")
        except ImportError as e:
            logger.error(f"加载云查杀引擎失败: 模块未找到 - {e}")
        except Exception as e:
            logger.error(f"加载云查杀引擎失败: {e}")
            logger.debug(traceback.format_exc())

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
            except PermissionError as e:
                logger.warning(f"权限不足，无法扫描 {filepath}: {e}")
                if callback and callback.on_error:
                    callback.on_error(filepath, f"权限不足: {e}")
            except FileNotFoundError as e:
                logger.warning(f"文件不存在，跳过扫描 {filepath}: {e}")
                if callback and callback.on_error:
                    callback.on_error(filepath, f"文件不存在: {e}")
            except Exception as e:
                logger.error(f"扫描引擎 {engine.name} 扫描 {filepath} 失败: {e}")
                logger.debug(traceback.format_exc())
                if callback and callback.on_error:
                    callback.on_error(filepath, str(e))

        return threats

    def scan(self, paths: List[str], mode: str = ScanMode.QUICK,
             callback: Optional[ScanCallback] = None) -> ScanReport:
        """扫描指定路径 - 使用生产者-消费者模式

        发现文件的同时开始扫描，提高效率。
        """
        report = ScanReport(mode)
        logger.info(f"开始{ScanMode.NAMES.get(mode, mode)}: {paths}")

        # 创建文件发现器
        discoverer = FileDiscoverer(
            max_size_mb=config.get('scan.max_file_size_mb', 200)
        )

        # 获取并行扫描线程数
        max_workers = config.get('scan.thread_count', 4)

        # 使用生产者-消费者模式:
        # 生产者: discover_iter 逐个产出文件
        # 消费者: ThreadPoolExecutor 并行扫描
        # 通过 Queue 或直接迭代进行协调

        # 收集所有文件（需要 total_files 用于进度报告）
        # 但同时也开始扫描已发现的文件
        all_files = []
        scanned_count = 0
        scan_lock = threading.Lock()

        # 用于同步发现和扫描的 Event
        discovery_complete = threading.Event()

        # 扫描结果收集
        def scan_worker(filepath: str) -> List[ThreatInfo]:
            """扫描工作线程"""
            nonlocal scanned_count
            if callback:
                if callback.is_cancelled():
                    return []
                if callback.on_file_start:
                    callback.on_file_start(filepath)

            threats = self.scan_file(filepath, callback)

            with scan_lock:
                scanned_count += 1
                if callback and callback.on_progress:
                    callback.on_progress(scanned_count, len(all_files) if all_files else scanned_count)

            if callback and callback.on_file_complete:
                callback.on_file_complete(filepath, threats[0] if threats else None)

            return threats

        # 第一阶段: 发现文件并开始扫描
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交已发现文件的扫描任务
            futures = {}

            # 遍历发现器迭代器
            for filepath in discoverer.discover_iter(paths):
                if callback and callback.is_cancelled():
                    logger.info("扫描被用户取消")
                    break

                all_files.append(filepath)
                future = executor.submit(scan_worker, filepath)
                futures[future] = filepath

            # 发现完成
            report.total_files = len(all_files)
            discovery_complete.set()
            logger.info(f"发现完成: {len(all_files)} 个文件待扫描")

            # 等待所有扫描任务完成
            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    threats = future.result(timeout=300)
                    report.scanned_files += 1
                    for threat in threats:
                        report.add_threat(threat)
                except TimeoutError:
                    report.add_error(filepath, "扫描超时")
                    logger.error(f"扫描文件超时 {filepath}")
                except Exception as e:
                    report.add_error(filepath, str(e))
                    logger.error(f"扫描文件失败 {filepath}: {e}")
                    logger.debug(traceback.format_exc())
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
        except ImportError:
            logger.warning("无法获取驱动器列表，仅扫描 C:")
            drives = ['C:\\']
        except Exception as e:
            logger.warning(f"获取驱动器列表失败: {e}，仅扫描 C:")
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