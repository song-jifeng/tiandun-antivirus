#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 日志系统
支持多级别日志、文件轮转、控制台输出、性能日志
"""
import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any
from datetime import datetime

# ============================================================
# 日志级别
# ============================================================
class LogLevel:
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    NAMES = {
        DEBUG: 'DEBUG', INFO: 'INFO', WARNING: 'WARNING',
        ERROR: 'ERROR', CRITICAL: 'CRITICAL'
    }

# ============================================================
# 日志记录器
# ============================================================
class Logger:
    """天盾日志系统 - 支持文件轮转、控制台输出、结构化日志"""

    _instances = {}
    _lock = threading.Lock()

    def __new__(cls, name: str = 'tiandun', log_dir: Optional[str] = None):
        with cls._lock:
            if name not in cls._instances:
                instance = super().__new__(cls)
                instance._initialized = False
                cls._instances[name] = instance
            return cls._instances[name]

    def __init__(self, name: str = 'tiandun', log_dir: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True

        self.name = name
        self.log_dir = log_dir or os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        os.makedirs(self.log_dir, exist_ok=True)

        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()

        # 日志格式
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # 文件处理器 - 轮转
        log_file = os.path.join(self.log_dir, f'{name}.log')
        file_handler = RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=10,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

        # 错误日志单独文件
        error_file = os.path.join(self.log_dir, f'{name}.error.log')
        error_handler = RotatingFileHandler(
            error_file, maxBytes=20 * 1024 * 1024, backupCount=5,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.WARNING)
        error_handler.setFormatter(formatter)
        self._logger.addHandler(error_handler)

        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)

        # 性能日志
        self._perf_log_file = os.path.join(self.log_dir, 'performance.log')
        self._scan_log_file = os.path.join(self.log_dir, 'scan_results.log')
        self._threat_log_file = os.path.join(self.log_dir, 'threats.log')

        self.info(f"日志系统初始化完成: {self.log_dir}")

    # ============================================================
    # 标准日志方法
    # ============================================================
    def debug(self, msg: str, *args, **kwargs):
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self._logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        self._logger.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs):
        self._logger.exception(msg, *args, **kwargs)

    # ============================================================
    # 结构化日志
    # ============================================================
    def log_struct(self, level: int, event: str, data: Dict[str, Any]):
        """结构化日志 - JSON 格式"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'level': LogLevel.NAMES.get(level, 'UNKNOWN'),
            'event': event,
            'data': data
        }
        line = json.dumps(record, ensure_ascii=False)
        level_name = LogLevel.NAMES.get(level, 'INFO')
        self._logger.log(level, f"[{event}] {json.dumps(data, ensure_ascii=False)}")

    # ============================================================
    # 扫描结果日志
    # ============================================================
    def log_scan_result(self, filepath: str, result: str, engine: str,
                        threat_name: str = '', duration_ms: float = 0):
        """记录扫描结果到专用日志文件"""
        try:
            line = (f"{datetime.now().isoformat()} | {result:8s} | {engine:12s} | "
                    f"{threat_name:20s} | {duration_ms:6.0f}ms | {filepath}\n")
            with open(self._scan_log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass

    # ============================================================
    # 威胁日志
    # ============================================================
    def log_threat(self, threat_info: Dict):
        """记录威胁信息到专用日志文件"""
        try:
            line = json.dumps(threat_info, ensure_ascii=False) + '\n'
            with open(self._threat_log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass

    # ============================================================
    # 性能日志
    # ============================================================
    def log_performance(self, operation: str, duration_ms: float,
                        details: Optional[Dict] = None):
        """记录性能指标"""
        try:
            timestamp = datetime.now().isoformat()
            detail_str = json.dumps(details or {}, ensure_ascii=False)
            line = f"{timestamp} | {operation:30s} | {duration_ms:8.2f}ms | {detail_str}\n"
            with open(self._perf_log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass

    # ============================================================
    # 性能计时器
    # ============================================================
    class Timer:
        def __init__(self, logger: 'Logger', operation: str, details: Optional[Dict] = None):
            self.logger = logger
            self.operation = operation
            self.details = details or {}
            self.start = 0

        def __enter__(self):
            self.start = time.time()
            return self

        def __exit__(self, *args):
            elapsed = (time.time() - self.start) * 1000
            self.logger.log_performance(self.operation, elapsed, self.details)

    def timer(self, operation: str, details: Optional[Dict] = None) -> 'Logger.Timer':
        return self.Timer(self, operation, details)


# ============================================================
# 全局日志实例
# ============================================================
logger = Logger()


# ============================================================
# 日志清理
# ============================================================
class LogCleaner:
    """定期清理旧日志文件"""

    def __init__(self, log_dir: str, max_size_mb: int = 100, max_files: int = 20):
        self.log_dir = log_dir
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_files = max_files

    def clean(self):
        """清理过期日志"""
        if not os.path.exists(self.log_dir):
            return
        try:
            files = []
            for f in os.listdir(self.log_dir):
                fpath = os.path.join(self.log_dir, f)
                if os.path.isfile(fpath):
                    files.append((fpath, os.path.getmtime(fpath)))

            # 按修改时间排序
            files.sort(key=lambda x: x[1], reverse=True)

            # 删除超过最大数量的文件
            if len(files) > self.max_files:
                for fpath, _ in files[self.max_files:]:
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

            # 检查总大小
            total_size = sum(os.path.getsize(f[0]) for f in files)
            if total_size > self.max_size_bytes:
                # 从最旧的开始删除，直到总大小低于阈值
                for fpath, _ in reversed(files):
                    try:
                        fsize = os.path.getsize(fpath)
                        os.remove(fpath)
                        total_size -= fsize
                        if total_size <= self.max_size_bytes:
                            break
                    except Exception:
                        pass

        except Exception:
            pass