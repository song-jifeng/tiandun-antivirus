#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - USB设备扫描器
"""
import os
import sys
import time
import threading
import subprocess
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.logger import logger
from engine.config import config


class USBScanner:
    """USB设备自动扫描器"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._known_drives = set()
        self._scan_results = []

    def start(self):
        if self._running:
            return
        self._running = True
        self._detect_current_drives()
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
        logger.info("USB扫描器已启动")

    def stop(self):
        self._running = False

    def _detect_current_drives(self):
        """检测当前已连接的驱动器"""
        if sys.platform == 'win32':
            try:
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i in range(26):
                    if bitmask & (1 << i):
                        drive = f'{chr(65 + i)}:\\'
                        if self._is_removable(drive):
                            self._known_drives.add(drive)
            except Exception:
                pass

    def _is_removable(self, drive: str) -> bool:
        """检查是否为可移动驱动器"""
        try:
            if sys.platform == 'win32':
                import ctypes
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                return drive_type == 2  # DRIVE_REMOVABLE
        except Exception:
            pass
        return False

    def _monitor(self):
        """监控USB插入"""
        while self._running:
            try:
                if sys.platform == 'win32':
                    self._check_windows_drives()
            except Exception:
                pass
            time.sleep(3)

    def _check_windows_drives(self):
        """检查Windows驱动器变化"""
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            current_drives = set()
            for i in range(26):
                if bitmask & (1 << i):
                    drive = f'{chr(65 + i)}:\\'
                    if self._is_removable(drive):
                        current_drives.add(drive)

            # 检测新插入的USB
            new_drives = current_drives - self._known_drives
            for drive in new_drives:
                logger.info(f"检测到USB设备: {drive}")
                self._scan_usb_drive(drive)

            self._known_drives = current_drives

        except Exception:
            pass

    def _scan_usb_drive(self, drive: str):
        """扫描USB驱动器"""
        if not config.get('realtime.usb_scan', True):
            return

        logger.info(f"开始扫描USB设备: {drive}")
        try:
            from scanner import scanner
            from engine import ScanCallback

            callback = ScanCallback()
            threats = []

            def on_threat(threat):
                threats.append(threat)
                logger.warning(f"USB发现威胁: {threat.file_name} - {threat.threat_name}")

            callback.on_threat_found = on_threat
            report = scanner.custom_scan([drive], callback)

            result = {
                'drive': drive,
                'scanned': report.scanned_files,
                'threats': report.threat_count,
                'threat_details': [t.to_dict() for t in threats],
                'timestamp': time.time(),
            }

            self._scan_results.append(result)
            logger.info(f"USB扫描完成: {drive} - {report.scanned_files}文件, {report.threat_count}威胁")

        except Exception as e:
            logger.error(f"USB扫描失败: {drive} - {e}")

    def get_scan_results(self) -> List[Dict]:
        return list(self._scan_results)

    def get_stats(self) -> Dict:
        return {
            'known_drives': len(self._known_drives),
            'scans_performed': len(self._scan_results),
        }


# ============================================================
# 全局USB扫描器
# ============================================================
usb_scanner = USBScanner()