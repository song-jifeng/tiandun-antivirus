#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 主动防御系统 (HIPS)
实时拦截高危操作：进程终止、注册表启动项清理、文件系统保护
"""
import os
import sys
import time
import ctypes
import threading
from typing import Dict, Optional, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger
from engine.config import config
from engine.behavior.win_registry import (
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER,
    KEY_READ, KEY_SET_VALUE, PROCESS_TERMINATE,
    SYNCHRONIZE,
    kill_process, set_file_readonly,
    format_key_path, delete_value, close_handle,
    open_process, terminate_process,
    open_reg_key, close_reg_key, enum_values,
)


class HIPSEngine:
    """主动防御系统 - 实时拦截高危操作"""

    SUSPICIOUS_NAMES = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
    ]

    RUN_KEY_PATHS = [
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def __init__(self):
        self.enabled = config.get('hips.enabled', True)
        self.level = config.get('hips.level', 'normal')
        self._running = False
        self._thread = None
        self._wmi_thread = None
        self._wmi_available = False
        self._intercepted = 0

    def start(self):
        if not self.enabled or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # 尝试启动WMI进程创建实时监控
        self._try_start_wmi_monitor()
        logger.info("HIPS引擎已启动")

    def stop(self):
        self._running = False
        if self._wmi_thread:
            self._wmi_thread.join(timeout=3)
            self._wmi_thread = None

    # ------------------------------------------------------------
    # WMI 进程创建监控（实时事件驱动）
    # ------------------------------------------------------------
    def _try_start_wmi_monitor(self):
        """尝试使用 WMI Win32_ProcessStartTrace 订阅进程创建事件"""
        try:
            import win32com.client  # type: ignore
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            service = locator.ConnectServer(".", "root\\cimv2")
            self._wmi_events = service.ExecNotificationQuery(
                "SELECT * FROM Win32_ProcessStartTrace"
            )
            self._wmi_thread = threading.Thread(
                target=self._wmi_monitor_loop, daemon=True
            )
            self._wmi_thread.start()
            self._wmi_available = True
            logger.info("HIPS: WMI 进程创建监控已启动")
        except Exception as e:
            self._wmi_available = False
            logger.warning(f"HIPS: WMI 监控不可用，回退到轮询模式: {e}")

    def _wmi_monitor_loop(self):
        """WMI 事件循环 — 等待进程创建事件"""
        while self._running and self._wmi_available:
            try:
                event = self._wmi_events.NextEvent(1000)
                if event is None:
                    continue
                proc_info = {
                    'pid': event.ProcessID,
                    'name': event.ProcessName,
                    'exe': getattr(event, 'ProcessName', ''),
                }
                self._evaluate_process(proc_info, source='wmi')
            except Exception:
                pass

    # ------------------------------------------------------------
    # 轮询监控（后备，也用于扫描已有进程）
    # ------------------------------------------------------------
    def _run(self):
        while self._running:
            try:
                self._check_hips_rules()
            except Exception:
                pass
            time.sleep(5)

    def _check_hips_rules(self):
        """检查HIPS规则 - 轮询所有进程"""
        if not config.get('hips.monitor_process_create', True):
            return
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe']:
                        self._evaluate_process(proc.info, source='poll')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            pass

    # ------------------------------------------------------------
    # 核心评估与拦截
    # ------------------------------------------------------------
    def _evaluate_process(self, proc_info: Dict, source: str = 'poll'):
        """
        评估进程风险并执行拦截。
        1. 白名单检查 -> 跳过
        2. 黑名单匹配 -> 终止 + 清理启动项 + 文件保护
        3. 高安全级别下检测可疑进程 -> 同上
        """
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower() or name
        pid = proc_info.get('pid', 0)

        # 白名单检查
        whitelist = config.get('hips.whitelist', [])
        for pattern in whitelist:
            if pattern.lower() in name or pattern.lower() in exe:
                return

        matched = False
        matched_reason = ''

        # 黑名单检查
        blacklist = config.get('hips.blacklist', [])
        for pattern in blacklist:
            if pattern.lower() in name or pattern.lower() in exe:
                matched = True
                matched_reason = f"黑名单匹配: {pattern}"
                break

        # 高安全级别下检测可疑进程
        if not matched and self.level in ('high', 'paranoid'):
            if name in self.SUSPICIOUS_NAMES:
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    parent = proc.parent()
                    parent_name = parent.name().lower() if parent else ''
                    if parent_name not in ('explorer.exe', 'svchost.exe', 'services.exe', 'winlogon.exe'):
                        matched = True
                        matched_reason = f"可疑进程 {name} 由 {parent_name} 启动"
                except Exception:
                    pass

        if matched:
            self._intercepted += 1
            logger.warning(f"HIPS 拦截: {matched_reason} (PID={pid}, name={name})")

            # === 动作 1: 终止进程 ===
            if pid > 0:
                self._terminate_process(pid, name)

            # === 动作 2: 清理注册表启动项 ===
            self._remove_registry_run_keys(name, exe)

            # === 动作 3: 文件系统保护 ===
            if exe and os.path.exists(exe):
                self._protect_file(exe)

    # ------------------------------------------------------------
    # 拦截动作实现
    # ------------------------------------------------------------
    def _terminate_process(self, pid: int, name: str):
        """通过 OpenProcess + TerminateProcess 终止进程"""
        handle = open_process(pid, PROCESS_TERMINATE | SYNCHRONIZE)
        if handle:
            try:
                if terminate_process(handle):
                    logger.warning(f"HIPS: 已终止进程 {name} (PID={pid})")
                else:
                    logger.error(f"HIPS: 终止进程失败 {name} (PID={pid})")
            finally:
                close_handle(handle)
        else:
            logger.error(f"HIPS: 无法打开进程 {name} (PID={pid})，权限不足或进程已退出")

    def _remove_registry_run_keys(self, name: str, exe: str):
        """扫描 Run / RunOnce 键，删除指向恶意进程的条目"""
        for hive, sub_key in self.RUN_KEY_PATHS:
            try:
                handle = open_reg_key(hive, sub_key, access=KEY_READ | KEY_SET_VALUE)
                if handle is None:
                    continue
                try:
                    values = enum_values(handle)
                    for val_name, (val_type, val_data) in values.items():
                        if not isinstance(val_data, str):
                            continue
                        val_lower = val_data.lower()
                        if name.lower() in val_lower or (exe and exe.lower() in val_lower):
                            if delete_value(handle, val_name):
                                logger.warning(
                                    f"HIPS: 已移除注册表启动项 "
                                    f"{format_key_path(hive, sub_key)} -> {val_name}"
                                )
                finally:
                    close_reg_key(handle)
            except Exception:
                pass

    def _protect_file(self, filepath: str):
        """设置文件为只读属性以防止进一步损害"""
        try:
            if set_file_readonly(filepath):
                logger.warning(f"HIPS: 已设置文件只读属性 {filepath}")
        except Exception:
            pass

    # ------------------------------------------------------------
    def get_stats(self) -> Dict:
        return {
            'enabled': self.enabled,
            'level': self.level,
            'intercepted': self._intercepted,
            'wmi_available': self._wmi_available,
        }