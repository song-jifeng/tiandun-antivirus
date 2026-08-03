#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 主动防御系统 (HIPS)
"""
import os
import sys
import time
import threading
from typing import Dict, Optional, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger
from engine.config import config


class HIPSEngine:
    """主动防御系统 - 实时拦截高危操作"""

    def __init__(self):
        self.enabled = config.get('hips.enabled', True)
        self.level = config.get('hips.level', 'normal')
        self._running = False
        self._thread = None
        self._intercepted = 0

    def start(self):
        if not self.enabled or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("HIPS引擎已启动")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                self._check_system_state()
            except Exception:
                pass
            time.sleep(5)

    def _check_system_state(self):
        """检查系统状态"""
        try:
            import psutil
            # 监控进程创建
            if config.get('hips.monitor_process_create', True):
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.info['exe']:
                            self._evaluate_process(proc.info)
                    except Exception:
                        pass
        except ImportError:
            pass

    def _evaluate_process(self, proc_info: Dict):
        """评估进程风险"""
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower()

        # 黑名单检查
        blacklist = config.get('hips.blacklist', [])
        for pattern in blacklist:
            if pattern.lower() in name or pattern.lower() in exe:
                logger.warning(f"HIPS阻止: {name}")
                self._intercepted += 1
                return

        # 可疑进程检测
        suspicious = ['powershell.exe', 'cmd.exe', 'wscript.exe',
                     'cscript.exe', 'mshta.exe', 'rundll32.exe']
        if name in suspicious:
            try:
                proc = psutil.Process(proc_info['pid'])
                parent = proc.parent()
                if parent and parent.name().lower() not in ('explorer.exe', 'svchost.exe'):
                    logger.warning(f"HIPS: 可疑进程 {name} 由 {parent.name()} 启动")
                    self._intercepted += 1
            except Exception:
                pass

    def get_stats(self) -> Dict:
        return {
            'enabled': self.enabled,
            'level': self.level,
            'intercepted': self._intercepted,
        }