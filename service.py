#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - Windows 服务包装
"""
import os
import sys
import time
import threading
import subprocess
import json
from pathlib import Path
from typing import Optional

from engine import PROJECT_ROOT, ENGINE_VERSION
from engine.logger import logger
from engine.config import config


class TiandunService:
    """天盾 Windows 服务"""
    SERVICE_NAME = 'TiandunAntivirus'
    DISPLAY_NAME = '天盾 Antivirus 安全服务'
    DESCRIPTION = '天盾 Antivirus 实时防护后台服务'

    @staticmethod
    def _run_python_script(script: str) -> subprocess.CompletedProcess:
        """运行Python脚本"""
        python = sys.executable
        return subprocess.run(
            [python, '-c', script],
            capture_output=True, text=True, timeout=30
        )

    @staticmethod
    def install() -> bool:
        """安装服务"""
        try:
            # 使用 PowerShell 安装服务
            script = f'''
            $serviceName = "{TiandunService.SERVICE_NAME}"
            $python = "{sys.executable}"
            $mainScript = "{PROJECT_ROOT / 'main.py'}"
            $password = "tiandun_service_2026"

            # 创建服务用户
            # New-LocalUser -Name "TiandunService" -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description "天盾安全服务账户"

            # 安装服务
            New-Service -Name $serviceName `
                -DisplayName "{TiandunService.DISPLAY_NAME}" `
                -Description "{TiandunService.DESCRIPTION}" `
                -BinaryPathName "`"$python`" `"$mainScript`" --daemon" `
                -StartupType Automatic `
                -ErrorAction SilentlyContinue
            '''
            subprocess.run(['powershell', '-Command', script], capture_output=True, timeout=30)
            logger.info("服务安装成功")
            return True
        except Exception as e:
            logger.error(f"服务安装失败: {e}")
            return False

    @staticmethod
    def uninstall() -> bool:
        """卸载服务"""
        try:
            subprocess.run(
                ['sc', 'stop', TiandunService.SERVICE_NAME],
                capture_output=True, timeout=10
            )
            time.sleep(2)
            subprocess.run(
                ['sc', 'delete', TiandunService.SERVICE_NAME],
                capture_output=True, timeout=10
            )
            logger.info("服务卸载成功")
            return True
        except Exception as e:
            logger.error(f"服务卸载失败: {e}")
            return False

    @staticmethod
    def start() -> bool:
        """启动服务"""
        try:
            subprocess.run(
                ['net', 'start', TiandunService.SERVICE_NAME],
                capture_output=True, timeout=30
            )
            logger.info("服务启动成功")
            return True
        except Exception as e:
            logger.error(f"服务启动失败: {e}")
            return False

    @staticmethod
    def stop() -> bool:
        """停止服务"""
        try:
            subprocess.run(
                ['net', 'stop', TiandunService.SERVICE_NAME],
                capture_output=True, timeout=30
            )
            logger.info("服务停止成功")
            return True
        except Exception as e:
            logger.error(f"服务停止失败: {e}")
            return False

    @staticmethod
    def status() -> dict:
        """获取服务状态"""
        try:
            result = subprocess.run(
                ['sc', 'query', TiandunService.SERVICE_NAME],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            status = 'unknown'
            if 'RUNNING' in output:
                status = 'running'
            elif 'STOPPED' in output:
                status = 'stopped'
            return {
                'name': TiandunService.SERVICE_NAME,
                'display_name': TiandunService.DISPLAY_NAME,
                'status': status,
            }
        except Exception:
            return {'name': TiandunService.SERVICE_NAME, 'status': 'unknown'}


class ServiceManager:
    """服务管理器 - 管理后台服务和实时保护"""

    def __init__(self):
        self._running = False
        self._threads = []
        self._watchdog = None
        self._components = {}

    def start(self):
        """启动所有后台服务"""
        if self._running:
            return
        self._running = True

        logger.info("启动后台服务...")

        # 启动组件
        self._start_component('hips', self._run_hips)
        self._start_component('monitor', self._run_monitor)
        self._start_component('watchdog', self._run_watchdog)

        logger.info(f"后台服务启动完成 ({len(self._components)} 个组件)")

    def stop(self):
        """停止所有后台服务"""
        self._running = False
        logger.info("停止后台服务...")
        # 线程会在下次循环时退出

    def _start_component(self, name: str, func):
        """启动组件线程"""
        thread = threading.Thread(target=func, name=f'svc-{name}', daemon=True)
        thread.start()
        self._components[name] = thread
        self._threads.append(thread)

    def _run_hips(self):
        """运行HIPS组件"""
        while self._running:
            try:
                if config.get('hips.enabled', True):
                    from engine.behavior.hips import HIPSEngine
                    if 'hips' not in self._components:
                        hips = HIPSEngine()
                        hips.start()
            except Exception as e:
                logger.error(f"HIPS组件错误: {e}")
            time.sleep(5)

    def _run_monitor(self):
        """运行监控组件"""
        while self._running:
            try:
                if config.get('realtime.enabled', True):
                    from engine.behavior.behavior_engine import BehaviorEngine
                    if 'monitor' not in self._components:
                        engine = BehaviorEngine()
                        engine.start()
            except Exception as e:
                logger.error(f"监控组件错误: {e}")
            time.sleep(5)

    def _run_watchdog(self):
        """运行看门狗"""
        while self._running:
            try:
                from self_protection.watchdog import Watchdog
                if 'watchdog' not in self._components:
                    wd = Watchdog()
                    wd.start()
            except Exception as e:
                logger.error(f"看门狗错误: {e}")
            time.sleep(5)

    def get_status(self) -> dict:
        """获取服务状态"""
        status = {
            'running': self._running,
            'components': {},
        }
        for name, thread in self._components.items():
            status['components'][name] = thread.is_alive()
        return status


# ============================================================
# 全局服务管理器
# ============================================================
service_manager = ServiceManager()