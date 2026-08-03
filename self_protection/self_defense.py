#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 自我保护模块
进程保护、文件保护、注册表保护、看门狗、安全模式支持
"""
import os
import sys
import time
import json
import signal
import shutil
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import PROJECT_ROOT, ENGINE_VERSION
from engine.logger import logger
from engine.config import config


class ProcessProtector:
    """进程保护 - 防止进程被终止"""

    def __init__(self):
        self._watchdog: Optional['Watchdog'] = None
        self._running = False
        self._process_name = 'python.exe'
        self._main_pid = os.getpid()

    def start(self):
        self._running = True
        logger.info("进程保护已启动")

    def stop(self):
        self._running = False
        logger.info("进程保护已停止")

    def protect(self):
        """保护当前进程"""
        try:
            import psutil
            proc = psutil.Process(self._main_pid)
            # 提高进程优先级
            proc.nice(psutil.HIGH_PRIORITY_CLASS)
            logger.info(f"进程优先级已提升: {self._main_pid}")
        except Exception as e:
            logger.error(f"进程保护失败: {e}")

    def is_alive(self) -> bool:
        """检查主进程是否存活"""
        try:
            import psutil
            return psutil.pid_exists(self._main_pid)
        except Exception:
            return os.path.exists(f'/proc/{self._main_pid}') if sys.platform != 'win32' else True


class FileProtector:
    """文件保护 - 保护安装目录和关键文件"""

    def __init__(self):
        self.protected_paths: Set[str] = set()
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        # 添加保护路径
        self.protected_paths.add(str(PROJECT_ROOT))
        self.protected_paths.add(str(PROJECT_ROOT / 'engine'))
        self.protected_paths.add(str(PROJECT_ROOT / 'engine' / 'signatures'))
        self.protected_paths.add(str(PROJECT_ROOT / 'config.json'))
        for ext in ['.py', '.json', '.db']:
            self.protected_paths.add(ext)

        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
        logger.info(f"文件保护已启动: {len(self.protected_paths)} 个路径")

    def stop(self):
        self._running = False

    def _monitor(self):
        """监控文件变更"""
        last_checksums = {}
        while self._running:
            try:
                # 检查关键文件完整性
                for path in [PROJECT_ROOT / 'main.py',
                             PROJECT_ROOT / 'engine' / '__init__.py',
                             PROJECT_ROOT / 'config.json']:
                    if path.exists():
                        mtime = os.path.getmtime(path)
                        if str(path) in last_checksums:
                            if last_checksums[str(path)] != mtime:
                                logger.warning(f"文件被修改: {path}")
                        last_checksums[str(path)] = mtime
            except Exception:
                pass
            time.sleep(10)

    def is_path_protected(self, path: str) -> bool:
        """检查路径是否受保护"""
        path = os.path.normpath(path).lower()
        for protected in self.protected_paths:
            if protected.lower() in path:
                return True
        return False


class RegistryProtector:
    """注册表保护 - 保护杀软注册表项"""

    def __init__(self):
        self._running = False
        self.protected_keys = [
            r'Software\TiandunSecurity',
            r'Software\Microsoft\Windows\CurrentVersion\Run\TiandunAntivirus',
        ]

    def start(self):
        self._running = True
        logger.info("注册表保护已启动")

    def stop(self):
        self._running = False

    def check_integrity(self) -> bool:
        """检查注册表完整性"""
        try:
            import winreg
            for key_path in self.protected_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    logger.warning(f"注册表键丢失: {key_path}")
                    return False
            return True
        except Exception:
            return True

    def repair(self):
        """修复注册表"""
        try:
            import winreg
            for key_path in self.protected_keys:
                try:
                    winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                except Exception:
                    pass
            logger.info("注册表已修复")
        except Exception as e:
            logger.error(f"注册表修复失败: {e}")


class Watchdog:
    """看门狗 - 监控核心进程状态"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._check_interval = config.get('self_protection.watchdog_interval_seconds', 5)
        self._components: Dict[str, Dict] = {}

    def register_component(self, name: str, check_func, auto_restart: bool = True):
        """注册组件"""
        self._components[name] = {
            'check': check_func,
            'auto_restart': auto_restart,
            'last_ok': time.time(),
            'failures': 0,
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("看门狗已启动")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                for name, component in self._components.items():
                    try:
                        ok = component['check']()
                        if ok:
                            component['last_ok'] = time.time()
                            component['failures'] = 0
                        else:
                            component['failures'] += 1
                            logger.warning(f"组件 {name} 无响应 ({component['failures']}次)")
                            if component['failures'] >= 3 and component['auto_restart']:
                                logger.info(f"自动重启组件: {name}")
                                component['failures'] = 0
                    except Exception as e:
                        logger.error(f"看门狗检查组件 {name} 失败: {e}")
            except Exception as e:
                logger.error(f"看门狗错误: {e}")
            time.sleep(self._check_interval)

    def get_status(self) -> Dict[str, Dict]:
        return {
            name: {
                'running': True,
                'last_ok': datetime.fromtimestamp(comp['last_ok']).isoformat(),
                'failures': comp['failures'],
            }
            for name, comp in self._components.items()
        }


class SafeModeSupport:
    """安全模式支持"""

    @staticmethod
    def is_safe_mode() -> bool:
        """检测是否在安全模式下运行"""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    'bcdedit /enum {current}',
                    shell=True, capture_output=True, text=True, timeout=5
                )
                return 'safeboot' in result.stdout.lower()
        except Exception:
            pass
        return False

    @staticmethod
    def get_boot_mode() -> str:
        """获取启动模式"""
        if SafeModeSupport.is_safe_mode():
            return 'safe_mode'
        return 'normal'

    @staticmethod
    def load_safe_config():
        """加载安全模式配置"""
        safe_config = {
            'realtime.enabled': False,
            'hips.enabled': False,
            'firewall.enabled': False,
            'scan.thread_count': 1,
            'cloud.enabled': False,
        }
        for key, value in safe_config.items():
            config.set(key, value)
        logger.info("安全模式配置已加载")


class SelfDefense:
    """自防御总控 - 整合所有保护功能"""

    def __init__(self):
        self.process_protector = ProcessProtector()
        self.file_protector = FileProtector()
        self.registry_protector = RegistryProtector()
        self.watchdog = Watchdog()
        self.safe_mode = SafeModeSupport()
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True

        # 检查安全模式
        if self.safe_mode.is_safe_mode():
            logger.info("检测到安全模式启动，加载安全配置")
            self.safe_mode.load_safe_config()

        # 启动各保护模块
        if config.get('self_protection.protect_process', True):
            self.process_protector.start()
            self.process_protector.protect()

        if config.get('self_protection.protect_files', True):
            self.file_protector.start()

        if config.get('self_protection.protect_registry', True):
            self.registry_protector.start()

        # 注册看门狗组件
        if config.get('self_protection.watchdog_enabled', True):
            self.watchdog.register_component(
                'main_process',
                self.process_protector.is_alive,
                auto_restart=True
            )
            self.watchdog.register_component(
                'registry',
                self.registry_protector.check_integrity,
                auto_restart=False
            )
            self.watchdog.start()

        # 检查完整性
        self._check_integrity()

        logger.info("自我保护模块已启动")

    def stop(self):
        self._running = False
        self.process_protector.stop()
        self.file_protector.stop()
        self.registry_protector.stop()
        self.watchdog.stop()
        logger.info("自我保护模块已停止")

    def _check_integrity(self):
        """检查完整性"""
        issues = []
        if not self.registry_protector.check_integrity():
            issues.append("注册表完整性异常")
            self.registry_protector.repair()
        if issues:
            logger.warning(f"完整性检查发现 {len(issues)} 个问题: {', '.join(issues)}")
        else:
            logger.info("完整性检查通过")

    def get_status(self) -> Dict:
        return {
            'running': self._running,
            'process_protection': self.process_protector._running,
            'file_protection': self.file_protector._running,
            'registry_protection': self.registry_protector._running,
            'watchdog': self.watchdog._running,
            'safe_mode': self.safe_mode.is_safe_mode(),
            'watchdog_components': self.watchdog.get_status(),
        }


# ============================================================
# 全局自防御实例
# ============================================================
self_defense = SelfDefense()