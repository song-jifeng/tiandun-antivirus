#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 安装脚本
"""
import os
import sys
import json
import shutil
import subprocess
import winreg
from pathlib import Path
from typing import List, Optional

from engine import PROJECT_ROOT, ENGINE_VERSION
from engine.logger import logger


class Installer:
    """安装管理器"""

    @staticmethod
    def install():
        """执行安装"""
        print("天盾 Antivirus 安装程序")
        print("=" * 50)

        # 创建目录
        Installer._create_directories()

        # 创建快捷方式
        if Installer._prompt("创建桌面快捷方式?"):
            Installer._create_shortcut()

        # 添加开机自启
        if Installer._prompt("添加开机自启?"):
            Installer._add_startup()

        # 安装服务
        if Installer._prompt("安装实时防护服务 (需要管理员权限)?"):
            Installer._install_service()

        # 创建右键菜单
        if Installer._prompt("添加右键菜单 (扫描文件)?"):
            Installer._add_context_menu()

        print("\n安装完成!")
        print(f"安装目录: {PROJECT_ROOT}")
        print(f"版本: {ENGINE_VERSION}")

    @staticmethod
    def uninstall():
        """卸载"""
        print("天盾 Antivirus 卸载程序")
        print("=" * 50)

        if not Installer._prompt("确认卸载天盾 Antivirus?"):
            return

        # 停止服务
        try:
            from service import TiandunService
            TiandunService.stop()
            TiandunService.uninstall()
        except Exception:
            pass

        # 移除开机自启
        Installer._remove_startup()

        # 移除右键菜单
        Installer._remove_context_menu()

        # 删除文件
        if Installer._prompt("删除所有文件 (包括隔离区)?"):
            shutil.rmtree(PROJECT_ROOT, ignore_errors=True)
            print("文件已删除")

        print("卸载完成!")

    @staticmethod
    def _create_directories():
        """创建目录结构"""
        dirs = [
            PROJECT_ROOT,
            PROJECT_ROOT / 'logs',
            PROJECT_ROOT / 'quarantine',
            PROJECT_ROOT / 'engine' / 'signatures',
            PROJECT_ROOT / 'engine' / 'heuristic',
            PROJECT_ROOT / 'engine' / 'behavior',
            PROJECT_ROOT / 'engine' / 'cloud',
            PROJECT_ROOT / 'self-protection',
            PROJECT_ROOT / 'cleanup',
            PROJECT_ROOT / 'firewall',
            PROJECT_ROOT / 'ui',
            PROJECT_ROOT / 'tools',
            PROJECT_ROOT / 'tests',
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
        print(f"目录结构已创建: {PROJECT_ROOT}")

    @staticmethod
    def _create_shortcut():
        """创建桌面快捷方式"""
        try:
            desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
            shortcut_path = os.path.join(desktop, '天盾 Antivirus.lnk')

            ps_script = f'''
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{sys.executable}"
            $Shortcut.Arguments = "{PROJECT_ROOT / 'main.py'}"
            $Shortcut.WorkingDirectory = "{PROJECT_ROOT}"
            $Shortcut.Description = "天盾 Antivirus v{ENGINE_VERSION}"
            $Shortcut.Save()
            '''
            subprocess.run(['powershell', '-Command', ps_script],
                         capture_output=True, timeout=10)
            print("桌面快捷方式已创建")
        except Exception as e:
            print(f"创建快捷方式失败: {e}")

    @staticmethod
    def _add_startup():
        """添加开机自启"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Run',
                0, winreg.KEY_WRITE
            )
            winreg.SetValueEx(
                key, 'TiandunAntivirus', 0, winreg.REG_SZ,
                f'"{sys.executable}" "{PROJECT_ROOT / "main.py"}" --daemon'
            )
            winreg.CloseKey(key)
            print("开机自启已添加")
        except Exception as e:
            print(f"添加开机自启失败: {e}")

    @staticmethod
    def _remove_startup():
        """移除开机自启"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Run',
                0, winreg.KEY_WRITE
            )
            try:
                winreg.DeleteValue(key, 'TiandunAntivirus')
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

    @staticmethod
    def _install_service():
        """安装服务"""
        try:
            from service import TiandunService
            TiandunService.install()
            TiandunService.start()
            print("实时防护服务已安装并启动")
        except Exception as e:
            print(f"安装服务失败: {e}")

    @staticmethod
    def _add_context_menu():
        """添加右键菜单"""
        try:
            # "扫描" 菜单
            key_path = r'*\shell\TiandunScan'
            key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '使用天盾扫描')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, str(PROJECT_ROOT / 'ui' / 'resources' / 'icon.ico'))
            winreg.CloseKey(key)

            cmd_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, rf'{key_path}\command')
            winreg.SetValueEx(cmd_key, '', 0, winreg.REG_SZ,
                            f'"{sys.executable}" "{PROJECT_ROOT / "main.py"}" --scan-path "%1"')
            winreg.CloseKey(cmd_key)

            # 文件夹菜单
            folder_key_path = r'Directory\shell\TiandunScan'
            folder_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, folder_key_path)
            winreg.SetValueEx(folder_key, '', 0, winreg.REG_SZ, '使用天盾扫描文件夹')
            winreg.CloseKey(folder_key)

            folder_cmd = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, rf'{folder_key_path}\command')
            winreg.SetValueEx(folder_cmd, '', 0, winreg.REG_SZ,
                            f'"{sys.executable}" "{PROJECT_ROOT / "main.py"}" --scan-path "%1"')
            winreg.CloseKey(folder_cmd)

            print("右键菜单已添加")
        except Exception as e:
            print(f"添加右键菜单失败: {e}")

    @staticmethod
    def _remove_context_menu():
        """移除右键菜单"""
        try:
            subprocess.run(
                ['reg', 'delete', r'HKCR\*\shell\TiandunScan', '/f'],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ['reg', 'delete', r'HKCR\Directory\shell\TiandunScan', '/f'],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    @staticmethod
    def _prompt(message: str) -> bool:
        """用户确认提示"""
        response = input(f"{message} (Y/n): ").strip().lower()
        return response in ('', 'y', 'yes')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'uninstall':
        Installer.uninstall()
    else:
        Installer.install()