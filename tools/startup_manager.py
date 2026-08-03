#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 启动项管理器
"""
import os
import sys
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class StartupManager:
    """启动项管理器"""

    @staticmethod
    def get_startup_items() -> List[Dict]:
        """获取所有启动项"""
        items = []

        # 注册表启动项
        try:
            import winreg
            startup_keys = [
                (winreg.HKEY_CURRENT_USER,
                 r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_CURRENT_USER,
                 r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
            ]

            for hive, key_path in startup_keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({
                                'name': name,
                                'command': str(value),
                                'location': '注册表',
                                'key_path': f'{hive}\\{key_path}',
                                'enabled': True,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except Exception:
            pass

        # 启动文件夹
        startup_dirs = [
            os.path.join(os.environ.get('APPDATA', ''),
                        'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            os.path.join(os.environ.get('PROGRAMDATA', ''),
                        'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        ]

        for startup_dir in startup_dirs:
            if os.path.exists(startup_dir):
                for f in os.listdir(startup_dir):
                    fpath = os.path.join(startup_dir, f)
                    if os.path.isfile(fpath):
                        items.append({
                            'name': f,
                            'command': fpath,
                            'location': '启动文件夹',
                            'key_path': startup_dir,
                            'enabled': True,
                        })

        # 计划任务
        try:
            import subprocess
            result = subprocess.run(
                'schtasks /query /fo csv /v',
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) > 3:
                        items.append({
                            'name': parts[0].strip('"'),
                            'command': parts[-1].strip('"') if parts[-1] else '',
                            'location': '计划任务',
                            'key_path': '',
                            'enabled': True,
                        })
        except Exception:
            pass

        return items

    @staticmethod
    def disable_item(item: Dict) -> bool:
        """禁用启动项"""
        try:
            if item['location'] == '注册表':
                import winreg
                hive, key_path = item['key_path'].split('\\', 1)
                hive_map = {
                    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                }
                h = hive_map.get(hive, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(h, key_path, 0, winreg.KEY_WRITE)
                winreg.DeleteValue(key, item['name'])
                winreg.CloseKey(key)
                return True
            elif item['location'] == '启动文件夹':
                import os
                os.rename(item['command'], item['command'] + '.disabled')
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def enable_item(item: Dict) -> bool:
        """启用启动项"""
        try:
            if item['location'] == '启动文件夹':
                disabled_path = item['command'] + '.disabled'
                if os.path.exists(disabled_path):
                    os.rename(disabled_path, item['command'])
                    return True
        except Exception:
            pass
        return False