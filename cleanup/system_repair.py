#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 系统修复模块
"""
import os
import sys
import shutil
import subprocess
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.logger import logger
from engine.config import config


class SystemRepair:
    """系统修复器"""

    @staticmethod
    def repair_hosts() -> Dict:
        """修复 Hosts 文件"""
        result = {'success': False, 'message': ''}
        try:
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 备份原始文件
                backup = hosts_path + '.tiandun_backup'
                if not os.path.exists(backup):
                    shutil.copy2(hosts_path, backup)

                # 移除恶意条目
                malicious_patterns = [
                    '127.0.0.1', '0.0.0.0',
                ]
                safe_lines = []
                modified = False
                for line in content.split('\n'):
                    should_remove = False
                    for pattern in malicious_patterns:
                        if pattern in line.lower() and any(s in line.lower()
                            for s in ['update', 'security', 'antivirus', 'microsoft']):
                            should_remove = True
                            modified = True
                            break
                    if not should_remove:
                        safe_lines.append(line)

                if modified:
                    with open(hosts_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(safe_lines))
                    result = {'success': True, 'message': 'Hosts 文件已修复'}
                else:
                    result = {'success': True, 'message': 'Hosts 文件无需修复'}
            else:
                result = {'success': True, 'message': 'Hosts 文件不存在，已创建默认文件'}
                with open(hosts_path, 'w', encoding='utf-8') as f:
                    f.write('# Copyright (c) 1993-2009 Microsoft Corp.\n')
                    f.write('# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n\n')
                    f.write('127.0.0.1       localhost\n')
                    f.write('::1             localhost\n')
        except Exception as e:
            result = {'success': False, 'message': f'修复 Hosts 失败: {e}'}

        return result

    @staticmethod
    def repair_file_associations() -> Dict:
        """修复文件关联"""
        result = {'success': False, 'message': ''}
        try:
            # 修复常见文件关联
            associations = {
                '.exe': 'exefile',
                '.txt': 'txtfile',
                '.bat': 'batfile',
                '.cmd': 'cmdfile',
                '.reg': 'regfile',
                '.vbs': 'VBSFile',
                '.js': 'JSFile',
                '.pdf': 'AcroExch.Document.DC',
            }
            for ext, progid in associations.items():
                subprocess.run(
                    f'assoc {ext}={progid}',
                    shell=True, capture_output=True, timeout=5
                )
            result = {'success': True, 'message': '文件关联已修复'}
        except Exception as e:
            result = {'success': False, 'message': f'修复文件关联失败: {e}'}

        return result

    @staticmethod
    def repair_browser_settings() -> Dict:
        """修复浏览器设置"""
        result = {'success': False, 'message': ''}
        try:
            import winreg
            # 修复 IE 主页
            ie_key = r'Software\Microsoft\Internet Explorer\Main'
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ie_key, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'Start Page', 0, winreg.REG_SZ, 'about:blank')
                winreg.SetValueEx(key, 'Default_Page_URL', 0, winreg.REG_SZ, 'about:blank')
                winreg.CloseKey(key)
            except Exception:
                pass

            # 修复搜索提供程序
            search_key = r'Software\Microsoft\Internet Explorer\SearchScopes'
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, search_key, 0, winreg.KEY_WRITE)
                # 枚举子键
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(key, i)
                        sub_key_path = f'{search_key}\\{subkey}'
                        sk = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key_path, 0, winreg.KEY_WRITE)
                        url = winreg.QueryValueEx(sk, 'URL')[0]
                        if 'bing' in url.lower() or 'baidu' in url.lower() or 'google' in url.lower():
                            pass  # 合法搜索引擎
                        else:
                            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub_key_path)
                        winreg.CloseKey(sk)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass

            result = {'success': True, 'message': '浏览器设置已修复'}
        except Exception as e:
            result = {'success': False, 'message': f'修复浏览器失败: {e}'}

        return result

    @staticmethod
    def repair_system_files() -> Dict:
        """修复系统文件 - 使用 SFC"""
        result = {'success': False, 'message': ''}
        try:
            logger.info("正在运行系统文件检查器 (SFC)...")
            subprocess.run('sfc /scannow', shell=True, timeout=600)
            result = {'success': True, 'message': '系统文件检查完成'}
        except subprocess.TimeoutExpired:
            result = {'success': True, 'message': '系统文件检查超时，建议手动运行 sfc /scannow'}
        except Exception as e:
            result = {'success': False, 'message': f'SFC 运行失败: {e}'}

        return result

    @staticmethod
    def repair_network() -> Dict:
        """修复网络设置"""
        result = {'success': False, 'message': ''}
        try:
            commands = [
                'netsh winsock reset',
                'netsh int ip reset',
                'netsh advfirewall reset',
                'ipconfig /flushdns',
                'ipconfig /release',
                'ipconfig /renew',
            ]
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
                except Exception:
                    pass
            result = {'success': True, 'message': '网络设置已重置'}
        except Exception as e:
            result = {'success': False, 'message': f'修复网络失败: {e}'}

        return result

    @staticmethod
    def repair_all() -> Dict:
        """执行所有修复"""
        results = {}
        if config.get('cleanup.repair_hosts', True):
            results['hosts'] = SystemRepair.repair_hosts()
        if config.get('cleanup.repair_association', True):
            results['associations'] = SystemRepair.repair_file_associations()
        if config.get('cleanup.repair_browser', True):
            results['browser'] = SystemRepair.repair_browser_settings()
        results['network'] = SystemRepair.repair_network()

        return {
            'success': all(r.get('success', False) for r in results.values()),
            'details': results,
        }


# ============================================================
# 全局系统修复器
# ============================================================
system_repair = SystemRepair()