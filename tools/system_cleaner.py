#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 系统清理工具
"""
import os
import sys
import shutil
from typing import Dict, List
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.logger import logger


class SystemCleaner:
    """系统清理器"""

    @staticmethod
    def clean_temp_files(dry_run: bool = False, max_files: int = 500) -> Dict:
        """清理临时文件

        Args:
            dry_run: 如果为 True，只统计不删除
            max_files: 最大处理文件数，防止长时间挂起
        """
        cleaned = 0
        freed_bytes = 0
        errors = []

        temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Temp'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
        ]

        for temp_dir in temp_dirs:
            if not temp_dir or not os.path.exists(temp_dir):
                continue
            if cleaned >= max_files:
                break
            try:
                # 使用 scandir 代替 os.walk 以提高性能
                for entry in os.scandir(temp_dir):
                    if cleaned >= max_files:
                        break
                    try:
                        if entry.is_file():
                            size = entry.stat().st_size
                            if not dry_run:
                                os.remove(entry.path)
                            cleaned += 1
                            freed_bytes += size
                        elif entry.is_dir():
                            # 只清理一层深度的目录
                            try:
                                for sub_entry in os.scandir(entry.path):
                                    if cleaned >= max_files:
                                        break
                                    if sub_entry.is_file():
                                        size = sub_entry.stat().st_size
                                        if not dry_run:
                                            os.remove(sub_entry.path)
                                        cleaned += 1
                                        freed_bytes += size
                                    elif sub_entry.is_dir():
                                        if not dry_run:
                                            shutil.rmtree(sub_entry.path, ignore_errors=True)
                                        cleaned += 1
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception as e:
                errors.append(str(e))

        return {
            'success': len(errors) == 0,
            'cleaned': cleaned,
            'freed_bytes': freed_bytes,
            'freed_mb': round(freed_bytes / (1024 * 1024), 1),
            'errors': errors,
        }

    @staticmethod
    def clean_browser_cache() -> Dict:
        """清理浏览器缓存"""
        cleaned = 0
        freed_bytes = 0
        errors = []

        cache_dirs = []

        # Chrome
        chrome_cache = os.path.join(
            os.environ.get('LOCALAPPDATA', ''),
            r'Google\Chrome\User Data\Default\Cache'
        )
        if os.path.exists(chrome_cache):
            cache_dirs.append(chrome_cache)

        # Edge
        edge_cache = os.path.join(
            os.environ.get('LOCALAPPDATA', ''),
            r'Microsoft\Edge\User Data\Default\Cache'
        )
        if os.path.exists(edge_cache):
            cache_dirs.append(edge_cache)

        # Firefox
        firefox_profiles = os.path.join(
            os.environ.get('APPDATA', ''),
            r'Mozilla\Firefox\Profiles'
        )
        if os.path.exists(firefox_profiles):
            for profile in os.listdir(firefox_profiles):
                cache = os.path.join(firefox_profiles, profile, 'cache2')
                if os.path.exists(cache):
                    cache_dirs.append(cache)

        for cache_dir in cache_dirs:
            try:
                for root, dirs, files in os.walk(cache_dir):
                    for f in files:
                        try:
                            fpath = os.path.join(root, f)
                            freed_bytes += os.path.getsize(fpath)
                            os.remove(fpath)
                            cleaned += 1
                        except Exception:
                            pass
            except Exception as e:
                errors.append(str(e))

        return {
            'success': len(errors) == 0,
            'cleaned': cleaned,
            'freed_bytes': freed_bytes,
            'freed_mb': round(freed_bytes / (1024 * 1024), 1),
            'errors': errors,
        }

    @staticmethod
    def clean_recycle_bin() -> Dict:
        """清空回收站"""
        try:
            import subprocess
            subprocess.run('rd /s /q C:\\$Recycle.Bin', shell=True,
                         capture_output=True, timeout=30)
            return {'success': True, 'message': '回收站已清空'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    @staticmethod
    def clean_all() -> Dict:
        """执行所有清理"""
        results = {}
        results['temp'] = SystemCleaner.clean_temp_files()
        results['browser'] = SystemCleaner.clean_browser_cache()
        return {
            'success': results['temp']['success'],
            'details': results,
        }