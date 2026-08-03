#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 文件恢复模块
"""
import os
import sys
import shutil
import subprocess
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.logger import logger


class FileRecovery:
    """文件恢复器"""

    @staticmethod
    def recover_hidden_files(directory: str) -> Dict:
        """恢复被隐藏的文件"""
        result = {'success': False, 'recovered': 0, 'message': ''}
        try:
            recovered = 0
            for root, dirs, files in os.walk(directory):
                for name in files + dirs:
                    path = os.path.join(root, name)
                    try:
                        # 检查隐藏属性
                        if sys.platform == 'win32':
                            import ctypes
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
                            if attrs != -1 and attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                                new_attrs = attrs & ~2
                                ctypes.windll.kernel32.SetFileAttributesW(path, new_attrs)
                                recovered += 1
                    except Exception:
                        pass

            result = {
                'success': True,
                'recovered': recovered,
                'message': f'已恢复 {recovered} 个隐藏文件/文件夹',
            }
        except Exception as e:
            result = {'success': False, 'recovered': 0, 'message': str(e)}

        return result

    @staticmethod
    def recover_file_associations() -> Dict:
        """恢复文件关联"""
        try:
            subprocess.run(
                'assoc .exe=exefile && assoc .txt=txtfile && assoc .bat=batfile',
                shell=True, capture_output=True, timeout=5
            )
            return {'success': True, 'message': '文件关联已恢复'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    @staticmethod
    def recover_desktop_icons() -> Dict:
        """恢复桌面图标"""
        try:
            subprocess.run(
                'ie4uinit.exe -show',
                shell=True, capture_output=True, timeout=10
            )
            return {'success': True, 'message': '桌面图标已刷新'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    @staticmethod
    def run_sfc() -> Dict:
        """运行系统文件检查器"""
        try:
            logger.info("正在运行 SFC 系统文件检查...")
            subprocess.run('sfc /scannow', shell=True, timeout=600)
            return {'success': True, 'message': '系统文件检查完成'}
        except subprocess.TimeoutExpired:
            return {'success': False, 'message': '检查超时'}
        except Exception as e:
            return {'success': False, 'message': str(e)}


# ============================================================
# 全局文件恢复器
# ============================================================
file_recovery = FileRecovery()