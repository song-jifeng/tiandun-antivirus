#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 勒索软件诱捕系统
"""
import os
import sys
import time
import threading
import hashlib
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import PROJECT_ROOT, HashUtil
from engine.logger import logger
from engine.config import config


class Honeypot:
    """勒索软件诱捕 - 蜜罐文件系统"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._honeypot_files: Dict[str, str] = {}  # path -> original_hash
        self._alerts: List[Dict] = []

    def start(self):
        if self._running:
            return
        self._running = True
        self._create_honeypot()
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
        logger.info("勒索软件诱捕已启动")

    def stop(self):
        self._running = False

    def _create_honeypot(self):
        """创建蜜罐文件"""
        try:
            # 在用户目录创建蜜罐文件
            user_profile = os.environ.get('USERPROFILE', '')
            if not user_profile:
                return

            honeypot_dirs = [
                os.path.join(user_profile, 'Documents'),
                os.path.join(user_profile, 'Desktop'),
                os.path.join(user_profile, 'Pictures'),
                os.path.join(user_profile, 'Downloads'),
            ]

            for directory in honeypot_dirs:
                if not os.path.exists(directory):
                    continue

                # 创建多个蜜罐文件
                honeypot_names = [
                    '重要文档_2026.docx',
                    '财务报告_Q3.xlsx',
                    '项目计划书.pptx',
                    '个人照片合集.zip',
                    '备份文件_2026.bak',
                    '客户资料.docx',
                    '合同模板.pdf',
                    '发票记录.xlsx',
                ]

                import random
                random.seed(42)
                for name in honeypot_names:
                    fpath = os.path.join(directory, name)
                    if os.path.exists(fpath):
                        continue
                    try:
                        # 创建模拟文件
                        content = self._generate_honeypot_content(name)
                        with open(fpath, 'wb') as f:
                            f.write(content)

                        # 设置隐藏属性
                        if sys.platform == 'win32':
                            import ctypes
                            ctypes.windll.kernel32.SetFileAttributesW(
                                fpath, 2  # FILE_ATTRIBUTE_HIDDEN
                            )

                        file_hash = HashUtil.md5_file(fpath)
                        self._honeypot_files[fpath] = file_hash
                        logger.debug(f"蜜罐文件已创建: {fpath}")
                    except Exception:
                        pass

            logger.info(f"蜜罐文件已创建: {len(self._honeypot_files)} 个")

        except Exception as e:
            logger.error(f"创建蜜罐文件失败: {e}")

    def _generate_honeypot_content(self, name: str) -> bytes:
        """生成蜜罐文件内容"""
        ext = os.path.splitext(name)[1].lower()
        if ext == '.docx':
            return b'PK\x03\x04' + os.urandom(1024)  # Office 文档头
        elif ext == '.xlsx':
            return b'PK\x03\x04' + os.urandom(1024)
        elif ext == '.pptx':
            return b'PK\x03\x04' + os.urandom(1024)
        elif ext == '.pdf':
            return b'%PDF-1.4\n' + os.urandom(1024)
        elif ext == '.zip':
            return b'PK\x03\x04' + os.urandom(1024)
        elif ext == '.bak':
            return os.urandom(2048)
        else:
            return os.urandom(1024)

    def _monitor(self):
        """监控蜜罐文件"""
        while self._running:
            try:
                for fpath, original_hash in list(self._honeypot_files.items()):
                    if not os.path.exists(fpath):
                        self._handle_alert('deleted', fpath)
                        continue
                    current_hash = HashUtil.md5_file(fpath)
                    if current_hash != original_hash and current_hash:
                        self._handle_alert('modified', fpath)
            except Exception:
                pass
            time.sleep(3)

    def _handle_alert(self, action: str, filepath: str):
        """处理蜜罐告警"""
        alert = {
            'timestamp': time.time(),
            'action': action,
            'filepath': filepath,
            'filename': os.path.basename(filepath),
        }
        self._alerts.append(alert)

        logger.critical(
            f"勒索软件诱捕告警: 文件被{action} - {filepath}"
        )

        # 触发紧急响应
        self._trigger_response(alert)

    def _trigger_response(self, alert: Dict):
        """触发紧急响应"""
        try:
            # 尝试找到修改文件的进程
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe']:
                        logger.warning(
                            f"可疑进程: {proc.info['name']} (PID: {proc.info['pid']})"
                        )
                except Exception:
                    pass
        except Exception:
            pass

    def get_alerts(self) -> List[Dict]:
        return list(self._alerts)

    def get_stats(self) -> Dict:
        return {
            'honeypot_files': len(self._honeypot_files),
            'alerts': len(self._alerts),
        }


# ============================================================
# 全局蜜罐
# ============================================================
honeypot = Honeypot()