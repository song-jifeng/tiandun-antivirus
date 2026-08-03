#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 系统托盘通知管理器
"""
import os
import sys
import time
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime

from engine.logger import logger
from engine.config import config


class Notifier:
    """通知管理器 - 系统托盘通知和弹窗提醒"""

    def __init__(self):
        self._enabled = config.get('general.show_notifications', True)
        self._queue: List[Dict] = []
        self._lock = threading.Lock()

    def notify(self, title: str, message: str, level: str = 'info',
               timeout: int = 5, action: Optional[str] = None):
        """发送通知"""
        if not self._enabled:
            return

        notification = {
            'title': title,
            'message': message,
            'level': level,
            'timeout': timeout,
            'action': action,
            'timestamp': time.time(),
        }

        # 记录日志
        log_msg = f"[{level.upper()}] {title}: {message}"
        if level == 'error':
            logger.error(log_msg)
        elif level == 'warning':
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

        # 尝试系统通知
        try:
            self._show_notification(notification)
        except Exception:
            pass

        with self._lock:
            self._queue.append(notification)
            if len(self._queue) > 100:
                self._queue.pop(0)

    def _show_notification(self, notification: Dict):
        """显示系统通知"""
        title = notification['title']
        message = notification['message']
        level = notification['level']

        if sys.platform == 'win32':
            try:
                from win32api import MessageBox
                icon_map = {'info': 64, 'warning': 48, 'error': 16}
                icon = icon_map.get(level, 64)
                MessageBox(0, message, title, icon | 0x1000)  # 0x1000 = MB_SYSTEMMODAL
            except Exception:
                # 尝试使用 PowerShell 通知
                import subprocess
                ps_script = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $textNodes = $template.GetElementsByTagName("text")
                $textNodes.Item(0).AppendChild($template.CreateTextNode("{title}")) > $null
                $textNodes.Item(1).AppendChild($template.CreateTextNode("{message}")) > $null
                $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier().Show($toast)
                '''
                subprocess.run(['powershell', '-Command', ps_script],
                             capture_output=True, timeout=5)
        else:
            print(f"\n[{level.upper()}] {title}: {message}")

    def threat_alert(self, threat_name: str, file_path: str, level: int):
        """威胁告警通知"""
        level_names = {5: '严重', 4: '高危', 3: '中等', 2: '低危', 1: '信息'}
        level_name = level_names.get(level, '未知')
        title = f"发现{level_name}威胁 - {threat_name}"
        message = f"文件: {os.path.basename(file_path)}\n威胁: {threat_name}\n请及时处理"
        self.notify(title, message, 'warning' if level >= 4 else 'info')

    def scan_complete(self, total: int, threats: int, duration: float):
        """扫描完成通知"""
        title = "扫描完成"
        if threats > 0:
            title = f"扫描完成 - 发现 {threats} 个威胁"
        message = f"扫描文件: {total}\n发现威胁: {threats}\n耗时: {duration:.1f}秒"
        level = 'warning' if threats > 0 else 'info'
        self.notify(title, message, level)

    def update_available(self, version: str):
        """更新可用通知"""
        self.notify(
            "更新可用",
            f"天盾 Antivirus {version} 版本已可用，请更新",
            'info'
        )

    def protection_status(self, enabled: bool):
        """防护状态变更通知"""
        status = "已启用" if enabled else "已禁用"
        self.notify("实时防护", f"实时防护{status}", 'info')

    def get_history(self, limit: int = 20) -> List[Dict]:
        """获取通知历史"""
        with self._lock:
            return list(self._queue)[-limit:]


# ============================================================
# 全局通知器
# ============================================================
notifier = Notifier()