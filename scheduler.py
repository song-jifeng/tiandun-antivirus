#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 任务调度器
定时扫描、更新、清理
"""
import os
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any, List

from engine.logger import logger
from engine.config import config
from engine import ENGINE_VERSION


class Scheduler:
    """任务调度器"""

    def __init__(self):
        self._running = False
        self._tasks: List[Dict] = []
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def add_task(self, name: str, callback: Callable, interval_hours: int,
                 enabled: bool = True, run_now: bool = False):
        """添加定时任务"""
        task = {
            'name': name,
            'callback': callback,
            'interval': interval_hours * 3600,
            'enabled': enabled,
            'last_run': 0,
            'next_run': time.time() if run_now else time.time() + interval_hours * 3600,
            'run_count': 0,
            'error_count': 0,
        }
        with self._lock:
            self._tasks.append(task)
        logger.info(f"添加定时任务: {name} (间隔: {interval_hours}小时)")

    def remove_task(self, name: str):
        """移除任务"""
        with self._lock:
            self._tasks = [t for t in self._tasks if t['name'] != name]

    def start(self):
        """启动调度器"""
        if self._running:
            return
        self._running = True

        # 添加默认任务
        self.add_task(
            'signature_update',
            self._update_signatures,
            config.get('general.update_interval_hours', 24),
            enabled=True
        )

        self._thread = threading.Thread(target=self._run, name='scheduler', daemon=True)
        self._thread.start()
        logger.info("任务调度器已启动")

    def stop(self):
        """停止调度器"""
        self._running = False
        logger.info("任务调度器已停止")

    def _run(self):
        """调度器主循环"""
        while self._running:
            now = time.time()
            with self._lock:
                for task in self._tasks:
                    if not task['enabled']:
                        continue
                    if now >= task['next_run']:
                        # 在后台线程执行
                        threading.Thread(
                            target=self._execute_task,
                            args=(task,),
                            name=f'task-{task["name"]}',
                            daemon=True
                        ).start()
                        task['last_run'] = now
                        task['next_run'] = now + task['interval']
                        task['run_count'] += 1
            time.sleep(30)  # 每30秒检查一次

    def _execute_task(self, task: Dict):
        """执行任务"""
        try:
            logger.info(f"执行定时任务: {task['name']}")
            task['callback']()
            logger.info(f"定时任务完成: {task['name']}")
        except Exception as e:
            task['error_count'] += 1
            logger.error(f"定时任务失败: {task['name']}: {e}")

    def _update_signatures(self):
        """更新病毒库"""
        try:
            from updater import updater
            updater.update_signatures()
        except Exception as e:
            logger.error(f"定时更新病毒库失败: {e}")

    def get_tasks(self) -> List[Dict]:
        """获取任务列表"""
        with self._lock:
            return [{
                'name': t['name'],
                'enabled': t['enabled'],
                'interval_hours': t['interval'] / 3600,
                'last_run': datetime.fromtimestamp(t['last_run']).isoformat() if t['last_run'] else '',
                'next_run': datetime.fromtimestamp(t['next_run']).isoformat() if t['next_run'] else '',
                'run_count': t['run_count'],
                'error_count': t['error_count'],
            } for t in self._tasks]


# ============================================================
# 全局调度器
# ============================================================
scheduler = Scheduler()