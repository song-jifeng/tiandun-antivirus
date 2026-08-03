#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 任务调度器补充
定时任务管理与执行
"""
import os
import sys
import time
import json
import threading
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TaskScheduler:
    """高级任务调度器"""

    def __init__(self):
        self._tasks = []
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    class Task:
        def __init__(self, name: str, callback: Callable, interval: int,
                     delay: int = 0, enabled: bool = True):
            self.name = name
            self.callback = callback
            self.interval = interval
            self.delay = delay
            self.enabled = enabled
            self.last_run = 0
            self.next_run = time.time() + delay
            self.run_count = 0
            self.error_count = 0
            self.last_error = ''

    def add_task(self, name: str, callback: Callable, interval_hours: int,
                 delay_minutes: int = 0, enabled: bool = True):
        task = self.Task(name, callback, interval_hours * 3600,
                        delay_minutes * 60, enabled)
        with self._lock:
            self._tasks.append(task)
        return task

    def remove_task(self, name: str):
        with self._lock:
            self._tasks = [t for t in self._tasks if t.name != name]

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            now = time.time()
            with self._lock:
                for task in self._tasks:
                    if not task.enabled:
                        continue
                    if now >= task.next_run:
                        threading.Thread(target=self._execute,
                                       args=(task,), daemon=True).start()
                        task.last_run = now
                        task.next_run = now + task.interval
                        task.run_count += 1
            time.sleep(10)

    def _execute(self, task):
        try:
            task.callback()
        except Exception as e:
            task.error_count += 1
            task.last_error = str(e)

    def get_status(self) -> List[Dict]:
        with self._lock:
            return [{
                'name': t.name, 'enabled': t.enabled,
                'interval_hours': t.interval / 3600,
                'last_run': datetime.fromtimestamp(t.last_run).isoformat() if t.last_run else '',
                'next_run': datetime.fromtimestamp(t.next_run).isoformat(),
                'run_count': t.run_count,
                'error_count': t.error_count,
                'last_error': t.last_error,
            } for t in self._tasks]


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self):
        self._metrics = {}
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._monitor, daemon=True).start()

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            try:
                import psutil
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                self._metrics['cpu'] = cpu
                self._metrics['memory_percent'] = mem.percent
                self._metrics['memory_available'] = mem.available
                self._metrics['disk_percent'] = disk.percent
                self._metrics['disk_free'] = disk.free
                self._metrics['timestamp'] = time.time()
            except Exception:
                pass
            time.sleep(5)

    def get_metrics(self) -> Dict:
        return dict(self._metrics)

    def get_resource_usage(self) -> Dict:
        try:
            import psutil
            proc = psutil.Process()
            return {
                'cpu_percent': proc.cpu_percent(),
                'memory_rss': proc.memory_info().rss,
                'memory_vms': proc.memory_info().vms,
                'num_threads': proc.num_threads(),
                'num_handles': proc.num_handles() if hasattr(proc, 'num_handles') else 0,
                'io_read_bytes': proc.io_counters().read_bytes if proc.io_counters() else 0,
                'io_write_bytes': proc.io_counters().write_bytes if proc.io_counters() else 0,
            }
        except Exception:
            return {}


class DatabaseManager:
    """数据库管理器"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(
            os.environ.get('TIANDUN_ROOT', 'D:/Antivirus'),
            'data', 'tiandun.db'
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._data = {}

    def save(self, key: str, value):
        self._data[key] = value
        self._persist()

    def load(self, key: str, default=None):
        self._load()
        return self._data.get(key, default)

    def _persist(self):
        try:
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _load(self):
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self._data = json.load(f)
        except Exception:
            pass


class StatisticCollector:
    """统计信息收集器"""

    def __init__(self):
        self._stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'threats_cleaned': 0,
            'files_quarantined': 0,
            'network_blocks': 0,
            'usb_scans': 0,
            'start_time': time.time(),
            'last_update': time.time(),
        }
        self._lock = threading.Lock()

    def increment(self, key: str, amount: int = 1):
        with self._lock:
            if key in self._stats:
                self._stats[key] += amount
            self._stats['last_update'] = time.time()

    def get(self, key: str) -> int:
        with self._lock:
            return self._stats.get(key, 0)

    def get_all(self) -> Dict:
        with self._lock:
            stats = dict(self._stats)
            stats['uptime'] = time.time() - stats['start_time']
            return stats

    def reset(self):
        with self._lock:
            self._stats = {
                'files_scanned': 0, 'threats_detected': 0,
                'threats_cleaned': 0, 'files_quarantined': 0,
                'network_blocks': 0, 'usb_scans': 0,
                'start_time': time.time(), 'last_update': time.time(),
            }


class AlertManager:
    """告警管理器"""

    def __init__(self):
        self._alerts = []
        self._max_alerts = 1000
        self._lock = threading.Lock()

    def add_alert(self, level: str, source: str, message: str,
                  details: Dict = None):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'source': source,
            'message': message,
            'details': details or {},
        }
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts:]

    def get_alerts(self, level: str = None, limit: int = 50) -> List[Dict]:
        with self._lock:
            alerts = self._alerts
            if level:
                alerts = [a for a in alerts if a['level'] == level]
            return alerts[-limit:]

    def get_stats(self) -> Dict:
        with self._lock:
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for a in self._alerts:
                lvl = a['level'].lower()
                if lvl in counts:
                    counts[lvl] += 1
            return counts


class CacheManager:
    """缓存管理器"""

    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        self._cache = {}
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                if time.time() < expiry:
                    return value
                del self._cache[key]
            return None

    def set(self, key: str, value, ttl: int = None):
        with self._lock:
            expiry = time.time() + (ttl or self._ttl)
            self._cache[key] = (value, expiry)
            if len(self._cache) > self._max_size:
                oldest = min(self._cache.keys(),
                           key=lambda k: self._cache[k][1])
                del self._cache[oldest]

    def clear(self):
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


class EventBus:
    """事件总线 - 模块间通信"""

    def __init__(self):
        self._listeners = {}
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable):
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            self._listeners[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable):
        with self._lock:
            if event_type in self._listeners:
                self._listeners[event_type] = [
                    cb for cb in self._listeners[event_type]
                    if cb != callback
                ]

    def emit(self, event_type: str, data: Dict = None):
        with self._lock:
            callbacks = list(self._listeners.get(event_type, []))
        for callback in callbacks:
            try:
                callback(data or {})
            except Exception:
                pass


# Global instances
scheduler = TaskScheduler()
performance_monitor = PerformanceMonitor()
statistics = StatisticCollector()
alerts = AlertManager()
event_bus = EventBus()