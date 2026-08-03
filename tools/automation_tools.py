#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 定时任务与自动化工具
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
    """任务调度器"""

    def __init__(self):
        self._tasks = []
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def add_task(self, name: str, callback: Callable, interval_hours: int,
                 delay_minutes: int = 0, enabled: bool = True) -> str:
        task_id = f"task_{int(time.time())}_{len(self._tasks)}"
        task = {
            'id': task_id,
            'name': name,
            'callback': callback,
            'interval': interval_hours * 3600,
            'delay': delay_minutes * 60,
            'enabled': enabled,
            'last_run': 0,
            'next_run': time.time() + delay_minutes * 60,
            'run_count': 0,
            'error_count': 0,
            'last_error': '',
            'created': time.time(),
        }
        with self._lock:
            self._tasks.append(task)
        return task_id

    def remove_task(self, task_id: str):
        with self._lock:
            self._tasks = [t for t in self._tasks if t['id'] != task_id]

    def enable_task(self, task_id: str):
        with self._lock:
            for t in self._tasks:
                if t['id'] == task_id:
                    t['enabled'] = True
                    break

    def disable_task(self, task_id: str):
        with self._lock:
            for t in self._tasks:
                if t['id'] == task_id:
                    t['enabled'] = False
                    break

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
                    if not task['enabled']:
                        continue
                    if now >= task['next_run']:
                        threading.Thread(target=self._execute,
                                       args=(task,), daemon=True).start()
                        task['last_run'] = now
                        task['next_run'] = now + task['interval']
                        task['run_count'] += 1
            time.sleep(15)

    def _execute(self, task):
        try:
            task['callback']()
        except Exception as e:
            task['error_count'] += 1
            task['last_error'] = str(e)

    def get_tasks(self) -> List[Dict]:
        with self._lock:
            return [{
                'id': t['id'], 'name': t['name'],
                'enabled': t['enabled'],
                'interval_hours': t['interval'] / 3600,
                'last_run': datetime.fromtimestamp(t['last_run']).isoformat() if t['last_run'] else '',
                'next_run': datetime.fromtimestamp(t['next_run']).isoformat(),
                'run_count': t['run_count'],
                'error_count': t['error_count'],
                'last_error': t['last_error'],
            } for t in self._tasks]

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'total_tasks': len(self._tasks),
                'enabled_tasks': sum(1 for t in self._tasks if t['enabled']),
                'total_runs': sum(t['run_count'] for t in self._tasks),
                'total_errors': sum(t['error_count'] for t in self._tasks),
            }


class CronParser:
    """Cron表达式解析器"""

    @staticmethod
    def parse(expression: str) -> Dict:
        parts = expression.strip().split()
        if len(parts) != 5:
            return {'error': 'Invalid cron expression, need 5 fields'}
        fields = ['minute', 'hour', 'day_of_month', 'month', 'day_of_week']
        return {fields[i]: CronParser._parse_field(parts[i], field) for i, field in enumerate(fields)}

    @staticmethod
    def _parse_field(field: str, name: str) -> Dict:
        result = {'expression': field, 'values': []}
        if field == '*':
            return result
        try:
            if '/' in field:
                base, step = field.split('/')
                result['step'] = int(step)
                if base == '*':
                    ranges = {'minute': (0, 59), 'hour': (0, 23),
                             'day_of_month': (1, 31), 'month': (1, 12),
                             'day_of_week': (0, 6)}
                    start, end = ranges.get(name, (0, 59))
                    result['values'] = list(range(start, end + 1, int(step)))
            elif '-' in field:
                start, end = field.split('-')
                result['values'] = list(range(int(start), int(end) + 1))
            elif ',' in field:
                result['values'] = [int(v) for v in field.split(',')]
            else:
                result['values'] = [int(field)]
        except (ValueError, IndexError):
            result['error'] = f'Cannot parse field: {field}'
        return result


class RecurringTask:
    """循环任务"""

    def __init__(self, name: str, callback: Callable, interval: int,
                 max_runs: int = -1):
        self.name = name
        self.callback = callback
        self.interval = interval
        self.max_runs = max_runs
        self.run_count = 0
        self._running = False
        self._thread = None

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
            if self.max_runs > 0 and self.run_count >= self.max_runs:
                break
            try:
                self.callback()
                self.run_count += 1
            except Exception:
                pass
            time.sleep(self.interval)


class ScheduledScan:
    """定时扫描"""

    def __init__(self, scanner):
        self.scanner = scanner
        self._tasks = []

    def add_daily_scan(self, hour: int = 3, minute: int = 0):
        """添加每日扫描"""
        def scan_task():
            self.scanner.quick_scan()
        delay = (hour * 3600 + minute * 60) - (time.time() % 86400)
        if delay < 0:
            delay += 86400
        task = RecurringTask('daily_scan', scan_task, 86400)
        self._tasks.append(task)
        return task

    def add_weekly_scan(self, day: int = 0, hour: int = 3):
        """添加每周扫描"""
        def scan_task():
            self.scanner.full_scan()
        task = RecurringTask('weekly_scan', scan_task, 604800)
        self._tasks.append(task)
        return task

    def start_all(self):
        for task in self._tasks:
            task.start()

    def stop_all(self):
        for task in self._tasks:
            task.stop()


class AutoUpdater:
    """自动更新器"""

    def __init__(self, check_interval: int = 86400):
        self.check_interval = check_interval
        self._task = None

    def start(self, update_func: Callable):
        def check_update():
            try:
                update_func()
            except Exception:
                pass
        self._task = RecurringTask('auto_update', check_update, self.check_interval)
        self._task.start()

    def stop(self):
        if self._task:
            self._task.stop()


class BatchProcessor:
    """批处理执行器"""

    @staticmethod
    def process_items(items: list, processor: Callable,
                      max_workers: int = 4, show_progress: bool = True) -> Dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results = {'total': len(items), 'success': 0, 'failed': 0, 'errors': []}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(processor, item): item for item in items}
            for i, future in enumerate(as_completed(futures)):
                item = futures[future]
                try:
                    future.result()
                    results['success'] += 1
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append({'item': str(item), 'error': str(e)})
                if show_progress and (i + 1) % max(1, len(items) // 10) == 0:
                    pct = (i + 1) / len(items) * 100
                    print(f"  Progress: {i + 1}/{len(items)} ({pct:.0f}%)")
        return results

    @staticmethod
    def retry(func: Callable, max_retries: int = 3, delay: int = 1):
        """重试装饰器"""
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))
            raise last_error
        return wrapper


class Pipeline:
    """管道处理"""

    def __init__(self, stages: List[Callable]):
        self.stages = stages

    def process(self, data):
        result = data
        for stage in self.stages:
            result = stage(result)
        return result

    def process_batch(self, items: list) -> list:
        results = []
        for item in items:
            results.append(self.process(item))
        return results


class EventEmitter:
    """事件发射器"""

    def __init__(self):
        self._listeners = {}

    def on(self, event: str, callback: Callable):
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable):
        if event in self._listeners:
            self._listeners[event] = [cb for cb in self._listeners[event] if cb != callback]

    def emit(self, event: str, *args, **kwargs):
        for callback in self._listeners.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception:
                pass

    def once(self, event: str, callback: Callable):
        def wrapper(*args, **kwargs):
            self.off(event, wrapper)
            callback(*args, **kwargs)
        self.on(event, wrapper)

    def remove_all(self, event: str = None):
        if event:
            self._listeners.pop(event, None)
        else:
            self._listeners.clear()


class StateMachine:
    """状态机"""

    def __init__(self, initial_state: str):
        self._state = initial_state
        self._transitions = {}
        self._on_enter = {}
        self._on_exit = {}
        self._lock = threading.Lock()

    def add_transition(self, from_state: str, to_state: str, event: str):
        if from_state not in self._transitions:
            self._transitions[from_state] = {}
        self._transitions[from_state][event] = to_state

    def on_enter(self, state: str, callback: Callable):
        self._on_enter[state] = callback

    def on_exit(self, state: str, callback: Callable):
        self._on_exit[state] = callback

    def trigger(self, event: str):
        with self._lock:
            transitions = self._transitions.get(self._state, {})
            next_state = transitions.get(event)
            if next_state is None:
                raise ValueError(f"No transition from {self._state} with event {event}")
            if self._state in self._on_exit:
                self._on_exit[self._state]()
            old_state = self._state
            self._state = next_state
            if self._state in self._on_enter:
                self._on_enter[self._state]()
            return old_state, self._state

    @property
    def state(self):
        return self._state


class Workflow:
    """工作流引擎"""

    def __init__(self, name: str):
        self.name = name
        self._steps = []
        self._current_step = -1
        self._results = {}

    def add_step(self, name: str, action: Callable, retry: int = 0):
        self._steps.append({
            'name': name,
            'action': action,
            'retry': retry,
            'status': 'pending',
        })

    def run(self, context: Dict = None) -> Dict:
        if context is None:
            context = {}
        for i, step in enumerate(self._steps):
            self._current_step = i
            step['status'] = 'running'
            attempts = 0
            while attempts <= step['retry']:
                try:
                    result = step['action'](context)
                    self._results[step['name']] = result
                    step['status'] = 'completed'
                    break
                except Exception as e:
                    attempts += 1
                    if attempts > step['retry']:
                        step['status'] = 'failed'
                        step['error'] = str(e)
                        return {'success': False, 'step': step['name'], 'error': str(e)}
        return {'success': True, 'results': self._results}

    def get_progress(self) -> Dict:
        return {
            'name': self.name,
            'total': len(self._steps),
            'current': self._current_step + 1,
            'steps': [{'name': s['name'], 'status': s['status']} for s in self._steps],
        }


class ConditionalExecutor:
    """条件执行器"""

    @staticmethod
    def if_true(condition: Callable, action: Callable, else_action: Callable = None):
        if condition():
            return action()
        elif else_action:
            return else_action()
        return None

    @staticmethod
    def switch(value, cases: Dict, default: Callable = None):
        action = cases.get(value, default)
        if action:
            return action()
        return None

    @staticmethod
    def retry_on_failure(func: Callable, max_retries: int = 3, delay: int = 1):
        for i in range(max_retries):
            try:
                return func()
            except Exception:
                if i < max_retries - 1:
                    time.sleep(delay)
                else:
                    raise


class AsyncTask:
    """异步任务"""

    def __init__(self, func: Callable, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._result = None
        self._error = None
        self._completed = False
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self._result = self.func(*self.args, **self.kwargs)
        except Exception as e:
            self._error = e
        finally:
            self._completed = True

    def is_completed(self) -> bool:
        return self._completed

    def get_result(self, timeout: float = None):
        if self._thread:
            self._thread.join(timeout)
        if self._error:
            raise self._error
        return self._result

    def wait(self, timeout: float = None):
        if self._thread:
            self._thread.join(timeout)
        return self._completed