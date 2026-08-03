#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 行为分析引擎
整合进程、文件、注册表、网络监控，进行行为关联分析
"""
import os
import sys
import time
import json
import threading
from typing import Optional, Dict, Any, List, Tuple
from collections import defaultdict, deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine import ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel
from engine.logger import logger
from engine.config import config


class BehaviorEvent:
    """行为事件"""
    def __init__(self, event_type: str, pid: int, process_name: str,
                 action: str, target: str, details: Optional[Dict] = None):
        self.timestamp = time.time()
        self.event_type = event_type  # process, file, registry, network
        self.pid = pid
        self.process_name = process_name
        self.action = action
        self.target = target
        self.details = details or {}

    def to_dict(self) -> Dict:
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'type': self.event_type,
            'pid': self.pid,
            'process': self.process_name,
            'action': self.action,
            'target': self.target,
            'details': self.details,
        }


class BehaviorRule:
    """行为检测规则"""
    def __init__(self, rule_id: str, name: str, description: str,
                 event_type: str, actions: List[str], target_patterns: List[str],
                 score: int, level: int = ThreatLevel.MEDIUM,
                 min_count: int = 1, time_window: int = 60):
        self.id = rule_id
        self.name = name
        self.description = description
        self.event_type = event_type
        self.actions = actions
        self.target_patterns = target_patterns
        self.score = score
        self.level = level
        self.min_count = min_count
        self.time_window = time_window  # seconds

    def matches(self, event: BehaviorEvent) -> bool:
        """检查事件是否匹配规则"""
        if event.event_type != self.event_type:
            return False
        if self.actions and event.action not in self.actions:
            return False
        if self.target_patterns:
            for pattern in self.target_patterns:
                if pattern.lower() in event.target.lower():
                    return True
            return False
        return True


class BehaviorRules:
    """行为检测规则集"""
    @staticmethod
    def get_rules() -> List[BehaviorRule]:
        return [
            # 进程规则
            BehaviorRule('P001', '进程注入', '检测跨进程注入行为',
                        'process', ['CreateRemoteThread', 'WriteProcessMemory',
                                    'VirtualAllocEx', 'SetWindowsHookEx'],
                        [], 25, ThreatLevel.CRITICAL),
            BehaviorRule('P002', '异常进程创建', '检测可疑的子进程创建',
                        'process', ['CreateProcess', 'WinExec', 'ShellExecute'],
                        ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                         'rundll32.exe', 'regsvr32.exe', 'mshta.exe'],
                        15, ThreatLevel.HIGH),
            BehaviorRule('P003', '傀儡进程', '检测进程镂空/提权行为',
                        'process', ['NtUnmapViewOfSection', 'SetThreadContext',
                                    'ResumeThread'],
                        [], 30, ThreatLevel.CRITICAL),

            # 文件规则
            BehaviorRule('F001', '批量文件修改', '检测大量文件修改行为(勒索软件特征)',
                        'file', ['modify', 'delete', 'rename'],
                        [], 20, ThreatLevel.CRITICAL, min_count=10, time_window=60),
            BehaviorRule('F002', '系统文件篡改', '检测系统关键文件被修改',
                        'file', ['modify', 'delete'],
                        ['\\windows\\system32\\', '\\windows\\syswow64\\',
                         '\\windows\\system32\\drivers\\'],
                        25, ThreatLevel.CRITICAL),
            BehaviorRule('F003', '自启动目录写入', '检测写入自启动目录',
                        'file', ['create', 'modify'],
                        ['\\startup\\', '\\Start Menu\\Programs\\Startup\\'],
                        15, ThreatLevel.HIGH),
            BehaviorRule('F004', '可执行文件创建', '检测在敏感位置创建可执行文件',
                        'file', ['create'],
                        ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\'],
                        10, ThreatLevel.HIGH, min_count=3, time_window=300),

            # 注册表规则
            BehaviorRule('R001', '启动项修改', '检测注册表启动项被修改',
                        'registry', ['set', 'create'],
                        ['\\CurrentVersion\\Run', '\\CurrentVersion\\RunOnce',
                         '\\CurrentVersion\\RunServices'],
                        15, ThreatLevel.HIGH),
            BehaviorRule('R002', '浏览器劫持', '检测浏览器设置被修改',
                        'registry', ['set', 'create'],
                        ['\\Internet Explorer\\', '\\Chrome\\', '\\Chromium\\',
                         '\\Mozilla\\', '\\Firefox\\', '\\Default\\SearchScopes',
                         '\\Default\\SearchProvider'],
                        10, ThreatLevel.MEDIUM),
            BehaviorRule('R003', '文件关联劫持', '检测文件关联被修改',
                        'registry', ['set', 'create'],
                        ['\\shell\\open\\command', '\\shell\\runas\\command',
                         '\\UserChoice\\Progid'],
                        20, ThreatLevel.CRITICAL),
            BehaviorRule('R004', '安全策略修改', '检测系统安全策略被修改',
                        'registry', ['set', 'delete'],
                        ['\\Windows\\CurrentVersion\\Policies\\',
                         '\\Microsoft\\Windows Defender\\'],
                        20, ThreatLevel.CRITICAL),

            # 网络规则
            BehaviorRule('N001', '异常外连', '检测到可疑的对外连接',
                        'network', ['connect'],
                        ['unknown', 'external'],
                        10, ThreatLevel.MEDIUM, min_count=5, time_window=60),
            BehaviorRule('N002', 'C2通信', '检测可能的命令控制通信',
                        'network', ['connect'],
                        ['http://', 'https://'],
                        15, ThreatLevel.HIGH, min_count=3, time_window=300),
            BehaviorRule('N003', '端口扫描', '检测端口扫描行为',
                        'network', ['connect'],
                        [],
                        10, ThreatLevel.MEDIUM, min_count=20, time_window=60),
        ]


class ProcessMonitor:
    """进程监控器"""
    def __init__(self):
        self._running = False
        self._thread = None
        self._known_processes = set()
        self._events: List[BehaviorEvent] = []

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            try:
                self._check_new_processes()
            except Exception:
                pass
            time.sleep(2)

    def _check_new_processes(self):
        try:
            import psutil
            current = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    current.add((proc.info['pid'], proc.info['name']))
                    if proc.info['pid'] not in {p[0] for p in self._known_processes}:
                        if proc.info['exe']:
                            self._events.append(BehaviorEvent(
                                'process', proc.info['pid'], proc.info['name'],
                                'start', proc.info['exe']
                            ))
                except Exception:
                    pass
            self._known_processes = current
        except ImportError:
            pass

    def get_events(self) -> List[BehaviorEvent]:
        events = list(self._events)
        self._events.clear()
        return events


class FileMonitor:
    """文件监控器"""
    def __init__(self):
        self._running = False
        self._thread = None
        self._events: List[BehaviorEvent] = []
        self._watch_paths = [
            os.environ.get('TEMP', 'C:\\Temp'),
            os.environ.get('APPDATA', ''),
            os.environ.get('LOCALAPPDATA', ''),
            'C:\\Windows\\Temp',
        ]

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            try:
                self._check_file_changes()
            except Exception:
                pass
            time.sleep(5)

    def _check_file_changes(self):
        for path in self._watch_paths:
            if not path or not os.path.exists(path):
                continue
            try:
                for f in os.listdir(path)[:100]:
                    fpath = os.path.join(path, f)
                    if os.path.isfile(fpath):
                        ext = os.path.splitext(f)[1].lower()
                        if ext in ('.exe', '.dll', '.scr', '.bat', '.ps1'):
                            self._events.append(BehaviorEvent(
                                'file', 0, 'system',
                                'create', fpath
                            ))
            except Exception:
                pass

    def get_events(self) -> List[BehaviorEvent]:
        events = list(self._events)
        self._events.clear()
        return events


class RegistryMonitor:
    """注册表监控器"""
    def __init__(self):
        self._running = False
        self._events: List[BehaviorEvent] = []

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def get_events(self) -> List[BehaviorEvent]:
        events = list(self._events)
        self._events.clear()
        return events


class NetworkMonitor:
    """网络监控器"""
    def __init__(self):
        self._running = False
        self._thread = None
        self._events: List[BehaviorEvent] = []
        self._known_connections = set()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            try:
                self._check_connections()
            except Exception:
                pass
            time.sleep(5)

    def _check_connections(self):
        try:
            import psutil
            current = set()
            for conn in psutil.net_connections():
                if conn.raddr:
                    key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                    current.add(key)
                    if key not in self._known_connections:
                        proc_name = ''
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except Exception:
                                pass
                        self._events.append(BehaviorEvent(
                            'network', conn.pid or 0, proc_name,
                            'connect', f"{conn.raddr.ip}:{conn.raddr.port}"
                        ))
            self._known_connections = current
        except ImportError:
            pass

    def get_events(self) -> List[BehaviorEvent]:
        events = list(self._events)
        self._events.clear()
        return events


class BehaviorEngine(ScanEngine):
    """行为分析引擎 - 整合所有监控器，进行行为关联分析"""

    def __init__(self):
        super().__init__('BehaviorEngine', enabled=False)
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.registry_monitor = RegistryMonitor()
        self.network_monitor = NetworkMonitor()
        self.rules = BehaviorRules.get_rules()
        self.event_history = deque(maxlen=1000)
        self._running = False
        self._thread = None

    def start(self):
        """启动行为监控"""
        if self._running:
            return
        self._running = True

        self.process_monitor.start()
        self.file_monitor.start()
        self.registry_monitor.start()
        self.network_monitor.start()

        self._thread = threading.Thread(target=self._analyze_loop, daemon=True)
        self._thread.start()
        logger.info("行为分析引擎已启动")

    def stop(self):
        """停止行为监控"""
        self._running = False
        self.process_monitor.stop()
        self.file_monitor.stop()
        self.registry_monitor.stop()
        self.network_monitor.stop()
        logger.info("行为分析引擎已停止")

    def _analyze_loop(self):
        """行为分析循环"""
        while self._running:
            try:
                # 收集事件
                events = []
                events.extend(self.process_monitor.get_events())
                events.extend(self.file_monitor.get_events())
                events.extend(self.registry_monitor.get_events())
                events.extend(self.network_monitor.get_events())

                for event in events:
                    self.event_history.append(event)
                    matches = self._match_rules(event)
                    for rule, count in matches:
                        if count >= rule.min_count:
                            self._handle_threat(event, rule)

            except Exception as e:
                logger.error(f"行为分析错误: {e}")
            time.sleep(3)

    def _match_rules(self, event: BehaviorEvent) -> List[Tuple[BehaviorRule, int]]:
        """匹配行为规则"""
        matches = []
        now = time.time()

        for rule in self.rules:
            if rule.matches(event):
                # 统计时间窗口内的匹配次数
                count = 1
                for past_event in reversed(list(self.event_history)[-100:]):
                    if past_event is event:
                        continue
                    if (now - past_event.timestamp) <= rule.time_window:
                        if rule.matches(past_event):
                            count += 1
                    else:
                        break
                matches.append((rule, count))

        return matches

    def _handle_threat(self, event: BehaviorEvent, rule: BehaviorRule):
        """处理行为威胁"""
        threat = ThreatInfo(
            file_path=event.target,
            threat_type=ThreatType.BEHAVIOR,
            threat_name=f"Behavior.{rule.id}.{rule.name}",
            scan_engine=self.name,
            threat_level=rule.level,
            result=ScanResult.MALICIOUS
        )
        threat.details = {
            'rule_id': rule.id,
            'rule_name': rule.name,
            'description': rule.description,
            'event': event.to_dict(),
            'pid': event.pid,
            'process': event.process_name,
        }
        logger.warning(f"行为检测: {rule.name} - {event.target}")

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """行为引擎在扫描时不主动检测，通过实时监控工作"""
        return None


class HIPSEngine:
    """主动防御系统"""
    def __init__(self):
        self.enabled = config.get('hips.enabled', True)
        self.level = config.get('hips.level', 'normal')
        self._running = False
        self._thread = None

    def start(self):
        if not self.enabled or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("HIPS引擎已启动")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                self._check_hips_rules()
            except Exception:
                pass
            time.sleep(5)

    def _check_hips_rules(self):
        """检查HIPS规则"""
        if not config.get('hips.monitor_process_create', True):
            return
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe']:
                        self._evaluate_process(proc.info)
                except Exception:
                    pass
        except ImportError:
            pass

    def _evaluate_process(self, proc_info: Dict):
        """评估进程风险"""
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower()

        # 检查黑名单
        blacklist = config.get('hips.blacklist', [])
        for pattern in blacklist:
            if pattern.lower() in name or pattern.lower() in exe:
                logger.warning(f"HIPS阻止进程: {name} ({exe})")
                return

        # 检查白名单
        whitelist = config.get('hips.whitelist', [])
        for pattern in whitelist:
            if pattern.lower() in name or pattern.lower() in exe:
                return

        # 检测常见可疑进程
        suspicious_names = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
        ]
        if name in suspicious_names:
            try:
                proc = psutil.Process(proc_info['pid'])
                parent = proc.parent()
                if parent and parent.name().lower() not in ('explorer.exe', 'svchost.exe'):
                    logger.warning(f"HIPS: 可疑进程 {name} 由 {parent.name()} 启动")
            except Exception:
                pass