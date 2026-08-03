#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 行为分析引擎
整合进程、文件、注册表、网络监控，进行行为关联分析

架构说明:
  - ProcessMonitor: 委托 process_monitor.py (WMI 事件驱动 + psutil 轮询 5s 后备)
  - FileMonitor:    委托 file_monitor.py (watchdog 事件驱动 + ReadDirectoryChangesW + 轮询后备)
  - RegistryMonitor: 使用 RegNotifyChangeKeyValue 实时事件驱动 (不轮询)
  - NetworkMonitor:  委托 network_monitor.py (IPHLPAPI ctypes + 10s 轮询 + 速率限制)
"""
import os
import sys
import time
import json
import ctypes
import threading
from typing import Optional, Dict, Any, List, Tuple
from collections import defaultdict, deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine import ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel
from engine.logger import logger
from engine.config import config
from engine.behavior.win_registry import (
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER,
    KEY_READ, KEY_SET_VALUE, PROCESS_TERMINATE,
    SYNCHRONIZE, REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_CHANGE_LAST_SET,
    kill_process, set_file_readonly, RegistryChangeWatcher,
    format_key_path, delete_value, close_handle,
    open_process, terminate_process,
    open_reg_key, close_reg_key, enum_values,
)


# ============================================================
# 行为事件定义
# ============================================================

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


class ThreatEvent:
    """
    威胁事件 - 由子监控器 (process_monitor, file_monitor) 生成，
    传递给 BehaviorEngine.on_threat_detected() 进行统一处理。
    """
    def __init__(self, source: str = '', rule_id: str = '', rule_name: str = '',
                 severity: int = 0, score: int = 0, confidence: int = 0,
                 description: str = '', event_data: Optional[Dict] = None,
                 timestamp: float = 0):
        self.source = source
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.score = score
        self.confidence = confidence
        self.description = description
        self.event_data = event_data or {}
        self.timestamp = timestamp or time.time()


# ============================================================
# 行为检测规则
# ============================================================

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


# ============================================================
# WMI 进程缓存 (用于 _get_calling_process 改进)
# ============================================================

class ProcessCache:
    """
    WMI 进程缓存 — 通过 Win32_ProcessStartTrace 实时跟踪进程创建。
    用于 _get_calling_process() 提供更准确的进程信息。
    在 WMI 不可用时降级为 psutil 查询。
    """
    def __init__(self, max_age: float = 5.0):
        self._cache: Dict[int, Tuple[str, float]] = {}  # pid -> (name, timestamp)
        self._max_age = max_age
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._wmi_available = False

    def start(self):
        """启动 WMI 进程缓存"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._wmi_loop, daemon=True, name='ProcessCache')
        self._thread.start()

    def stop(self):
        """停止 WMI 进程缓存"""
        self._running = False

    def _wmi_loop(self):
        """WMI 事件循环 — 收集进程创建事件"""
        import pythoncom  # type: ignore
        pythoncom.CoInitialize()

        # 优先尝试 wmi 模块
        try:
            import wmi  # type: ignore
            c = wmi.WMI()
            watcher = c.WatchFor(
                notification_type="Creation",
                wmi_class="Win32_ProcessStartTrace",
            )
            self._wmi_available = True
            while self._running:
                try:
                    event = watcher(timeout_ms=1000)
                    if event is not None:
                        with self._lock:
                            self._cache[event.ProcessID] = (event.ProcessName, time.time())
                except Exception:
                    pass
            return
        except ImportError:
            pass
        except Exception:
            pass

        # 回退到 win32com.client
        try:
            import win32com.client  # type: ignore
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            service = locator.ConnectServer(".", "root\\cimv2")
            events = service.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
            self._wmi_available = True
            while self._running:
                try:
                    event = events.NextEvent(1000)
                    if event is not None:
                        with self._lock:
                            self._cache[event.ProcessID] = (event.ProcessName, time.time())
                except Exception:
                    pass
        except ImportError:
            self._wmi_available = False
        except Exception:
            self._wmi_available = False

    def get_most_recent(self) -> Tuple[str, int]:
        """
        返回最近启动的进程 (name, pid)。
        从缓存中取时间戳最新的条目，同时清理过期条目。
        """
        now = time.time()
        with self._lock:
            # 清理过期条目
            expired = [pid for pid, (_, ts) in self._cache.items() if now - ts > self._max_age]
            for pid in expired:
                del self._cache[pid]

            if not self._cache:
                return '', 0

            # 返回最近启动的进程
            most_recent = max(self._cache.items(), key=lambda x: x[1][1])
            pid, (name, _) = most_recent
            return name, pid

    def get_process_name(self, pid: int) -> str:
        """查询指定 PID 的进程名（从缓存中）"""
        with self._lock:
            if pid in self._cache:
                return self._cache[pid][0]
        return ''

    def is_available(self) -> bool:
        return self._wmi_available


# ============================================================
# 监控器 — 委托实现
# ============================================================

class ProcessMonitor:
    """
    进程监控器 — 委托 engine.behavior.process_monitor.ProcessMonitor。
    WMI 事件驱动（Win32_ProcessStartTrace / Win32_ProcessStopTrace），
    psutil 5s 轮询作为后备。
    """
    def __init__(self, engine=None):
        self._engine = engine
        self._running = False
        self._monitor = None

    def start(self):
        if self._running:
            return
        self._running = True
        try:
            from engine.behavior.process_monitor import ProcessMonitor as _ProcessMonitor
            self._monitor = _ProcessMonitor(engine=self._engine)
            self._monitor.start()
            logger.info("行为引擎: ProcessMonitor 已委托到 process_monitor.py")
        except Exception as e:
            logger.error(f"行为引擎: ProcessMonitor 委托启动失败: {e}")

    def stop(self):
        self._running = False
        if self._monitor:
            try:
                self._monitor.stop()
            except Exception:
                pass

    def get_events(self) -> List[BehaviorEvent]:
        """从 process_monitor 获取事件并转换为 BehaviorEvent"""
        events = []
        if self._monitor:
            try:
                for pe in self._monitor.get_events():
                    events.append(BehaviorEvent(
                        event_type='process',
                        pid=pe.pid,
                        process_name=pe.process_name,
                        action=pe.event_type,
                        target=pe.process_path or pe.process_name,
                        details=pe.to_dict(),
                    ))
            except Exception as e:
                logger.debug("ProcessMonitor 获取事件失败: %s", e)
        return events


class FileMonitor:
    """
    文件监控器 — 委托 engine.behavior.file_monitor.FileMonitor。
    watchdog 事件驱动 + ReadDirectoryChangesW 辅助 + 轮询后备。
    """
    def __init__(self, engine=None):
        self._engine = engine
        self._running = False
        self._monitor = None           # file_monitor.py 的 FileMonitor
        self._rdcw_monitor = None      # ReadDirectoryChangesW 辅助监控
        self._events: List[BehaviorEvent] = []

    def start(self):
        if self._running:
            return
        self._running = True

        # 启动 file_monitor.py 的 FileMonitor (watchdog + 轮询)
        try:
            from engine.behavior.file_monitor import FileMonitor as _FileMonitor
            self._monitor = _FileMonitor(engine=self._engine)
            self._monitor.start()
            logger.info("行为引擎: FileMonitor 已委托到 file_monitor.py")
        except Exception as e:
            logger.error(f"行为引擎: FileMonitor 委托启动失败: {e}")

        # 尝试启动 ReadDirectoryChangesW 辅助监控
        self._try_start_rdcw()

    def stop(self):
        self._running = False
        if self._monitor:
            try:
                self._monitor.stop()
            except Exception:
                pass
        self._stop_rdcw()

    def _try_start_rdcw(self):
        """尝试使用 ReadDirectoryChangesW 作为辅助事件源"""
        if sys.platform != 'win32':
            return
        try:
            self._rdcw_monitor = _ReadDirectoryChangesMonitor(
                on_event=self._on_rdcw_event,
            )
            self._rdcw_monitor.start()
            logger.info("行为引擎: ReadDirectoryChangesW 辅助监控已启动")
        except Exception as e:
            logger.debug("行为引擎: ReadDirectoryChangesW 不可用: %s", e)

    def _stop_rdcw(self):
        if self._rdcw_monitor:
            try:
                self._rdcw_monitor.stop()
            except Exception:
                pass
            self._rdcw_monitor = None

    def _on_rdcw_event(self, action: str, file_path: str):
        """ReadDirectoryChangesW 回调 — 转换为 BehaviorEvent"""
        self._events.append(BehaviorEvent(
            event_type='file',
            pid=0,
            process_name='system',
            action=action,
            target=file_path,
            details={'source': 'ReadDirectoryChangesW'},
        ))

    def get_events(self) -> List[BehaviorEvent]:
        """从 file_monitor 获取事件并转换为 BehaviorEvent"""
        events = []
        if self._monitor:
            try:
                for fe in self._monitor.get_events():
                    events.append(BehaviorEvent(
                        event_type='file',
                        pid=fe.process_pid or 0,
                        process_name=fe.process_name or 'system',
                        action=fe.event_type,
                        target=fe.file_path,
                        details=fe.to_dict(),
                    ))
            except Exception as e:
                logger.debug("FileMonitor 获取事件失败: %s", e)

        # 合并 ReadDirectoryChangesW 事件
        events.extend(self._events)
        self._events.clear()
        return events


class _ReadDirectoryChangesMonitor:
    """
    ReadDirectoryChangesW 辅助监控器。
    监控关键目录，当文件变更时通过回调通知。
    作为 watchdog 的补充，用于 watchdog 无法覆盖的目录。
    """
    def __init__(self, on_event=None):
        self._on_event = on_event
        self._running = False
        self._thread = None
        self._handles = {}

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._handles:
            try:
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                for h in self._handles.values():
                    try:
                        kernel32.CancelIo(h)
                        kernel32.CloseHandle(h)
                    except Exception:
                        pass
            except Exception:
                pass
            self._handles.clear()

    def _monitor_loop(self):
        """ReadDirectoryChangesW 监控循环"""
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        from ctypes import wintypes, create_string_buffer, sizeof, byref, c_ubyte, c_uint

        FILE_LIST_DIRECTORY = 0x0001
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_FLAG_OVERLAPPED = 0x40000000

        # 要监控的目录
        watch_dirs = set()
        for d in [os.environ.get('TEMP', ''), os.environ.get('TMP', ''),
                  os.environ.get('APPDATA', ''), 'C:\\Windows\\Temp']:
            if d and os.path.isdir(d):
                watch_dirs.add(d)

        # 打开目录句柄
        for wd in watch_dirs:
            try:
                h = kernel32.CreateFileW(
                    wd,
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    None,
                )
                if h and h not in (-1, 0):
                    self._handles[wd] = h
            except Exception:
                pass

        if not self._handles:
            return

        # 监控循环
        buf_size = 65536
        FILE_NOTIFY_CHANGE_ALL = (
            0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 |
            0x00000010 | 0x00000040
        )

        while self._running:
            for watch_dir, h_dir in list(self._handles.items()):
                if not self._running:
                    break
                try:
                    buf = create_string_buffer(buf_size)
                    bytes_returned = c_uint(0)
                    success = kernel32.ReadDirectoryChangesW(
                        h_dir, buf, sizeof(buf), True,
                        FILE_NOTIFY_CHANGE_ALL,
                        byref(bytes_returned), None, None,
                    )
                    if success and bytes_returned.value > 0:
                        self._parse_notifications(buf, bytes_returned.value, watch_dir)
                except Exception:
                    time.sleep(0.5)

    def _parse_notifications(self, buffer, bytes_returned, watch_dir):
        """解析 FILE_NOTIFY_INFORMATION 结构"""
        try:
            offset = 0
            while offset < bytes_returned:
                # 读取 FILE_NOTIFY_INFORMATION 头部
                data = buffer.raw
                if offset + 12 > len(data):
                    break

                next_offset = int.from_bytes(data[offset:offset+4], 'little')
                action = int.from_bytes(data[offset+4:offset+8], 'little')
                name_len = int.from_bytes(data[offset+8:offset+12], 'little')

                if name_len <= 0 or offset + 12 + name_len > len(data):
                    break

                # 读取文件名 (UTF-16LE)
                file_name = data[offset+12:offset+12+name_len].decode('utf-16-le', errors='replace')
                full_path = os.path.join(watch_dir, file_name)

                # 动作映射
                action_map = {
                    1: 'create',
                    2: 'delete',
                    3: 'modify',
                    4: 'rename',
                    5: 'rename',
                }
                action_str = action_map.get(action, 'modify')

                # 回调触发
                if self._on_event:
                    try:
                        self._on_event(action_str, full_path)
                    except Exception:
                        pass

                if next_offset == 0:
                    break
                offset += next_offset
        except Exception:
            pass


class RegistryMonitor:
    """注册表监控器 - 使用 RegNotifyChangeKeyValue 实时监控"""
    def __init__(self):
        self._running = False
        self._events: List[BehaviorEvent] = []
        self._lock = threading.Lock()
        self._watchers: List[RegistryChangeWatcher] = []

    def start(self):
        """启动注册表监控"""
        if self._running:
            return
        self._running = True

        # 监控目标: Run 启动项 + Services 服务键
        watch_targets = [
            (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]

        for hive, sub_key in watch_targets:
            watcher = RegistryChangeWatcher(
                hive=hive, sub_key=sub_key,
                on_change=self._on_change,
                filter_flags=REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
            )
            if watcher.start():
                self._watchers.append(watcher)
                logger.info(f"注册表监控已启动: {format_key_path(hive, sub_key)}")
            else:
                logger.warning(f"注册表监控启动失败: {format_key_path(hive, sub_key)}")

    def stop(self):
        """停止注册表监控"""
        self._running = False
        for watcher in self._watchers:
            watcher.stop()
        self._watchers.clear()

    def _on_change(self, hive_name: str, sub_key: str, action: str, value_name: str):
        """注册表变化回调"""
        event = BehaviorEvent(
            event_type='registry',
            pid=0,
            process_name='system',
            action=action,
            target=f"{hive_name}\\{sub_key}\\{value_name}",
            details={
                'hive': hive_name,
                'key': sub_key,
                'value': value_name,
            }
        )
        with self._lock:
            self._events.append(event)

    def get_events(self) -> List[BehaviorEvent]:
        """获取并清空事件列表"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events


class NetworkMonitor:
    """
    网络监控器 — 委托 engine.behavior.network_monitor.NetworkMonitor。
    IPHLPAPI ctypes 高效查询 + 10s 轮询 + 速率限制。
    """
    def __init__(self, engine=None):
        self._engine = engine
        self._running = False
        self._monitor = None

    def start(self):
        if self._running:
            return
        self._running = True
        try:
            from engine.behavior.network_monitor import NetworkMonitor as _NetworkMonitor
            self._monitor = _NetworkMonitor(engine=self._engine)
            self._monitor.start()
            logger.info("行为引擎: NetworkMonitor 已委托到 network_monitor.py")
        except Exception as e:
            logger.error(f"行为引擎: NetworkMonitor 委托启动失败: {e}")

    def stop(self):
        self._running = False
        if self._monitor:
            try:
                self._monitor.stop()
            except Exception:
                pass

    def get_events(self) -> List[BehaviorEvent]:
        """从 network_monitor 获取事件并转换为 BehaviorEvent"""
        events = []
        if self._monitor:
            try:
                for ne in self._monitor.get_events():
                    events.append(BehaviorEvent(
                        event_type='network',
                        pid=ne.pid,
                        process_name=ne.process_name,
                        action=ne.event_type,
                        target=f"{ne.remote_ip}:{ne.remote_port}",
                        details=ne.to_dict(),
                    ))
            except Exception as e:
                logger.debug("NetworkMonitor 获取事件失败: %s", e)
        return events


# ============================================================
# 行为引擎
# ============================================================

class BehaviorEngine(ScanEngine):
    """行为分析引擎 - 整合所有监控器，进行行为关联分析"""

    def __init__(self):
        super().__init__('BehaviorEngine', enabled=False)
        self.process_monitor = ProcessMonitor(engine=self)
        self.file_monitor = FileMonitor(engine=self)
        self.registry_monitor = RegistryMonitor()
        self.network_monitor = NetworkMonitor(engine=self)
        self.rules = BehaviorRules.get_rules()
        self.event_history = deque(maxlen=1000)
        self._running = False
        self._thread = None
        self._process_cache = ProcessCache()

    def start(self):
        """启动行为监控"""
        if self._running:
            return
        self._running = True

        self.process_monitor.start()
        self.file_monitor.start()
        self.registry_monitor.start()
        self.network_monitor.start()
        self._process_cache.start()

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
        self._process_cache.stop()
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

    def on_threat_detected(self, threat: ThreatEvent):
        """
        子监控器 (process_monitor, file_monitor) 检测到威胁时回调。
        将 ThreatEvent 转换为 ThreatInfo 并记录。
        """
        target = ''
        if threat.event_data:
            target = threat.event_data.get('file_path', '') or threat.event_data.get('process_path', '')
        threat_info = ThreatInfo(
            file_path=target or 'unknown',
            threat_type=ThreatType.BEHAVIOR,
            threat_name=f"Behavior.{threat.rule_id}.{threat.rule_name}",
            scan_engine=self.name,
            threat_level=threat.severity,
            result=ScanResult.MALICIOUS,
        )
        threat_info.details = {
            'source': threat.source,
            'rule_id': threat.rule_id,
            'rule_name': threat.rule_name,
            'description': threat.description,
            'confidence': threat.confidence,
            'score': threat.score,
            'event_data': threat.event_data,
        }
        logger.warning(
            f"[{threat.source}] {threat.rule_name} - 置信度={threat.confidence}% 评分={threat.score}"
        )

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """行为引擎在扫描时不主动检测，通过实时监控工作"""
        return None

    # ------------------------------------------------------------
    # _get_calling_process 改进 — 使用 WMI 进程缓存
    # ------------------------------------------------------------
    def _get_calling_process(self) -> Tuple[str, int]:
        """
        获取最近启动的进程信息，用于关联文件操作与进程。
        优先使用 WMI 进程缓存，回退到 psutil 父进程查询。
        """
        # 优先使用 WMI 缓存
        if self._process_cache.is_available():
            name, pid = self._process_cache.get_most_recent()
            if name:
                return name, pid

        # 回退到 psutil
        try:
            import psutil
            current = psutil.Process()
            proc = current.parent()
            if proc:
                return proc.name() or '', proc.pid or 0
        except Exception:
            pass
        return '', 0


# ============================================================
# HIPS 主动防御
# ============================================================

class HIPSEngine:
    """主动防御系统 - 实时拦截高危操作"""

    SUSPICIOUS_NAMES = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
    ]

    RUN_KEY_PATHS = [
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def __init__(self):
        self.enabled = config.get('hips.enabled', True)
        self.level = config.get('hips.level', 'normal')
        self._running = False
        self._thread = None
        self._wmi_thread = None
        self._wmi_available = False
        self._intercepted = 0

    def start(self):
        if not self.enabled or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # 尝试启动WMI进程创建实时监控
        self._try_start_wmi_monitor()
        logger.info("HIPS引擎已启动")

    def stop(self):
        self._running = False
        if self._wmi_thread:
            self._wmi_thread.join(timeout=3)
            self._wmi_thread = None

    # ------------------------------------------------------------
    # WMI 进程创建监控（实时）
    # ------------------------------------------------------------
    def _try_start_wmi_monitor(self):
        """尝试使用 WMI Win32_ProcessStartTrace 事件订阅进程创建"""
        try:
            import win32com.client  # type: ignore
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            service = locator.ConnectServer(".", "root\\cimv2")
            self._wmi_events = service.ExecNotificationQuery(
                "SELECT * FROM Win32_ProcessStartTrace"
            )
            self._wmi_thread = threading.Thread(
                target=self._wmi_monitor_loop, daemon=True
            )
            self._wmi_thread.start()
            self._wmi_available = True
            logger.info("HIPS: WMI 进程创建监控已启动")
        except Exception as e:
            self._wmi_available = False
            logger.warning(f"HIPS: WMI 监控不可用，回退到轮询模式: {e}")

    def _wmi_monitor_loop(self):
        """WMI 事件循环 — 等待进程创建事件"""
        while self._running and self._wmi_available:
            try:
                # 1000 ms 超时; 超时时返回 None 或抛出异常
                event = self._wmi_events.NextEvent(1000)
                if event is None:
                    continue
                proc_info = {
                    'pid': event.ProcessID,
                    'name': event.ProcessName,
                    'exe': getattr(event, 'ProcessName', ''),
                }
                self._evaluate_process(proc_info, source='wmi')
            except Exception:
                # 超时异常或其它暂时性错误，继续循环
                pass

    # ------------------------------------------------------------
    # 轮询监控（后备）
    # ------------------------------------------------------------
    def _run(self):
        while self._running:
            try:
                self._check_hips_rules()
            except Exception:
                pass
            time.sleep(5)

    def _check_hips_rules(self):
        """检查HIPS规则 - 轮询所有进程"""
        if not config.get('hips.monitor_process_create', True):
            return
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe']:
                        self._evaluate_process(proc.info, source='poll')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            pass

    # ------------------------------------------------------------
    # 核心评估与拦截
    # ------------------------------------------------------------
    def _evaluate_process(self, proc_info: Dict, source: str = 'poll'):
        """
        评估进程风险并执行拦截。
        1. 白名单检查 → 跳过
        2. 黑名单匹配 → 终止 + 清理启动项 + 文件保护
        3. 高安全级别下可疑进程检测 → 同上
        """
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower() or name
        pid = proc_info.get('pid', 0)

        # 白名单检查
        whitelist = config.get('hips.whitelist', [])
        for pattern in whitelist:
            if pattern.lower() in name or pattern.lower() in exe:
                return

        matched = False
        matched_reason = ''

        # 黑名单检查
        blacklist = config.get('hips.blacklist', [])
        for pattern in blacklist:
            if pattern.lower() in name or pattern.lower() in exe:
                matched = True
                matched_reason = f"黑名单匹配: {pattern}"
                break

        # 高安全级别下检测可疑进程
        if not matched and self.level in ('high', 'paranoid'):
            if name in self.SUSPICIOUS_NAMES:
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    parent = proc.parent()
                    parent_name = parent.name().lower() if parent else ''
                    if parent_name not in ('explorer.exe', 'svchost.exe', 'services.exe', 'winlogon.exe'):
                        matched = True
                        matched_reason = f"可疑进程 {name} 由 {parent_name} 启动"
                except Exception:
                    pass

        if matched:
            self._intercepted += 1
            logger.warning(f"HIPS 拦截: {matched_reason} (PID={pid}, name={name})")

            # === 动作 1: 终止进程 ===
            if pid > 0:
                self._terminate_process(pid, name)

            # === 动作 2: 清理注册表启动项 ===
            self._remove_registry_run_keys(name, exe)

            # === 动作 3: 文件系统保护 ===
            if exe and os.path.exists(exe):
                self._protect_file(exe)

    # ------------------------------------------------------------
    # 拦截动作实现
    # ------------------------------------------------------------
    def _terminate_process(self, pid: int, name: str):
        """通过 OpenProcess + TerminateProcess 终止进程"""
        handle = open_process(pid, PROCESS_TERMINATE | SYNCHRONIZE)
        if handle:
            try:
                if terminate_process(handle):
                    logger.warning(f"HIPS: 已终止进程 {name} (PID={pid})")
                else:
                    err = ctypes.WinError() if 'ctypes' in dir() else None
                    logger.error(f"HIPS: 终止进程失败 {name} (PID={pid}): {err}")
            finally:
                close_handle(handle)
        else:
            logger.error(f"HIPS: 无法打开进程 {name} (PID={pid})，权限不足或进程已退出")

    def _remove_registry_run_keys(self, name: str, exe: str):
        """扫描 Run / RunOnce 键，删除指向恶意进程的条目"""
        for hive, sub_key in self.RUN_KEY_PATHS:
            try:
                handle = open_reg_key(hive, sub_key, access=KEY_READ | KEY_SET_VALUE)
                if handle is None:
                    continue
                try:
                    values = enum_values(handle)
                    for val_name, (val_type, val_data) in values.items():
                        if not isinstance(val_data, str):
                            continue
                        val_lower = val_data.lower()
                        if name.lower() in val_lower or (exe and exe.lower() in val_lower):
                            if delete_value(handle, val_name):
                                logger.warning(
                                    f"HIPS: 已移除注册表启动项 "
                                    f"{format_key_path(hive, sub_key)} -> {val_name}"
                                )
                finally:
                    close_reg_key(handle)
            except Exception:
                pass

    def _protect_file(self, filepath: str):
        """设置文件为只读属性以防止进一步损害"""
        try:
            if set_file_readonly(filepath):
                logger.warning(f"HIPS: 已设置文件只读属性 {filepath}")
        except Exception:
            pass

    # ------------------------------------------------------------
    def get_stats(self) -> Dict:
        return {
            'enabled': self.enabled,
            'level': self.level,
            'intercepted': self._intercepted,
            'wmi_available': self._wmi_available,
        }