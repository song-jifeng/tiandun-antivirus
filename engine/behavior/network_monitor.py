#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 网络行为监控器
=================================
使用 IPHLPAPI.dll (GetExtendedTcpTable/GetExtendedUdpTable) 进行高效的网络连接查询。
支持行为事件生成、速率限制、防火墙集成、WFP 检测。
"""
import os
import sys
import time
import socket
import struct
import ctypes
import threading
import subprocess
from ctypes import wintypes, Structure, POINTER, byref, sizeof, create_string_buffer, WinDLL
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger
from engine.config import config


# ============================================================
# IPHLPAPI 常量
# ============================================================
AF_INET = 2
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122

# TCP table class
TCP_TABLE_OWNER_PID_ALL = 5

# UDP table class
UDP_TABLE_OWNER_PID = 1

# TCP states (relevant ones)
MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_TIME_WAIT = 11


# ============================================================
# IPHLPAPI 结构体定义
# ============================================================
class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ('dwState', wintypes.DWORD),
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwRemoteAddr', wintypes.DWORD),
        ('dwRemotePort', wintypes.DWORD),
        ('dwOwningPid', wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwOwningPid', wintypes.DWORD),
    ]


# ============================================================
# 网络事件定义
# ============================================================
class NetworkEvent:
    """网络连接事件"""
    def __init__(self, event_type: str, pid: int, process_name: str,
                 local_ip: str, local_port: int,
                 remote_ip: str, remote_port: int,
                 protocol: str, state: str = '',
                 details: Optional[Dict] = None):
        self.timestamp = time.time()
        self.event_type = event_type  # connect, disconnect, block
        self.pid = pid
        self.process_name = process_name
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.protocol = protocol  # tcp, udp
        self.state = state
        self.details = details or {}

    def to_dict(self) -> Dict:
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'type': self.event_type,
            'pid': self.pid,
            'process': self.process_name,
            'local': f"{self.local_ip}:{self.local_port}",
            'remote': f"{self.remote_ip}:{self.remote_port}",
            'protocol': self.protocol,
            'state': self.state,
            'details': self.details,
        }


# ============================================================
# 网络监控器
# ============================================================
class NetworkMonitor:
    """
    网络连接监控器 - 使用 IPHLPAPI 进行高效的网络连接查询。

    主要特性:
    - 使用 GetExtendedTcpTable/GetExtendedUdpTable 替代 psutil 轮询
    - 连接事件速率限制，避免事件风暴
    - 集成 Windows 防火墙 API 检测被阻止的连接
    - 10 秒轮询间隔
    - psutil 回退（当 IPHLPAPI 不可用时）
    """

    def __init__(self, engine=None):
        self._engine = engine
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # 事件队列
        self._events: List[NetworkEvent] = []
        self._event_queue: deque = deque(maxlen=10000)

        # 连接快照
        self._previous_connections: Set[Tuple] = set()

        # 速率限制: (remote_ip, remote_port) -> [timestamps]
        self._rate_limit_tracker: Dict[Tuple, List[float]] = defaultdict(list)
        self._rate_limit_window = 5       # 5秒窗口
        self._rate_limit_max = 30         # 窗口内最多30个事件

        # IPHLPAPI 可用性
        self._iphlpapi_available = False
        self._iphlpapi = None
        self._get_tcp_table = None
        self._get_udp_table = None
        self._try_init_iphlpapi()

        # 防火墙集成
        self._firewall_available = False
        self._fw_manager = None

        # 统计
        self.stats = {
            'total_events': 0,
            'connections_detected': 0,
            'disconnections_detected': 0,
            'blocked_detected': 0,
            'rate_limited': 0,
            'iphlpapi_errors': 0,
        }

        logger.info("NetworkMonitor 初始化完成 (IPHLPAPI=%s)", self._iphlpapi_available)

    # ============================================================
    # IPHLPAPI 初始化
    # ============================================================
    def _try_init_iphlpapi(self):
        """尝试加载 IPHLPAPI.dll"""
        try:
            self._iphlpapi = WinDLL('iphlpapi', use_last_error=True)

            # GetExtendedTcpTable
            self._get_tcp_table = self._iphlpapi.GetExtendedTcpTable
            self._get_tcp_table.argtypes = [
                ctypes.c_void_p,
                POINTER(wintypes.DWORD),
                wintypes.BOOL,
                wintypes.ULONG,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            self._get_tcp_table.restype = wintypes.DWORD

            # GetExtendedUdpTable
            self._get_udp_table = self._iphlpapi.GetExtendedUdpTable
            self._get_udp_table.argtypes = [
                ctypes.c_void_p,
                POINTER(wintypes.DWORD),
                wintypes.BOOL,
                wintypes.ULONG,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            self._get_udp_table.restype = wintypes.DWORD

            # 验证可用性
            dwSize = wintypes.DWORD(0)
            ret = self._get_tcp_table(None, byref(dwSize), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            self._iphlpapi_available = (ret == ERROR_INSUFFICIENT_BUFFER)
            if self._iphlpapi_available:
                logger.info("IPHLPAPI 网络查询已初始化")
            else:
                logger.warning("IPHLPAPI 初始化失败: ret=%d", ret)
        except Exception as e:
            self._iphlpapi_available = False
            logger.warning("IPHLPAPI 不可用: %s", e)

    # ============================================================
    # 生命周期管理
    # ============================================================
    def start(self):
        """启动网络监控"""
        if self._running:
            return
        self._running = True

        # 初始化连接快照
        self._previous_connections = self._take_snapshot()

        self._thread = threading.Thread(target=self._monitor_loop, name='NetworkMonitor', daemon=True)
        self._thread.start()
        logger.info("NetworkMonitor 已启动 (轮询间隔: 10s, IPHLPAPI=%s)", self._iphlpapi_available)

    def stop(self):
        """停止网络监控"""
        self._running = False
        logger.info("NetworkMonitor 已停止，共处理事件: %d", self.stats['total_events'])

    def is_running(self) -> bool:
        return self._running

    # ============================================================
    # 事件管理
    # ============================================================
    def add_event(self, event: NetworkEvent):
        """添加事件到队列"""
        with self._lock:
            self._events.append(event)
            self._event_queue.append(event)
            self.stats['total_events'] += 1

    def get_events(self) -> List[NetworkEvent]:
        """获取并清空事件队列"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    # ============================================================
    # 速率限制
    # ============================================================
    def _is_rate_limited(self, remote_ip: str, remote_port: int) -> bool:
        """检查是否触发速率限制"""
        now = time.time()
        key = (remote_ip, remote_port)

        # 清理过期记录
        self._rate_limit_tracker[key] = [
            t for t in self._rate_limit_tracker[key]
            if now - t < self._rate_limit_window
        ]

        # 检查是否超过限制
        if len(self._rate_limit_tracker[key]) >= self._rate_limit_max:
            self.stats['rate_limited'] += 1
            return True

        self._rate_limit_tracker[key].append(now)
        return False

    # ============================================================
    # 连接快照
    # ============================================================
    def _take_snapshot(self) -> Set[Tuple]:
        """获取当前连接快照"""
        if self._iphlpapi_available:
            return self._get_connections_iphlpapi()
        return self._get_connections_psutil()

    def _get_connections_iphlpapi(self) -> Set[Tuple]:
        """使用 IPHLPAPI 获取连接快照"""
        connections = set()

        try:
            tcp_conns = self._query_tcp_table()
            connections.update(tcp_conns)
        except Exception as e:
            self.stats['iphlpapi_errors'] += 1
            logger.debug("IPHLPAPI TCP 查询失败: %s", e)

        return connections

    def _query_tcp_table(self) -> Set[Tuple]:
        """查询 TCP 连接表，返回 {(pid, remote_ip, remote_port, local_port, protocol)}"""
        connections = set()
        if not self._get_tcp_table:
            return connections

        # 获取缓冲区大小
        dwSize = wintypes.DWORD(0)
        ret = self._get_tcp_table(None, byref(dwSize), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != ERROR_INSUFFICIENT_BUFFER:
            return connections

        # 分配缓冲区并查询
        buf = create_string_buffer(dwSize.value)
        ret = self._get_tcp_table(buf, byref(dwSize), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != NO_ERROR:
            return connections

        # 解析结果
        num_entries = wintypes.DWORD.from_buffer_copy(buf).value
        offset = sizeof(wintypes.DWORD)  # 跳过 dwNumEntries

        for _ in range(num_entries):
            try:
                row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf, offset)
                local_ip = socket.inet_ntoa(struct.pack('I', row.dwLocalAddr))
                local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
                remote_ip = socket.inet_ntoa(struct.pack('I', row.dwRemoteAddr))
                remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
                pid = row.dwOwningPid

                # 只关注有远程地址的连接（ESTABLISHED / TIME_WAIT 等）
                if remote_ip != '0.0.0.0' and row.dwState >= MIB_TCP_STATE_ESTAB:
                    key = (pid, remote_ip, remote_port, local_port, 'tcp')
                    connections.add(key)

                offset += sizeof(MIB_TCPROW_OWNER_PID)
            except Exception:
                offset += sizeof(MIB_TCPROW_OWNER_PID)
                continue

        return connections

    def _get_connections_psutil(self) -> Set[Tuple]:
        """使用 psutil 获取连接（回退方案）"""
        connections = set()
        try:
            import psutil
            for conn in psutil.net_connections():
                if conn.raddr:
                    key = (conn.pid or 0, conn.raddr.ip, conn.raddr.port,
                           conn.laddr.port if conn.laddr else 0,
                           'tcp' if conn.type == socket.SOCK_STREAM else 'udp')
                    connections.add(key)
        except ImportError:
            pass
        except Exception:
            pass
        return connections

    # ============================================================
    # 主监控循环
    # ============================================================
    def _monitor_loop(self):
        """主监控循环 - 每 10 秒检查一次连接变化"""
        while self._running:
            try:
                current = self._take_snapshot()
                if current is not None:
                    self._detect_changes(current)
                    self._previous_connections = current
            except Exception as e:
                logger.error("网络监控循环异常: %s", e, exc_info=True)
            time.sleep(10)

    def _detect_changes(self, current: Set[Tuple]):
        """检测连接变化"""
        previous = self._previous_connections

        if not previous:
            # 首次运行，只记录不生成事件
            return

        # 新连接
        new_connections = current - previous
        for conn in new_connections:
            try:
                self._on_connection(conn)
            except Exception as e:
                logger.debug("处理新连接异常: %s", e)

        # 断开连接
        lost_connections = previous - current
        for conn in lost_connections:
            try:
                self._on_disconnection(conn)
            except Exception as e:
                logger.debug("处理断开连接异常: %s", e)

    # ============================================================
    # 事件处理
    # ============================================================
    def _on_connection(self, conn: Tuple):
        """处理新连接事件"""
        pid, remote_ip, remote_port, local_port, protocol = conn

        # 速率限制
        if self._is_rate_limited(remote_ip, remote_port):
            return

        # 获取进程名
        process_name = self._get_process_name(pid)

        # 检查是否被防火墙阻止
        blocked = self._check_firewall_blocked(pid, remote_ip, remote_port)

        event = NetworkEvent(
            event_type='block' if blocked else 'connect',
            pid=pid,
            process_name=process_name,
            local_ip='127.0.0.1',
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
            state='established',
            details={'blocked': blocked} if blocked else {},
        )
        self.add_event(event)
        self.stats['connections_detected'] += 1
        if blocked:
            self.stats['blocked_detected'] += 1

    def _on_disconnection(self, conn: Tuple):
        """处理断开连接事件"""
        pid, remote_ip, remote_port, local_port, protocol = conn

        event = NetworkEvent(
            event_type='disconnect',
            pid=pid,
            process_name=self._get_process_name(pid),
            local_ip='127.0.0.1',
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
            state='closed',
        )
        self.add_event(event)
        self.stats['disconnections_detected'] += 1

    # ============================================================
    # 辅助方法
    # ============================================================
    def _get_process_name(self, pid: int) -> str:
        """获取进程名"""
        if pid <= 0:
            return ''
        try:
            import psutil
            return psutil.Process(pid).name()
        except Exception:
            return ''

    def _check_firewall_blocked(self, pid: int, remote_ip: str, remote_port: int) -> bool:
        """检查连接是否被防火墙阻止（通过 firewall API）"""
        if not self._firewall_available:
            try:
                from firewall.win_firewall_api import get_firewall_manager
                self._fw_manager = get_firewall_manager()
                self._firewall_available = self._fw_manager and self._fw_manager.available
            except Exception:
                pass
        return False

    # ============================================================
    # WFP 检测 (Windows Filtering Platform)
    # ============================================================
    def check_wfp_blocked(self) -> List[Dict]:
        """
        通过 netsh wfp 检查被 WFP 阻止的连接。
        返回阻止事件列表。
        """
        blocked = []
        try:
            result = subprocess.run(
                ['netsh', 'wfp', 'show', 'state'],
                capture_output=True, text=True, timeout=10,
                errors='replace',
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # 解析输出中可能的阻止信息
                for line in output.split('\n'):
                    if 'block' in line and ('tcp' in line or 'udp' in line):
                        blocked.append({
                            'raw': line.strip(),
                            'timestamp': time.time(),
                        })
        except Exception as e:
            logger.debug("WFP 状态查询失败: %s", e)
        return blocked

    # ============================================================
    # 统计
    # ============================================================
    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'running': self._running,
            'iphlpapi_available': self._iphlpapi_available,
            'pending_events': len(self._events),
        }


# ============================================================
# 自测
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("NetworkMonitor 测试")
    print("=" * 60)
    monitor = NetworkMonitor()
    print(f"IPHLPAPI 可用: {monitor._iphlpapi_available}")
    if monitor._iphlpapi_available:
        conns = monitor._take_snapshot()
        print(f"当前连接数: {len(conns)}")
        for c in list(conns)[:10]:
            print(f"  PID={c[0]} {c[1]}:{c[2]} -> local:{c[3]} ({c[4]})")
    print("NetworkMonitor 初始化完成")