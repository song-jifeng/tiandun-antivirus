#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 防火墙引擎
整合 Windows 防火墙 API (COM/netsh) 与规则匹配，实现真正的网络流量拦截
"""
import os
import sys
import time
import json
import threading
import subprocess
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.logger import logger
from engine.config import config
from engine.behavior.win_registry import (
    kill_process, open_process, terminate_process, close_handle,
    PROCESS_TERMINATE, SYNCHRONIZE,
)
from firewall.win_firewall_api import (
    get_firewall_manager, WinFirewallManager,
    HIGH_RISK_PORTS, FW_ACTION_BLOCK, FW_ACTION_ALLOW,
    FW_DIRECTION_IN, FW_DIRECTION_OUT,
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ANY,
)


class FirewallRule:
    """防火墙规则"""
    def __init__(self, rule_id: str, name: str, direction: str = 'in',
                 action: str = 'block', protocol: str = 'any',
                 local_port: int = 0, remote_port: int = 0,
                 remote_ip: str = '*', local_ip: str = '*',
                 program_path: str = '*', enabled: bool = True):
        self.id = rule_id
        self.name = name
        self.direction = direction  # in, out
        self.action = action  # allow, block
        self.protocol = protocol  # tcp, udp, any
        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_ip = remote_ip
        self.local_ip = local_ip
        self.program_path = program_path
        self.enabled = enabled
        self.created = time.time()
        self.hit_count = 0

    def matches(self, conn_info: Dict) -> bool:
        """检查连接是否匹配规则"""
        if not self.enabled:
            return False
        if self.program_path != '*' and conn_info.get('program', '') != self.program_path:
            return False
        if self.remote_ip != '*' and conn_info.get('remote_ip', '') != self.remote_ip:
            return False
        if self.remote_port > 0 and conn_info.get('remote_port', 0) != self.remote_port:
            return False
        if self.local_port > 0 and conn_info.get('local_port', 0) != self.local_port:
            return False
        if self.protocol != 'any' and conn_info.get('protocol', '') != self.protocol:
            return False
        return True

    def to_dict(self) -> Dict:
        return {
            'id': self.id, 'name': self.name, 'direction': self.direction,
            'action': self.action, 'protocol': self.protocol,
            'local_port': self.local_port, 'remote_port': self.remote_port,
            'remote_ip': self.remote_ip, 'local_ip': self.local_ip,
            'program_path': self.program_path, 'enabled': self.enabled,
            'created': self.created, 'hit_count': self.hit_count,
        }


class FirewallEngine:
    """防火墙引擎 - 使用 Windows 防火墙 API 实现真实拦截"""

    def __init__(self):
        self._rules: List[FirewallRule] = []
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._fw_api: Optional[WinFirewallManager] = None
        self._fw_rules_synced = False
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认规则并同步到 Windows 防火墙"""
        self._rules = [
            FirewallRule('FW001', '允许本地回环', 'in', 'allow', 'any',
                        local_ip='127.0.0.1'),
            FirewallRule('FW002', '允许本地回环出站', 'out', 'allow', 'any',
                        local_ip='127.0.0.1'),
            FirewallRule('FW003', '阻止高危端口入站 (135/TCP)', 'in', 'block', 'tcp',
                        remote_port=135),
            FirewallRule('FW004', '阻止高危端口入站 (445/TCP)', 'in', 'block', 'tcp',
                        remote_port=445),
            FirewallRule('FW005', '阻止高危端口入站 (139/TCP)', 'in', 'block', 'tcp',
                        remote_port=139),
            FirewallRule('FW006', '阻止高危端口入站 (3389/TCP)', 'in', 'block', 'tcp',
                        remote_port=3389),
            FirewallRule('FW007', '阻止远程桌面暴力破解', 'in', 'block', 'tcp',
                        remote_port=3389, remote_ip='0.0.0.0/0'),
        ]

    def _sync_to_windows_firewall(self):
        """将内部规则同步到 Windows 防火墙"""
        try:
            self._fw_api = get_firewall_manager()
            if not self._fw_api.available:
                logger.warning("防火墙: Windows 防火墙 API 不可用，仅进行软件层规则匹配")
                return

            # 封锁高危端口
            blocked = self._fw_api.block_high_risk_ports()
            success_count = sum(1 for _, ok in blocked if ok)
            logger.info(f"防火墙: 已同步 {success_count}/{len(blocked)} 条高危端口封锁规则到 Windows 防火墙")

            # 同步软件规则中的端口封锁
            with self._lock:
                for rule in self._rules:
                    if rule.action == 'block' and rule.remote_port > 0:
                        proto = 'tcp' if rule.protocol == 'tcp' else 'udp'
                        self._fw_api.block_port(rule.remote_port, proto, rule.direction)

            self._fw_rules_synced = True
            logger.info("防火墙: 规则同步完成")
        except Exception as e:
            logger.error(f"防火墙: 同步规则失败: {e}")

    def start(self):
        if self._running:
            return
        self._running = True

        # 同步到 Windows 防火墙
        self._sync_to_windows_firewall()

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("防火墙引擎已启动")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                self._check_connections()
                # 定期重新同步防火墙规则（每5分钟）
                if self._fw_rules_synced and int(time.time()) % 300 < 10:
                    self._sync_to_windows_firewall()
            except Exception:
                pass
            time.sleep(10)

    def _check_connections(self):
        """检查网络连接并匹配规则"""
        try:
            import psutil
            for conn in psutil.net_connections():
                if not conn.raddr:
                    continue
                conn_info = {
                    'local_ip': conn.laddr.ip if conn.laddr else '',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else '',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'protocol': 'tcp' if conn.type == 1 else 'udp',
                    'pid': conn.pid,
                    'program': '',
                }
                if conn.pid:
                    try:
                        conn_info['program'] = psutil.Process(conn.pid).exe()
                    except Exception:
                        pass

                with self._lock:
                    for rule in self._rules:
                        if rule.matches(conn_info) and rule.action == 'block':
                            rule.hit_count += 1
                            if rule.hit_count <= 3:
                                logger.warning(
                                    f"防火墙阻止: {rule.name} - "
                                    f"{conn_info['remote_ip']}:{conn_info['remote_port']}"
                                    f" (PID={conn_info['pid']})"
                                )

                            # 尝试终止发起连接的进程
                            if conn.pid and conn.pid > 0:
                                self._terminate_connection_process(conn.pid, conn_info)
        except ImportError:
            pass
        except Exception:
            pass

    def _terminate_connection_process(self, pid: int, conn_info: Dict):
        """终止发起恶意连接的进程"""
        handle = open_process(pid, PROCESS_TERMINATE | SYNCHRONIZE)
        if handle:
            try:
                if terminate_process(handle):
                    logger.warning(
                        f"防火墙: 已终止恶意连接进程 PID={pid} "
                        f"({conn_info.get('remote_ip', '')}:{conn_info.get('remote_port', '')})"
                    )
            finally:
                close_handle(handle)

    # ------------------------------------------------------------
    # 规则管理
    # ------------------------------------------------------------
    def add_rule(self, rule: FirewallRule):
        """添加规则，同时同步到 Windows 防火墙"""
        with self._lock:
            self._rules.append(rule)

        # 同步到 Windows 防火墙
        if self._fw_api and self._fw_api.available:
            try:
                if rule.action == 'block':
                    if rule.remote_port > 0:
                        proto = 'tcp' if rule.protocol == 'tcp' else 'udp'
                        self._fw_api.block_port(rule.remote_port, proto, rule.direction)
                    elif rule.program_path != '*':
                        self._fw_api.block_program(rule.program_path)
            except Exception:
                pass

    def remove_rule(self, rule_id: str):
        """删除规则"""
        rule_to_remove = None
        with self._lock:
            for rule in self._rules:
                if rule.id == rule_id:
                    rule_to_remove = rule
                    break
            self._rules = [r for r in self._rules if r.id != rule_id]

        # 从 Windows 防火墙移除
        if rule_to_remove and self._fw_api and self._fw_api.available:
            try:
                if rule_to_remove.remote_port > 0:
                    proto = 'tcp' if rule_to_remove.protocol == 'tcp' else 'udp'
                    self._fw_api.unblock_port(rule_to_remove.remote_port, proto, rule_to_remove.direction)
            except Exception:
                pass

    def get_rules(self) -> List[Dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def get_stats(self) -> Dict:
        with self._lock:
            total_hits = sum(r.hit_count for r in self._rules)
            return {
                'total_rules': len(self._rules),
                'enabled_rules': sum(1 for r in self._rules if r.enabled),
                'total_hits': total_hits,
                'blocked_connections': total_hits,
                'windows_firewall_available': self._fw_api.available if self._fw_api else False,
                'windows_rules_synced': self._fw_rules_synced,
            }


class IntrusionDetection:
    """入侵检测系统"""

    def __init__(self):
        self._connection_log = defaultdict(list)
        self._running = False

    def start(self):
        self._running = True
        logger.info("入侵检测已启动")

    def stop(self):
        self._running = False

    def detect_port_scan(self, conn_info: Dict) -> bool:
        """检测端口扫描"""
        src_ip = conn_info.get('remote_ip', '')
        now = time.time()

        self._connection_log[src_ip].append(now)
        # 清理过期记录
        self._connection_log[src_ip] = [
            t for t in self._connection_log[src_ip]
            if now - t < 60
        ]

        # 60秒内超过20个连接 = 端口扫描
        if len(self._connection_log[src_ip]) > 20:
            logger.warning(f"检测到端口扫描: {src_ip}")
            # 尝试通过 Windows 防火墙封锁该 IP
            try:
                fw = get_firewall_manager()
                if fw.available:
                    rule_name = f"Tiandun_Block_Scan_{src_ip.replace('.', '_')}"
                    fw.add_rule(
                        rule_name=rule_name,
                        description=f"天盾入侵检测 - 封锁扫描源 {src_ip}",
                        direction='in', action='block',
                        protocol='any', remote_ip=src_ip,
                    )
                    logger.warning(f"入侵检测: 已封锁扫描源 IP {src_ip}")
            except Exception:
                pass
            return True

        return False


class DNSProtection:
    """DNS保护"""

    MALICIOUS_DOMAINS = [
        'malware.example.com', 'c2.server.com', 'ransom.pay.com',
        'phishing.example.com', 'botnet.cnc.com',
    ]

    def check_domain(self, domain: str) -> bool:
        """检查域名是否恶意"""
        domain = domain.lower().strip()
        for malicious in self.MALICIOUS_DOMAINS:
            if domain == malicious or domain.endswith('.' + malicious):
                logger.warning(f"DNS保护: 阻止恶意域名 {domain}")
                return False
        return True


# ============================================================
# 全局防火墙
# ============================================================
firewall = FirewallEngine()
intrusion_detection = IntrusionDetection()
dns_protection = DNSProtection()