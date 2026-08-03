#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 防火墙引擎
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
    """防火墙引擎"""

    def __init__(self):
        self._rules: List[FirewallRule] = []
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认规则"""
        self._rules = [
            FirewallRule('FW001', '允许本地回环', 'in', 'allow', 'any',
                        local_ip='127.0.0.1'),
            FirewallRule('FW002', '允许本地回环出站', 'out', 'allow', 'any',
                        local_ip='127.0.0.1'),
            FirewallRule('FW003', '阻止高危端口入站', 'in', 'block', 'tcp',
                        remote_port=135),
            FirewallRule('FW004', '阻止高危端口入站', 'in', 'block', 'tcp',
                        remote_port=445),
            FirewallRule('FW005', '阻止高危端口入站', 'in', 'block', 'tcp',
                        remote_port=139),
            FirewallRule('FW006', '阻止高危端口入站', 'in', 'block', 'tcp',
                        remote_port=3389),
            FirewallRule('FW007', '阻止远程桌面暴力破解', 'in', 'block', 'tcp',
                        remote_port=3389, remote_ip='0.0.0.0/0'),
        ]

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("防火墙引擎已启动")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                self._check_connections()
            except Exception:
                pass
            time.sleep(10)

    def _check_connections(self):
        """检查网络连接"""
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
                                )
        except ImportError:
            pass
        except Exception:
            pass

    def add_rule(self, rule: FirewallRule):
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, rule_id: str):
        with self._lock:
            self._rules = [r for r in self._rules if r.id != rule_id]

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