#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - Windows 防火墙 API 封装
通过 COM (INetFwPolicy2) 或 netsh 命令管理 Windows 防火墙规则
"""
import os
import sys
import time
import subprocess
import threading
from typing import Dict, List, Optional, Tuple

# ============================================================
# 防火墙动作常量
# ============================================================
FW_ACTION_BLOCK = 3
FW_ACTION_ALLOW = 2

# ============================================================
# 防火墙方向常量
# ============================================================
FW_DIRECTION_IN = 1
FW_DIRECTION_OUT = 2

# ============================================================
# 协议常量
# ============================================================
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ANY = 256

# ============================================================
# 配置文件类型
# ============================================================
FW_PROFILE_DOMAIN = 1
FW_PROFILE_PRIVATE = 2
FW_PROFILE_PUBLIC = 4
FW_PROFILE_ALL = 0x7FFFFFFF

# ============================================================
# 高危端口
# ============================================================
HIGH_RISK_PORTS = [135, 445, 139, 3389]

# ============================================================
# COM CLSID 常量
# ============================================================
CLSID_NETFW_POLICY2 = "{E2B3C97D-6AE5-46AC-9943-246C7E8B16D4}"


# ============================================================
# 防火墙规则管理
# ============================================================

class WinFirewallManager:
    """
    Windows 防火墙管理器。
    优先使用 COM (INetFwPolicy2)，回退到 netsh advfirewall 命令。
    """

    def __init__(self):
        self._com_available = False
        self._policy = None
        self._lock = threading.Lock()
        self._rules_cache: Dict[str, dict] = {}
        self._last_sync = 0.0

        # 尝试初始化 COM
        self._try_init_com()

    def _try_init_com(self):
        """尝试初始化 COM 接口"""
        try:
            import win32com.client  # type: ignore
            # 初始化 COM 单线程单元
            import pythoncom  # type: ignore
            pythoncom.CoInitialize()
            self._policy = win32com.client.Dispatch(CLSID_NETFW_POLICY2)
            # 验证接口可用
            _ = self._policy.Rules.Count
            self._com_available = True
        except Exception:
            self._com_available = False
            # 验证 netsh 可用
            try:
                subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'currentprofile'],
                    capture_output=True, timeout=5, check=False,
                    errors='replace',
                )
            except Exception:
                pass

    @property
    def available(self) -> bool:
        """是否可用（COM 或 netsh 任一通道）"""
        return self._com_available

    # ------------------------------------------------------------
    # 添加规则
    # ------------------------------------------------------------
    def add_rule(self, rule_name: str, description: str = '',
                 direction: str = 'in', action: str = 'block',
                 protocol: str = 'tcp', local_ports: str = '',
                 remote_ports: str = '', program_path: str = '',
                 remote_ip: str = '', local_ip: str = '') -> bool:
        """
        添加防火墙规则。
        返回 True 表示成功，False 表示失败。
        """
        with self._lock:
            if self._com_available:
                return self._add_rule_com(
                    rule_name, description, direction, action,
                    protocol, local_ports, remote_ports,
                    program_path, remote_ip, local_ip,
                )
            else:
                return self._add_rule_netsh(
                    rule_name, direction, action, protocol,
                    local_ports, remote_ports, program_path,
                    remote_ip, local_ip,
                )

    def _add_rule_com(self, rule_name: str, description: str,
                      direction: str, action: str,
                      protocol: str, local_ports: str,
                      remote_ports: str, program_path: str,
                      remote_ip: str, local_ip: str) -> bool:
        """通过 COM 添加规则"""
        try:
            import win32com.client  # type: ignore
            import pythoncom  # type: ignore

            # 检查是否已存在同名规则
            existing = self._find_rule_com(rule_name)
            if existing:
                return True  # 规则已存在

            rule = win32com.client.Dispatch("HNetCfg.FwRule")
            rule.Name = rule_name
            rule.Description = description
            rule.Enabled = True

            # 方向
            if direction == 'in':
                rule.Direction = FW_DIRECTION_IN
            elif direction == 'out':
                rule.Direction = FW_DIRECTION_OUT

            # 动作
            if action == 'block':
                rule.Action = FW_ACTION_BLOCK
            elif action == 'allow':
                rule.Action = FW_ACTION_ALLOW

            # 协议
            if protocol == 'tcp':
                rule.Protocol = PROTOCOL_TCP
            elif protocol == 'udp':
                rule.Protocol = PROTOCOL_UDP
            else:
                rule.Protocol = PROTOCOL_ANY

            # 端口
            if local_ports:
                rule.LocalPorts = local_ports
            if remote_ports:
                rule.RemotePorts = remote_ports

            # 程序路径
            if program_path:
                rule.ApplicationName = program_path

            # IP 地址
            if remote_ip:
                rule.RemoteAddresses = remote_ip
            if local_ip:
                rule.LocalAddresses = local_ip

            # 应用到所有配置文件
            self._policy.Rules.Add(rule)
            return True
        except Exception:
            return False

    def _add_rule_netsh(self, rule_name: str, direction: str,
                        action: str, protocol: str,
                        local_ports: str, remote_ports: str,
                        program_path: str, remote_ip: str,
                        local_ip: str) -> bool:
        """通过 netsh 添加规则"""
        try:
            dir_arg = 'in' if direction == 'in' else 'out'
            action_arg = 'block' if action == 'block' else 'allow'

            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                f'dir={dir_arg}',
                f'action={action_arg}',
                'enable=yes',
            ]

            if protocol and protocol != 'any':
                cmd.append(f'protocol={protocol}')
            if local_ports:
                cmd.append(f'localport={local_ports}')
            if remote_ports:
                cmd.append(f'remoteport={remote_ports}')
            if program_path:
                cmd.append(f'program="{program_path}"')
            if remote_ip:
                cmd.append(f'remoteip={remote_ip}')
            if local_ip:
                cmd.append(f'localip={local_ip}')

            result = subprocess.run(
                cmd, capture_output=True, timeout=10, text=True, check=False,
                errors='replace',
            )
            return result.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------
    # 删除规则
    # ------------------------------------------------------------
    def remove_rule(self, rule_name: str) -> bool:
        """删除防火墙规则"""
        with self._lock:
            if self._com_available:
                return self._remove_rule_com(rule_name)
            else:
                return self._remove_rule_netsh(rule_name)

    def _remove_rule_com(self, rule_name: str) -> bool:
        """通过 COM 删除规则"""
        try:
            existing = self._find_rule_com(rule_name)
            if existing:
                self._policy.Rules.Remove(rule_name)
            return True
        except Exception:
            return False

    def _find_rule_com(self, rule_name: str) -> bool:
        """通过 COM 查找规则是否存在"""
        try:
            rules = self._policy.Rules
            for i in range(rules.Count):
                rule = rules.Item(i + 1)
                if rule.Name == rule_name:
                    return True
            return False
        except Exception:
            return False

    def _remove_rule_netsh(self, rule_name: str) -> bool:
        """通过 netsh 删除规则"""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}'],
                capture_output=True, timeout=10, text=True, check=False,
                errors='replace',
            )
            return result.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------
    # 批量端口封锁
    # ------------------------------------------------------------
    def block_port(self, port: int, protocol: str = 'tcp',
                   direction: str = 'in') -> bool:
        """封锁指定端口"""
        rule_name = f"Tiandun_Block_{protocol.upper()}_{port}_{direction.upper()}"
        description = f"天盾安全防护 - 封锁端口 {port}/{protocol} ({direction})"
        local_ports = str(port)
        return self.add_rule(
            rule_name=rule_name,
            description=description,
            direction=direction,
            action='block',
            protocol=protocol,
            local_ports=local_ports,
        )

    def unblock_port(self, port: int, protocol: str = 'tcp',
                     direction: str = 'in') -> bool:
        """解除端口封锁"""
        rule_name = f"Tiandun_Block_{protocol.upper()}_{port}_{direction.upper()}"
        return self.remove_rule(rule_name)

    def block_high_risk_ports(self) -> List[Tuple[int, bool]]:
        """封锁所有高危端口，返回 (端口, 成功) 列表"""
        results = []
        for port in HIGH_RISK_PORTS:
            ok = self.block_port(port, 'tcp', 'in')
            results.append((port, ok))
            # UDP 也封锁
            ok2 = self.block_port(port, 'udp', 'in')
            results.append((port, ok2))
        return results

    # ------------------------------------------------------------
    # 程序封锁
    # ------------------------------------------------------------
    def block_program(self, program_path: str, rule_name: str = None) -> bool:
        """封锁指定程序的所有网络访问"""
        if rule_name is None:
            base_name = os.path.basename(program_path)
            rule_name = f"Tiandun_Block_Program_{base_name}"

        # 入站 + 出站均封锁
        in_ok = self.add_rule(
            rule_name=rule_name + "_IN",
            description=f"天盾安全防护 - 封锁程序入站 {program_path}",
            direction='in', action='block',
            protocol='any', program_path=program_path,
        )
        out_ok = self.add_rule(
            rule_name=rule_name + "_OUT",
            description=f"天盾安全防护 - 封锁程序出站 {program_path}",
            direction='out', action='block',
            protocol='any', program_path=program_path,
        )
        return in_ok and out_ok

    def unblock_program(self, program_path: str) -> bool:
        """解除程序封锁"""
        base_name = os.path.basename(program_path)
        rule_name = f"Tiandun_Block_Program_{base_name}"
        in_ok = self.remove_rule(rule_name + "_IN")
        out_ok = self.remove_rule(rule_name + "_OUT")
        return in_ok or out_ok

    # ------------------------------------------------------------
    # 规则查询
    # ------------------------------------------------------------
    def list_rules(self) -> List[Dict]:
        """列出所有 Tiandun 开头的规则"""
        rules = []
        if self._com_available:
            try:
                all_rules = self._policy.Rules
                for i in range(all_rules.Count):
                    rule = all_rules.Item(i + 1)
                    name = rule.Name
                    if name.startswith('Tiandun'):
                        rules.append({
                            'name': name,
                            'description': getattr(rule, 'Description', ''),
                            'direction': 'in' if rule.Direction == FW_DIRECTION_IN else 'out',
                            'action': 'block' if rule.Action == FW_ACTION_BLOCK else 'allow',
                            'protocol': rule.Protocol,
                            'local_ports': getattr(rule, 'LocalPorts', ''),
                            'remote_ports': getattr(rule, 'RemotePorts', ''),
                            'program': getattr(rule, 'ApplicationName', ''),
                            'enabled': rule.Enabled,
                        })
            except Exception:
                pass
        else:
            # netsh 方式查询
            try:
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                     'name=all', 'verbose'],
                    capture_output=True, timeout=10, text=True, check=False,
                    errors='replace',
                )
                # 简单解析输出
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current = {}
                    for line in lines:
                        line = line.strip()
                        if line.startswith('Rule Name:'):
                            if current and current.get('name', '').startswith('Tiandun'):
                                rules.append(current)
                            current = {'name': line.split(':', 1)[1].strip()}
                        elif line.startswith('Description:'):
                            current['description'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Enabled:'):
                            current['enabled'] = 'Yes' in line
                        elif line.startswith('Direction:'):
                            current['direction'] = line.split(':', 1)[1].strip().lower()
                        elif line.startswith('Action:'):
                            current['action'] = line.split(':', 1)[1].strip().lower()
                    if current and current.get('name', '').startswith('Tiandun'):
                        rules.append(current)
            except Exception:
                pass
        return rules

    # ------------------------------------------------------------
    # 启用/禁用防火墙
    # ------------------------------------------------------------
    def set_firewall_state(self, profile: str = 'all', enabled: bool = True) -> bool:
        """设置防火墙状态（启用/禁用）"""
        try:
            state = 'on' if enabled else 'off'
            result = subprocess.run(
                ['netsh', 'advfirewall', 'set', f'{profile}profile',
                 f'firewallpolicy=blockinbound,allowoutbound'],
                capture_output=True, timeout=10, text=True, check=False,
                errors='replace',
            )
            # 启用防火墙
            result2 = subprocess.run(
                ['netsh', 'advfirewall', 'set', f'{profile}profile',
                 f'state={state}'],
                capture_output=True, timeout=10, text=True, check=False,
                errors='replace',
            )
            return result2.returncode == 0
        except Exception:
            return False


# ============================================================
# 全局实例
# ============================================================
_fw_manager = None
_fw_manager_lock = threading.Lock()


def get_firewall_manager() -> WinFirewallManager:
    """获取全局防火墙管理器单例"""
    global _fw_manager
    if _fw_manager is None:
        with _fw_manager_lock:
            if _fw_manager is None:
                _fw_manager = WinFirewallManager()
    return _fw_manager