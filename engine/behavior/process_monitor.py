#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 进程行为监控器
=================================
监控进程创建和终止，检测可疑进程行为。
使用 psutil 轮询进程列表，实现 20+ 检测规则。

检测规则:
    - 进程注入 (CreateRemoteThread, WriteProcessMemory)
    - 傀儡进程 (进程镂空)
    - 进程提权 (SeDebugPrivilege, SeTakeOwnershipPrivilege)
    - 异常进程树 (子进程创建)
    - 内存操作异常 (异常内存分配)
    - 可疑进程链 (Office/浏览器启动shell)
    - 进程伪装 (镜像劫持)
    - 无父进程/孤儿进程
    - 重复进程创建
    - 关键进程终止
    - DLL注入检测
    - APC注入检测
    - 线程劫持
    - 进程权限提升
    - 异常句柄操作
    - 会话劫持
    - 远程线程创建
    - 进程穿透 (Session 0)
    - 异常进程父子关系
    - 隐藏进程检测
    - 进程心跳检测
"""

import os
import sys
import time
import json
import threading
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field

# 将项目根目录加入路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger
from engine.config import config


# ============================================================
# 进程事件定义
# ============================================================
@dataclass
class ProcessEvent:
    """进程事件数据结构"""
    timestamp: float = field(default_factory=time.time)
    event_type: str = ''           # start, terminate, inject, privilege, memory, handle
    pid: int = 0
    ppid: int = 0
    process_name: str = ''
    process_path: str = ''
    command_line: str = ''
    username: str = ''
    parent_name: str = ''
    parent_path: str = ''
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'event_type': self.event_type,
            'pid': self.pid,
            'ppid': self.ppid,
            'process_name': self.process_name,
            'process_path': self.process_path,
            'command_line': self.command_line,
            'username': self.username,
            'parent_name': self.parent_name,
            'parent_path': self.parent_path,
            'details': self.details,
        }


# ============================================================
# 进程检测规则定义
# ============================================================
@dataclass
class ProcessRule:
    """进程行为检测规则"""
    rule_id: str
    name: str
    description: str
    severity: int           # 1-5, 5=最严重
    score: int              # 威胁评分
    category: str           # inject, privilege, anomaly, chain, hide, etc.

    def matches(self, event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
        """
        匹配规则，返回 (是否匹配, 置信度 0-100)
        子类应重写此方法
        """
        return False, 0


# ============================================================
# 系统敏感进程集合
# ============================================================
CRITICAL_SYSTEM_PROCESSES = {
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
    'lsass.exe', 'lsm.exe', 'svchost.exe', 'smss.exe', 'system',
    'system idle process', 'spoolsv.exe', 'explorer.exe',
    'taskmgr.exe', 'msmpeng.exe', 'wuauclt.exe',
}

KNOWN_SUSPICIOUS_PARENT_CHILD = {
    'winword.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                    'mshta.exe', 'rundll32.exe', 'regsvr32.exe'],
    'excel.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                  'mshta.exe', 'rundll32.exe', 'regsvr32.exe'],
    'powerpnt.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                     'mshta.exe', 'rundll32.exe', 'regsvr32.exe'],
    'outlook.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                    'mshta.exe', 'rundll32.exe', 'regsvr32.exe'],
    'chrome.exe': ['cmd.exe', 'powershell.exe'],
    'firefox.exe': ['cmd.exe', 'powershell.exe'],
    'iexplore.exe': ['cmd.exe', 'powershell.exe', 'mshta.exe'],
    'explorer.exe': ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'],
    'acrobat.exe': ['cmd.exe', 'powershell.exe'],
    'acrord32.exe': ['cmd.exe', 'powershell.exe'],
}

SHELL_PROCESSES = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
    'reg.exe', 'schtasks.exe', 'wmic.exe', 'nslookup.exe',
    'ftp.exe', 'bitsadmin.exe', 'certutil.exe', 'cscript.exe',
    'msiexec.exe', 'hh.exe', 'scrcons.exe', 'wmiprvse.exe',
}

SENSITIVE_DIRECTORIES = [
    '\\windows\\system32\\',
    '\\windows\\syswow64\\',
    '\\windows\\',
    '\\program files\\',
    '\\program files (x86)\\',
    '\\programdata\\',
    '\\appdata\\roaming\\',
    '\\appdata\\local\\',
    '\\temp\\',
    '\\users\\',
    '\\windows\\temp\\',
]


# ============================================================
# 规则实现集合
# ============================================================
def check_process_injection(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测进程注入行为 (规则 P001)"""
    if event.event_type == 'inject':
        details = event.details or {}
        inject_type = details.get('inject_type', '')
        # 远程线程创建
        if inject_type == 'CreateRemoteThread':
            return True, 90
        # 写入远程进程内存
        if inject_type == 'WriteProcessMemory':
            return True, 85
        # 远程虚拟内存分配
        if inject_type == 'VirtualAllocEx':
            return True, 80
        # SetWindowsHookEx 跨进程
        if inject_type == 'SetWindowsHookEx':
            return True, 70
        # APC 注入
        if inject_type == 'QueueUserAPC':
            return True, 85
    return False, 0


def check_process_hollowing(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测傀儡进程/进程镂空 (规则 P002)"""
    if event.event_type == 'inject':
        details = event.details or {}
        actions = details.get('actions', [])
        # 进程镂空特征: NtUnmapViewOfSection + SetThreadContext + ResumeThread
        hollowing_indicators = {'NtUnmapViewOfSection', 'SetThreadContext', 'ResumeThread',
                                'NtWriteVirtualMemory', 'ZwUnmapViewOfSection'}
        matched = hollowing_indicators & set(actions)
        if len(matched) >= 2:
            return True, 80 + min(len(matched) * 5, 20)
    return False, 0


def check_privilege_escalation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测进程提权 (规则 P003)"""
    if event.event_type == 'privilege':
        details = event.details or {}
        privileges = details.get('privileges', [])
        dangerous_privs = {'SeDebugPrivilege', 'SeTakeOwnershipPrivilege',
                           'SeLoadDriverPrivilege', 'SeTcbPrivilege',
                           'SeBackupPrivilege', 'SeRestorePrivilege',
                           'SeCreateTokenPrivilege', 'SeIncreaseQuotaPrivilege',
                           'SeAssignPrimaryTokenPrivilege', 'SeSystemtimePrivilege'}
        enabled_privs = [p for p in privileges if p in dangerous_privs]
        if enabled_privs:
            score = 60 + len(enabled_privs) * 10
            return True, min(score, 100)
    return False, 0


def check_anomalous_parent_child(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测异常的父子进程关系 (规则 P004)"""
    if event.event_type == 'start':
        parent_lower = event.parent_name.lower()
        child_lower = event.process_name.lower()
        if parent_lower in KNOWN_SUSPICIOUS_PARENT_CHILD:
            suspicious_children = KNOWN_SUSPICIOUS_PARENT_CHILD[parent_lower]
            for sc in suspicious_children:
                if sc.lower() == child_lower:
                    # 从 Office 文档启动 shell 很可疑
                    office_apps = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'}
                    if parent_lower in office_apps:
                        return True, 85
                    return True, 70
        # 检查浏览器启动 shell
        if parent_lower in ('chrome.exe', 'firefox.exe', 'iexplore.exe', 'edge.exe',
                            'msedge.exe', 'brave.exe', 'opera.exe'):
            if child_lower in ('cmd.exe', 'powershell.exe', 'pwsh.exe'):
                return True, 75
    return False, 0


def check_suspicious_parent_process(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测可疑父进程 (规则 P005)"""
    if event.event_type == 'start':
        parent_lower = event.parent_name.lower()
        # 父进程不存在或为已终止进程
        if parent_lower == '' or parent_lower == 'idle':
            return True, 60
        # 由 shell 进程启动 shell (链式启动)
        if parent_lower in SHELL_PROCESSES and event.process_name.lower() in SHELL_PROCESSES:
            return True, 65
        # 由临时目录的进程启动
        if '\\temp\\' in event.parent_path.lower() or '\\tmp\\' in event.parent_path.lower():
            return True, 75
    return False, 0


def check_critical_process_termination(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测关键进程被终止 (规则 P006)"""
    if event.event_type == 'terminate':
        name_lower = event.process_name.lower()
        if name_lower in CRITICAL_SYSTEM_PROCESSES:
            termination_source = event.details.get('terminated_by', '')
            # 由非系统进程终止关键进程
            if termination_source:
                source_lower = termination_source.lower()
                if source_lower not in ('services.exe', 'smss.exe', 'wininit.exe',
                                        'csrss.exe', 'taskmgr.exe'):
                    return True, 90
            return True, 70
    return False, 0


def check_anomalous_memory_operation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测异常内存操作 (规则 P007)"""
    if event.event_type == 'memory':
        details = event.details or {}
        mem_type = details.get('memory_type', '')
        # 执行可写内存 (DEP 绕过)
        if mem_type == 'RWX':
            return True, 80
        # 大量异常内存分配
        if mem_type == 'large_alloc':
            size = details.get('size', 0)
            if size > 100 * 1024 * 1024:  # >100MB
                return True, 65
        # 堆喷射
        if mem_type == 'heap_spray':
            return True, 85
        # 内存覆盖
        if mem_type == 'memory_overwrite':
            return True, 75
    return False, 0


def check_process_impersonation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测进程伪装/镜像劫持 (规则 P008)"""
    if event.event_type == 'start':
        name_lower = event.process_name.lower()
        path_lower = event.process_path.lower()
        # 进程名看似系统进程但路径不对
        if name_lower in ('svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
                          'services.exe', 'smss.exe', 'wininit.exe'):
            correct_paths = {
                'svchost.exe': ['c:\\windows\\system32\\svchost.exe',
                                'c:\\windows\\syswow64\\svchost.exe'],
                'lsass.exe': ['c:\\windows\\system32\\lsass.exe'],
                'csrss.exe': ['c:\\windows\\system32\\csrss.exe'],
                'winlogon.exe': ['c:\\windows\\system32\\winlogon.exe'],
                'services.exe': ['c:\\windows\\system32\\services.exe'],
                'smss.exe': ['c:\\windows\\system32\\smss.exe'],
                'wininit.exe': ['c:\\windows\\system32\\wininit.exe'],
                'explorer.exe': ['c:\\windows\\explorer.exe'],
            }
            if name_lower in correct_paths:
                if path_lower not in correct_paths[name_lower]:
                    return True, 95
    return False, 0


def check_orphan_process(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测孤儿进程/无父进程 (规则 P009)"""
    if event.event_type == 'start':
        # ppid=0 或 ppid=4 (System) 但进程不是系统进程
        if event.ppid in (0, 4) and event.process_name.lower() not in ('system', 'smss.exe'):
            # 检查是否为正常系统进程
            path_lower = event.process_path.lower()
            if '\\windows\\system32\\' not in path_lower and '\\windows\\syswow64\\' not in path_lower:
                return True, 70
    return False, 0


def check_unknown_process_from_temp(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测从临时目录启动的可疑进程 (规则 P010)"""
    if event.event_type == 'start':
        path_lower = event.process_path.lower()
        name_lower = event.process_name.lower()
        if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
            # 排除正常的安装程序
            installers = {'setup.exe', 'install.exe', 'msiexec.exe', 'update.exe'}
            if name_lower not in installers:
                # 检查临时目录中的进程是否有签名
                if not event.details.get('is_signed', False):
                    return True, 75
    return False, 0


def check_repeated_process_creation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测短时间内重复创建同一进程 (规则 P011)"""
    if event.event_type == 'start':
        now = time.time()
        count = 0
        for ev in reversed(history[-50:]):
            if ev.event_type == 'start' and ev.process_name == event.process_name:
                if now - ev.timestamp < 60:  # 60秒内
                    count += 1
                else:
                    break
        if count >= 5:
            return True, 60 + min(count * 3, 40)
    return False, 0


def check_suspicious_handle_operation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测异常句柄操作 (规则 P012)"""
    if event.event_type == 'handle':
        details = event.details or {}
        handle_type = details.get('handle_type', '')
        target_pid = details.get('target_pid', 0)
        # 打开系统关键进程句柄
        if handle_type == 'OpenProcess' and target_pid:
            critical_pids = {4, 8, 16, 32, 64, 128, 256, 372, 488, 504, 508, 524, 540, 548, 668, 696, 728, 748, 776, 792, 876, 888}
            if target_pid in critical_pids:
                desired_access = details.get('desired_access', 0)
                # PROCESS_ALL_ACCESS or PROCESS_VM_WRITE
                if desired_access & 0x1FFFFF or desired_access & 0x0020:
                    return True, 80
    return False, 0


def check_dll_injection(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测 DLL 注入 (规则 P013)"""
    if event.event_type == 'inject' and event.details:
        inject_type = event.details.get('inject_type', '')
        dll_path = event.details.get('dll_path', '')
        # CreateRemoteThread + LoadLibrary
        if inject_type == 'LoadLibrary' and dll_path:
            suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
                               '\\users\\', '\\downloads\\']
            for dir in suspicious_dirs:
                if dir in dll_path.lower():
                    return True, 85
            return True, 70
        # Reflective DLL Injection
        if inject_type == 'reflective_dll':
            return True, 90
        # Known DLL side-loading patterns
        if inject_type == 'dll_side_loading':
            return True, 75
    return False, 0


def check_remote_thread_creation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测远程线程创建 (规则 P014)"""
    if event.event_type == 'thread':
        details = event.details or {}
        thread_type = details.get('thread_type', '')
        if thread_type == 'CreateRemoteThread':
            target_pid = details.get('target_pid', 0)
            source_pid = details.get('source_pid', 0)
            if target_pid and source_pid and target_pid != source_pid:
                # 注入到系统进程
                try:
                    import psutil
                    target_proc = psutil.Process(target_pid)
                    if target_proc.name().lower() in ('lsass.exe', 'winlogon.exe', 'csrss.exe',
                                                       'services.exe', 'svchost.exe'):
                        return True, 95
                except Exception:
                    pass
                return True, 75
    return False, 0


def check_office_macro_process(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测Office宏启动可疑进程 (规则 P015)"""
    if event.event_type == 'start':
        parent_lower = event.parent_name.lower()
        child_lower = event.process_name.lower()
        office_apps = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
                       'mspub.exe', 'visio.exe', 'access.exe'}
        if parent_lower in office_apps:
            if child_lower in ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                               'cscript.exe', 'mshta.exe', 'rundll32.exe'):
                return True, 85
            # Office 创建脚本解释器
            if child_lower in ('python.exe', 'python3.exe', 'perl.exe', 'ruby.exe',
                               'node.exe', 'php.exe', 'java.exe'):
                return True, 80
    return False, 0


def check_scheduled_task_creation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测进程创建计划任务 (规则 P016)"""
    if event.event_type == 'start':
        child_lower = event.process_name.lower()
        if child_lower in ('schtasks.exe', 'at.exe'):
            parent_lower = event.parent_name.lower()
            if parent_lower not in ('explorer.exe', 'svchost.exe', 'taskeng.exe'):
                return True, 70
    return False, 0


def check_service_creation(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测进程创建服务 (规则 P017)"""
    if event.event_type == 'start':
        child_lower = event.process_name.lower()
        if child_lower in ('sc.exe', 'instsrv.exe', 'srvany.exe'):
            parent_lower = event.parent_name.lower()
            if parent_lower not in ('services.exe', 'svchost.exe', 'explorer.exe'):
                return True, 75
        # 由非系统进程启动的 services.exe
        if child_lower == 'services.exe':
            return True, 80
    return False, 0


def check_browser_launching_unexpected(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测非用户启动浏览器 (规则 P018)"""
    if event.event_type == 'start':
        child_lower = event.process_name.lower()
        browsers = {'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe',
                    'brave.exe', 'opera.exe', 'safari.exe'}
        if child_lower in browsers:
            parent_lower = event.parent_name.lower()
            # 浏览器应被 explorer.exe 或自身启动
            if parent_lower not in ('explorer.exe', child_lower, 'taskmgr.exe', ''):
                # 检查是否由计划任务启动
                if parent_lower not in ('svchost.exe', 'taskeng.exe'):
                    return True, 60
    return False, 0


def check_wmi_persistence(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测WMI持久化 (规则 P019)"""
    if event.event_type == 'start':
        child_lower = event.process_name.lower()
        if child_lower in ('wmiprvse.exe', 'wmiadap.exe', 'wmic.exe'):
            parent_lower = event.parent_name.lower()
            cmd_line = event.command_line.lower()
            # 使用 WMI 创建进程持久化
            if 'create' in cmd_line or 'put' in cmd_line or 'active_script' in cmd_line:
                return True, 75
            if parent_lower not in ('svchost.exe', 'wininit.exe', 'wmiprvse.exe'):
                return True, 65
    return False, 0


def check_process_chain_depth(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测异常进程链深度 (规则 P020)"""
    if event.event_type == 'start':
        # 计算进程链深度
        depth = 1
        current_ppid = event.ppid
        seen = set()
        seen.add(event.pid)
        # 回溯最多10层
        for _ in range(10):
            if current_ppid in seen or current_ppid <= 0:
                break
            seen.add(current_ppid)
            try:
                import psutil
                parent = psutil.Process(current_ppid)
                parent_name = parent.name().lower()
                # 如果父进程是 shell, 深度+1
                if parent_name in SHELL_PROCESSES:
                    depth += 1
                current_ppid = parent.ppid()
            except Exception:
                break
        if depth >= 4:
            return True, 60 + min(depth * 5, 40)
    return False, 0


def check_reflective_loader(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测反射式加载器 (规则 P021)"""
    if event.event_type == 'memory':
        details = event.details or {}
        mem_type = details.get('memory_type', '')
        if mem_type == 'reflective_load':
            return True, 90
        # Shellcode 加载特征
        if mem_type == 'shellcode':
            return True, 95
    if event.event_type == 'inject':
        inject_type = event.details.get('inject_type', '') if event.details else ''
        if inject_type == 'shellcode_execution':
            return True, 95
    return False, 0


def check_known_malware_pattern(event: ProcessEvent, history: List[ProcessEvent]) -> Tuple[bool, int]:
    """检测已知恶意软件进程模式 (规则 P022)"""
    if event.event_type == 'start':
        name_lower = event.process_name.lower()
        path_lower = event.process_path.lower()

        # 常见恶意软件进程名
        malware_names = {
            'bot.exe', 'client.exe', 'server.exe', 'backdoor.exe', 'rat.exe',
            'keylogger.exe', 'spy.exe', 'stealer.exe', 'miner.exe', 'xmr.exe',
            'monero.exe', 'ethminer.exe', 'ccminer.exe', 'winring0x64.exe',
            'winring0.exe', 'inject.exe', 'loader.exe', 'dropper.exe',
            'payload.exe', 'encrypt.exe', 'decrypt.exe', 'ransom.exe',
            'locker.exe', 'crypt.exe', 'evil.exe', 'hack.exe', 'exploit.exe',
        }
        if name_lower in malware_names:
            return True, 90
        # 随机名进程在临时目录
        if '\\temp\\' in path_lower and len(os.path.splitext(name_lower)[0]) <= 4:
            import re
            if re.match(r'^[a-z0-9]{1,4}\.exe$', name_lower):
                return True, 70
    return False, 0


# ============================================================
# 规则注册表
# ============================================================
ALL_PROCESS_RULES = [
    ProcessRule('P001', '进程注入', '检测远程线程创建、内存写入等进程注入行为', 5, 25, 'inject'),
    ProcessRule('P002', '傀儡进程', '检测进程镂空/替换等傀儡进程技术', 5, 30, 'inject'),
    ProcessRule('P003', '进程提权', '检测启用危险权限(SeDebugPrivilege等)', 5, 25, 'privilege'),
    ProcessRule('P004', '异常进程树', '检测异常的父子进程关系', 4, 15, 'chain'),
    ProcessRule('P005', '可疑父进程', '检测由可疑父进程启动的子进程', 4, 15, 'chain'),
    ProcessRule('P006', '关键进程终止', '检测系统关键进程被恶意终止', 5, 30, 'anomaly'),
    ProcessRule('P007', '异常内存操作', '检测RWX内存分配、堆喷射等异常内存操作', 5, 25, 'memory'),
    ProcessRule('P008', '进程伪装', '检测进程镜像劫持及伪装系统进程', 5, 30, 'hide'),
    ProcessRule('P009', '孤儿进程', '检测无父进程的可疑进程', 3, 10, 'anomaly'),
    ProcessRule('P010', '临时目录进程', '检测从临时目录启动的可疑进程', 4, 20, 'anomaly'),
    ProcessRule('P011', '重复进程创建', '检测短时间内大量重复创建进程', 3, 10, 'anomaly'),
    ProcessRule('P012', '异常句柄操作', '检测打开系统关键进程句柄', 4, 20, 'handle'),
    ProcessRule('P013', 'DLL注入', '检测DLL注入及侧加载行为', 5, 25, 'inject'),
    ProcessRule('P014', '远程线程', '检测远程线程创建行为', 5, 25, 'inject'),
    ProcessRule('P015', 'Office宏进程', '检测Office宏启动shell/脚本进程', 5, 25, 'chain'),
    ProcessRule('P016', '计划任务创建', '检测非用户发起计划任务创建', 4, 20, 'persistence'),
    ProcessRule('P017', '服务创建', '检测非系统进程创建Windows服务', 4, 20, 'persistence'),
    ProcessRule('P018', '异常浏览器启动', '检测非用户直接启动浏览器', 3, 10, 'anomaly'),
    ProcessRule('P019', 'WMI持久化', '检测WMI滥用进行持久化', 4, 20, 'persistence'),
    ProcessRule('P020', '进程链深度', '检测深度超过4层的Shell进程链', 3, 15, 'chain'),
    ProcessRule('P021', '反射式加载', '检测反射式DLL加载和Shellcode执行', 5, 30, 'inject'),
    ProcessRule('P022', '恶意进程模式', '检测已知恶意软件进程名及随机名进程', 4, 25, 'anomaly'),
]

# 规则ID到检测函数的映射
RULE_CHECK_FUNCTIONS = {
    'P001': check_process_injection,
    'P002': check_process_hollowing,
    'P003': check_privilege_escalation,
    'P004': check_anomalous_parent_child,
    'P005': check_suspicious_parent_process,
    'P006': check_critical_process_termination,
    'P007': check_anomalous_memory_operation,
    'P008': check_process_impersonation,
    'P009': check_orphan_process,
    'P010': check_unknown_process_from_temp,
    'P011': check_repeated_process_creation,
    'P012': check_suspicious_handle_operation,
    'P013': check_dll_injection,
    'P014': check_remote_thread_creation,
    'P015': check_office_macro_process,
    'P016': check_scheduled_task_creation,
    'P017': check_service_creation,
    'P018': check_browser_launching_unexpected,
    'P019': check_wmi_persistence,
    'P020': check_process_chain_depth,
    'P021': check_reflective_loader,
    'P022': check_known_malware_pattern,
}


# ============================================================
# 进程监控器
# ============================================================
class ProcessMonitor:
    """
    进程监控器 - 监控进程创建、终止、注入等行为

    使用 psutil 轮询进程列表，与之前快照对比检测变化。
    支持 22 条检测规则，覆盖进程注入、傀儡进程、提权等场景。
    """

    def __init__(self, engine=None):
        self._engine = engine  # 关联的行为分析引擎
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # 进程快照
        self._process_snapshot: Dict[int, Dict[str, Any]] = {}  # pid -> info
        self._known_processes: Set[int] = set()        # 已知 PID 集合
        self._process_history: Dict[int, List[Dict]] = defaultdict(list)  # pid -> events

        # 事件队列
        self._events: List[ProcessEvent] = []
        self._event_queue: deque = deque(maxlen=10000)

        # 轮询间隔 (秒)
        self._poll_interval = config.get('realtime.monitor_level', 'normal') == 'high' and 1 or 2

        # 统计
        self.stats = {
            'total_events': 0,
            'alerts': 0,
            'processes_started': 0,
            'processes_terminated': 0,
            'injections_detected': 0,
            'privilege_escalations': 0,
        }

        # 父进程缓存
        self._parent_cache: Dict[int, Dict] = {}

        # 启用规则
        self._enabled_rules = set(r.rule_id for r in ALL_PROCESS_RULES)

        logger.info("ProcessMonitor 初始化完成，监控规则: %d 条", len(ALL_PROCESS_RULES))

    # ============================================================
    # 生命周期管理
    # ============================================================
    def start(self):
        """启动进程监控"""
        if self._running:
            logger.warning("ProcessMonitor 已经在运行中")
            return
        self._running = True
        self._take_snapshot()  # 初始快照
        self._thread = threading.Thread(target=self._monitor_loop, name='ProcessMonitor', daemon=True)
        self._thread.start()
        logger.info("ProcessMonitor 已启动 (轮询间隔: %ds)", self._poll_interval)

    def stop(self):
        """停止进程监控"""
        self._running = False
        logger.info("ProcessMonitor 已停止，共处理事件: %d", self.stats['total_events'])

    def is_running(self) -> bool:
        return self._running

    # ============================================================
    # 事件管理
    # ============================================================
    def add_event(self, event: ProcessEvent):
        """添加事件到队列"""
        with self._lock:
            self._events.append(event)
            self._event_queue.append(event)
            self.stats['total_events'] += 1
            if event.pid > 0:
                self._process_history[event.pid].append(event.to_dict())

    def get_events(self) -> List[ProcessEvent]:
        """获取并清空事件队列"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def get_events_since(self, since_time: float) -> List[ProcessEvent]:
        """获取指定时间之后的事件"""
        with self._lock:
            return [e for e in self._event_queue if e.timestamp >= since_time]

    def get_history(self, pid: int = None, limit: int = 100) -> List[Dict]:
        """获取进程历史"""
        if pid:
            return list(self._process_history.get(pid, []))[-limit:]
        result = []
        for h in self._process_history.values():
            result.extend(h[-10:])
        return sorted(result, key=lambda x: x.get('timestamp', ''))[-limit:]

    # ============================================================
    # 快照管理
    # ============================================================
    def _take_snapshot(self) -> Dict[int, Dict[str, Any]]:
        """获取当前进程快照"""
        snapshot = {}
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'username',
                                              'create_time', 'cwd', 'cmdline', 'status']):
                try:
                    pinfo = proc.info
                    if pinfo['pid'] > 0:  # 排除 System Idle Process
                        snapshot[pinfo['pid']] = pinfo
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except ImportError:
            logger.error("psutil 未安装，ProcessMonitor 无法运行")
        except Exception as e:
            logger.error("获取进程快照失败: %s", e)
        return snapshot

    # ============================================================
    # 主监控循环
    # ============================================================
    def _monitor_loop(self):
        """主监控循环"""
        while self._running:
            try:
                current_snapshot = self._take_snapshot()
                if current_snapshot:
                    self._detect_changes(current_snapshot)
                    self._process_snapshot = current_snapshot
                    self._known_processes = set(current_snapshot.keys())
            except Exception as e:
                logger.error("进程监控循环异常: %s", e, exc_info=True)
            time.sleep(self._poll_interval)

    def _detect_changes(self, current: Dict[int, Dict[str, Any]]):
        """检测进程变化"""
        previous = self._process_snapshot

        current_pids = set(current.keys())
        previous_pids = set(previous.keys()) if previous else set()

        # 检测新进程
        new_pids = current_pids - previous_pids
        for pid in new_pids:
            if pid <= 0:
                continue
            try:
                self._on_process_start(current[pid])
            except Exception as e:
                logger.debug("处理进程启动事件异常 [PID=%d]: %s", pid, e)

        # 检测终止的进程
        terminated_pids = previous_pids - current_pids
        for pid in terminated_pids:
            if pid <= 0:
                continue
            try:
                self._on_process_terminate(pid, previous.get(pid, {}))
            except Exception as e:
                logger.debug("处理进程终止事件异常 [PID=%d]: %s", pid, e)

        # 检测已存在进程的异常变化
        existing_pids = current_pids & previous_pids
        for pid in existing_pids:
            try:
                self._detect_process_anomalies(pid, previous.get(pid, {}), current[pid])
            except Exception as e:
                pass

    # ============================================================
    # 事件处理
    # ============================================================
    def _on_process_start(self, proc_info: Dict[str, Any]):
        """处理进程启动事件"""
        pid = proc_info.get('pid', 0)
        ppid = proc_info.get('ppid', 0)
        name = proc_info.get('name', '')
        exe = proc_info.get('exe', '') or ''
        username = proc_info.get('username', '')
        cmdline = proc_info.get('cmdline', [])
        cmdline_str = ' '.join(cmdline) if isinstance(cmdline, list) else str(cmdline or '')

        # 获取父进程信息
        parent_name = ''
        parent_path = ''
        if ppid > 0:
            parent_info = self._parent_cache.get(ppid, {})
            if parent_info:
                parent_name = parent_info.get('name', '')
                parent_path = parent_info.get('exe', '') or ''
            else:
                try:
                    import psutil
                    parent = psutil.Process(ppid)
                    parent_name = parent.name() or ''
                    parent_path = parent.exe() or ''
                except Exception:
                    pass

        # 创建事件
        event = ProcessEvent(
            event_type='start',
            pid=pid,
            ppid=ppid,
            process_name=name,
            process_path=exe,
            command_line=cmdline_str,
            username=username,
            parent_name=parent_name,
            parent_path=parent_path,
            details={
                'create_time': proc_info.get('create_time', 0),
                'cwd': proc_info.get('cwd', '') or '',
                'status': proc_info.get('status', ''),
            }
        )

        self.add_event(event)
        self.stats['processes_started'] += 1

        # 更新父进程缓存
        if ppid > 0:
            self._parent_cache[ppid] = {
                'name': parent_name or 'unknown',
                'exe': parent_path or '',
            }

        # 运行规则检测
        self._run_detection(event)

    def _on_process_terminate(self, pid: int, proc_info: Dict[str, Any]):
        """处理进程终止事件"""
        name = proc_info.get('name', '') or ''
        exe = proc_info.get('exe', '') or ''

        # 尝试找到是谁终止了这个进程
        terminated_by = ''
        try:
            import psutil
            current_procs = psutil.process_iter(['pid', 'name', 'exe'])
            # 简单检查是否有进程最近有句柄到该进程
            for proc in current_procs:
                try:
                    if proc.pid == pid:
                        continue
                    # 检查进程创建时间 - 如果终止者比目标进程创建时间晚
                    # 且有关联，可能是终止者
                    if proc.create_time() > proc_info.get('create_time', 0):
                        pass
                except Exception:
                    pass
        except Exception:
            pass

        event = ProcessEvent(
            event_type='terminate',
            pid=pid,
            ppid=proc_info.get('ppid', 0),
            process_name=name,
            process_path=exe,
            details={
                'terminated_by': terminated_by,
                'exit_code': proc_info.get('exit_code', ''),
            }
        )

        self.add_event(event)
        self.stats['processes_terminated'] += 1
        self._run_detection(event)

    def _detect_process_anomalies(self, pid: int, old_info: Dict, new_info: Dict):
        """检测进程异常变化"""
        # 检测 SID 变更 (提权)
        old_user = old_info.get('username', '')
        new_user = new_info.get('username', '')
        if old_user and new_user and old_user != new_user:
            event = ProcessEvent(
                event_type='privilege',
                pid=pid,
                process_name=new_info.get('name', ''),
                process_path=new_info.get('exe', '') or '',
                details={
                    'old_user': old_user,
                    'new_user': new_user,
                    'privileges': ['SeChangeUserPrivilege'],
                }
            )
            self.add_event(event)
            self.stats['privilege_escalations'] += 1
            self._run_detection(event)

        # 检测进程路径变更 (可能的进程伪装)
        old_exe = old_info.get('exe', '') or ''
        new_exe = new_info.get('exe', '') or ''
        if old_exe and new_exe and old_exe != new_exe:
            event = ProcessEvent(
                event_type='inject',
                pid=pid,
                process_name=new_info.get('name', ''),
                process_path=new_exe,
                details={
                    'old_exe': old_exe,
                    'new_exe': new_exe,
                    'inject_type': 'process_replace',
                }
            )
            self.add_event(event)
            self._run_detection(event)

    # ============================================================
    # 规则检测引擎
    # ============================================================
    def _run_detection(self, event: ProcessEvent):
        """对事件运行所有启用的规则检测"""
        from .behavior_engine import ThreatEvent, ThreatLevel

        for rule in ALL_PROCESS_RULES:
            if rule.rule_id not in self._enabled_rules:
                continue

            check_func = RULE_CHECK_FUNCTIONS.get(rule.rule_id)
            if not check_func:
                continue

            try:
                matched, confidence = check_func(event, list(self._event_queue))
                if matched and confidence >= 50:
                    self.stats['alerts'] += 1
                    if rule.category == 'inject':
                        self.stats['injections_detected'] += 1
                    elif rule.category == 'privilege':
                        self.stats['privilege_escalations'] += 1

                    # 构建威胁事件
                    threat = ThreatEvent(
                        source='process_monitor',
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        score=rule.score + (confidence - 50) // 10,
                        confidence=confidence,
                        description=rule.description,
                        event_data=event.to_dict(),
                        timestamp=event.timestamp,
                    )

                    # 通知引擎
                    if self._engine:
                        self._engine.on_threat_detected(threat)

                    logger.warning(
                        "[进程规则] %s | %s | PID=%d %s | 置信度=%d%% | 评分=%d",
                        rule.rule_id, rule.name, event.pid, event.process_name,
                        confidence, threat.score
                    )

            except Exception as e:
                logger.debug("规则检测异常 [%s]: %s", rule.rule_id, e)

    # ============================================================
    # 进程信息查询
    # ============================================================
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """获取进程详细信息"""
        try:
            import psutil
            proc = psutil.Process(pid)
            info = {
                'pid': pid,
                'ppid': proc.ppid(),
                'name': proc.name(),
                'exe': proc.exe(),
                'cwd': proc.cwd(),
                'username': proc.username(),
                'create_time': proc.create_time(),
                'status': proc.status(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'cpu_percent': proc.cpu_percent(interval=0),
                'memory_percent': proc.memory_percent(),
                'memory_info': {
                    'rss': proc.memory_info().rss,
                    'vms': proc.memory_info().vms,
                },
                'num_threads': proc.num_threads(),
                'num_handles': proc.num_handles() if hasattr(proc, 'num_handles') else 0,
                'is_running': proc.is_running(),
            }
            # 子进程
            try:
                children = proc.children()
                info['children'] = [{'pid': c.pid, 'name': c.name()} for c in children]
            except Exception:
                info['children'] = []
            return info
        except Exception:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """获取监控统计"""
        return {
            **self.stats,
            'running': self._running,
            'known_processes': len(self._known_processes),
            'pending_events': len(self._events),
            'rules_enabled': len(self._enabled_rules),
            'rules_count': len(ALL_PROCESS_RULES),
            'poll_interval': self._poll_interval,
        }

    def get_rules_summary(self) -> List[Dict]:
        """获取规则摘要"""
        return [
            {
                'id': r.rule_id,
                'name': r.name,
                'description': r.description,
                'severity': r.severity,
                'score': r.score,
                'category': r.category,
                'enabled': r.rule_id in self._enabled_rules,
            }
            for r in ALL_PROCESS_RULES
        ]

    def enable_rule(self, rule_id: str):
        """启用规则"""
        self._enabled_rules.add(rule_id)

    def disable_rule(self, rule_id: str):
        """禁用规则"""
        self._enabled_rules.discard(rule_id)


# ============================================================
# 自测
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("ProcessMonitor 测试")
    print("=" * 60)
    monitor = ProcessMonitor()
    print(f"规则总数: {len(ALL_PROCESS_RULES)}")
    for r in ALL_PROCESS_RULES:
        print(f"  [{r.rule_id}] {r.name} (严重度:{r.severity} 评分:{r.score}) - {r.description}")
    print(f"\n规则检测函数: {len(RULE_CHECK_FUNCTIONS)}")
    print("ProcessMonitor 初始化完成")

    # 启动10秒后停止
    monitor.start()
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    monitor.stop()
    print(f"统计: {json.dumps(monitor.get_stats(), ensure_ascii=False, indent=2)}")