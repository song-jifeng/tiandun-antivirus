#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 文件系统行为监控器
=================================
监控文件创建、修改、删除、重命名等操作。
使用 watchdog 库监控文件系统事件，实现 20+ 检测规则。

检测规则:
    - 批量文件修改 (勒索软件加密特征)
    - 系统文件篡改
    - 可执行文件创建
    - 隐藏文件创建
    - 自启动目录文件创建
    - 文档批量加密/重命名
    - 脚本文件创建
    - 敏感目录文件修改
    - 文件扩展名变更
    - 临时文件创建可执行文件
    - 诱饵文件操作
    - 快捷方式创建
    - 关键文件删除
    - 文件权限修改
    - 大量文件移动到同一目录
    - 系统目录可疑文件创建
    - 反删除特征 (卷影复制删除)
    - 浏览器下载目录监控
    - 下载的可执行文件
    - Office 文件异常宏
    - 压缩包释放可执行文件
"""

import os
import sys
import time
import json
import hashlib
import threading
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

# 将项目根目录加入路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine.logger import logger
from engine.config import config


# ============================================================
# 文件事件定义
# ============================================================
@dataclass
class FileEvent:
    """文件系统事件"""
    timestamp: float = field(default_factory=time.time)
    event_type: str = ''           # create, modify, delete, move, renames
    file_path: str = ''
    dest_path: str = ''            # 目标路径 (move/rename)
    process_name: str = ''         # 触发进程
    process_pid: int = 0
    file_size: int = 0
    file_hash: str = ''            # SHA256
    is_directory: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'event_type': self.event_type,
            'file_path': self.file_path,
            'dest_path': self.dest_path,
            'process_name': self.process_name,
            'process_pid': self.process_pid,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'is_directory': self.is_directory,
            'details': self.details,
        }


# ============================================================
# 常量定义
# ============================================================

# 监控的文件扩展名
EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.drv', '.ocx',
    '.cpl', '.ax', '.msi', '.msp', '.bat', '.cmd', '.ps1', '.psm1',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.jar',
}

SCRIPT_EXTENSIONS = {
    '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.hta', '.py', '.pyw',
    '.pl', '.rb', '.php', '.sh', '.bash', '.au3', '.ahk',
}

DOCUMENT_EXTENSIONS = {
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.xlsb',
    '.ppt', '.pptx', '.pptm', '.pps', '.ppsx', '.ppsm',
    '.pdf', '.rtf', '.odt', '.ods', '.odp', '.csv',
    '.txt', '.xml', '.html', '.htm',
}

RANSOMWARE_EXTENSIONS = {
    '.encrypted', '.locked', '.crypt', '.cryptolocker', '.wanna',
    '.wncry', '.wcry', '.wnry', '.onion', '.cerber', '.aaa',
    '.vvv', '.ccc', '.zzz', '.xyz', '.locky', '.zepto',
    '.odin', '.thor', '.ber', '.cry', '.crypz', '.enbr',
    '.filecrypted', '.petya', '.notpetya', '.gks', '.cbf',
    '.encrypt', '.ecc', '.enc', '.crinf', '.wallet', '.torrent',
    '.3dm', '.3dm', '.xtbl', '.data', '.crypt1', '.blue',
    '.rabbit', '.satan', '.dabl', '.dxxx', '.reco', '.rmd',
}

SENSITIVE_SYSTEM_DIRS = [
    'c:\\windows\\system32\\',
    'c:\\windows\\syswow64\\',
    'c:\\windows\\system32\\drivers\\',
    'c:\\windows\\system32\\config\\',
    'c:\\windows\\',
    'c:\\program files\\',
    'c:\\program files (x86)\\',
    'c:\\programdata\\',
]

STARTUP_DIRS = [
    os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.join(os.environ.get('PROGRAMDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
]

SENSITIVE_EXTENSIONS = {
    '.exe': '可执行文件',
    '.dll': '动态链接库',
    '.sys': '系统驱动',
    '.bat': '批处理脚本',
    '.cmd': '命令脚本',
    '.ps1': 'PowerShell脚本',
    '.vbs': 'VBScript脚本',
    '.js': 'JavaScript',
    '.hta': 'HTML应用',
    '.scr': '屏幕保护程序',
    '.msi': '安装包',
    '.jar': 'Java程序',
    '.ocx': 'ActiveX控件',
    '.cpl': '控制面板项',
    '.drv': '驱动程序',
}

# 批量操作阈值
BATCH_FILE_THRESHOLD = 15        # 批量文件操作阈值
BATCH_TIME_WINDOW = 60           # 批量操作时间窗口(秒)
RANSOMWARE_FILE_THRESHOLD = 10    # 勒索软件加密文件阈值
RANSOMWARE_TIME_WINDOW = 120      # 勒索软件检测时间窗口(秒)
EXTENSION_CHANGE_FILE_THRESHOLD = 3  # 扩展名变更阈值


# ============================================================
# 文件检测规则函数
# ============================================================

def check_batch_file_modification_check(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测批量文件修改 (规则 F001)
    勒索软件特征: 短时间内大量修改/删除/重命名文件
    """
    if event.event_type in ('modify', 'delete', 'move'):
        now = time.time()
        count = 0
        modified_count = 0
        for ev in reversed(history[-200:]):
            if now - ev.timestamp > BATCH_TIME_WINDOW:
                break
            if ev.event_type in ('modify', 'delete', 'move'):
                count += 1
                if ev.event_type == 'modify':
                    modified_count += 1
        # 阈值: 60秒内修改超过15个文件
        if count >= BATCH_FILE_THRESHOLD:
            severity = min(100, 60 + (count - BATCH_FILE_THRESHOLD) * 2)
            return True, severity
        if modified_count >= BATCH_FILE_THRESHOLD:
            return True, 70
    return False, 0


def check_system_file_tampering(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测系统文件篡改 (规则 F002)
    监控系统关键目录中文件的修改/删除
    """
    if event.event_type in ('modify', 'delete'):
        path_lower = event.file_path.lower()
        for sensitive_dir in SENSITIVE_SYSTEM_DIRS:
            if path_lower.startswith(sensitive_dir):
                # 检测系统关键文件的修改
                file_name = os.path.basename(path_lower).lower()
                critical_files = {
                    'ntoskrnl.exe', 'hal.dll', 'kdcom.dll', 'bootmgr.exe',
                    'winload.exe', 'winresume.exe', 'ntdll.dll',
                    'kernel32.dll', 'kernelbase.dll', 'user32.dll',
                    'advapi32.dll', 'gdi32.dll', 'shell32.dll',
                    'ole32.dll', 'rpcrt4.dll', 'shlwapi.dll',
                    'ws2_32.dll', 'wininet.dll', 'urlmon.dll',
                    'dnsapi.dll', 'samlib.dll', 'lsasrv.dll',
                    'drivers\\tcpip.sys', 'drivers\\ndis.sys',
                    'drivers\\fvevol.sys', 'drivers\\mountmgr.sys',
                    'config\\sam', 'config\\system', 'config\\security',
                    'config\\software', 'config\\default',
                }
                for critical in critical_files:
                    if critical in path_lower:
                        return True, 95
                # 系统目录中任何可执行文件修改
                ext = os.path.splitext(path_lower)[1]
                if ext in EXECUTABLE_EXTENSIONS:
                    return True, 80
                return True, 70
    return False, 0


def check_executable_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测可执行文件创建 (规则 F003)
    监控敏感位置中可执行文件/脚本的创建
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        path_lower = event.file_path.lower()

        if ext in EXECUTABLE_EXTENSIONS:
            # 在临时目录创建可执行文件
            temp_dirs = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
                         '\\windows\\temp\\', '\\cache\\']
            is_temp = any(d in path_lower for d in temp_dirs)
            is_system = any(path_lower.startswith(d) for d in SENSITIVE_SYSTEM_DIRS)
            is_startup = any(path_lower.startswith(d.lower()) for d in STARTUP_DIRS if d)

            if is_temp:
                return True, 80
            if is_system:
                return True, 85
            if is_startup:
                return True, 90
            # 从浏览器下载目录创建可执行文件
            download_dirs = ['\\downloads\\', '\\download\\', '\\桌面\\', '\\desktop\\']
            if any(d in path_lower for d in download_dirs):
                return True, 65
            # 一般位置创建可执行文件
            if ext in ('.exe', '.dll', '.sys', '.ps1', '.vbs', '.hta', '.scr'):
                return True, 50
    return False, 0


def check_hidden_file_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测隐藏文件创建 (规则 F004)
    恶意软件常创建隐藏文件或带隐藏属性的文件
    """
    if event.event_type == 'create' and not event.is_directory:
        # 检查文件名以点开头 (类Unix隐藏文件)
        file_name = os.path.basename(event.file_path)
        if file_name.startswith('.') and not file_name in ('.', '..'):
            return True, 60

        # 检查系统隐藏文件特征
        hidden_names = {
            'thumbs.db', 'desktop.ini', '~$', '.DS_Store',
            'autorun.inf', 'boot.ini', 'io.sys', 'msdos.sys',
        }
        for hn in hidden_names:
            if hn in file_name.lower():
                return True, 55

        # 检查文件是否被设置为隐藏属性 (Windows)
        try:
            import stat as stat_module
            attrs = os.stat(event.file_path).st_file_attributes
            if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                # 可执行文件+隐藏属性 = 高可疑
                ext = os.path.splitext(event.file_path)[1].lower()
                if ext in EXECUTABLE_EXTENSIONS:
                    return True, 85
                return True, 65
        except Exception:
            pass
    return False, 0


def check_startup_directory_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测自启动目录文件创建 (规则 F005)
    监控所有自启动目录中的文件创建
    """
    if event.event_type == 'create' and not event.is_directory:
        path_lower = event.file_path.lower()
        startup_dirs_lower = [d.lower() for d in STARTUP_DIRS if d]
        for startup_dir in startup_dirs_lower:
            if path_lower.startswith(startup_dir):
                ext = os.path.splitext(path_lower)[1].lower()
                if ext in ('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.lnk'):
                    return True, 90
                return True, 75
    return False, 0


def check_batch_rename_document(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测文档批量重命名 (规则 F006)
    勒索软件经常批量重命名文档并添加加密扩展名
    """
    if event.event_type == 'move' and not event.is_directory:
        now = time.time()
        rename_count = 0
        doc_files = 0
        suspicious_ext = False

        src_ext = os.path.splitext(event.file_path)[1].lower()
        dst_ext = os.path.splitext(event.dest_path)[1].lower() if event.dest_path else ''

        # 检查是否是文档被重命名
        if src_ext in DOCUMENT_EXTENSIONS:
            # 检查目标扩展名是否为勒索软件扩展名
            if dst_ext in RANSOMWARE_EXTENSIONS:
                suspicious_ext = True

            # 统计时间窗口内的重命名/移动操作
            for ev in reversed(history[-200:]):
                if now - ev.timestamp > RANSOMWARE_TIME_WINDOW:
                    break
                if ev.event_type == 'move':
                    rename_count += 1
                    s_ext = os.path.splitext(ev.file_path)[1].lower()
                    if s_ext in DOCUMENT_EXTENSIONS:
                        doc_files += 1

            if suspicious_ext:
                return True, 90
            if rename_count >= EXTENSION_CHANGE_FILE_THRESHOLD and doc_files >= 3:
                return True, 75
            if rename_count >= 5:
                return True, 60
    return False, 0


def check_script_file_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测脚本文件创建 (规则 F007)
    监控脚本文件在敏感位置的创建
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        path_lower = event.file_path.lower()

        if ext in SCRIPT_EXTENSIONS:
            # 脚本在启动目录
            for startup_dir in [d.lower() for d in STARTUP_DIRS if d]:
                if path_lower.startswith(startup_dir):
                    return True, 85
            # 脚本在系统目录
            for sys_dir in SENSITIVE_SYSTEM_DIRS:
                if path_lower.startswith(sys_dir):
                    return True, 80
            # 脚本在临时目录
            if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
                return True, 70
            # 脚本在用户目录
            if '\\users\\' in path_lower or '\\appdata\\' in path_lower:
                return True, 55
    return False, 0


def check_office_file_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测Office文件创建 (规则 F008)
    监控启用宏的Office文档创建
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        path_lower = event.file_path.lower()

        # 检测启用宏的Office文档
        macro_extensions = {'.docm', '.xlsm', '.pptm', '.xlsb'}
        if ext in macro_extensions:
            # 从临时目录或下载目录创建
            if '\\temp\\' in path_lower or '\\download' in path_lower:
                return True, 75
            # 从邮件附件或浏览器下载
            if '\\outlook' in path_lower or '\\attachment' in path_lower:
                return True, 70
            return True, 55

        # 检测Office文档包含VBA (通过文件内容分析)
        if ext in ('.doc', '.xls', '.ppt') and event.file_size > 0:
            try:
                with open(event.file_path, 'rb') as f:
                    header = f.read(4096)
                # 检查OLE2格式 (Docfile)
                if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                    # 检查VBA宏标记
                    if b'VBA' in header or b'MACRO' in header.upper():
                        return True, 70
            except Exception:
                pass
    return False, 0


def check_extension_change(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测文件扩展名变更 (规则 F009)
    恶意软件常通过扩展名变更伪装文件
    """
    if event.event_type == 'move' and not event.is_directory:
        src_ext = os.path.splitext(event.file_path)[1].lower()
        dst_ext = os.path.splitext(event.dest_path)[1].lower() if event.dest_path else ''

        if src_ext and dst_ext and src_ext != dst_ext:
            # 可执行文件伪装成文档
            if src_ext in EXECUTABLE_EXTENSIONS and dst_ext in DOCUMENT_EXTENSIONS:
                return True, 85
            # 文档被改为可执行文件
            if src_ext in DOCUMENT_EXTENSIONS and dst_ext in EXECUTABLE_EXTENSIONS:
                return True, 80
            # 改为勒索软件扩展名
            if dst_ext in RANSOMWARE_EXTENSIONS:
                return True, 90
            # 隐藏扩展名 (如 .pdf.exe)
            if 'exe' in dst_ext and 'pdf' in src_ext:
                return True, 85
            # 双扩展名
            if '.' in event.dest_path and event.dest_path.count('.') >= 2:
                if dst_ext in EXECUTABLE_EXTENSIONS:
                    return True, 75
    return False, 0


def check_temp_executable_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测临时目录可执行文件创建 (规则 F010)
    恶意软件通常在临时目录释放并执行
    """
    if event.event_type == 'create' and not event.is_directory:
        path_lower = event.file_path.lower()
        ext = os.path.splitext(path_lower)[1].lower()

        if ext in ('.exe', '.dll', '.scr', '.ps1', '.vbs', '.bat', '.cmd', '.hta'):
            temp_dirs = ['\\temp\\', '\\tmp\\', '\\windows\\temp\\',
                         '\\appdata\\local\\temp\\', '\\cache\\']
            for temp_dir in temp_dirs:
                if temp_dir in path_lower:
                    file_name = os.path.basename(path_lower)
                    # 随机名临时文件
                    if len(os.path.splitext(file_name)[0]) <= 6:
                        return True, 85
                    # 临时目录中的可执行文件
                    return True, 70
    return False, 0


def check_honeypot_file_access(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测诱饵文件操作 (规则 F011)
    监控诱饵文件的任何操作 (勒索软件诱捕)
    """
    honeypot_paths = config.get('firewall.honeypot_paths', [])
    if not honeypot_paths:
        return False, 0

    if event.event_type in ('create', 'modify', 'delete', 'move'):
        path_lower = event.file_path.lower()
        for hp in honeypot_paths:
            if hp.lower() in path_lower:
                # 任何对诱饵文件的操作都高度可疑
                return True, 95
    return False, 0


def check_shortcut_file_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测快捷方式创建 (规则 F012)
    恶意软件通过 LNK 文件传播
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        if ext == '.lnk':
            path_lower = event.file_path.lower()
            # 启动目录中的 LNK
            for startup_dir in [d.lower() for d in STARTUP_DIRS if d]:
                if path_lower.startswith(startup_dir):
                    return True, 80
            # USB 设备中的 LNK
            for drive_letter in range(ord('d'), ord('z')):
                drive = f'{chr(drive_letter)}:\\'
                if path_lower.startswith(drive.lower()) and not any(
                    path_lower.startswith(d) for d in SENSITIVE_SYSTEM_DIRS
                ):
                    return True, 65
            # 系统目录中的 LNK
            for sys_dir in SENSITIVE_SYSTEM_DIRS:
                if path_lower.startswith(sys_dir):
                    return True, 70
    return False, 0


def check_critical_file_deletion(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测关键文件删除 (规则 F013)
    监控系统关键文件的删除操作
    """
    if event.event_type == 'delete' and not event.is_directory:
        path_lower = event.file_path.lower()
        file_name = os.path.basename(path_lower).lower()

        # 卷影复制相关文件删除 (勒索软件特征)
        shadow_copy_related = {
            'vssadmin.exe', 'vssvc.exe', 'vsstrace.dll',
            'swprv.dll', 'vss_ps.dll',
        }
        if file_name in shadow_copy_related:
            return True, 90

        # 系统关键文件删除
        critical_for_deletion = {
            'ntldr', 'ntdetect.com', 'boot.ini', 'bootmgr',
            'bootmgfw.efi', 'bootstat.dat', 'hal.dll',
            'winload.exe', 'winresume.exe',
        }
        if file_name in critical_for_deletion:
            return True, 95

        # 安全软件相关文件删除
        av_related = {
            'msmpeng.exe', 'msseces.exe', 'avguard.exe',
            'avastui.exe', 'avgui.exe', 'ekrn.exe',
            'egui.exe', 'nod32krn.exe', 'bdagent.exe',
            'ccsvchst.exe', 'rtvscan.exe', 'mcshield.exe',
            'firefox.exe', 'chrome.exe', 'msedge.exe',
        }
        if file_name in av_related:
            return True, 80

        # 备份文件删除
        backup_extensions = {'.bak', '.backup', '.old', '.sav', '.vhd',
                             '.vhdx', '.bac', '.bkf', '.wbcat'}
        ext = os.path.splitext(path_lower)[1].lower()
        if ext in backup_extensions:
            count = 0
            now = time.time()
            for ev in reversed(history[-200:]):
                if now - ev.timestamp > 300:  # 5分钟
                    break
                if ev.event_type == 'delete':
                    e_ext = os.path.splitext(ev.file_path)[1].lower()
                    if e_ext in backup_extensions:
                        count += 1
            if count >= 5:
                return True, 75
    return False, 0


def check_file_permission_change(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测文件权限修改 (规则 F014)
    恶意软件通过修改权限绕过安全控制
    """
    if event.event_type == 'modify':
        details = event.details or {}
        if details.get('attribute_changed') or details.get('permission_changed'):
            path_lower = event.file_path.lower()
            # 系统文件权限修改
            if any(path_lower.startswith(d) for d in SENSITIVE_SYSTEM_DIRS):
                return True, 80
            # 设置可执行权限
            if details.get('set_executable'):
                return True, 70
    return False, 0


def check_batch_file_move(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测大量文件移动到同一目录 (规则 F015)
    恶意软件收集文件到特定目录
    """
    if event.event_type == 'move' and not event.is_directory:
        if not event.dest_path:
            return False, 0
        now = time.time()
        dest_dir = os.path.dirname(event.dest_path).lower()
        count = 0
        for ev in reversed(history[-200:]):
            if now - ev.timestamp > 60:
                break
            if ev.event_type == 'move' and ev.dest_path:
                if os.path.dirname(ev.dest_path).lower() == dest_dir:
                    count += 1
        if count >= 10:
            return True, 65
        if count >= 5:
            ext = os.path.splitext(event.dest_path)[1].lower()
            if ext in DOCUMENT_EXTENSIONS:
                return True, 55
    return False, 0


def check_system_dir_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测系统目录文件创建 (规则 F016)
    监控系统目录中非正常文件的创建
    """
    if event.event_type == 'create' and not event.is_directory:
        path_lower = event.file_path.lower()
        for sys_dir in SENSITIVE_SYSTEM_DIRS:
            if path_lower.startswith(sys_dir):
                ext = os.path.splitext(path_lower)[1].lower()
                file_name = os.path.basename(path_lower).lower()

                # 系统目录中创建未知DLL或可执行文件
                if ext in ('.dll', '.exe', '.sys', '.ocx', '.cpl'):
                    # 检查是否在已知白名单中
                    known_system_files = {
                        'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
                        'concrt140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll',
                        'ucrtbase.dll', 'vcomp140.dll',
                    }
                    if file_name not in known_system_files:
                        return True, 75
                # 系统目录中创建脚本
                if ext in SCRIPT_EXTENSIONS:
                    return True, 80
    return False, 0


def check_shadow_copy_deletion(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测卷影副本删除 (规则 F017)
    勒索软件通过删除卷影副本阻止恢复
    """
    if event.event_type in ('create', 'modify'):
        path_lower = event.file_path.lower()
        file_name = os.path.basename(path_lower).lower()

        # vssadmin delete shadows 执行
        if 'vssadmin' in file_name or 'vssvc' in file_name:
            return True, 90

        # wmic shadowcopy delete
        if 'shadowcopy' in path_lower:
            return True, 85

        # diskshadow 执行
        if 'diskshadow' in file_name:
            return True, 85

        # bcdedit 修改 (禁用恢复)
        if 'bcdedit' in file_name:
            return True, 80

    # 检测 vssadmin.exe 或 wmic 的调用 (通过进程信息)
    if event.details:
        cmdline = event.details.get('command_line', '').lower()
        if any(kw in cmdline for kw in ['vssadmin delete shadows', 'wmic shadowcopy delete',
                                         'diskshadow', 'bcdedit /set']):
            return True, 90

    return False, 0


def check_downloaded_executable(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测下载的可执行文件 (规则 F018)
    监控浏览器下载目录中的可执行文件创建
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        path_lower = event.file_path.lower()

        if ext in ('.exe', '.msi', '.scr', '.jar', '.ps1', '.vbs', '.bat', '.cmd'):
            # 浏览器下载目录
            download_dirs = ['\\downloads\\', '\\download\\', '\\desktop\\']
            for d in download_dirs:
                if d in path_lower:
                    # 浏览器下载的可执行文件
                    browser_processes = {'chrome.exe', 'firefox.exe', 'msedge.exe',
                                         'iexplore.exe', 'brave.exe', 'opera.exe'}
                    if event.process_name.lower() in browser_processes:
                        return True, 75
                    return True, 60
    return False, 0


def check_zip_extraction_executable(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测压缩包释放可执行文件 (规则 F019)
    恶意软件常通过压缩包释放载荷
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        path_lower = event.file_path.lower()

        if ext in ('.exe', '.dll', '.scr', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta'):
            # 压缩软件进程
            archive_processes = {'winrar.exe', '7z.exe', '7zg.exe', 'winzip.exe',
                                 'bandizip.exe', 'peazip.exe', 'unzip.exe',
                                 'tar.exe', 'explorer.exe'}
            if event.process_name.lower() in archive_processes:
                # 从压缩包释放到临时目录
                if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
                    return True, 80
                # 释放到桌面或下载目录
                if '\\desktop\\' in path_lower or '\\download' in path_lower:
                    return True, 70
                return True, 60
    return False, 0


def check_alternate_data_stream(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测备用数据流 (ADS) 创建 (规则 F020)
    恶意软件使用 ADS 隐藏数据
    """
    if event.event_type == 'create':
        # 检测文件路径中的 ADS 标记
        if ':' in event.file_path:
            path_part = event.file_path.split(':')[0]
            stream_name = event.file_path.split(':')[1] if ':' in event.file_path else ''
            if stream_name and stream_name not in ('Zone.Identifier', ':$DATA'):
                return True, 80
            # Zone.Identifier 是正常的，但其他流可疑
            if stream_name and stream_name != 'Zone.Identifier':
                return True, 85
    return False, 0


def check_driver_file_installation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测驱动文件安装 (规则 F021)
    监控驱动文件 (.sys) 在系统目录的创建
    """
    if event.event_type == 'create' and not event.is_directory:
        ext = os.path.splitext(event.file_path)[1].lower()
        if ext == '.sys':
            path_lower = event.file_path.lower()
            driver_dir = 'c:\\windows\\system32\\drivers\\'
            if path_lower.startswith(driver_dir):
                file_name = os.path.basename(path_lower)
                # 检查是否为已知系统驱动
                known_drivers = {
                    'ntfs.sys', 'tcpip.sys', 'ndis.sys', 'fvevol.sys',
                    'mountmgr.sys', 'volmgr.sys', 'disk.sys', 'partmgr.sys',
                    'ksecpkg.sys', 'cng.sys', 'ksecdd.sys', 'pci.sys',
                    'acpi.sys', 'usbhub.sys', 'usbhub3.sys',
                }
                if file_name not in known_drivers:
                    return True, 85
                return True, 70
            # 非标准目录中的驱动
            return True, 75
    return False, 0


def check_ransomware_note_creation(event: FileEvent, history: List[FileEvent]) -> Tuple[bool, int]:
    """
    检测勒索信创建 (规则 F022)
    勒索软件通常在加密后创建勒索信
    """
    if event.event_type == 'create' and not event.is_directory:
        file_name = os.path.basename(event.file_path).lower()
        path_lower = event.file_path.lower()

        # 勒索信常见文件名
        ransom_notes = {
            'readme.txt', 'readme.html', 'decrypt.txt', 'how_to_decrypt.txt',
            'how_to_decrypt.html', 'help_decrypt.txt', 'help_decrypt.html',
            'recover.txt', 'recover.html', 'restore.txt', 'restore.html',
            'info.txt', 'info.html', 'instructions.txt', 'instructions.html',
            '!!!_read_me_!!!', '!!!_read_me_!!!.txt', 'read_me.txt',
            'decrypt_instructions.txt', 'how_to_back_files.txt',
            'where_are_my_files.txt', 'your_files_are_encrypted.txt',
            'all_files_are_encrypted.txt', '#_decrypt_#.txt',
            'recover_instructions.txt', 'encrypt_readme.txt',
            'ransomware.txt', 'ransomware.html', 'what_happened.txt',
            'locknote.txt', 'locknote.html', 'crypt_info.txt',
            '!!!readme!!!.txt', '!!!readme!!!.html',
        }
        if file_name in ransom_notes:
            # 在桌面或文档目录中创建勒索信
            if '\\desktop\\' in path_lower or '\\documents\\' in path_lower:
                # 检查是否有批量文件操作
                now = time.time()
                modify_count = 0
                for ev in reversed(history[-200:]):
                    if now - ev.timestamp > 120:
                        break
                    if ev.event_type == 'modify':
                        modify_count += 1
                if modify_count >= 5:
                    return True, 95
                return True, 80
            return True, 75
    return False, 0


# ============================================================
# 规则注册表
# ============================================================
FILE_RULES = [
    ('F001', '批量文件修改', '检测短时间内大量文件修改/删除/重命名 (勒索软件)', 5, 25, check_batch_file_modification_check),
    ('F002', '系统文件篡改', '检测系统关键目录中文件的修改和删除', 5, 30, check_system_file_tampering),
    ('F003', '可执行文件创建', '检测敏感位置可执行文件(EXE/DLL/PS1等)的创建', 4, 20, check_executable_creation),
    ('F004', '隐藏文件创建', '检测隐藏属性文件或点的创建', 3, 15, check_hidden_file_creation),
    ('F005', '自启动目录写入', '检测自启动目录中文件创建', 5, 25, check_startup_directory_creation),
    ('F006', '文档批量重命名', '检测文档批量重命名/加密 (勒索软件)', 5, 30, check_batch_rename_document),
    ('F007', '脚本文件创建', '检测脚本文件在敏感位置创建', 4, 20, check_script_file_creation),
    ('F008', 'Office宏文件', '检测启用宏的Office文档创建', 4, 20, check_office_file_creation),
    ('F009', '扩展名变更', '检测文件扩展名被篡改', 4, 20, check_extension_change),
    ('F010', '临时目录可执行文件', '检测临时目录中释放的可执行文件', 4, 25, check_temp_executable_creation),
    ('F011', '诱饵文件操作', '检测对诱饵文件的任何操作', 5, 30, check_honeypot_file_access),
    ('F012', '快捷方式创建', '检测LNK文件在敏感位置创建', 3, 15, check_shortcut_file_creation),
    ('F013', '关键文件删除', '检测系统关键文件/备份文件被删除', 5, 30, check_critical_file_deletion),
    ('F014', '文件权限修改', '检测系统文件权限异常修改', 4, 20, check_file_permission_change),
    ('F015', '批量文件移动', '检测大量文件移动到同一目录', 3, 15, check_batch_file_move),
    ('F016', '系统目录写入', '检测系统目录中非正常文件创建', 4, 25, check_system_dir_creation),
    ('F017', '卷影副本删除', '检测卷影复制删除命令 (勒索软件)', 5, 30, check_shadow_copy_deletion),
    ('F018', '下载可执行文件', '检测浏览器下载目录中的可执行文件', 3, 15, check_downloaded_executable),
    ('F019', '压缩包释放', '检测压缩包释放可执行文件', 4, 20, check_zip_extraction_executable),
    ('F020', '备用数据流', '检测NTFS备用数据流(ADS)创建', 4, 20, check_alternate_data_stream),
    ('F021', '驱动文件安装', '检测驱动文件(.sys)在系统目录安装', 5, 25, check_driver_file_installation),
    ('F022', '勒索信创建', '检测勒索软件留下的勒索信文件', 5, 25, check_ransomware_note_creation),
]


# ============================================================
# 文件监控器
# ============================================================
class FileMonitor:
    """
    文件系统监控器 - 使用 watchdog 监控文件系统事件

    支持 22 条检测规则，覆盖勒索软件、系统篡改、恶意软件释放等场景。
    可同时使用 watchdog 事件驱动和轮询两种模式。
    """

    def __init__(self, engine=None):
        self._engine = engine
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._watchdog_observer = None

        # 事件队列
        self._events: List[FileEvent] = []
        self._event_queue: deque = deque(maxlen=20000)

        # 监控路径
        self._watch_paths: List[str] = []
        self._exclude_paths = [p.lower() for p in config.get('realtime.exclude_paths', [])]
        self._monitor_extensions = set(config.get('realtime.monitor_extensions', []))

        # 文件快照 (用于轮询模式)
        self._file_snapshots: Dict[str, Tuple[float, int]] = {}  # path -> (mtime, size)
        self._snapshot_taken = False

        # 统计
        self.stats = {
            'total_events': 0,
            'alerts': 0,
            'files_created': 0,
            'files_modified': 0,
            'files_deleted': 0,
            'files_moved': 0,
            'ransomware_alerts': 0,
            'system_tamper_alerts': 0,
        }

        # 已启用规则
        self._enabled_rules = set(r[0] for r in FILE_RULES)

        # 初始化监控路径
        self._init_watch_paths()

        logger.info("FileMonitor 初始化完成，监控规则: %d 条，监控路径: %d 个",
                     len(FILE_RULES), len(self._watch_paths))

    # ============================================================
    # 初始化
    # ============================================================
    def _init_watch_paths(self):
        """初始化监控路径列表"""
        paths = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.environ.get('APPDATA', ''),
            os.environ.get('LOCALAPPDATA', ''),
            os.environ.get('PROGRAMDATA', ''),
            os.environ.get('USERPROFILE', ''),
            'C:\\Windows\\Temp',
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\ProgramData',
            'C:\\Users',
        ]
        # 添加启动目录
        for sd in STARTUP_DIRS:
            if sd:
                paths.append(sd)

        self._watch_paths = [p for p in paths if p and os.path.exists(p)]

    # ============================================================
    # 生命周期管理
    # ============================================================
    def start(self):
        """启动文件监控"""
        if self._running:
            logger.warning("FileMonitor 已经在运行中")
            return
        self._running = True

        # 尝试启动 watchdog
        watchdog_available = self._start_watchdog()

        if not watchdog_available:
            logger.info("watchdog 不可用，使用轮询模式")
            self._thread = threading.Thread(target=self._poll_loop, name='FileMonitor', daemon=True)
            self._thread.start()

        logger.info("FileMonitor 已启动 (watchdog=%s)", watchdog_available)

    def stop(self):
        """停止文件监控"""
        self._running = False
        self._stop_watchdog()
        logger.info("FileMonitor 已停止，共处理事件: %d", self.stats['total_events'])

    def is_running(self) -> bool:
        return self._running

    # ============================================================
    # Watchdog 事件驱动模式
    # ============================================================
    def _start_watchdog(self) -> bool:
        """启动 watchdog 监控"""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class TiandunFileHandler(FileSystemEventHandler):
                def __init__(self, monitor):
                    self.monitor = monitor

                def on_created(self, event):
                    self.monitor._on_watchdog_event('create', event)

                def on_modified(self, event):
                    self.monitor._on_watchdog_event('modify', event)

                def on_deleted(self, event):
                    self.monitor._on_watchdog_event('delete', event)

                def on_moved(self, event):
                    self.monitor._on_watchdog_event('move', event)

            self._watchdog_observer = Observer()
            handler = TiandunFileHandler(self)
            for path in self._watch_paths:
                try:
                    self._watchdog_observer.schedule(handler, path, recursive=True)
                except Exception as e:
                    logger.debug("watchdog 监控路径失败 [%s]: %s", path, e)

            self._watchdog_thread = threading.Thread(
                target=self._watchdog_observer.start,
                name='Watchdog', daemon=True
            )
            self._watchdog_thread.start()
            return True

        except ImportError:
            logger.info("watchdog 未安装，使用轮询模式")
            return False
        except Exception as e:
            logger.error("watchdog 启动失败: %s", e)
            return False

    def _stop_watchdog(self):
        """停止 watchdog"""
        if self._watchdog_observer:
            try:
                self._watchdog_observer.stop()
                self._watchdog_observer.join(timeout=3)
            except Exception:
                pass
            self._watchdog_observer = None

    def _on_watchdog_event(self, event_type: str, event):
        """处理 watchdog 事件"""
        try:
            if event.is_directory:
                return

            src_path = event.src_path.replace('/', '\\')
            dest_path = ''
            if hasattr(event, 'dest_path') and event.dest_path:
                dest_path = event.dest_path.replace('/', '\\')

            # 检查排除路径
            if self._is_excluded(src_path):
                return

            # 获取文件大小
            file_size = 0
            if event_type in ('create', 'modify') and os.path.exists(src_path):
                try:
                    file_size = os.path.getsize(src_path)
                except Exception:
                    pass

            # 获取触发进程信息
            proc_name, proc_pid = self._get_calling_process()

            file_event = FileEvent(
                event_type=event_type,
                file_path=src_path,
                dest_path=dest_path,
                process_name=proc_name,
                process_pid=proc_pid,
                file_size=file_size,
                is_directory=event.is_directory,
            )

            self.add_event(file_event)

        except Exception as e:
            logger.debug("watchdog 事件处理异常: %s", e)

    # ============================================================
    # 轮询模式
    # ============================================================
    def _poll_loop(self):
        """轮询监控循环"""
        # 初始快照
        self._take_file_snapshot()

        while self._running:
            try:
                self._check_file_changes()
            except Exception as e:
                logger.error("文件轮询异常: %s", e)
            time.sleep(5)

    def _take_file_snapshot(self):
        """获取文件系统快照"""
        snapshot = {}
        for watch_path in self._watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for root, dirs, files in os.walk(watch_path):
                    # 限制遍历深度
                    depth = root.replace(watch_path, '').count(os.sep)
                    if depth > 5:
                        dirs.clear()
                        continue
                    for f in files:
                        try:
                            fpath = os.path.join(root, f)
                            if self._is_excluded(fpath):
                                continue
                            stat = os.stat(fpath)
                            snapshot[fpath] = (stat.st_mtime, stat.st_size)
                        except Exception:
                            pass
            except Exception:
                pass
        self._file_snapshots = snapshot
        self._snapshot_taken = True
        logger.info("文件快照完成: %d 个文件", len(snapshot))

    def _check_file_changes(self):
        """检查文件变化"""
        if not self._snapshot_taken:
            return

        current = {}
        for watch_path in self._watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for root, dirs, files in os.walk(watch_path):
                    depth = root.replace(watch_path, '').count(os.sep)
                    if depth > 5:
                        dirs.clear()
                        continue
                    for f in files:
                        try:
                            fpath = os.path.join(root, f)
                            if self._is_excluded(fpath):
                                continue
                            stat = os.stat(fpath)
                            current[fpath] = (stat.st_mtime, stat.st_size)
                        except Exception:
                            pass
            except Exception:
                pass

        # 检测新文件
        for fpath in current:
            if fpath not in self._file_snapshots:
                fe = FileEvent(
                    event_type='create',
                    file_path=fpath,
                    file_size=current[fpath][1],
                    is_directory=False,
                )
                self.add_event(fe)

        # 检测修改的文件
        for fpath in current:
            if fpath in self._file_snapshots:
                old_mtime, old_size = self._file_snapshots[fpath]
                new_mtime, new_size = current[fpath]
                if old_mtime != new_mtime or old_size != new_size:
                    fe = FileEvent(
                        event_type='modify',
                        file_path=fpath,
                        file_size=new_size,
                        is_directory=False,
                    )
                    self.add_event(fe)

        # 检测删除的文件
        for fpath in self._file_snapshots:
            if fpath not in current:
                fe = FileEvent(
                    event_type='delete',
                    file_path=fpath,
                    is_directory=False,
                )
                self.add_event(fe)

        self._file_snapshots = current

    # ============================================================
    # 辅助方法
    # ============================================================
    def _is_excluded(self, path: str) -> bool:
        """检查路径是否在排除列表中"""
        path_lower = path.lower()
        for excl in self._exclude_paths:
            if excl and excl.lower() in path_lower:
                return True
        return False

    def _get_calling_process(self) -> Tuple[str, int]:
        """获取调用进程信息"""
        try:
            import psutil
            current = psutil.Process()
            # 获取当前进程的发起者 (简化实现)
            proc = current.parent()
            if proc:
                return proc.name() or '', proc.pid or 0
        except Exception:
            pass
        return '', 0

    # ============================================================
    # 事件管理
    # ============================================================
    def add_event(self, event: FileEvent):
        """添加事件到队列"""
        with self._lock:
            self._events.append(event)
            self._event_queue.append(event)
            self.stats['total_events'] += 1
            if event.event_type == 'create':
                self.stats['files_created'] += 1
            elif event.event_type == 'modify':
                self.stats['files_modified'] += 1
            elif event.event_type == 'delete':
                self.stats['files_deleted'] += 1
            elif event.event_type == 'move':
                self.stats['files_moved'] += 1

        # 运行规则检测
        self._run_detection(event)

    def get_events(self) -> List[FileEvent]:
        """获取并清空事件队列"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def get_events_since(self, since_time: float) -> List[FileEvent]:
        """获取指定时间之后的事件"""
        with self._lock:
            return [e for e in self._event_queue if e.timestamp >= since_time]

    # ============================================================
    # 规则检测引擎
    # ============================================================
    def _run_detection(self, event: FileEvent):
        """对事件运行所有启用的规则检测"""
        from .behavior_engine import ThreatEvent, ThreatLevel

        for rule_id, rule_name, rule_desc, severity, score, check_func in FILE_RULES:
            if rule_id not in self._enabled_rules:
                continue

            try:
                matched, confidence = check_func(event, list(self._event_queue))
                if matched and confidence >= 50:
                    self.stats['alerts'] += 1
                    if '勒索' in rule_desc or 'ransom' in rule_desc.lower():
                        self.stats['ransomware_alerts'] += 1
                    if '系统' in rule_desc or 'system' in rule_desc.lower():
                        self.stats['system_tamper_alerts'] += 1

                    threat = ThreatEvent(
                        source='file_monitor',
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity=severity,
                        score=score + (confidence - 50) // 10,
                        confidence=confidence,
                        description=rule_desc,
                        event_data=event.to_dict(),
                        timestamp=event.timestamp,
                    )

                    if self._engine:
                        self._engine.on_threat_detected(threat)

                    severity_tag = {5: '严重', 4: '高危', 3: '中等', 2: '低危'}.get(severity, '未知')
                    logger.warning(
                        "[文件规则] %s | %s [%s] | %s | 置信度=%d%% | 评分=%d",
                        rule_id, rule_name, severity_tag,
                        event.file_path, confidence, threat.score
                    )

            except Exception as e:
                logger.debug("文件规则检测异常 [%s]: %s", rule_id, e)

    # ============================================================
    # 统计与查询
    # ============================================================
    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'running': self._running,
            'watch_paths': len(self._watch_paths),
            'pending_events': len(self._events),
            'rules_enabled': len(self._enabled_rules),
            'rules_count': len(FILE_RULES),
            'watchdog_active': self._watchdog_observer is not None and self._watchdog_observer.is_alive(),
        }

    def get_rules_summary(self) -> List[Dict]:
        """获取规则摘要"""
        return [
            {
                'id': r[0],
                'name': r[1],
                'description': r[2],
                'severity': r[3],
                'score': r[4],
                'enabled': r[0] in self._enabled_rules,
            }
            for r in FILE_RULES
        ]

    def enable_rule(self, rule_id: str):
        self._enabled_rules.add(rule_id)

    def disable_rule(self, rule_id: str):
        self._enabled_rules.discard(rule_id)

    def add_watch_path(self, path: str):
        """添加监控路径"""
        if path and os.path.exists(path) and path not in self._watch_paths:
            self._watch_paths.append(path)
            if self._watchdog_observer:
                try:
                    from watchdog.observers import Observer
                    self._watchdog_observer.schedule(
                        self._watchdog_observer._handlers[0], path, recursive=True
                    )
                except Exception:
                    pass


# ============================================================
# 自测
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("FileMonitor 测试")
    print("=" * 60)
    monitor = FileMonitor()
    print(f"规则总数: {len(FILE_RULES)}")
    for r in FILE_RULES:
        print(f"  [{r[0]}] {r[1]} (严重度:{r[3]} 评分:{r[4]}) - {r[2]}")
    print(f"\n监控路径: {len(monitor._watch_paths)} 个")
    print("FileMonitor 初始化完成")