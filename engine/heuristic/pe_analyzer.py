#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - PE文件启发式分析器
解析PE文件结构，检测可疑特征、加壳/混淆、敏感API调用等
实现 50+ 检测规则
"""

import os
import re
import struct
import hashlib
from typing import Tuple, List, Dict, Optional, Any
from collections import Counter


# ============================================================
# PE 常量定义
# ============================================================

# 已知机器类型
KNOWN_MACHINE_TYPES = {
    0x0:   'Unknown',
    0x14c: 'I386',
    0x8664: 'AMD64',
    0x1c0: 'ARM',
    0x1c4: 'ARMNT',
    0x1c2: 'ARM Thumb',
    0x200: 'IA64',
    0x184: 'ALPHA',
    0x284: 'ALPHA64',
    0x1c8: 'ARM64',
    0x1d3: 'ARM64EC',
    0x1d6: 'ARM64X',
    0x266: 'MIPS16',
    0x366: 'MIPSFPU',
    0x466: 'MIPSFPU16',
    0xEBC: 'EBC',
    0x5032: 'R3000',
    0x9066: 'R10000',
    0xC0EE: 'CEE',
    0x1f0: 'SH3',
    0x1f2: 'SH3DSP',
    0x1f3: 'SH4',
    0x1f8: 'THUMB',
    0x2000: 'WCEMIPSV2',
    0x20C: 'M32R',
    0xABC: 'LOONGARCH32',
    0xABD: 'LOONGARCH64',
    0xBBC: 'RISCV32',
    0xBBD: 'RISCV64',
    0xBBC + 2: 'RISCV128',
}

# 已知子系统
KNOWN_SUBSYSTEMS = {
    0:  'UNKNOWN',
    1:  'NATIVE',
    2:  'WINDOWS_GUI',
    3:  'WINDOWS_CUI',
    5:  'OS2_CUI',
    7:  'POSIX_CUI',
    9:  'WINDOWS_CE_GUI',
    10: 'EFI_APPLICATION',
    11: 'EFI_BOOT_SERVICE_DRIVER',
    12: 'EFI_RUNTIME_DRIVER',
    13: 'EFI_ROM',
    14: 'XBOX',
    16: 'WINDOWS_BOOT_APPLICATION',
}

# 常见加壳/保护工具特征
PACKER_SIGNATURES = {
    'UPX': [
        b'UPX0', b'UPX1', b'UPX2', b'UPX!',
        b'UPX 0', b'UPX 1', b'UPX 2', b'UPX 3',
    ],
    'ASPack': [
        b'.aspack', b'.adata', b'ASPack',
    ],
    'Armadillo': [
        b'.arm0', b'.arm1', b'.arm2', b'.arm3',
        b'.armadillo', b'Balloon',
    ],
    'VMProtect': [
        b'.vmp0', b'.vmp1', b'.vmp2', b'.vmp3',
        b'VMProtect',
    ],
    'Themida': [
        b'.themida', b'.enigma', b'.ecrypt',
        b'Themida', b'WinLicense',
    ],
    'MPRESS': [
        b'.mpress', b'MPRESS',
    ],
    'Enigma': [
        b'.enigma', b'Enigma',
    ],
    'PELock': [
        b'.pelock', b'PELock',
    ],
    'PECompact': [
        b'.pecpt', b'.pecrypt',
        b'PECompact',
    ],
    'Obsidium': [
        b'.obs0', b'.obs1',
        b'Obsidium',
    ],
    'EXECryptor': [
        b'.ecrypt', b'EXECryptor',
    ],
    'SVKP': [
        b'.svkp', b'SVKP',
    ],
    'Telock': [
        b'.tlock', b'.telock', b'Telock',
    ],
    'DBPE': [
        b'.dbpe', b'DBPE',
    ],
    'NsPack': [
        b'.nsp0', b'.nsp1', b'.nsp2',
        b'NsPack',
    ],
    'BeRoEXEPacker': [
        b'.ber0', b'.ber1',
    ],
    'MEW': [
        b'.mew', b'MEW',
    ],
    'Petite': [
        b'.petite', b'Petite',
    ],
    'Yoda': [
        b'.yoda', b'yoda',
    ],
    'RLPack': [
        b'.rlpack', b'RLPack',
    ],
    'Kkrunchy': [
        b'.krnch', b'kkrunchy',
    ],
    'eXPressor': [
        b'.xpress', b'eXPressor',
    ],
    'WinUpack': [
        b'.upack', b'Upack',
    ],
    'ASProtect': [
        b'.aspr', b'ASProtect',
    ],
    'StarForce': [
        b'.sforce', b'StarForce',
    ],
    'SafeNet': [
        b'.safenet', b'SafeNet',
    ],
    'Safengine': [
        b'.safengine', b'Safengine',
    ],
    'CodeVirtualizer': [
        b'.cv', b'CodeVirtualizer',
    ],
    'DotFuscator': [
        b'.dotfuscator',
    ],
    'Confuser': [
        b'Confuser',
    ],
    'Obfuscar': [
        b'Obfuscar',
    ],
}

# 可疑的节区名称
SUSPICIOUS_SECTION_NAMES = {
    '.upx0', '.upx1', '.upx2', '.upx3',
    '.aspack', '.adata',
    '.arm0', '.arm1', '.arm2', '.arm3',
    '.vmp0', '.vmp1', '.vmp2', '.vmp3',
    '.themida', '.enigma', '.ecrypt',
    '.mpress', '.mackt',
    '.klin', '.kl0', '.kl1', '.kl2',
    '.nsp0', '.nsp1', '.nsp2',
    '.pecpt', '.pecrypt', '.pelock',
    '.obs0', '.obs1',
    '.tlock', '.telock', '.svkp', '.dbpe',
    '.ber0', '.ber1', '.mew',
    '.petite', '.yoda', '.rlpack', '.krnch',
    '.xpress', '.upack', '.aspr',
    '.sforce', '.safenet',
    '.cv', '.packed', '.pepack', '.blob',
    '.adata', '.bss', '.reloc',
    '.tsx', '.tls', '.sxs',
    '.zgz', '.zdata', '.ztext', '.zrsrc',
    '.boom', '.ccg', '.hack', '.tmp',
    '.mask', '.mack', '.mnb', '.mny',
    '.pdata', '.pr0', '.pr1', '.pr2',
    '.rdata', '.scode', '.sdata',
    '.shrink', '.spack', '.spr',
    '.strp', '.t', '.t0', '.t1', '.t2',
    '.tmp', '.ttt', '.txt', '.url',
    '.v', '.v1', '.v2', '.v3',
    '.vmp', '.vmp0', '.vmp1', '.vmp2',
    '.vprot', '.wasm', '.winapi',
    '.x', '.x1', '.x2', '.x3',
    '.xy', '.y', '.z', '.zzz',
}

# 敏感 API 列表 - 按功能分组
SENSITIVE_APIS = {
    # 进程注入
    'PROCESS_INJECTION': [
        'WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx',
        'VirtualProtectEx', 'NtUnmapViewOfSection', 'QueueUserAPC',
        'SetThreadContext', 'GetThreadContext', 'ResumeThread',
        'SuspendThread', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'ZwCreateThreadEx', 'NtQueueApcThread', 'ZwQueueApcThread',
    ],
    # 钩子/注入
    'HOOKING': [
        'SetWindowsHookEx', 'SetWinEventHook', 'SetWindowsHook',
        'SetWinEventHook', 'UnhookWindowsHook',
    ],
    # 进程操作
    'PROCESS_OPERATION': [
        'OpenProcess', 'OpenThread', 'TerminateProcess',
        'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA',
        'CreateProcessAsUserW', 'CreateProcessWithLogonW',
        'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA',
        'ShellExecuteExW', 'WinExec', 'system',
    ],
    # 动态加载
    'DYNAMIC_LOADING': [
        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA',
        'LoadLibraryExW', 'GetProcAddress', 'LdrLoadDll',
        'LdrGetDllHandle', 'LdrGetProcedureAddress',
    ],
    # 注册表操作
    'REGISTRY': [
        'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA',
        'RegCreateKeyExW', 'RegSetValueA', 'RegSetValueW',
        'RegSetValueExA', 'RegSetValueExW', 'RegDeleteKeyA',
        'RegDeleteKeyW', 'RegDeleteValueA', 'RegDeleteValueW',
        'RegOpenKeyExA', 'RegOpenKeyExW',
    ],
    # 加密/解密
    'CRYPTO': [
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA',
        'CryptAcquireContextW', 'CryptCreateHash', 'CryptHashData',
        'CryptDeriveKey', 'CryptGenKey', 'CryptExportKey',
        'CryptImportKey', 'CryptEncryptMessage',
        'CryptDecryptMessage', 'CryptSignMessage',
        'CryptVerifyMessageSignature',
    ],
    # 网络操作
    'NETWORK': [
        'InternetOpenA', 'InternetOpenW', 'InternetConnectA',
        'InternetConnectW', 'HttpOpenRequestA', 'HttpOpenRequestW',
        'HttpSendRequestA', 'HttpSendRequestW', 'URLDownloadToFileA',
        'URLDownloadToFileW', 'URLDownloadToCacheFileA',
        'URLDownloadToCacheFileW', 'socket', 'connect', 'send',
        'recv', 'WSASocketA', 'WSASocketW', 'WSAConnect',
        'sendto', 'recvfrom', 'bind', 'listen', 'accept',
        'WSAStartup', 'gethostbyname', 'gethostbyaddr',
        'getaddrinfo', 'FreeAddrInfoW', 'DnsQuery_A',
        'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
        'WinHttpSendRequest', 'WinHttpReceiveResponse',
    ],
    # 文件操作
    'FILE_OPERATION': [
        'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'MoveFileW',
        'MoveFileExA', 'MoveFileExW', 'CopyFileA', 'CopyFileW',
        'CopyFileExA', 'CopyFileExW', 'CreateFileA', 'CreateFileW',
        'WriteFile', 'ReadFile', 'SetFileAttributesA',
        'SetFileAttributesW', 'GetTempPathA', 'GetTempPathW',
        'GetTempFileNameA', 'GetTempFileNameW',
    ],
    # 服务操作
    'SERVICE': [
        'CreateServiceA', 'CreateServiceW', 'StartServiceA',
        'StartServiceW', 'StartServiceCtrlDispatcherA',
        'StartServiceCtrlDispatcherW', 'OpenSCManagerA',
        'OpenSCManagerW', 'OpenServiceA', 'OpenServiceW',
        'ControlService', 'DeleteService',
    ],
    # 计划任务
    'SCHEDULED_TASK': [
        'NetScheduleJobAdd', 'SchRpcRegisterTask',
        'SchRpcRun', 'ITaskScheduler',
    ],
    # 内存操作
    'MEMORY': [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
        'VirtualProtectEx', 'VirtualFree', 'VirtualFreeEx',
        'HeapCreate', 'HeapAlloc', 'GlobalAlloc', 'LocalAlloc',
        'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
        'NtFreeVirtualMemory', 'ZwAllocateVirtualMemory',
        'ZwProtectVirtualMemory', 'ZwFreeVirtualMemory',
    ],
    # 隐藏/反调试
    'ANTI_DEBUG': [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'ZwQueryInformationProcess',
        'NtSetInformationThread', 'ZwSetInformationThread',
        'NtClose', 'OutputDebugStringA', 'OutputDebugStringW',
        'GetTickCount', 'QueryPerformanceCounter',
        'rdtsc', 'NtRaiseHardError',
    ],
    # 键盘记录
    'KEYLOGGER': [
        'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
        'GetKeyboardState', 'GetForegroundWindow',
        'GetWindowTextA', 'GetWindowTextW',
        'GetClipboardData', 'SetClipboardData',
        'RegisterHotKey', 'UnregisterHotKey',
    ],
    # 持久化
    'PERSISTENCE': [
        'RegisterApplicationRestart',
        'RegisterRestart', 'SetSecurityInfo',
        'WmiExecQuery', 'WmiOpenNamespace',
    ],
    # 提权
    'PRIVILEGE_ESCALATION': [
        'AdjustTokenPrivileges', 'LookupPrivilegeValueA',
        'LookupPrivilegeValueW', 'OpenProcessToken',
        'OpenThreadToken', 'ImpersonateNamedPipeClient',
        'ImpersonateLoggedOnUser', 'RevertToSelf',
        'SetTokenInformation', 'CreateProcessAsUser',
        'NtSetInformationProcess',
    ],
    # 自删除
    'SELF_DELETE': [
        'MoveFileEx', 'NtSetInformationFile',
        'FILE_DELETE_ON_CLOSE',
    ],
}

# 敏感导入DLL
SUSPICIOUS_IMPORT_DLLS = {
    'kernel32.dll': ['WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx'],
    'ntdll.dll':    ['NtUnmapViewOfSection', 'NtCreateThreadEx'],
    'user32.dll':   ['SetWindowsHookEx', 'GetAsyncKeyState'],
    'wininet.dll':  ['InternetOpen', 'InternetConnect', 'HttpOpenRequest'],
    'urlmon.dll':   ['URLDownloadToFile'],
    'ws2_32.dll':   ['socket', 'connect', 'send', 'recv'],
    'advapi32.dll': ['CreateService', 'RegCreateKeyEx', 'CryptEncrypt'],
    'psapi.dll':    ['EnumProcesses', 'EnumProcessModules'],
    'ole32.dll':    ['CoCreateInstance', 'CoInitialize'],
    'oleaut32.dll': ['SafeArrayCreate', 'VariantChangeType'],
    'crypt32.dll':  ['CryptEncrypt', 'CryptDecrypt'],
    'winhttp.dll':  ['WinHttpOpen', 'WinHttpConnect'],
    'shell32.dll':  ['ShellExecute', 'ShellExecuteEx'],
    'shlwapi.dll':  ['SHDeleteKey', 'SHRegSetValue'],
    'wmi.dll':      ['IWbemServices', 'IWbemLocator'],
    'wbemprox.dll': ['WmiExecQuery'],
    'secur32.dll':  ['ImpersonateSecurityContext'],
    'samlib.dll':   ['SamConnect', 'SamQueryInformationUser'],
    'netapi32.dll': ['NetUserAdd', 'NetUserDel', 'NetLocalGroupAddMembers'],
    'dnsapi.dll':   ['DnsQuery', 'DnsQuery_A'],
    'iphlpapi.dll': ['GetAdaptersInfo', 'GetIpAddrTable'],
    'setupapi.dll': ['SetupDiGetClassDevs', 'SetupDiEnumDeviceInfo'],
    'wtsapi32.dll': ['WTSEnumerateSessions', 'WTSQuerySessionInformation'],
    'winsta.dll':   ['WinStationEnumerate'],
    'bcrypt.dll':   ['BCryptEncrypt', 'BCryptDecrypt'],
    'ncrypt.dll':   ['NCryptEncrypt', 'NCryptDecrypt'],
}

# 可疑的导入表DLL（用于恶意目的）
MALICIOUS_IMPORT_PATTERNS = {
    'wmi:', 'winmgmts:', 'powershell', 'cmd.exe',
    'hidden', 'bypass', 'download', 'upload',
    'reverse', 'backconnect', 'bind',
}

# 资源类型
RESOURCE_TYPES = {
    1:  'CURSOR',
    2:  'BITMAP',
    3:  'ICON',
    4:  'MENU',
    5:  'DIALOG',
    6:  'STRING',
    7:  'FONTDIR',
    8:  'FONT',
    9:  'ACCELERATOR',
    10: 'RCDATA',
    11: 'MESSAGETABLE',
    12: 'GROUP_CURSOR',
    14: 'GROUP_ICON',
    16: 'VERSION',
    17: 'DLGINCLUDE',
    19: 'PLUGPLAY',
    20: 'VXD',
    21: 'ANICURSOR',
    22: 'ANIICON',
    23: 'HTML',
    24: 'MANIFEST',
}


class PEAnalyzer:
    """
    PE文件分析器

    解析PE文件头(DOS头、NT头、节区表)，检测可疑特征：
    - 节区名称异常
    - 入口点异常
    - 文件大小异常
    - 加壳/混淆检测
    - 导入表分析
    - 数字签名验证
    - 资源段分析
    - 50+ 检测规则
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._suspicious_apis = {}
        for group, apis in SENSITIVE_APIS.items():
            for api in apis:
                self._suspicious_apis[api] = group

    def analyze(self, filepath: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        分析PE文件，返回 (风险分数, 检测原因列表, 详细数据)

        Args:
            filepath: PE文件路径

        Returns:
            (风险分数0-100, 检测原因列表, 详细分析数据)
        """
        score = 0.0
        reasons = []
        details = {}

        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            file_size = len(data)

            if file_size < 64:
                return 0.0, [], {'error': '文件太小，不是有效的PE文件'}

            # ============================================================
            # 规则 1: 检查DOS头
            # ============================================================
            if data[:2] != b'MZ':
                return 0.0, [], {'error': '不是有效的PE文件 (缺少MZ头)'}

            # ============================================================
            # 规则 2: 获取PE头偏移
            # ============================================================
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 4 > file_size:
                score += 10
                reasons.append('PE头偏移超出文件范围')
                details['pe_offset_invalid'] = True
                return score, reasons, details

            # ============================================================
            # 规则 3: 检查PE签名
            # ============================================================
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                score += 10
                reasons.append('PE签名无效 (不是PE\\x00\\x00)')
                details['pe_signature_invalid'] = True
                return score, reasons, details

            # ============================================================
            # 解析NT头
            # ============================================================
            machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
            symbol_table_offset = struct.unpack_from('<I', data, pe_offset + 12)[0]
            symbol_count = struct.unpack_from('<I', data, pe_offset + 16)[0]
            opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
            characteristics = struct.unpack_from('<H', data, pe_offset + 22)[0]

            details['machine'] = f'0x{machine:04x}'
            details['machine_name'] = KNOWN_MACHINE_TYPES.get(machine, '未知')
            details['num_sections'] = num_sections
            details['timestamp'] = timestamp
            details['characteristics'] = f'0x{characteristics:04x}'
            details['is_dll'] = bool(characteristics & 0x2000)

            # ============================================================
            # 规则 4: 检查机器类型
            # ============================================================
            if machine not in KNOWN_MACHINE_TYPES:
                score += 5
                reasons.append(f'规则4: 未知机器类型 0x{machine:04x}')
                details['unknown_machine'] = True

            # ============================================================
            # 规则 5: 检查符号表（通常发布版PE不应有符号表）
            # ============================================================
            if symbol_table_offset > 0 and symbol_count > 0:
                score += 3
                reasons.append(f'规则5: 文件包含符号表 ({symbol_count}个符号)')
                details['has_symbol_table'] = True

            # ============================================================
            # 规则 6: 检查可选头大小
            # ============================================================
            if opt_header_size < 96 or opt_header_size > 256:
                score += 5
                reasons.append(f'规则6: 可选头大小异常: {opt_header_size}')
                details['opt_header_size_anomaly'] = opt_header_size

            # ============================================================
            # 解析可选头
            # ============================================================
            optional_header_offset = pe_offset + 24
            if optional_header_offset + 4 > file_size:
                score += 10
                reasons.append('可选头超出文件范围')
                return score, reasons, details

            magic = struct.unpack_from('<H', data, optional_header_offset)[0]

            details['pe_magic'] = f'0x{magic:04x}'

            if magic == 0x10b:  # PE32
                is_pe32plus = False
                header_size = 224
                entry_point_offset = optional_header_offset + 16
                image_base_offset = optional_header_offset + 28
                section_alignment_offset = optional_header_offset + 32
                file_alignment_offset = optional_header_offset + 36
                image_size_offset = optional_header_offset + 56
                size_of_headers_offset = optional_header_offset + 60
                checksum_offset = optional_header_offset + 64
                subsystem_offset = optional_header_offset + 68
                dll_chars_offset = optional_header_offset + 70
                stack_reserve_offset = optional_header_offset + 72
                stack_commit_offset = optional_header_offset + 76
                heap_reserve_offset = optional_header_offset + 80
                heap_commit_offset = optional_header_offset + 84
                num_data_dir_offset = optional_header_offset + 92
            elif magic == 0x20b:  # PE32+
                is_pe32plus = True
                header_size = 240
                entry_point_offset = optional_header_offset + 16
                image_base_offset = optional_header_offset + 24
                section_alignment_offset = optional_header_offset + 32
                file_alignment_offset = optional_header_offset + 36
                image_size_offset = optional_header_offset + 56
                size_of_headers_offset = optional_header_offset + 60
                checksum_offset = optional_header_offset + 64
                subsystem_offset = optional_header_offset + 68
                dll_chars_offset = optional_header_offset + 70
                stack_reserve_offset = optional_header_offset + 72
                stack_commit_offset = optional_header_offset + 76
                heap_reserve_offset = optional_header_offset + 80
                heap_commit_offset = optional_header_offset + 84
                num_data_dir_offset = optional_header_offset + 92
            else:
                score += 10
                reasons.append(f'规则7: 未知PE魔数 0x{magic:04x}')
                details['unknown_pe_magic'] = True
                return score, reasons, details

            # ============================================================
            # 解析关键字段
            # ============================================================
            entry_point = struct.unpack_from('<I', data, entry_point_offset)[0]
            details['entry_point'] = f'0x{entry_point:08x}'

            if is_pe32plus:
                image_base = struct.unpack_from('<Q', data, image_base_offset)[0]
            else:
                image_base = struct.unpack_from('<I', data, image_base_offset)[0]
            details['image_base'] = f'0x{image_base:08x}'

            section_alignment = struct.unpack_from('<I', data, section_alignment_offset)[0]
            file_alignment = struct.unpack_from('<I', data, file_alignment_offset)[0]
            details['section_alignment'] = section_alignment
            details['file_alignment'] = file_alignment

            size_of_image = struct.unpack_from('<I', data, image_size_offset)[0]
            size_of_headers = struct.unpack_from('<I', data, size_of_headers_offset)[0]
            details['size_of_image'] = size_of_image
            details['size_of_headers'] = size_of_headers

            checksum = struct.unpack_from('<I', data, checksum_offset)[0]
            details['checksum'] = checksum

            subsystem = struct.unpack_from('<H', data, subsystem_offset)[0]
            details['subsystem'] = subsystem
            details['subsystem_name'] = KNOWN_SUBSYSTEMS.get(subsystem, '未知')

            dll_characteristics = struct.unpack_from('<H', data, dll_chars_offset)[0]
            details['dll_characteristics'] = f'0x{dll_characteristics:04x}'

            # ============================================================
            # 规则 8: 检查子系统
            # ============================================================
            if subsystem not in KNOWN_SUBSYSTEMS:
                score += 5
                reasons.append(f'规则8: 未知子系统 {subsystem}')
                details['unknown_subsystem'] = True

            # ============================================================
            # 规则 9: 检查入口点
            # ============================================================
            if entry_point < 0x1000:
                score += 5
                reasons.append(f'规则9: 入口点地址异常 (过低): 0x{entry_point:08x}')
                details['entry_point_too_low'] = True

            # ============================================================
            # 规则 10: 检查文件对齐
            # ============================================================
            if file_alignment not in (0x200, 0x400, 0x1000):
                score += 3
                reasons.append(f'规则10: 文件对齐值异常: 0x{file_alignment:08x}')
                details['file_alignment_anomaly'] = file_alignment

            # ============================================================
            # 规则 11: 检查节区对齐
            # ============================================================
            if section_alignment not in (0x1000, 0x2000, 0x4000, 0x10000):
                if section_alignment != file_alignment:
                    score += 3
                    reasons.append(f'规则11: 节区对齐值异常: 0x{section_alignment:08x}')
                    details['section_alignment_anomaly'] = section_alignment

            # ============================================================
            # 规则 12: 检查节区数量
            # ============================================================
            if num_sections <= 2:
                score += 10
                reasons.append(f'规则12: 节区数量异常少: {num_sections}')
                details['few_sections'] = True
            elif num_sections > 30:
                score += 5
                reasons.append(f'规则12: 节区数量异常多: {num_sections}')
                details['many_sections'] = True

            # ============================================================
            # 规则 13: 检查镜像大小异常
            # ============================================================
            if size_of_image > file_size * 20 and size_of_image > 0:
                score += 5
                reasons.append(f'规则13: 镜像大小远大于文件大小: {size_of_image} vs {file_size}')
                details['image_size_anomaly'] = True

            # ============================================================
            # 规则 14: 检查头大小
            # ============================================================
            if size_of_headers > file_size:
                score += 5
                reasons.append('规则14: 头大小超过文件大小')
                details['header_size_anomaly'] = True

            # ============================================================
            # 规则 15: 检查校验和
            # ============================================================
            if checksum == 0 and not details.get('is_dll'):
                score += 2
                reasons.append('规则15: 校验和为0')
                details['checksum_zero'] = True

            # ============================================================
            # 解析节区表
            # ============================================================
            section_table_offset = optional_header_offset + header_size
            entry_point_section = -1
            suspicious_sections_count = 0
            rwx_sections = 0
            section_anomalies = []
            sections_info = []

            for i in range(num_sections):
                sec_offset = section_table_offset + i * 40
                if sec_offset + 40 > file_size:
                    break

                section_name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
                virtual_size = struct.unpack_from('<I', data, sec_offset + 8)[0]
                virtual_address = struct.unpack_from('<I', data, sec_offset + 12)[0]
                raw_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                raw_offset = struct.unpack_from('<I', data, sec_offset + 20)[0]
                reloc_offset = struct.unpack_from('<I', data, sec_offset + 24)[0]
                line_numbers = struct.unpack_from('<I', data, sec_offset + 28)[0]
                section_chars = struct.unpack_from('<I', data, sec_offset + 36)[0]

                sec_info = {
                    'name': section_name.strip(),
                    'virtual_size': virtual_size,
                    'virtual_address': f'0x{virtual_address:08x}',
                    'raw_size': raw_size,
                    'raw_offset': raw_offset,
                    'characteristics': f'0x{section_chars:08x}',
                }
                sections_info.append(sec_info)

                # 计算权限标志
                is_code = bool(section_chars & 0x20)
                is_readable = bool(section_chars & 0x40000000)
                is_writeable = bool(section_chars & 0x80000000)
                is_executable = bool(section_chars & 0x20000000)
                is_shared = bool(section_chars & 0x10000000)

                # ============================================================
                # 规则 16: 检查可疑节区名称
                # ============================================================
                if section_name.strip().lower() in SUSPICIOUS_SECTION_NAMES:
                    suspicious_sections_count += 1
                    section_anomalies.append(f'规则16: 可疑节区名称: {section_name.strip()}')
                    reasons.append(f'规则16: 可疑节区名称 "{section_name.strip()}"')

                # ============================================================
                # 规则 17: 检查可写可执行节区
                # ============================================================
                if is_writeable and is_executable:
                    rwx_sections += 1
                    section_anomalies.append(f'规则17: 节区 "{section_name.strip()}" 同时可写可执行')
                    reasons.append(f'规则17: 节区 "{section_name.strip()}" 同时可写可执行')

                # ============================================================
                # 规则 18: 检查虚拟大小和原始大小差异
                # ============================================================
                if virtual_size > 0 and raw_size > 0:
                    ratio = virtual_size / raw_size
                    if ratio > 10:
                        score += 5
                        reasons.append(f'规则18: 节区 "{section_name.strip()}" 虚拟大小是原始大小的{ratio:.0f}倍')
                        details['virtual_raw_mismatch'] = True
                    elif raw_size > 0 and virtual_size == 0 and raw_size > 0:
                        score += 2
                        reasons.append(f'规则18: 节区 "{section_name.strip()}" 虚拟大小为0但原始大小非0')

                # ============================================================
                # 规则 19: 检查原始大小=0但虚拟大小>0的节区
                # ============================================================
                if raw_size == 0 and virtual_size > 0x1000:
                    score += 3
                    reasons.append(f'规则19: 节区 "{section_name.strip()}" 原始大小为0但虚拟大小={virtual_size}')
                    details['raw_size_zero'] = True

                # ============================================================
                # 规则 20: 检查节区原始偏移
                # ============================================================
                if raw_offset + raw_size > file_size:
                    score += 5
                    reasons.append(f'规则20: 节区 "{section_name.strip()}" 原始数据超出文件范围')
                    details['section_out_of_file'] = True

                # ============================================================
                # 规则 21: 检查节区共享属性
                # ============================================================
                if is_shared and is_writeable:
                    score += 3
                    reasons.append(f'规则21: 节区 "{section_name.strip()}" 可写且共享')
                    details['shared_writable_section'] = True

                # ============================================================
                # 规则 22: 检查入口点所在节区
                # ============================================================
                if virtual_address <= entry_point < virtual_address + max(virtual_size, raw_size):
                    entry_point_section = i
                    sec_info['is_entry_point'] = True

                # ============================================================
                # 规则 23: 检查节区名称为空或异常
                # ============================================================
                if not section_name.strip() or section_name.strip() == '\x00':
                    score += 3
                    reasons.append(f'规则23: 节区{i}名称为空')

            details['sections'] = sections_info

            # ============================================================
            # 规则 24: 入口点不在任何节区中
            # ============================================================
            if entry_point_section < 0 and num_sections > 0:
                score += 10
                reasons.append('规则24: 入口点不在任何节区中')
                details['entry_point_outside_sections'] = True

            # ============================================================
            # 规则 25: 入口点在可疑节区
            # ============================================================
            if entry_point_section >= 0 and entry_point_section < len(sections_info):
                ep_section_name = sections_info[entry_point_section].get('name', '')
                if ep_section_name.lower() in SUSPICIOUS_SECTION_NAMES:
                    score += 10
                    reasons.append(f'规则25: 入口点在可疑节区 "{ep_section_name}"')
                    details['entry_point_in_suspicious_section'] = True

            # ============================================================
            # 规则 26: 汇总可疑节区评分
            # ============================================================
            if suspicious_sections_count > 0:
                score += 10 * suspicious_sections_count
                details['suspicious_sections_count'] = suspicious_sections_count

            # ============================================================
            # 规则 27: 汇总可写可执行节区评分
            # ============================================================
            if rwx_sections > 0:
                score += 15 * rwx_sections
                details['rwx_sections_count'] = rwx_sections

            # ============================================================
            # 规则 28: 检查.RSRC节区 - 缺少资源节区
            # ============================================================
            has_resource = any(s['name'].lower() == '.rsrc' for s in sections_info)
            if not has_resource and details.get('is_dll'):
                score += 2
                reasons.append('规则28: DLL文件缺少资源节区(.rsrc)')
                details['missing_resource_section'] = True

            # ============================================================
            # 规则 29: 检查.reloc节区 - 缺少重定位节区
            # ============================================================
            has_reloc = any(s['name'].lower() == '.reloc' for s in sections_info)
            if not has_reloc and details.get('is_dll'):
                score += 3
                reasons.append('规则29: DLL文件缺少重定位节区(.reloc)')
                details['missing_reloc_section'] = True

            # ============================================================
            # 规则 30: 检查.tls节区
            # ============================================================
            has_tls = any(s['name'].lower() == '.tls' for s in sections_info)
            if has_tls:
                score += 3
                reasons.append('规则30: 文件包含TLS节区')
                details['has_tls_section'] = True

            # ============================================================
            # 规则 31: 检查非标准节区名称
            # ============================================================
            standard_sections = {'.text', '.data', '.rdata', '.rsrc', '.reloc',
                                '.bss', '.idata', '.edata', '.tls', '.pdata',
                                '.debug', '.stab', '.stabstr', '.crt', '.didat',
                                '.sxdata', '.gfids', '.00cfg', '.ndata', '.rsrc2',
                                '.textmn', '.data1', '.text01', '.text02',
                                '.xdata', '.gfids', '.build', '.sdata',
                                '.code', '.const', '.init', '.fini'}
            for sec in sections_info:
                sec_name = sec['name'].lower()
                if sec_name and sec_name not in standard_sections and \
                   not sec_name.startswith('.') and len(sec_name) > 0:
                    score += 2
                    reasons.append(f'规则31: 非标准节区名称 "{sec_name}"')
                    details['non_standard_section'] = sec_name

            # ============================================================
            # 解析数据目录
            # ============================================================
            num_data_dir = struct.unpack_from('<I', data, num_data_dir_offset)[0]
            data_dir_offset = num_data_dir_offset + 4

            # 限制数据目录数量
            if num_data_dir > 20:
                score += 3
                reasons.append(f'规则32: 数据目录数量异常: {num_data_dir}')
                details['many_data_dirs'] = num_data_dir

            # 安全地解析数据目录
            max_data_dir = min(num_data_dir, 16)
            data_dirs = []
            for i in range(max_data_dir):
                dir_offset = data_dir_offset + i * 8
                if dir_offset + 8 > file_size:
                    break
                dir_va = struct.unpack_from('<I', data, dir_offset)[0]
                dir_size = struct.unpack_from('<I', data, dir_offset + 4)[0]
                data_dirs.append({'index': i, 'va': dir_va, 'size': dir_size})

            details['data_directories'] = data_dirs

            # ============================================================
            # 规则 33: 检查导入表
            # ============================================================
            if len(data_dirs) > 1:
                import_dir = data_dirs[1]  # IMAGE_DIRECTORY_ENTRY_IMPORT
                if import_dir['va'] == 0 and import_dir['size'] > 0:
                    score += 5
                    reasons.append('规则33: 导入表VA为0但大小非0')
                    details['import_table_anomaly'] = True
                elif import_dir['va'] == 0 and import_dir['size'] == 0:
                    # 无导入表 - 可能是加壳
                    score += 5
                    reasons.append('规则33: 文件没有导入表 (可能已加壳)')
                    details['no_import_table'] = True

            # ============================================================
            # 规则 34: 检查导出表
            # ============================================================
            if len(data_dirs) > 0:
                export_dir = data_dirs[0]  # IMAGE_DIRECTORY_ENTRY_EXPORT
                if not details.get('is_dll') and export_dir['va'] > 0 and export_dir['size'] > 0:
                    score += 3
                    reasons.append('规则34: EXE文件包含导出表')
                    details['exe_has_export'] = True

            # ============================================================
            # 规则 35: 检查TLS目录
            # ============================================================
            if len(data_dirs) > 9:
                tls_dir = data_dirs[9]  # IMAGE_DIRECTORY_ENTRY_TLS
                if tls_dir['va'] > 0 and tls_dir['size'] > 0:
                    score += 5
                    reasons.append('规则35: 文件包含TLS目录 (可能存在TLS回调)')
                    details['has_tls_directory'] = True

            # ============================================================
            # 规则 36: 检查安全目录 (数字签名)
            # ============================================================
            if len(data_dirs) > 4:
                security_dir = data_dirs[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
                details['has_digital_signature'] = (security_dir['va'] > 0 and security_dir['size'] > 0)
                if not details['has_digital_signature']:
                    score += 2
                    reasons.append('规则36: 文件没有数字签名')
                    details['no_signature'] = True

            # ============================================================
            # 规则 37: 检查调试目录
            # ============================================================
            if len(data_dirs) > 6:
                debug_dir = data_dirs[6]  # IMAGE_DIRECTORY_ENTRY_DEBUG
                if debug_dir['va'] > 0 and debug_dir['size'] > 0:
                    score += 1
                    reasons.append('规则37: 文件包含调试信息')
                    details['has_debug_info'] = True

            # ============================================================
            # 规则 38: 检查延迟导入表
            # ============================================================
            if len(data_dirs) > 15:
                delay_dir = data_dirs[15]  # IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
                if delay_dir['va'] > 0 and delay_dir['size'] > 0:
                    score += 3
                    reasons.append('规则38: 文件包含延迟导入表')
                    details['has_delay_import'] = True

            # ============================================================
            # 规则 39: 检查COM目录
            # ============================================================
            if len(data_dirs) > 14:
                com_dir = data_dirs[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
                if com_dir['va'] > 0 and com_dir['size'] > 0:
                    score += 2
                    reasons.append('规则39: 文件包含.NET元数据')
                    details['is_dotnet'] = True

            # ============================================================
            # 规则 40: 检查文件叠加 (Overlay)
            # ============================================================
            # 计算最后一个节区的末尾
            last_section_end = 0
            for sec in sections_info:
                sec_end = sec['raw_offset'] + sec['raw_size']
                if sec_end > last_section_end:
                    last_section_end = sec_end

            if last_section_end > 0 and last_section_end < file_size:
                overlay_size = file_size - last_section_end
                if overlay_size > 100:
                    score += 5
                    reasons.append(f'规则40: 文件包含叠加数据 ({overlay_size}字节)')
                    details['has_overlay'] = True
                    details['overlay_size'] = overlay_size

            # ============================================================
            # 规则 41: 检查空字节填充
            # ============================================================
            # 检查文件末尾是否有大量空字节
            if file_size > 1024:
                tail = data[-1024:]
                null_tail = tail.count(b'\x00')
                if null_tail > 900:
                    score += 3
                    reasons.append(f'规则41: 文件末尾空字节过多 ({null_tail}/1024)')
                    details['null_tail'] = True

            # ============================================================
            # 规则 42: 检查是否为.NET程序集
            # ============================================================
            if details.get('is_dotnet'):
                score += 2  # .NET程序本身不危险，但检测到
                reasons.append('规则42: 检测到.NET程序集')

            # ============================================================
            # 规则 43: 检查DLL特性
            # ============================================================
            if dll_characteristics:
                if dll_characteristics & 0x0040:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    pass  # ASLR启用，正常
                if dll_characteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    pass  # DEP启用，正常
                if dll_characteristics & 0x0020:  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
                    pass  # 高熵ASLR，正常

            # ============================================================
            # 规则 44: 检查入口点是否在DLL的DllMain中
            # ============================================================
            if details.get('is_dll') and entry_point < 0x10000:
                score += 5
                reasons.append('规则44: DLL入口点地址异常')
                details['dll_entry_point_anomaly'] = True

            # ============================================================
            # 规则 45: 加壳/保护工具检测
            # ============================================================
            packer_detected = self._detect_packers(data, sections_info)
            if packer_detected:
                score += 15
                packer_names = ', '.join(packer_detected)
                reasons.append(f'规则45: 检测到加壳/保护工具: {packer_names}')
                details['packers'] = packer_detected

            # ============================================================
            # 规则 46-49: 导入表分析
            # ============================================================
            api_analysis = self._analyze_imports(data, sections_info, file_size)
            if api_analysis:
                score += api_analysis['score']
                for reason in api_analysis['reasons']:
                    reasons.append(reason)
                details['api_analysis'] = api_analysis

            # ============================================================
            # 规则 50: 字符串分析
            # ============================================================
            string_analysis = self._analyze_strings(data)
            if string_analysis:
                score += string_analysis['score']
                for reason in string_analysis['reasons']:
                    reasons.append(reason)
                details['string_analysis'] = string_analysis

            # ============================================================
            # 规则 51: 熵值分析
            # ============================================================
            entropy_analysis = self._analyze_entropy(data)
            if entropy_analysis:
                score += entropy_analysis['score']
                for reason in entropy_analysis['reasons']:
                    reasons.append(reason)
                details['entropy_analysis'] = entropy_analysis

            # ============================================================
            # 规则 52: 资源段分析
            # ============================================================
            resource_analysis = self._analyze_resource(data, sections_info)
            if resource_analysis:
                score += resource_analysis['score']
                for reason in resource_analysis['reasons']:
                    reasons.append(reason)
                details['resource_analysis'] = resource_analysis

            # ============================================================
            # 规则 53: 检查时间戳
            # ============================================================
            import datetime
            if timestamp > 0:
                ts_date = datetime.datetime.fromtimestamp(timestamp)
                details['compile_time'] = ts_date.strftime('%Y-%m-%d %H:%M:%S')
                # 检查未来时间戳
                if timestamp > time.time() + 86400 * 30:
                    score += 5
                    reasons.append('规则53: 时间戳在未来 (可能是伪造的编译时间)')
                    details['future_timestamp'] = True
                # 检查时间戳为0
            elif timestamp == 0:
                score += 3
                reasons.append('规则53: 时间戳为0 (可能被修改)')
                details['timestamp_zero'] = True

            # ============================================================
            # 规则 54: Rich头检测
            # ============================================================
            if self._has_rich_header(data):
                details['has_rich_header'] = True
            else:
                score += 3
                reasons.append('规则54: 缺少Rich头 (可能被移除)')
                details['rich_header_missing'] = True

            # ============================================================
            # 规则 55: 检查DOS存根
            # ============================================================
            dos_stub = data[64:pe_offset]
            if len(dos_stub) > 0:
                stub_text = dos_stub.decode('ascii', errors='replace')
                # 标准DOS存根包含"This program cannot be run in DOS mode"
                if 'This program cannot be run' not in stub_text:
                    if len(dos_stub) > 200:
                        score += 5
                        reasons.append(f'规则55: DOS存根异常 (大小={len(dos_stub)})')
                        details['dos_stub_anomaly'] = True

            # ============================================================
            # 规则 56: 检查文件大小
            # ============================================================
            if file_size < 2048 and not details.get('is_dll'):
                score += 5
                reasons.append(f'规则56: 可执行文件大小异常小: {file_size}字节')
                details['file_size_too_small'] = True
            elif file_size > 100 * 1024 * 1024:  # > 100MB
                score += 3
                reasons.append(f'规则56: 可执行文件异常大: {file_size}字节')
                details['file_size_too_large'] = True

            # ============================================================
            # 规则 57: 检查可疑的DLL特性
            # ============================================================
            if characteristics & 0x1000:  # IMAGE_FILE_SYSTEM
                score += 3
                reasons.append('规则57: 文件标记为系统文件')
                details['system_file'] = True
            if characteristics & 0x0004:  # IMAGE_FILE_LINE_NUMS_STRIPPED
                pass  # 正常
            if characteristics & 0x2000:  # IMAGE_FILE_DLL
                pass  # 正常

            # ============================================================
            # 规则 58: 检查异常的空节区
            # ============================================================
            for sec in sections_info:
                if sec['virtual_size'] == 0 and sec['raw_size'] == 0:
                    score += 2
                    reasons.append(f'规则58: 空节区 "{sec["name"]}"')
                    details['empty_section'] = sec['name']

            # ============================================================
            # 规则 59: 检查节区权限
            # ============================================================
            text_section = None
            for sec in sections_info:
                if sec['name'].lower() == '.text':
                    text_section = sec
                    break
            if text_section:
                text_chars = int(text_section.get('characteristics', '0'), 16)
                if not (text_chars & 0x20) and not (text_chars & 0x20000000):
                    score += 3
                    reasons.append('规则59: .text节区不含代码')
                    details['text_not_code'] = True

            # ============================================================
            # 规则 60: 检查.0_tls节区 (可疑)
            # ============================================================
            for sec in sections_info:
                name = sec['name'].lower()
                if name.startswith('.0') or name.startswith('.__'):
                    score += 3
                    reasons.append(f'规则60: 可疑节区命名 "{name}"')
                    details['suspicious_section_naming'] = True

        except Exception as e:
            score += 5
            reasons.append(f'PE分析异常: {str(e)}')
            details['error'] = str(e)

        # 限制分数范围
        score = min(score, 100.0)

        return score, reasons, details

    # ============================================================
    # 辅助方法
    # ============================================================

    def _detect_packers(self, data: bytes, sections: List[Dict]) -> List[str]:
        """检测加壳/保护工具"""
        detected = []
        data_lower = data.lower()

        for packer_name, signatures in PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data or sig.lower() in data_lower:
                    if packer_name not in detected:
                        detected.append(packer_name)
                    break

        # 通过节区名称检测
        for sec in sections:
            sec_name = sec['name'].lower()
            for packer_name, signatures in PACKER_SIGNATURES.items():
                for sig in signatures:
                    sig_str = sig.decode('ascii', errors='replace').lower().strip()
                    if sig_str == sec_name:
                        if packer_name not in detected:
                            detected.append(packer_name)
                        break

        return detected

    def _analyze_imports(self, data: bytes, sections: List[Dict],
                         file_size: int) -> Optional[Dict]:
        """分析导入表，检测敏感API"""
        score = 0.0
        reasons = []
        api_counts = {}
        suspicious_dlls = {}

        try:
            # 查找导入表（通过搜索导入函数名）
            all_strings = self._extract_strings(data, min_len=4)

            # 统计敏感API调用
            for s in all_strings:
                if s in self._suspicious_apis:
                    group = self._suspicious_apis[s]
                    api_counts[s] = api_counts.get(s, 0) + 1

            # 检查敏感API分组
            for group, apis in SENSITIVE_APIS.items():
                found = [api for api in apis if api in api_counts]
                if len(found) >= 3:
                    score += 8
                    reasons.append(f'规则46: 检测到{group}相关API ({len(found)}个): {", ".join(found[:5])}')
                elif len(found) >= 1:
                    score += 3
                    reasons.append(f'规则46: 检测到{group}相关API: {found[0]}')

            # 检查导入DLL
            for s in all_strings:
                dll_lower = s.lower()
                if dll_lower in SUSPICIOUS_IMPORT_DLLS:
                    suspicious_dlls[dll_lower] = suspicious_dlls.get(dll_lower, 0) + 1

            if len(suspicious_dlls) >= 3:
                score += 5
                reasons.append(f'规则47: 导入多个可疑DLL: {", ".join(list(suspicious_dlls.keys())[:5])}')
            elif len(suspicious_dlls) >= 1:
                score += 2
                reasons.append(f'规则47: 导入可疑DLL: {", ".join(list(suspicious_dlls.keys())[:3])}')

            # 检查导入表条目总数
            total_apis = len(api_counts)
            if total_apis > 20:
                score += 5
                reasons.append(f'规则48: 大量敏感API调用 ({total_apis}个)')

            # 检查特定恶意组合
            injection_apis = ['WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx']
            if all(api in api_counts for api in injection_apis):
                score += 15
                reasons.append('规则49: 检测到进程注入API组合 (WriteProcessMemory + CreateRemoteThread + VirtualAllocEx)')

            keylogger_apis = ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow']
            if sum(1 for api in keylogger_apis if api in api_counts) >= 2:
                score += 10
                reasons.append('规则49: 检测到键盘记录API组合')

            # 检查自删除
            if 'MoveFileEx' in api_counts or 'FILE_DELETE_ON_CLOSE' in ''.join(all_strings):
                score += 5
                reasons.append('规则49: 检测到自删除相关API')

            if score > 0:
                return {
                    'score': min(score, 40.0),
                    'reasons': reasons,
                    'api_counts': {k: v for k, v in sorted(api_counts.items(), key=lambda x: x[1], reverse=True)[:20]},
                    'suspicious_dlls': list(suspicious_dlls.keys()),
                }

        except Exception:
            pass

        return None

    def _analyze_strings(self, data: bytes) -> Optional[Dict]:
        """分析字符串内容"""
        score = 0.0
        reasons = []
        strings = self._extract_strings(data, min_len=4)
        string_data = {}

        # 检查URL
        urls = [s for s in strings if s.startswith('http://') or s.startswith('https://')]
        if urls:
            score += 3 * min(len(urls), 5)
            reasons.append(f'规则50a: 包含网络URL ({len(urls)}个)')
            string_data['urls'] = urls[:10]

        # 检查IP地址
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = [s for s in strings if ip_pattern.match(s)]
        if ips:
            score += 3 * min(len(ips), 5)
            reasons.append(f'规则50b: 包含IP地址 ({len(ips)}个)')
            string_data['ips'] = ips[:10]

        # 检查恶意关键词
        malware_keywords = [
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'password',
            'keylog', 'inject', 'shellcode', 'payload', 'exploit', 'bypass',
            'backdoor', 'rat', 'trojan', 'steal', 'capture', 'hook',
            'hidden', 'stealth', 'elevation', 'privilege', 'admin',
            'rootkit', 'mbr', 'bootkit', 'uac', 'bypassuac',
            'reverse', 'connect', 'bind', 'listen', 'backconnect',
            'crypt', 'decrypt', 'encode', 'obfuscate', 'packer',
            'dump', 'miner', 'coinhive', 'monero', 'eth',
            'phish', 'fraud', 'spam', 'redirect',
            'worm', 'downloader', 'dropper', 'loader',
            'antidebug', 'antivm', 'antianalysis', 'antidisassemble',
            'vbox', 'vmware', 'virtualbox', 'qemu', 'sandbox',
            'debugger', 'ollydbg', 'x64dbg', 'ida', 'windbg',
            'processhacker', 'procexp', 'wireshark',
            'mimikatz', 'hashdump', 'sam', 'lsass',
            'psexec', 'wmiexec', 'smbexec', 'atexec',
            'cobaltstrike', 'beacon', 'meterpreter', 'empire',
            'powershell -enc', '-windowstyle hidden', '-exec bypass',
        ]
        found_keywords = [kw for kw in malware_keywords if kw in data.lower()]
        if found_keywords:
            score += 5 * min(len(found_keywords), 5)
            reasons.append(f'规则50c: 包含恶意关键词 ({len(found_keywords)}个): {", ".join(found_keywords[:5])}')
            string_data['malware_keywords'] = found_keywords[:10]

        # 检查Base64编码
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{40,}')
        b64_strings = [s for s in strings if b64_pattern.match(s) and len(s) >= 40]
        if len(b64_strings) > 3:
            score += 5
            reasons.append(f'规则50d: 包含大量Base64编码字符串 ({len(b64_strings)}个)')
            string_data['base64_count'] = len(b64_strings)

        # 检查注册表路径
        reg_paths = [s for s in strings if s.startswith('HKEY_') or s.startswith('HK')]
        if reg_paths:
            score += 2
            reasons.append(f'规则50e: 包含注册表路径 ({len(reg_paths)}个)')
            string_data['registry_paths'] = reg_paths[:5]

        if score > 0:
            return {
                'score': min(score, 25.0),
                'reasons': reasons,
                'string_data': string_data,
            }

        return None

    def _analyze_entropy(self, data: bytes) -> Optional[Dict]:
        """分析文件熵值"""
        score = 0.0
        reasons = []
        entropy_data = {}

        # 整体熵值
        overall_entropy = self._calculate_entropy(data)
        entropy_data['overall_entropy'] = overall_entropy

        if overall_entropy > 7.5:
            score += 10
            reasons.append(f'规则51a: 整体熵值异常高 (可能已加壳/加密): {overall_entropy:.2f}')
        elif overall_entropy > 6.5:
            score += 5
            reasons.append(f'规则51a: 整体熵值较高: {overall_entropy:.2f}')

        # 分块熵值分析 - 检查不同区域的熵值差异
        chunk_size = max(4096, len(data) // 16)
        high_entropy_chunks = 0
        for i in range(0, len(data) - chunk_size + 1, chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) >= 256:
                chunk_entropy = self._calculate_entropy(chunk)
                if chunk_entropy > 7.0:
                    high_entropy_chunks += 1

        if high_entropy_chunks > len(data) // chunk_size * 0.5:
            score += 5
            reasons.append(f'规则51b: 超过50%的区块具有高熵值')
            entropy_data['high_entropy_chunks'] = high_entropy_chunks

        # 熵值分布分析
        if overall_entropy < 1.0 and len(data) > 1024:
            score += 3
            reasons.append(f'规则51c: 熵值异常低 (可能是空数据或填充): {overall_entropy:.2f}')
            entropy_data['low_entropy'] = True

        if score > 0:
            return {
                'score': min(score, 20.0),
                'reasons': reasons,
                'entropy_data': entropy_data,
            }

        return None

    def _analyze_resource(self, data: bytes, sections: List[Dict]) -> Optional[Dict]:
        """分析资源段"""
        score = 0.0
        reasons = []
        resource_data = {}

        # 查找.rsrc节区
        rsrc_section = None
        for sec in sections:
            if sec['name'].lower() == '.rsrc':
                rsrc_section = sec
                break

        if rsrc_section:
            raw_offset = rsrc_section.get('raw_offset', 0)
            raw_size = rsrc_section.get('raw_size', 0)

            if raw_offset > 0 and raw_size > 0:
                rsrc_data = data[raw_offset:raw_offset + raw_size]

                # 检查资源中是否包含可执行文件
                if b'MZ' in rsrc_data:
                    score += 10
                    reasons.append('规则52a: 资源段包含嵌入式PE文件')
                    resource_data['embedded_pe'] = True

                # 检查资源中是否包含脚本
                if b'powershell' in rsrc_data.lower() or b'vbs' in rsrc_data.lower():
                    score += 8
                    reasons.append('规则52b: 资源段包含脚本')
                    resource_data['embedded_script'] = True

                # 检查资源熵值
                rsrc_entropy = self._calculate_entropy(rsrc_data)
                if rsrc_entropy > 7.0:
                    score += 5
                    reasons.append(f'规则52c: 资源段熵值高 (可能加密): {rsrc_entropy:.2f}')
                    resource_data['rsrc_entropy'] = rsrc_entropy

                # 检查资源大小
                if raw_size > 10 * 1024 * 1024:  # > 10MB
                    score += 3
                    reasons.append(f'规则52d: 资源段异常大: {raw_size}字节')
                    resource_data['large_resource'] = True

                # 检查资源中是否包含HTML/钓鱼页面
                if b'<html' in rsrc_data.lower() or b'<form' in rsrc_data.lower():
                    score += 5
                    reasons.append('规则52e: 资源段包含HTML内容 (可能为钓鱼页面)')
                    resource_data['phishing_content'] = True

        if score > 0:
            return {
                'score': min(score, 20.0),
                'reasons': reasons,
                'resource_data': resource_data,
            }

        return None

    def _has_rich_header(self, data: bytes) -> bool:
        """检查是否包含Rich头"""
        # Rich头在DOS存根中，以'Rich'开头
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset > 0:
            # 在DOS存根中搜索'Rich'
            dos_stub = data[64:pe_offset]
            return b'Rich' in dos_stub
        return False

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """从二进制数据中提取可打印字符串"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_len:
            strings.append(''.join(current))
        return strings

    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据的香农熵"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counter = Counter(data)
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length())  # 简化计算
        # 使用标准香农熵公式重新计算
        from math import log2
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * log2(p)
        return entropy


# 兼容性导入
import time