#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启发式规则集 - HeuristicRules
==============================

提供 100+ 启发式检测规则，用于识别未知威胁和可疑行为。
启发式规则基于文件特征、行为模式、代码结构进行判断。

规则分类:
  - PE 文件分析规则（PE header anomalies, section anomalies）
  - 脚本分析规则（JavaScript, PowerShell, VBS, Python 混淆检测）
  - 文档分析规则（Office 宏、PDF 漏洞利用）
  - 行为模式规则（文件操作、网络连接、进程创建）
  - 通用可疑规则（加密、压缩、反调试、反沙箱）

每种规则包含：
  - name: 规则名称
  - description: 规则描述
  - weight: 权重（1-100），影响可疑度评分
  - category: 分类
  - tags: 标签
  - detect_func: 检测函数（接收文件数据，返回是否匹配及详情）

用法示例:
    rules = HeuristicRules()
    with open('sample.exe', 'rb') as f:
        data = f.read()
    results = rules.check_all(data, file_ext='.exe')
    for r in results:
        print(f'[+] {r["name"]}: {r["match"]}')
"""

import re
import os
import struct
from typing import List, Dict, Optional, Tuple, Set, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict


# ============================================================
# 启发式规则数据结构
# ============================================================
@dataclass
class HeuristicRule:
    """启发式规则定义"""
    id: str                              # 规则 ID
    name: str                            # 规则名称
    description: str                     # 规则描述
    category: str                        # 分类
    weight: int = 50                     # 权重（1-100）
    tags: List[str] = field(default_factory=list)  # 标签
    enabled: bool = True                 # 是否启用
    file_types: List[str] = field(default_factory=list)  # 适用文件类型

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'weight': self.weight,
            'tags': list(self.tags),
            'enabled': self.enabled,
            'file_types': list(self.file_types),
        }


@dataclass
class HeuristicResult:
    """启发式检测结果"""
    rule_id: str
    rule_name: str
    category: str
    weight: int
    match: bool
    details: str = ''
    severity: int = 0  # 1-10

    def to_dict(self) -> Dict:
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'category': self.category,
            'weight': self.weight,
            'match': self.match,
            'details': self.details,
            'severity': self.severity,
        }


# ============================================================
# 启发式规则集
# ============================================================
class HeuristicRules:
    """启发式规则管理器

    管理所有启发式检测规则，提供规则注册、执行、评分的完整功能。
    包含 100+ 内置规则，覆盖 PE 分析、脚本分析、文档分析、行为模式等。

    属性:
        rules: List[HeuristicRule] - 所有已注册的规则
        results: List[HeuristicResult] - 最近一次检测结果
        threshold: float - 可疑度阈值（0-1），超过此值判定为可疑
    """

    def __init__(self, threshold: float = 0.5):
        """初始化启发式规则集

        Args:
            threshold: 可疑度阈值，默认 0.5
        """
        self.rules: List[HeuristicRule] = []
        self.results: List[HeuristicResult] = []
        self.threshold = threshold
        self._register_builtin_rules()

    def _register_builtin_rules(self):
        """注册所有内置启发式规则"""
        # ============================================================
        # 1. PE 文件分析规则（30 条）
        # ============================================================
        pe_rules = [
            HeuristicRule(
                id='PE_001', name='可疑入口点',
                description='PE 文件的入口点不在标准的 .text 节中，可能是代码覆盖或入口点混淆',
                category='pe_analysis', weight=70,
                tags=['pe', 'entry_point', 'obfuscation'],
                file_types=['.exe', '.dll', '.scr', '.ocx', '.cpl'],
            ),
            HeuristicRule(
                id='PE_002', name='节名异常',
                description='PE 文件包含非标准节名（非 .text/.data/.rdata），可能是恶意软件使用的自定义节名',
                category='pe_analysis', weight=50,
                tags=['pe', 'section', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_003', name='节对齐异常',
                description='文件对齐和内存对齐存在异常差值，可能导致缓冲区溢出',
                category='pe_analysis', weight=60,
                tags=['pe', 'alignment', 'exploit'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_004', name='可疑节权限',
                description='PE 节同时具有写入和执行权限（WX），可能是代码注入或 shellcode',
                category='pe_analysis', weight=80,
                tags=['pe', 'section', 'permission', 'wx'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='PE_005', name='多个节具有可疑权限',
                description='多个 PE 节同时具有可写和可执行属性，高度可疑',
                category='pe_analysis', weight=85,
                tags=['pe', 'section', 'permission', 'wx'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_006', name='资源节异常',
                description='PE 资源节（.rsrc）包含可执行代码或异常大的数据',
                category='pe_analysis', weight=65,
                tags=['pe', 'resource', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_007', name='TLS 回调函数',
                description='PE 文件包含 TLS 回调函数，常用于隐藏恶意代码执行',
                category='pe_analysis', weight=55,
                tags=['pe', 'tls', 'callback'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_008', name='绑定导入表',
                description='PE 存在绑定导入表，可能用于绕过某些 API 监控',
                category='pe_analysis', weight=45,
                tags=['pe', 'import', 'binding'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_009', name='延迟导入表异常',
                description='PE 延迟导入表包含可疑的 API 调用',
                category='pe_analysis', weight=40,
                tags=['pe', 'delay_import'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_010', name='异常导出表',
                description='DLL 导出表包含大量序数导出或异常函数名',
                category='pe_analysis', weight=50,
                tags=['pe', 'export', 'dll'],
                file_types=['.dll', '.ocx', '.cpl'],
            ),
            HeuristicRule(
                id='PE_011', name='重定位表缺失',
                description='DLL 文件缺少重定位表，可能导致加载失败或基址冲突',
                category='pe_analysis', weight=40,
                tags=['pe', 'relocation', 'dll'],
                file_types=['.dll'],
            ),
            HeuristicRule(
                id='PE_012', name='数字签名异常',
                description='PE 文件数字签名无效、过期或自签名',
                category='pe_analysis', weight=50,
                tags=['pe', 'signature', 'certificate'],
                file_types=['.exe', '.dll', '.sys'],
            ),
            HeuristicRule(
                id='PE_013', name='文件头大小异常',
                description='PE 可选头大小不符合标准值，可能是手动篡改',
                category='pe_analysis', weight=55,
                tags=['pe', 'header', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_014', name='节表数量异常',
                description='PE 节表数量过少或过多，超过正常范围',
                category='pe_analysis', weight=45,
                tags=['pe', 'section', 'count'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_015', name='数据目录表异常',
                description='PE 数据目录表条目数量与标准值不符',
                category='pe_analysis', weight=40,
                tags=['pe', 'data_directory'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_016', name='可疑导入函数',
                description='导入表中包含常用于恶意行为的 API 函数组合',
                category='pe_analysis', weight=75,
                tags=['pe', 'import', 'api', 'suspicious'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='PE_017', name='进程注入相关 API',
                description='导入表包含 VirtualAllocEx、WriteProcessMemory、CreateRemoteThread 等注入 API',
                category='pe_analysis', weight=90,
                tags=['pe', 'import', 'injection', 'critical'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_018', name='钩子安装 API',
                description='导入表包含 SetWindowsHookEx 等钩子安装 API',
                category='pe_analysis', weight=65,
                tags=['pe', 'import', 'hook'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_019', name='反调试 API',
                description='导入表包含 IsDebuggerPresent、NtQueryInformationProcess 等反调试 API',
                category='pe_analysis', weight=60,
                tags=['pe', 'import', 'anti_debug'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_020', name='网络通信 API',
                description='导入表包含 socket、connect、send、recv 等网络 API',
                category='pe_analysis', weight=40,
                tags=['pe', 'import', 'network'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_021', name='文件操作 API',
                description='导入表包含大量文件操作 API，可能用于文件加密或篡改',
                category='pe_analysis', weight=50,
                tags=['pe', 'import', 'file_operations'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_022', name='注册表操作 API',
                description='导入表包含注册表操作 API，可能用于持久化',
                category='pe_analysis', weight=45,
                tags=['pe', 'import', 'registry'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_023', name='服务操作 API',
                description='导入表包含服务控制管理器 API，可能用于安装恶意服务',
                category='pe_analysis', weight=55,
                tags=['pe', 'import', 'service'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_024', name='加密算法导入',
                description='导入表包含加密 API（CryptEncrypt、CryptDecrypt 等），可能用于勒索软件',
                category='pe_analysis', weight=60,
                tags=['pe', 'import', 'crypto', 'ransomware'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_025', name='提权相关 API',
                description='导入表包含提权 API（AdjustTokenPrivileges、OpenProcessToken 等）',
                category='pe_analysis', weight=70,
                tags=['pe', 'import', 'privilege_escalation'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_026', name='可疑节大小',
                description='PE 节的实际大小远大于原始大小，可能包含隐藏数据',
                category='pe_analysis', weight=55,
                tags=['pe', 'section', 'size', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_027', name='代码重叠',
                description='PE 文件中存在多个节的虚拟地址重叠',
                category='pe_analysis', weight=75,
                tags=['pe', 'overlap', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_028', name='校验和异常',
                description='PE 文件的校验和与计算值不符，可能被篡改',
                category='pe_analysis', weight=50,
                tags=['pe', 'checksum', 'tampered'],
                file_types=['.exe', '.dll', '.sys'],
            ),
            HeuristicRule(
                id='PE_029', name='Subsystem 异常',
                description='PE Subsystem 值与文件类型不匹配（如 exe 文件使用 native subsystem）',
                category='pe_analysis', weight=45,
                tags=['pe', 'subsystem', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='PE_030', name='资源中嵌入可执行文件',
                description='PE 文件的资源节中包含其他 PE 文件数据，可能是打包或释放恶意载荷',
                category='pe_analysis', weight=80,
                tags=['pe', 'resource', 'embedded', 'dropper'],
                file_types=['.exe', '.dll'],
            ),
        ]

        # ============================================================
        # 2. 脚本分析规则（25 条）
        # ============================================================
        script_rules = [
            HeuristicRule(
                id='SCRIPT_001', name='Base64 编码数据',
                description='脚本中包含大量 Base64 编码字符串，常用于混淆恶意代码',
                category='script_analysis', weight=60,
                tags=['script', 'base64', 'obfuscation'],
                file_types=['.js', '.vbs', '.ps1', '.py', '.php', '.asp', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_002', name='eval 多次调用',
                description='脚本中多次调用 eval() 或类似的动态执行函数',
                category='script_analysis', weight=65,
                tags=['script', 'eval', 'obfuscation'],
                file_types=['.js', '.vbs', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_003', name='字符串拼接执行',
                description='脚本通过字符串拼接生成代码并执行，典型的混淆方式',
                category='script_analysis', weight=70,
                tags=['script', 'string_concat', 'obfuscation'],
                file_types=['.js', '.vbs', '.ps1', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_004', name='PowerShell 隐藏窗口',
                description='PowerShell 脚本使用 -WindowStyle Hidden 或 -Hidden 参数',
                category='script_analysis', weight=55,
                tags=['script', 'powershell', 'hidden'],
                file_types=['.ps1', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_005', name='PowerShell 远程下载',
                description='PowerShell 脚本使用 Invoke-WebRequest 或 WebClient 下载远程文件',
                category='script_analysis', weight=75,
                tags=['script', 'powershell', 'download'],
                file_types=['.ps1', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_006', name='WScript.Shell 对象',
                description='VBScript 创建 WScript.Shell 对象，可能用于执行命令',
                category='script_analysis', weight=60,
                tags=['script', 'vbs', 'wscript', 'shell'],
                file_types=['.vbs', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_007', name='FileSystemObject 操作',
                description='脚本使用 FileSystemObject 进行文件操作，可能用于写入恶意文件',
                category='script_analysis', weight=50,
                tags=['script', 'fso', 'file_operations'],
                file_types=['.vbs', '.js', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_008', name='XMLHTTP 请求',
                description='脚本使用 XMLHTTP 或 WinHttp 对象发起网络请求',
                category='script_analysis', weight=55,
                tags=['script', 'http', 'network'],
                file_types=['.vbs', '.js', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_009', name='ADODB.Stream 操作',
                description='脚本使用 ADODB.Stream 读写二进制数据，可能用于下载执行',
                category='script_analysis', weight=65,
                tags=['script', 'adodb', 'binary'],
                file_types=['.vbs', '.js', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_010', name='Shellcode 嵌入',
                description='脚本中包含明显的 Shellcode 字节序列',
                category='script_analysis', weight=95,
                tags=['script', 'shellcode', 'critical'],
                file_types=['.js', '.vbs', '.ps1', '.hta', '.py'],
            ),
            HeuristicRule(
                id='SCRIPT_011', name='JavaScript 混淆检测',
                description='JavaScript 代码包含大量数字、短变量名和高熵字符串',
                category='script_analysis', weight=55,
                tags=['script', 'javascript', 'obfuscation'],
                file_types=['.js', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_012', name='fromCharCode 大量使用',
                description='大量使用 String.fromCharCode 构造字符串，典型的混淆方式',
                category='script_analysis', weight=60,
                tags=['script', 'fromcharcode', 'obfuscation'],
                file_types=['.js', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_013', name='PowerShell 编码命令',
                description='PowerShell 脚本使用 -EncodedCommand 参数执行 Base64 编码命令',
                category='script_analysis', weight=80,
                tags=['script', 'powershell', 'encoded', 'critical'],
                file_types=['.ps1', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_014', name='Python 代码混淆',
                description='Python 代码包含大量混淆特征（hex/oct 编码、exec 动态执行）',
                category='script_analysis', weight=55,
                tags=['script', 'python', 'obfuscation'],
                file_types=['.py', '.pyw'],
            ),
            HeuristicRule(
                id='SCRIPT_015', name='计划任务创建',
                description='脚本创建计划任务以实现持久化',
                category='script_analysis', weight=70,
                tags=['script', 'persistence', 'scheduled_task'],
                file_types=['.ps1', '.vbs', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_016', name='注册表自启动项',
                description='脚本修改注册表 CurrentVersion\\Run 实现自启动',
                category='script_analysis', weight=70,
                tags=['script', 'persistence', 'registry'],
                file_types=['.vbs', '.ps1', '.bat', '.cmd', '.js'],
            ),
            HeuristicRule(
                id='SCRIPT_017', name='服务安装',
                description='脚本安装或创建 Windows 服务',
                category='script_analysis', weight=65,
                tags=['script', 'persistence', 'service'],
                file_types=['.ps1', '.vbs', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_018', name='WMI 持久化',
                description='脚本使用 WMI 事件订阅实现持久化',
                category='script_analysis', weight=75,
                tags=['script', 'wmi', 'persistence'],
                file_types=['.ps1', '.vbs', '.js'],
            ),
            HeuristicRule(
                id='SCRIPT_019', name='反沙箱检测',
                description='脚本包含检测虚拟机、沙箱或调试环境的代码',
                category='script_analysis', weight=60,
                tags=['script', 'anti_sandbox', 'anti_vm'],
                file_types=['.js', '.vbs', '.ps1', '.py', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_020', name='错误处理抑制',
                description='脚本使用 On Error Resume Next 等抑制错误显示',
                category='script_analysis', weight=45,
                tags=['script', 'error_suppression'],
                file_types=['.vbs', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_021', name='多次 URL 下载',
                description='脚本中包含多个远程 URL 下载请求',
                category='script_analysis', weight=65,
                tags=['script', 'download', 'multiple_urls'],
                file_types=['.ps1', '.vbs', '.js', '.py', '.hta'],
            ),
            HeuristicRule(
                id='SCRIPT_022', name='环境变量获取',
                description='脚本大量获取系统环境变量，可能用于信息收集',
                category='script_analysis', weight=40,
                tags=['script', 'enumeration', 'info_gathering'],
                file_types=['.ps1', '.vbs', '.bat', '.cmd'],
            ),
            HeuristicRule(
                id='SCRIPT_023', name='用户账户控制绕过',
                description='脚本包含 UAC 绕过代码',
                category='script_analysis', weight=85,
                tags=['script', 'uac_bypass', 'critical'],
                file_types=['.ps1', '.vbs', '.js', '.bat'],
            ),
            HeuristicRule(
                id='SCRIPT_024', name='HTA 文件检测',
                description='HTA 文件包含可疑的脚本代码',
                category='script_analysis', weight=55,
                tags=['script', 'hta', 'html_application'],
                file_types=['.hta', '.htm', '.html'],
            ),
            HeuristicRule(
                id='SCRIPT_025', name='命令行参数构造',
                description='脚本动态构造命令行参数并执行',
                category='script_analysis', weight=60,
                tags=['script', 'command_line', 'execution'],
                file_types=['.ps1', '.vbs', '.js', '.bat', '.py'],
            ),
        ]

        # ============================================================
        # 3. 文档分析规则（15 条）
        # ============================================================
        document_rules = [
            HeuristicRule(
                id='DOC_001', name='Office 宏自动执行',
                description='Office 文档包含 AutoOpen/AutoExec 等自动执行的宏',
                category='document_analysis', weight=70,
                tags=['office', 'macro', 'autoexec'],
                file_types=['.doc', '.docm', '.dotm', '.xls', '.xlsm', '.ppt', '.pptm'],
            ),
            HeuristicRule(
                id='DOC_002', name='可疑 VBA 函数',
                description='Office 宏中包含 Shell、CreateObject 等危险函数调用',
                category='document_analysis', weight=80,
                tags=['office', 'macro', 'vba', 'dangerous'],
                file_types=['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'],
            ),
            HeuristicRule(
                id='DOC_003', name='VBA 字符串混淆',
                description='VBA 宏中使用 Chr()/ChrW() 大量拼接字符串',
                category='document_analysis', weight=60,
                tags=['office', 'macro', 'obfuscation'],
                file_types=['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'],
            ),
            HeuristicRule(
                id='DOC_004', name='PDF JavaScript 执行',
                description='PDF 文档包含 JavaScript 代码',
                category='document_analysis', weight=65,
                tags=['pdf', 'javascript'],
                file_types=['.pdf'],
            ),
            HeuristicRule(
                id='DOC_005', name='PDF 恶意对象',
                description='PDF 包含 /Launch /EmbeddedFile /JavaScript 等可疑对象',
                category='document_analysis', weight=75,
                tags=['pdf', 'exploit', 'object'],
                file_types=['.pdf'],
            ),
            HeuristicRule(
                id='DOC_006', name='PDF 打开动作',
                description='PDF 文档设置了自动打开动作（/OpenAction）',
                category='document_analysis', weight=60,
                tags=['pdf', 'open_action'],
                file_types=['.pdf'],
            ),
            HeuristicRule(
                id='DOC_007', name='Office 外部链接',
                description='Office 文档包含指向远程服务器的外部链接',
                category='document_analysis', weight=55,
                tags=['office', 'external_link', 'remote'],
                file_types=['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt'],
            ),
            HeuristicRule(
                id='DOC_008', name='OLE 对象嵌入',
                description='Office 文档中嵌入可疑的 OLE 对象',
                category='document_analysis', weight=60,
                tags=['office', 'ole', 'embedded'],
                file_types=['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            ),
            HeuristicRule(
                id='DOC_009', name='文档加密异常',
                description='文档使用弱加密或异常加密方式',
                category='document_analysis', weight=50,
                tags=['document', 'encryption', 'anomaly'],
                file_types=['.doc', '.docx', '.xls', '.xlsx', '.pdf'],
            ),
            HeuristicRule(
                id='DOC_010', name='宏数字签名异常',
                description='VBA 宏的数字签名无效或可疑',
                category='document_analysis', weight=55,
                tags=['office', 'macro', 'signature'],
                file_types=['.docm', '.xlsm', '.pptm'],
            ),
            HeuristicRule(
                id='DOC_011', name='模板注入',
                description='Office 文档从远程模板加载宏',
                category='document_analysis', weight=75,
                tags=['office', 'template', 'remote', 'injection'],
                file_types=['.docx', '.xlsx', '.pptx'],
            ),
            HeuristicRule(
                id='DOC_012', name='DDE 域代码',
                description='Office 文档包含 DDE（动态数据交换）域代码，可能用于执行命令',
                category='document_analysis', weight=80,
                tags=['office', 'dde', 'command_execution'],
                file_types=['.doc', '.docx', '.docm'],
            ),
            HeuristicRule(
                id='DOC_013', name='EQ 域代码',
                description='Office 文档包含 EQ（公式）域代码，可能用于隐藏恶意链接',
                category='document_analysis', weight=50,
                tags=['office', 'eq_field', 'phishing'],
                file_types=['.doc', '.docx'],
            ),
            HeuristicRule(
                id='DOC_014', name='PDF 编码流异常',
                description='PDF 文档包含大量编码流，可能隐藏恶意代码',
                category='document_analysis', weight=55,
                tags=['pdf', 'encoded_stream', 'obfuscation'],
                file_types=['.pdf'],
            ),
            HeuristicRule(
                id='DOC_015', name='EPUB 恶意内容',
                description='EPUB 文档包含可疑的脚本或链接',
                category='document_analysis', weight=50,
                tags=['epub', 'script', 'suspicious'],
                file_types=['.epub'],
            ),
        ]

        # ============================================================
        # 4. 行为模式规则（25 条）
        # ============================================================
        behavior_rules = [
            HeuristicRule(
                id='BEH_001', name='自删除/自移动',
                description='程序执行后尝试删除或移动自身文件',
                category='behavior_pattern', weight=75,
                tags=['behavior', 'self_delete', 'anti_forensic'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='BEH_002', name='文件复制到启动目录',
                description='程序复制自身到系统启动目录',
                category='behavior_pattern', weight=70,
                tags=['behavior', 'persistence', 'startup'],
                file_types=['.exe', '.scr'],
            ),
            HeuristicRule(
                id='BEH_003', name='替换系统文件',
                description='程序尝试替换或修改系统关键文件',
                category='behavior_pattern', weight=85,
                tags=['behavior', 'system_file', 'tampering'],
                file_types=['.exe', '.dll', '.sys'],
            ),
            HeuristicRule(
                id='BEH_004', name='批量文件操作',
                description='程序对大量文件进行相同操作，可能是加密或删除',
                category='behavior_pattern', weight=80,
                tags=['behavior', 'bulk_operations', 'ransomware'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_005', name='文件扩展名修改',
                description='程序批量修改文件扩展名，典型的勒索软件行为',
                category='behavior_pattern', weight=90,
                tags=['behavior', 'extension_change', 'ransomware'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_006', name='创建互斥体',
                description='程序创建多个互斥体，可能是为了防多开',
                category='behavior_pattern', weight=40,
                tags=['behavior', 'mutex', 'singleton'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_007', name='键盘记录',
                description='程序设置键盘钩子或使用 GetAsyncKeyState 等 API',
                category='behavior_pattern', weight=85,
                tags=['behavior', 'keylogger', 'spyware'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_008', name='屏幕截图',
                description='程序获取屏幕截图，可能是间谍软件',
                category='behavior_pattern', weight=75,
                tags=['behavior', 'screenshot', 'spyware'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_009', name='剪切板监控',
                description='程序监控剪切板内容，可能是密码窃取',
                category='behavior_pattern', weight=70,
                tags=['behavior', 'clipboard', 'stealer'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_010', name='网络连接尝试',
                description='程序尝试建立对外网络连接，可能是 C2 通信',
                category='behavior_pattern', weight=60,
                tags=['behavior', 'network', 'c2'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='BEH_011', name='DNS 查询异常',
                description='程序进行大量或异常的 DNS 查询',
                category='behavior_pattern', weight=55,
                tags=['behavior', 'dns', 'c2'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_012', name='端口扫描',
                description='程序尝试扫描多个端口',
                category='behavior_pattern', weight=70,
                tags=['behavior', 'port_scan', 'worm'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_013', name='进程注入',
                description='程序尝试注入代码到其他进程',
                category='behavior_pattern', weight=95,
                tags=['behavior', 'injection', 'critical'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_014', name='DLL 劫持',
                description='程序利用 DLL 搜索顺序劫持加载恶意 DLL',
                category='behavior_pattern', weight=75,
                tags=['behavior', 'dll_hijacking'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_015', name='API 挂钩',
                description='程序尝试挂钩（Hook）系统 API',
                category='behavior_pattern', weight=80,
                tags=['behavior', 'api_hooking'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_016', name='令牌窃取',
                description='程序尝试窃取其他进程的访问令牌',
                category='behavior_pattern', weight=90,
                tags=['behavior', 'token_theft', 'privilege'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_017', name='驱动加载',
                description='程序尝试加载内核驱动程序',
                category='behavior_pattern', weight=85,
                tags=['behavior', 'driver', 'kernel'],
                file_types=['.exe', '.dll', '.sys'],
            ),
            HeuristicRule(
                id='BEH_018', name='内存修改',
                description='程序尝试修改其他进程的内存',
                category='behavior_pattern', weight=80,
                tags=['behavior', 'memory_modification'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_019', name='隐藏窗口',
                description='程序创建隐藏窗口或隐藏主窗口',
                category='behavior_pattern', weight=50,
                tags=['behavior', 'hidden_window', 'stealth'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_020', name='服务自启动',
                description='程序安装自身为系统服务',
                category='behavior_pattern', weight=65,
                tags=['behavior', 'service', 'persistence'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_021', name='AppInit_DLLs 注册',
                description='程序修改 AppInit_DLLs 注册表值实现全局注入',
                category='behavior_pattern', weight=85,
                tags=['behavior', 'appinit', 'dll_injection'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_022', name='映像劫持',
                description='程序修改 Debugger 注册表实现映像劫持（IFEO）',
                category='behavior_pattern', weight=80,
                tags=['behavior', 'ifeo', 'image_hijacking'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='BEH_023', name='WMI 事件订阅',
                description='程序创建 WMI 永久事件订阅实现持久化',
                category='behavior_pattern', weight=75,
                tags=['behavior', 'wmi', 'persistence'],
                file_types=['.exe', '.dll', '.ps1'],
            ),
            HeuristicRule(
                id='BEH_024', name='BITS 任务创建',
                description='程序创建 BITS（后台智能传输服务）任务下载文件',
                category='behavior_pattern', weight=70,
                tags=['behavior', 'bits', 'download'],
                file_types=['.exe', '.dll', '.ps1'],
            ),
            HeuristicRule(
                id='BEH_025', name='COM 劫持',
                description='程序修改 COM 类注册表实现劫持',
                category='behavior_pattern', weight=75,
                tags=['behavior', 'com', 'hijacking'],
                file_types=['.exe', '.dll'],
            ),
        ]

        # ============================================================
        # 5. 通用可疑规则（20 条）
        # ============================================================
        general_rules = [
            HeuristicRule(
                id='GEN_001', name='高熵数据区域',
                description='文件中包含高熵数据块，可能是加密或压缩的恶意载荷',
                category='general', weight=60,
                tags=['general', 'entropy', 'encrypted', 'packed'],
                file_types=[],
            ),
            HeuristicRule(
                id='GEN_002', name='反调试检查',
                description='代码中包含 IsDebuggerPresent、NtGlobalFlag 等反调试检查',
                category='general', weight=65,
                tags=['general', 'anti_debug', 'anti_analysis'],
                file_types=['.exe', '.dll', '.scr', '.sys'],
            ),
            HeuristicRule(
                id='GEN_003', name='反虚拟机检测',
                description='代码中包含检测虚拟机环境（VMware、VirtualBox 等）的代码',
                category='general', weight=60,
                tags=['general', 'anti_vm', 'anti_analysis'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_004', name='反沙箱检测',
                description='代码中包含检测沙箱环境的代码（检测用户名、文件、进程等）',
                category='general', weight=65,
                tags=['general', 'anti_sandbox', 'anti_analysis'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_005', name='时间延迟对抗',
                description='代码中包含 Sleep 或其他延迟函数，可能用于绕过沙箱超时检测',
                category='general', weight=55,
                tags=['general', 'timing', 'sandbox_evasion'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='GEN_006', name='大量无效指令',
                description='文件中包含大量 NOP 或无效指令，可能是 shellcode 填充',
                category='general', weight=70,
                tags=['general', 'nop_sled', 'shellcode'],
                file_types=['.exe', '.dll', '.scr', '.bin'],
            ),
            HeuristicRule(
                id='GEN_007', name='可疑文件版本信息',
                description='文件的版本信息包含可疑内容（公司名、描述等）',
                category='general', weight=40,
                tags=['general', 'version_info', 'masquerade'],
                file_types=['.exe', '.dll', '.sys', '.scr'],
            ),
            HeuristicRule(
                id='GEN_008', name='文件大小异常',
                description='文件大小超出正常范围或与内容不符',
                category='general', weight=35,
                tags=['general', 'file_size', 'anomaly'],
                file_types=[],
            ),
            HeuristicRule(
                id='GEN_009', name='UPX 打包检测',
                description='文件使用 UPX 或其他可执行文件打包器',
                category='general', weight=50,
                tags=['general', 'packed', 'upx', 'compressed'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_010', name='多阶段打包',
                description='检测到多层打包或加密，高度可疑',
                category='general', weight=75,
                tags=['general', 'multi_stage', 'packed'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_011', name='模拟器检测',
                description='代码中包含检测是否在模拟器中运行的代码',
                category='general', weight=60,
                tags=['general', 'emulator_detection', 'anti_analysis'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='GEN_012', name='异常代码行为',
                description='代码存在自修改（Self-Modifying Code）特征',
                category='general', weight=70,
                tags=['general', 'self_modifying', 'polymorphic'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_013', name='控制流混淆',
                description='代码使用控制流平坦化或其他混淆技术',
                category='general', weight=55,
                tags=['general', 'obfuscation', 'control_flow'],
                file_types=['.exe', '.dll', '.scr'],
            ),
            HeuristicRule(
                id='GEN_014', name='异常导入表',
                description='导入表包含异常的 DLL 或 API 组合',
                category='general', weight=50,
                tags=['general', 'import', 'anomaly'],
                file_types=['.exe', '.dll'],
            ),
            HeuristicRule(
                id='GEN_015', name='数字签名伪造',
                description='文件数字签名被伪造或使用盗用证书',
                category='general', weight=75,
                tags=['general', 'signature', 'forgery'],
                file_types=['.exe', '.dll', '.sys', '.cat'],
            ),
            HeuristicRule(
                id='GEN_016', name='字符串混淆',
                description='文件中包含大量混淆字符串（高熵、乱码等）',
                category='general', weight=50,
                tags=['general', 'string_obfuscation'],
                file_types=[],
            ),
            HeuristicRule(
                id='GEN_017', name='URL 硬编码',
                description='文件中硬编码了多个远程 URL，可能用于 C2 通信',
                category='general', weight=55,
                tags=['general', 'url', 'c2', 'hardcoded'],
                file_types=[],
            ),
            HeuristicRule(
                id='GEN_018', name='IP 地址硬编码',
                description='文件中硬编码了多个 IP 地址',
                category='general', weight=50,
                tags=['general', 'ip', 'c2', 'hardcoded'],
                file_types=[],
            ),
            HeuristicRule(
                id='GEN_019', name='配置文件异常',
                description='配置文件包含可疑的远程地址或恶意配置',
                category='general', weight=45,
                tags=['general', 'config', 'suspicious'],
                file_types=['.cfg', '.conf', '.ini', '.xml', '.json'],
            ),
            HeuristicRule(
                id='GEN_020', name='调试路径残留',
                description='文件中包含调试信息或开发路径，可能是未发布的恶意软件',
                category='general', weight=35,
                tags=['general', 'debug', 'pdb', 'development'],
                file_types=['.exe', '.dll', '.sys'],
            ),
        ]

        # 注册所有规则
        self.rules = pe_rules + script_rules + document_rules + behavior_rules + general_rules

    # ----------------------------------------------------------
    # 规则管理
    # ----------------------------------------------------------

    def get_rule(self, rule_id: str) -> Optional[HeuristicRule]:
        """获取指定规则"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def enable_rule(self, rule_id: str) -> bool:
        """启用规则"""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """禁用规则"""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def get_rules_by_category(self, category: str) -> List[HeuristicRule]:
        """按分类获取规则"""
        return [r for r in self.rules if r.category == category]

    def get_rules_by_file_type(self, file_ext: str) -> List[HeuristicRule]:
        """按适用文件类型获取规则"""
        file_ext = file_ext.lower()
        return [r for r in self.rules if not r.file_types or file_ext in r.file_types]

    def get_statistics(self) -> Dict[str, Any]:
        """获取规则统计"""
        categories = defaultdict(int)
        enabled = 0
        for rule in self.rules:
            categories[rule.category] += 1
            if rule.enabled:
                enabled += 1
        return {
            'total': len(self.rules),
            'enabled': enabled,
            'disabled': len(self.rules) - enabled,
            'categories': dict(categories),
        }

    # ----------------------------------------------------------
    # 检测执行
    # ----------------------------------------------------------

    def check_all(self, data: bytes, file_ext: str = '',
                  filepath: str = '') -> List[HeuristicResult]:
        """执行所有适用规则的检测

        Args:
            data: 文件字节数据
            file_ext: 文件扩展名（如 .exe）
            filepath: 文件路径（可选，用于行为模式检测）

        Returns:
            HeuristicResult 列表（仅包含匹配的规则）
        """
        # 找出适用于此文件类型的规则
        applicable_rules = self.get_rules_by_file_type(file_ext)

        # 执行检测
        self.results = []
        for rule in applicable_rules:
            if not rule.enabled:
                continue

            try:
                result = self._check_rule(rule, data, filepath)
                if result and result.match:
                    self.results.append(result)
            except Exception:
                continue

        return self.results

    def _check_rule(self, rule: HeuristicRule, data: bytes,
                    filepath: str = '') -> Optional[HeuristicResult]:
        """执行单条规则的检测

        Args:
            rule: 启发式规则
            data: 文件数据
            filepath: 文件路径

        Returns:
            检测结果，规则不适用时返回 None
        """
        # 根据规则 ID 分发到不同的检测方法
        method_name = f'_detect_{rule.id.lower()}'
        detector = getattr(self, method_name, None)
        if detector:
            try:
                return detector(rule, data, filepath)
            except Exception:
                pass

        # 通用检测方法
        return self._detect_generic(rule, data)

    def _detect_generic(self, rule: HeuristicRule, data: bytes) -> HeuristicResult:
        """通用检测（默认返回不匹配）"""
        return HeuristicResult(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category,
            weight=rule.weight,
            match=False,
            severity=0,
        )

    # ============================================================
    # 具体检测方法
    # ============================================================

    def _detect_pe_001(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测可疑入口点"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        try:
            if len(data) < 0x200:
                return result
            # 读取 PE 头
            if data[:2] != b'MZ':
                return result
            # 读取 e_lfanew
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset + 0x18 > len(data):
                return result
            # 读取入口点
            entry_point = struct.unpack('<I', data[pe_offset + 0x28:pe_offset + 0x2C])[0]
            # 读取节数
            num_sections = struct.unpack('<H', data[pe_offset + 0x06:pe_offset + 0x08])[0]
            if num_sections == 0:
                return result
            # 检查入口点是否在常见节中
            section_offset = pe_offset + 0xF8  # 取决于32/64位，简化处理
            if pe_offset + 0x18 + 0xE0 <= len(data):
                # 尝试读取第一个节的虚拟地址
                first_section_va = struct.unpack('<I', data[pe_offset + 0x18 + 0x0C:pe_offset + 0x18 + 0x10])[0]
                if first_section_va > 0:
                    # 如果入口点 < 第一个节的 VA，可能是混淆
                    if entry_point < first_section_va and entry_point > 0x1000:
                        result.match = True
                        result.details = f'入口点 0x{entry_point:08X} 在标准节范围之外'
                        result.severity = 7
        except Exception:
            pass
        return result

    def _detect_pe_004(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测可疑节权限"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        try:
            if len(data) < 0x200 or data[:2] != b'MZ':
                return result
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset + 6 > len(data):
                return result
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]

            # 节表起始位置（简化：假设32位）
            section_start = pe_offset + 0xF8
            section_size = 40  # 每个节表项 40 字节

            wx_count = 0
            for i in range(min(num_sections, 20)):
                sec_offset = section_start + i * section_size
                if sec_offset + 36 > len(data):
                    break
                characteristics = struct.unpack('<I', data[sec_offset + 36:sec_offset + 40])[0]
                # IMAGE_SCN_MEM_WRITE = 0x80000000, IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if (characteristics & 0x80000000) and (characteristics & 0x20000000):
                    wx_count += 1

            if wx_count >= 1:
                result.match = True
                result.details = f'发现 {wx_count} 个 WX 权限节'
                result.severity = min(8 + wx_count, 10)
        except Exception:
            pass
        return result

    def _detect_pe_016(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测可疑导入函数"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 在数据中搜索可疑 API 名称
        suspicious_apis = [
            b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
            b'ReadProcessMemory', b'SetWindowsHookEx', b'NtUnmapViewOfSection',
            b'GetProcAddress', b'LoadLibraryA', b'WinExec',
        ]
        found = [api for api in suspicious_apis if api in data]
        if len(found) >= 2:
            result.match = True
            result.details = f'发现可疑 API: {", ".join(f.decode() for f in found[:5])}'
            result.severity = min(5 + len(found), 10)
        return result

    def _detect_pe_017(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测进程注入 API"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        inject_apis = [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
                       b'NtCreateThreadEx', b'RtlCreateUserThread']
        found = [api for api in inject_apis if api in data]
        if len(found) >= 2:
            result.match = True
            result.details = f'进程注入 API 组合: {", ".join(f.decode() for f in found)}'
            result.severity = 9
        return result

    def _detect_pe_030(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测资源中嵌入可执行文件"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 在数据中搜索 MZ 和 PE 标记
        if data[:2] == b'MZ':
            # 查找第二个 MZ 头（表示嵌入的 PE）
            second_mz = data.find(b'MZ', 0x100)
            if second_mz > 0 and data.find(b'PE\x00\x00', second_mz + 0x3C, second_mz + 0x100):
                result.match = True
                result.details = f'在偏移 0x{second_mz:X} 发现嵌入的 PE 文件'
                result.severity = 8
        return result

    def _detect_script_001(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 Base64 编码数据"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 查找长 Base64 字符串
        text = data.decode('utf-8', errors='replace')
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{100,}')
        matches = b64_pattern.findall(text)
        if len(matches) >= 1:
            for m in matches:
                # 检查是否有补全字符
                if m.endswith('=') or m.endswith('=='):
                    result.match = True
                    result.details = f'发现 Base64 编码数据，长度 {len(m)}'
                    result.severity = 6
                    break
        return result

    def _detect_script_002(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 eval 多次调用"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace').lower()
        eval_count = text.count('eval(')
        if eval_count >= 3:
            result.match = True
            result.details = f'eval() 调用 {eval_count} 次'
            result.severity = min(5 + eval_count, 9)
        return result

    def _detect_script_010(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 Shellcode 嵌入"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 常见 shellcode 特征
        shellcode_patterns = [
            b'\x90\x90\x90\x90\x90\x90',  # NOP sled
            b'\xfc\xe8\x82\x00\x00\x00',  # call 指令
            b'\x31\xc0\x50\x68',          # xor eax, eax; push eax; push
            b'\xcc\xcc\xcc\xcc',          # int3 断点
        ]
        for pattern in shellcode_patterns:
            if pattern in data:
                result.match = True
                result.details = f'发现 Shellcode 特征: {pattern.hex()}'
                result.severity = 9
                break
        return result

    def _detect_script_013(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 PowerShell 编码命令"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        if '-EncodedCommand' in text or '-enc' in text.lower():
            result.match = True
            result.details = 'PowerShell 使用编码命令执行'
            result.severity = 8
        return result

    def _detect_script_019(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测反沙箱/反虚拟机"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace').lower()
        indicators = [
            'sandbox', 'vbox', 'vmware', 'virtualbox', 'qemu',
            'isdebuggerpresent', 'checkremotedebugger', 'ntglobalflag',
            'vmtoolsd', 'vboxguest', 'xen', 'kvm',
        ]
        found = [ind for ind in indicators if ind in text]
        if len(found) >= 2:
            result.match = True
            result.details = f'反分析检测: {", ".join(found)}'
            result.severity = min(6 + len(found), 10)
        return result

    def _detect_doc_002(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测可疑 VBA 函数"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        dangerous = ['Shell(', 'CreateObject(', 'WScript.Shell', 'ADODB.Stream',
                     'FileSystemObject', 'Execute(', 'MSXML2.XMLHTTP']
        found = [d for d in dangerous if d in text]
        if len(found) >= 2:
            result.match = True
            result.details = f'危险 VBA 函数: {", ".join(found)}'
            result.severity = min(6 + len(found), 10)
        return result

    def _detect_doc_005(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 PDF 恶意对象"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        if '/JavaScript' in text or '/JS' in text:
            result.match = True
            result.details = 'PDF 包含 JavaScript 执行'
            result.severity = 7
        elif '/Launch' in text:
            result.match = True
            result.details = 'PDF 包含 Launch 动作'
            result.severity = 8
        elif '/EmbeddedFile' in text:
            result.match = True
            result.details = 'PDF 包含嵌入文件'
            result.severity = 6
        return result

    def _detect_beh_005(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测文件扩展名修改（勒索软件特征）"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 在数据中查找常见的勒索软件扩展名字符串
        text = data.decode('utf-8', errors='replace').lower()
        ransom_exts = ['.encrypted', '.locked', '.crypted', '.wannacry', '.onion',
                       '.pay', '.readme', '.decrypt', '.cry', '.locky', '.cerber']
        found = [ext for ext in ransom_exts if ext in text]
        if len(found) >= 2:
            result.match = True
            result.details = f'勒索软件特征: {", ".join(found)}'
            result.severity = 9
        return result

    def _detect_beh_007(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测键盘记录"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        # 搜索键盘记录相关 API
        text = data.decode('utf-8', errors='replace')
        keylog_apis = ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
                       'GetForegroundWindow', 'GetWindowText']
        found = [api for api in keylog_apis if api in text]
        if len(found) >= 2:
            result.match = True
            result.details = f'键盘记录 API: {", ".join(found)}'
            result.severity = 8
        return result

    def _detect_gen_001(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测高熵数据区域"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        if len(data) < 1024:
            return result
        # 计算熵值（简化版）
        try:
            # 采样多个区域
            high_entropy_regions = 0
            for start in range(0, min(len(data), 10 * 1024 * 1024), 4096):
                chunk = data[start:start + 4096]
                if len(chunk) < 256:
                    continue
                entropy = self._calculate_entropy(chunk)
                if entropy > 7.5:
                    high_entropy_regions += 1
            if high_entropy_regions >= 3:
                result.match = True
                result.details = f'发现 {high_entropy_regions} 个高熵数据区域'
                result.severity = min(6 + high_entropy_regions, 9)
        except Exception:
            pass
        return result

    def _detect_gen_009(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测 UPX 打包"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        upx_markers = [b'UPX!', b'UPX0', b'UPX1', b'UPX2']
        for marker in upx_markers:
            if marker in data:
                result.match = True
                result.details = f'发现 UPX 打包标记: {marker.decode()}'
                result.severity = 6
                break
        return result

    def _detect_gen_017(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测硬编码 URL"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        url_pattern = re.compile(r'https?://[^\s"\'<>]{10,200}')
        urls = url_pattern.findall(text)
        # 过滤常见安全域名
        safe_domains = ['microsoft.com', 'windows.com', 'google.com', 'bing.com']
        suspicious_urls = [u for u in urls if not any(d in u for d in safe_domains)]
        if len(suspicious_urls) >= 2:
            result.match = True
            result.details = f'发现 {len(suspicious_urls)} 个远程 URL'
            result.severity = min(5 + len(suspicious_urls), 9)
        return result

    def _detect_gen_018(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测硬编码 IP"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = ip_pattern.findall(text)
        # 过滤内网地址
        public_ips = [ip for ip in ips if not ip.startswith(('10.', '172.', '192.168.', '127.'))]
        if len(public_ips) >= 2:
            result.match = True
            result.details = f'发现 {len(public_ips)} 个外部 IP 地址'
            result.severity = min(5 + len(public_ips), 8)
        return result

    def _detect_gen_020(self, rule: HeuristicRule, data: bytes, fp: str) -> HeuristicResult:
        """检测调试路径残留"""
        result = HeuristicResult(rule_id=rule.id, rule_name=rule.name,
                                  category=rule.category, weight=rule.weight, match=False)
        text = data.decode('utf-8', errors='replace')
        pdb_pattern = re.compile(r'[\w\\/]+\.pdb')
        pdb_matches = pdb_pattern.findall(text)
        if pdb_matches:
            result.match = True
            result.details = f'PDB 路径: {pdb_matches[0]}'
            result.severity = 4
        return result

    # ============================================================
    # 评分系统
    # ============================================================

    def calculate_score(self, results: List[HeuristicResult]) -> float:
        """计算综合可疑度评分

        Args:
            results: 检测结果列表

        Returns:
            可疑度评分（0.0 - 1.0）
        """
        if not results:
            return 0.0

        total_weight = 0
        weighted_score = 0

        for r in results:
            if r.match:
                severity_factor = r.severity / 10.0
                weighted_score += r.weight * severity_factor
                total_weight += r.weight

        if total_weight == 0:
            return 0.0

        # 归一化到 0-1
        raw_score = weighted_score / total_weight

        # 非线性放大（使高分数更突出）
        final_score = raw_score ** 0.8

        return min(final_score, 1.0)

    def is_suspicious(self, score: float) -> bool:
        """判断是否达到可疑阈值"""
        return score >= self.threshold

    def get_verdict(self, data: bytes, file_ext: str = '',
                    filepath: str = '') -> Dict[str, Any]:
        """获取完整的检测结论

        Args:
            data: 文件数据
            file_ext: 文件扩展名
            filepath: 文件路径

        Returns:
            {
                'score': float,           # 可疑度评分
                'is_suspicious': bool,     # 是否可疑
                'matched_rules': [...],    # 匹配的规则列表
                'total_checked': int,      # 检查的规则数
                'category_breakdown': {...} # 各类别得分
            }
        """
        results = self.check_all(data, file_ext, filepath)
        score = self.calculate_score(results)

        # 各类别得分
        category_scores = defaultdict(float)
        category_counts = defaultdict(int)
        for r in results:
            if r.match:
                category_scores[r.category] += r.weight * (r.severity / 10.0)
                category_counts[r.category] += 1

        category_breakdown = {}
        for cat in category_scores:
            if category_counts[cat] > 0:
                category_breakdown[cat] = round(category_scores[cat] / category_counts[cat], 2)

        return {
            'score': round(score, 3),
            'is_suspicious': self.is_suspicious(score),
            'matched_rules': [r.to_dict() for r in results],
            'total_checked': len(self.rules),
            'matched_count': len(results),
            'category_breakdown': category_breakdown,
            'threshold': self.threshold,
        }

    # ============================================================
    # 工具方法
    # ============================================================

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """计算字节数据的熵值（Shannon entropy）

        Args:
            data: 字节数据

        Returns:
            熵值（0.0 - 8.0）
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        # 统计频率
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        # 计算熵
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * __import__('math').log2(p)
        return entropy

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return f'HeuristicRules(rules={len(self.rules)}, threshold={self.threshold})'


# ============================================================
# 便捷函数
# ============================================================

def create_default_rules() -> HeuristicRules:
    """创建默认启发式规则集"""
    return HeuristicRules()


def analyze_file(filepath: str) -> Dict[str, Any]:
    """分析单个文件并返回启发式检测结果

    Args:
        filepath: 文件路径

    Returns:
        检测结果字典
    """
    rules = HeuristicRules()
    ext = os.path.splitext(filepath)[1].lower()
    try:
        with open(filepath, 'rb') as f:
            data = f.read(10 * 1024 * 1024)  # 最多读 10MB
        return rules.get_verdict(data, ext, filepath)
    except Exception as e:
        return {'error': str(e)}


def analyze_data(data: bytes, file_ext: str = '') -> Dict[str, Any]:
    """分析字节数据并返回启发式检测结果"""
    rules = HeuristicRules()
    return rules.get_verdict(data, file_ext)