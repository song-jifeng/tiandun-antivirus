#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 文档文件启发式分析器
分析 Office 文档 (OLE2/OOXML)、PDF文档，检测宏代码和可疑嵌入式对象
实现 20+ 检测规则
"""

import os
import re
import struct
import zlib
from typing import Tuple, List, Dict, Optional, Any


# ============================================================
# OLE2 签名
# ============================================================
OLE2_SIGNATURE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
PDF_SIGNATURE = b'%PDF-'

# OLE2 流名称
OLE2_STREAMS_MACRO = [
    'Macros', 'VBA', 'VBAPROJECT', 'PROJECT',
    'MODULE', 'CLASS', 'FORM', 'STREAM',
    'ThisDocument', 'ThisWorkbook', 'ThisPresentation',
    'Sheet1', 'Sheet2', 'Sheet3',
    'Module1', 'Module2', 'Module3',
    'UserForm1', 'UserForm2', 'UserForm3',
    'Class1', 'Class2', 'Class3',
    '_VBA_PROJECT', 'dir',
]

# VBA 恶意关键词
VBA_SUSPICIOUS_KEYWORDS = [
    b'AutoOpen', b'AutoExec', b'AutoClose', b'AutoExit',
    b'Document_Open', b'Document_Close', b'Document_BeforeClose',
    b'Workbook_Open', b'Workbook_BeforeClose', b'Workbook_Activate',
    b'Worksheet_Activate', b'Worksheet_Change', b'Worksheet_SelectionChange',
    b'Presentation_Open', b'Presentation_Close', b'Presentation_SlideShowBegin',
    b'SlideShowBegin', b'SlideShowEnd',
    b'Private Sub', b'Public Sub', b'Function ',
    b'Call Shell', b'Shell(', b'CreateObject',
    b'WScript.Shell', b'WScript', b'Scripting.FileSystemObject',
    b'Shell.Application', b'MSXML2', b'MSXML2.XMLHTTP',
    b'WinHttp', b'WinHttp.WinHttpRequest',
    b'URLDownloadToFile', b'URLDownloadToFileA', b'URLDownloadToFileW',
    b'WriteProcessMemory', b'VirtualAlloc', b'VirtualAllocEx',
    b'CreateThread', b'CreateRemoteThread',
    b'kernel32', b'kernel32.dll', b'ntdll', b'ntdll.dll', b'user32',
    b'Declare PtrSafe', b'Declare Function',
    b'RtlMoveMemory', b'CopyMemory',
    b'GetProcAddress', b'LoadLibrary', b'LoadLibraryA',
    b'Embed', b'Embedded', b'Package',
    b'ActiveX', b'ActiveXObject',
    b'ExecuteExcel4Macro', b'ExecuteExcel4Macro',
    b'RegOpenKey', b'RegSetValue', b'RegCreateKey',
    b'FileSystemObject', b'GetSpecialFolder',
    b'OpenTextFile', b'CreateTextFile', b'WriteLine',
    b'ReadAll', b'ReadTextFile',
    b'XMLHTTP', b'ServerXMLHTTP',
    b'ADODB.Stream', b'ADODB',
    b'InternetExplorer', b'InternetExplorer.Application',
    b'Outlook', b'Outlook.Application',
    b'Word.Application', b'Excel.Application',
    b'PowerPoint.Application', b'Access.Application',
    b'MSComctlLib', b'Comctl32',
    b'Environment(', b'Environ(',
    b'Chr(', b'ChrW(', b'Asc(',
    b'StrReverse', b'Replace(', b'Mid(',
    b'InStrRev', b'InStr(',
    b'Len(', b'Split(', b'Join(',
    b'PtrSafe', b'AddressOf',
    b'crypt', b'encrypt', b'decrypt',
    b'DeleteSetting', b'SaveSetting',
    b'GetSetting', b'GetAllSettings',
    b'Kill ', b'RmDir ', b'MkDir ',
    b'FileCopy', b'Name ', b'SetAttr',
    b'GetAttr', b'FileLen', b'FileDateTime',
    b'FileExists', b'FolderExists',
    b'DriveExists', b'RootFolder',
    b'Windows_', b'ActiveX', b'Class_Initialize',
    b'UserForm_Initialize', b'UserForm_Activate',
    b'cmd.exe', b'powershell', b'powershell.exe',
    b'rundll32', b'rundll32.exe',
    b'regsvr32', b'regsvr32.exe',
    b'mshta', b'mshta.exe',
    b'cscript', b'wscript',
    b'bitsadmin', b'certutil',
    b'curl', b'wget',
    b'http://', b'https://',
    b'\\\\', b'\\\\(',  # UNC路径
    b'WinHttp.WinHttpRequest', b'WinHttpRequest',
    b'XMLHttpRequest', b'MSXML2.ServerXMLHTTP',
    b'WriteProcessMemory', b'ReadProcessMemory',
    b'VirtualProtect', b'VirtualProtectEx',
    b'QueueUserAPC', b'SetWindowsHookEx',
    b'GetAsyncKeyState', b'GetForegroundWindow',
    b'GetKeyboardState', b'GetKeyState',
    b'MapVirtualKey', b'ToAscii',
    b'Clipboard', b'GetClipboardData', b'SetClipboardData',
    b'SendKeys', b'AppActivate',
    b'FindWindow', b'FindWindowEx',
    b'GetWindowText', b'EnumWindows',
    b'ShellExecute', b'ShellExecuteA',
    b'OpenProcess', b'TerminateProcess',
    b'CreateProcess', b'CreateProcessA',
    b'WinExec', b'WinExec',
]

# PDF 可疑关键词
PDF_SUSPICIOUS_KEYWORDS = [
    b'/JavaScript', b'/JS',
    b'/OpenAction', b'/AA',
    b'/Launch', b'/EmbeddedFile', b'/EmbeddedFiles',
    b'/URI', b'/AcroForm', b'/RichMedia',
    b'/ObjStm', b'/XObject',
    b'/Annots', b'/Action',
    b'/GoTo', b'/GoToR',
    b'/SubmitForm', b'/ImportData',
    b'/Import', b'/Export',
    b'/Named', b'/NamedAction',
    b'/Sound', b'/Movie',
    b'/Hide', b'/Show',
    b'/SubmitForm', b'/ResetForm',
    b'/MailDoc', b'/MailMsg',
    b'/Media', b'/Rendition',
    b'/Thread', b'/ThreadAction',
    b'/Win', b'/DOS',
    b'/App', b'/Application',
    b'/Cmd', b'/Command',
    b'/Exec', b'/Execute',
    b'/Spider', b'/SpiderMonkey',
    b'/Flash', b'/FlashPlayer',
    b'/PDFLib', b'/pdfe',
    b'/ObjStm', b'/Filter',
    b'/FlateDecode', b'/ASCIIHexDecode',
    b'/ASCII85Decode', b'/LZWDecode',
    b'/RunLengthDecode', b'/CCITTFaxDecode',
    b'/JBIG2Decode', b'/DCTDecode',
    b'/Crypt', b'/Encrypt',
    b'/XFA', b'/XDP',
    b'/NeedAppearances',
    b'/SigFlags', b'/Lock',
    b'/TransformParams', b'/TransformMethod',
    b'/DocMDP', b'/UR',
    b'/UR3', b'/DRM',
    b'/Identity', b'/DefaultCryptFilter',
]


class DocAnalyzer:
    """
    文档文件分析器

    分析 Office 文档 (OLE2/OOXML) 和 PDF 文档：
    - 检测宏代码
    - 分析嵌入式对象
    - 检测可疑的自动执行动作
    - 20+ 检测规则
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def analyze(self, filepath: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        分析文档文件

        Args:
            filepath: 文件路径

        Returns:
            (风险分数0-100, 检测原因列表, 详细分析数据)
        """
        score = 0.0
        reasons = []
        details = {}
        ext = os.path.splitext(filepath)[1].lower()

        try:
            with open(filepath, 'rb') as f:
                header = f.read(8)

            # 检测OLE2 Office文档
            if header[:8] == OLE2_SIGNATURE:
                s, r, d = self._analyze_ole2(filepath)
                score += s
                reasons.extend(r)
                details['format'] = 'OLE2'
                details['ole2'] = d
            elif ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm',
                         '.dotx', '.dotm', '.xltx', '.xltm', '.potx', '.potm'):
                s, r, d = self._analyze_ooxml(filepath)
                score += s
                reasons.extend(r)
                details['format'] = 'OOXML'
                details['ooxml'] = d
            elif header[:5] == PDF_SIGNATURE:
                s, r, d = self._analyze_pdf(filepath)
                score += s
                reasons.extend(r)
                details['format'] = 'PDF'
                details['pdf'] = d
            elif ext in ('.rtf',):
                s, r, d = self._analyze_rtf(filepath)
                score += s
                reasons.extend(r)
                details['format'] = 'RTF'
                details['rtf'] = d

        except Exception as e:
            score += 5
            reasons.append(f'文档分析异常: {str(e)}')
            details['error'] = str(e)

        score = min(score, 100.0)
        return score, reasons, details

    # ============================================================
    # OLE2 文档分析
    # ============================================================

    def _analyze_ole2(self, filepath: str) -> Tuple[float, List[str], Dict]:
        """分析OLE2文档 (doc, xls, ppt, docm, xlsm, pptm)"""
        score = 0.0
        reasons = []
        data = {}

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # ============================================================
            # 规则 1: 检测VBA宏关键词
            # ============================================================
            found_keywords = []
            for kw in VBA_SUSPICIOUS_KEYWORDS:
                if kw in content:
                    found_keywords.append(kw.decode('ascii', errors='replace'))

            if found_keywords:
                score += 3 * min(len(found_keywords), 6)
                reasons.append(f'规则1: 检测到{len(found_keywords)}个VBA宏关键词')
                data['vba_keywords'] = found_keywords[:15]

            # ============================================================
            # 规则 2: 检测自动执行宏
            # ============================================================
            auto_macros = []
            for kw in [b'AutoOpen', b'AutoExec', b'AutoClose', b'AutoExit',
                       b'Document_Open', b'Workbook_Open', b'Presentation_Open',
                       b'SlideShowBegin', b'Worksheet_Activate']:
                if kw in content:
                    auto_macros.append(kw.decode('ascii'))

            if auto_macros:
                score += 10
                reasons.append(f'规则2: 检测到自动执行宏: {", ".join(auto_macros)}')
                data['auto_macros'] = auto_macros

            # ============================================================
            # 规则 3: 检测Shell执行
            # ============================================================
            if b'Shell(' in content or b'Call Shell' in content:
                score += 10
                reasons.append('规则3: 检测到Shell执行')
                data['shell_exec'] = True

            # ============================================================
            # 规则 4: 检测CreateObject
            # ============================================================
            create_objects = re.findall(rb'CreateObject\s*\([^)]+\)', content)
            if create_objects:
                score += 5 * min(len(create_objects), 4)
                obj_names = [obj.decode('ascii', errors='replace') for obj in create_objects[:5]]
                reasons.append(f'规则4: 检测到{len(create_objects)}个CreateObject')
                data['create_objects'] = obj_names

            # ============================================================
            # 规则 5: 检测嵌入式OLE对象
            # ============================================================
            ole_object_pattern = b'\x01\x05\x00\x00\x02'
            if ole_object_pattern in content:
                score += 10
                reasons.append('规则5: 检测到嵌入式OLE对象')
                data['ole_objects'] = True

            # ============================================================
            # 规则 6: 检测WMI操作
            # ============================================================
            if b'GetObject("winmgmts:' in content or b'SWbemLocator' in content:
                score += 8
                reasons.append('规则6: 检测到WMI操作')
                data['wmi_op'] = True

            # ============================================================
            # 规则 7: 检测网络请求
            # ============================================================
            network_patterns = [
                (b'MSXML2.XMLHTTP', 'XMLHTTP'),
                (b'WinHttp.WinHttpRequest', 'WinHttp'),
                (b'URLDownloadToFile', 'URLDownloadToFile'),
                (b'InternetExplorer.Application', 'InternetExplorer'),
                (b'http://', 'HTTP URL'),
                (b'https://', 'HTTPS URL'),
            ]
            found_network = []
            for pattern, name in network_patterns:
                if pattern in content:
                    found_network.append(name)
            if found_network:
                score += 8
                reasons.append(f'规则7: 检测到网络请求: {", ".join(found_network)}')
                data['network'] = found_network

            # ============================================================
            # 规则 8: 检测文件操作
            # ============================================================
            file_ops = []
            if b'FileSystemObject' in content:
                file_ops.append('FileSystemObject')
            if b'OpenTextFile' in content or b'CreateTextFile' in content:
                file_ops.append('文本文件操作')
            if b'WriteLine' in content or b'ReadAll' in content:
                file_ops.append('文件读写')
            if b'GetSpecialFolder' in content:
                file_ops.append('系统文件夹')
            if b'Kill ' in content or b'RmDir ' in content or b'MkDir ' in content:
                file_ops.append('文件/目录操作')

            if file_ops:
                score += 5
                reasons.append(f'规则8: 检测到文件操作: {", ".join(file_ops)}')
                data['file_ops'] = file_ops

            # ============================================================
            # 规则 9: 检测进程/内存操作
            # ============================================================
            memory_ops = []
            if b'VirtualAlloc' in content:
                memory_ops.append('VirtualAlloc')
            if b'CreateThread' in content:
                memory_ops.append('CreateThread')
            if b'WriteProcessMemory' in content:
                memory_ops.append('WriteProcessMemory')
            if b'RtlMoveMemory' in content or b'CopyMemory' in content:
                memory_ops.append('内存复制')
            if b'GetProcAddress' in content:
                memory_ops.append('GetProcAddress')
            if b'LoadLibrary' in content:
                memory_ops.append('LoadLibrary')
            if b'CreateRemoteThread' in content:
                memory_ops.append('CreateRemoteThread')
            if b'SetWindowsHookEx' in content:
                memory_ops.append('SetWindowsHookEx')

            if memory_ops:
                score += 12
                reasons.append(f'规则9: 检测到内存/进程操作: {", ".join(memory_ops)}')
                data['memory_ops'] = memory_ops

            # ============================================================
            # 规则 10: 检测注册表操作
            # ============================================================
            reg_ops = []
            if b'RegOpenKey' in content:
                reg_ops.append('RegOpenKey')
            if b'RegSetValue' in content:
                reg_ops.append('RegSetValue')
            if b'RegCreateKey' in content:
                reg_ops.append('RegCreateKey')
            if b'DeleteSetting' in content or b'SaveSetting' in content:
                reg_ops.append('注册表设置')

            if reg_ops:
                score += 5
                reasons.append(f'规则10: 检测到注册表操作: {", ".join(reg_ops)}')
                data['registry'] = reg_ops

            # ============================================================
            # 规则 11: 检测系统命令执行
            # ============================================================
            cmd_patterns = [
                (b'cmd.exe', 'cmd.exe'),
                (b'powershell', 'PowerShell'),
                (b'rundll32', 'rundll32'),
                (b'regsvr32', 'regsvr32'),
                (b'mshta', 'mshta'),
                (b'cscript', 'cscript'),
                (b'wscript', 'wscript'),
                (b'bitsadmin', 'bitsadmin'),
                (b'certutil', 'certutil'),
                (b'curl', 'curl'),
                (b'wget', 'wget'),
            ]
            found_cmds = []
            for pattern, name in cmd_patterns:
                if pattern in content:
                    found_cmds.append(name)

            if found_cmds:
                score += 8
                reasons.append(f'规则11: 检测到系统命令: {", ".join(found_cmds)}')
                data['system_commands'] = found_cmds

            # ============================================================
            # 规则 12: 检测加密/编码
            # ============================================================
            if b'Chr(' in content or b'ChrW(' in content:
                chr_count = len(re.findall(rb'Chr[W]?\(', content))
                if chr_count > 10:
                    score += 5
                    reasons.append(f'规则12: 大量Chr函数调用 ({chr_count}次)')
                    data['chr_obfuscation'] = chr_count

            if b'StrReverse' in content:
                score += 3
                reasons.append('规则12: 检测到字符串反转')
                data['str_reverse'] = True

            # ============================================================
            # 规则 13: 检测混淆
            # ============================================================
            if b'Xor' in content or b'And ' in content or b'Or ' in content:
                xor_count = len(re.findall(rb'\bXor\b|\bAnd\b|\bOr\b', content, re.IGNORECASE))
                if xor_count > 20:
                    score += 5
                    reasons.append(f'规则13: 检测到大量位运算混淆 ({xor_count}次)')
                    data['xor_obfuscation'] = xor_count

            # ============================================================
            # 规则 14: 检测编码/解码
            # ============================================================
            if b'Decode' in content or b'Encode' in content:
                score += 5
                reasons.append('规则14: 检测到编码/解码操作')
                data['encode_decode'] = True

            # ============================================================
            # 规则 15: 检测Excel 4.0宏
            # ============================================================
            if b'ExecuteExcel4Macro' in content:
                score += 8
                reasons.append('规则15: 检测到Excel 4.0宏')
                data['excel4_macro'] = True

            # ============================================================
            # 规则 16: 检测键盘记录
            # ============================================================
            keylog_patterns = [
                b'GetAsyncKeyState', b'GetForegroundWindow',
                b'GetKeyboardState', b'GetKeyState',
                b'MapVirtualKey', b'ToAscii',
                b'SetWindowsHookEx',
            ]
            found_keylog = [p.decode('ascii') for p in keylog_patterns if p in content]
            if found_keylog:
                score += 10
                reasons.append(f'规则16: 检测到键盘记录: {", ".join(found_keylog)}')
                data['keylogger'] = found_keylog

            # ============================================================
            # 规则 17: 检测剪贴板操作
            # ============================================================
            if b'Clipboard' in content or b'GetClipboardData' in content:
                score += 5
                reasons.append('规则17: 检测到剪贴板操作')
                data['clipboard'] = True

            # ============================================================
            # 规则 18: 检测VBA project加密
            # ============================================================
            if b'DPB' in content or b'DPx' in content or b'GC' in content:
                score += 5
                reasons.append('规则18: 检测到VBA项目加密')
                data['vba_encrypted'] = True

            # ============================================================
            # 规则 19: 检测VBA stomping（VBA版本不匹配）
            # ============================================================
            # 检查是否存在多个VBA版本
            perf_locations = [m.start() for m in re.finditer(rb'Performance', content)]
            if len(perf_locations) > 1:
                score += 5
                reasons.append('规则19: 检测到VBA Stomping可能')
                data['vba_stomping'] = True

            # ============================================================
            # 规则 20: 检测公式注入
            # ============================================================
            if b'=HYPERLINK' in content or b'=DDE' in content or b'=MSE' in content:
                score += 8
                reasons.append('规则20: 检测到公式注入')
                data['formula_injection'] = True

            # ============================================================
            # 规则 21: 检测动态数据交换(DDE)
            # ============================================================
            if b'DDE' in content or b'DDEAUTO' in content:
                score += 8
                reasons.append('规则21: 检测到DDE字段')
                data['dde'] = True

            # ============================================================
            # 规则 22: 检测外部链接
            # ============================================================
            if b'\\server\\' in content or b'\\\\' in content:
                score += 5
                reasons.append('规则22: 检测到UNC路径')
                data['unc_path'] = True

            # ============================================================
            # 规则 23: 检测ActiveX
            # ============================================================
            if b'ActiveX' in content or b'ActiveXObject' in content:
                score += 5
                reasons.append('规则23: 检测到ActiveX控件')
                data['activex'] = True

            # ============================================================
            # 规则 24: 检测Outlook
            # ============================================================
            if b'Outlook.Application' in content or b'Outlook' in content:
                score += 5
                reasons.append('规则24: 检测到Outlook操作')
                data['outlook'] = True

            # ============================================================
            # 规则 25: 检测Word/Excel/PowerPoint Application
            # ============================================================
            app_patterns = [
                (b'Word.Application', 'Word'),
                (b'Excel.Application', 'Excel'),
                (b'PowerPoint.Application', 'PowerPoint'),
                (b'Access.Application', 'Access'),
            ]
            found_apps = [name for pattern, name in app_patterns if pattern in content]
            if found_apps:
                score += 5
                reasons.append(f'规则25: 检测到Office应用调用: {", ".join(found_apps)}')
                data['office_apps'] = found_apps

        except Exception as e:
            score += 5
            reasons.append(f'OLE2分析异常: {str(e)}')
            data['error'] = str(e)

        return min(score, 60.0), reasons, data

    # ============================================================
    # OOXML 文档分析
    # ============================================================

    def _analyze_ooxml(self, filepath: str) -> Tuple[float, List[str], Dict]:
        """分析OOXML文档 (docx, xlsx, pptx, docm, xlsm, pptm)"""
        score = 0.0
        reasons = []
        data = {}

        try:
            import zipfile
            with zipfile.ZipFile(filepath, 'r') as z:
                names = z.namelist()
                data['files'] = names

                # ============================================================
                # 规则 26: 检测VBA宏
                # ============================================================
                vba_files = [n for n in names if 'vba' in n.lower() or 'macro' in n.lower()]
                if vba_files:
                    score += 10
                    reasons.append(f'规则26: 检测到VBA宏文件: {len(vba_files)}个')
                    data['vba_files'] = vba_files[:5]

                # ============================================================
                # 规则 27: 检测外部引用
                # ============================================================
                external_refs = []
                for name in names:
                    if name.endswith('.xml') or name.endswith('.rels'):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')
                            if 'External' in content and 'Target' in content:
                                # 提取URL
                                urls = re.findall(r'Target="([^"]+)"', content)
                                for url in urls:
                                    if url.startswith('http://') or url.startswith('https://') or url.startswith('\\\\'):
                                        external_refs.append(url)
                        except Exception:
                            pass

                if external_refs:
                    score += 8
                    reasons.append(f'规则27: 检测到外部引用: {len(external_refs)}个')
                    data['external_refs'] = external_refs[:5]

                # ============================================================
                # 规则 28: 检测嵌入式对象
                # ============================================================
                embedded = [n for n in names if 'embeddings' in n.lower() or 'ole' in n.lower()]
                if embedded:
                    score += 8
                    reasons.append(f'规则28: 检测到嵌入式对象: {len(embedded)}个')
                    data['embedded'] = embedded[:5]

                # ============================================================
                # 规则 29: 检测ActiveX
                # ============================================================
                activex = [n for n in names if 'activex' in n.lower() or 'control' in n.lower()]
                if activex:
                    score += 5
                    reasons.append(f'规则29: 检测到ActiveX控件: {len(activex)}个')
                    data['activex'] = activex[:5]

                # ============================================================
                # 规则 30: 检测外部链接（Excel）
                # ============================================================
                ext_links = [n for n in names if 'externallink' in n.lower() or 'externalLink' in n]
                if ext_links:
                    score += 8
                    reasons.append(f'规则30: 检测到外部链接: {len(ext_links)}个')
                    data['external_links'] = ext_links[:5]

                # ============================================================
                # 规则 31: 检测自定义XML
                # ============================================================
                custom_xml = [n for n in names if 'customxml' in n.lower() or 'customXml' in n]
                if custom_xml:
                    score += 3
                    reasons.append('规则31: 检测到自定义XML')
                    data['custom_xml'] = custom_xml[:3]

                # ============================================================
                # 规则 32: 检测模板注入
                # ============================================================
                template_refs = []
                for name in names:
                    if name.endswith('.xml') or name.endswith('.rels'):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')
                            # 检测模板引用
                            if 'TargetMode="External"' in content and '.dot' in content:
                                template_refs.append(name)
                        except Exception:
                            pass

                if template_refs:
                    score += 5
                    reasons.append(f'规则32: 检测到模板引用: {len(template_refs)}个')
                    data['template_refs'] = template_refs[:3]

                # ============================================================
                # 规则 33: 检测宏启用标志
                # ============================================================
                for name in names:
                    if name.endswith('.xml') and 'vbaProject' in z.read(name).decode('utf-8', errors='replace'):
                        score += 5
                        reasons.append('规则33: 检测到VBA项目启用')
                        data['vba_enabled'] = True
                        break

        except Exception as e:
            score += 5
            reasons.append(f'OOXML分析异常: {str(e)}')
            data['error'] = str(e)

        return min(score, 45.0), reasons, data

    # ============================================================
    # PDF 文档分析
    # ============================================================

    def _analyze_pdf(self, filepath: str) -> Tuple[float, List[str], Dict]:
        """分析PDF文档"""
        score = 0.0
        reasons = []
        data = {}

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            content_lower = content.lower()

            # ============================================================
            # 规则 34: 检测JavaScript
            # ============================================================
            if b'/JavaScript' in content or b'/JS' in content:
                score += 10
                reasons.append('规则34: 检测到PDF JavaScript')
                data['javascript'] = True

            # ============================================================
            # 规则 35: 检测自动执行动作
            # ============================================================
            if b'/OpenAction' in content:
                score += 10
                reasons.append('规则35: 检测到自动执行动作')
                data['open_action'] = True

            # ============================================================
            # 规则 36: 检测附加动作
            # ============================================================
            if b'/AA' in content:
                # 进一步检查哪些动作
                aa_patterns = {
                    b'/O': '页面打开',
                    b'/C': '页面关闭',
                    b'/D': '书签跳转',
                    b'/E': '鼠标进入',
                    b'/X': '鼠标离开',
                    b'/Fo': '获得焦点',
                    b'/Bl': '失去焦点',
                    b'/PV': '页面可见',
                    b'/PI': '页面不可见',
                }
                found_aa = []
                for key, desc in aa_patterns.items():
                    idx = content.find(b'/AA')
                    if idx >= 0:
                        nearby = content[idx:idx+200]
                        if key in nearby:
                            found_aa.append(desc)

                if found_aa:
                    score += 8
                    reasons.append(f'规则36: 检测到附加动作: {", ".join(found_aa)}')
                    data['additional_actions'] = found_aa

            # ============================================================
            # 规则 37: 检测嵌入式文件
            # ============================================================
            if b'/EmbeddedFile' in content or b'/EmbeddedFiles' in content:
                score += 8
                reasons.append('规则37: 检测到嵌入式文件')
                data['embedded_file'] = True

            # ============================================================
            # 规则 38: 检测启动动作
            # ============================================================
            if b'/Launch' in content:
                score += 10
                reasons.append('规则38: 检测到启动动作')
                data['launch_action'] = True

            # ============================================================
            # 规则 39: 检测URI操作
            # ============================================================
            if b'/URI' in content:
                score += 3
                reasons.append('规则39: 检测到URI链接')
                data['uri'] = True

            # ============================================================
            # 规则 40: 检测表单
            # ============================================================
            if b'/AcroForm' in content:
                score += 3
                reasons.append('规则40: 检测到交互表单')
                data['acro_form'] = True

            # ============================================================
            # 规则 41: 检测RichMedia (Flash)
            # ============================================================
            if b'/RichMedia' in content:
                score += 8
                reasons.append('规则41: 检测到RichMedia (Flash)')
                data['rich_media'] = True

            # ============================================================
            # 规则 42: 检测对象流
            # ============================================================
            if b'/ObjStm' in content:
                score += 5
                reasons.append('规则42: 检测到对象流')
                data['obj_stm'] = True

            # ============================================================
            # 规则 43: 检测提交表单
            # ============================================================
            if b'/SubmitForm' in content:
                score += 8
                reasons.append('规则43: 检测到表单提交')
                data['submit_form'] = True

            # ============================================================
            # 规则 44: 检测导入数据
            # ============================================================
            if b'/ImportData' in content:
                score += 8
                reasons.append('规则44: 检测到数据导入')
                data['import_data'] = True

            # ============================================================
            # 规则 45: 检测XFA表单
            # ============================================================
            if b'/XFA' in content:
                score += 5
                reasons.append('规则45: 检测到XFA表单')
                data['xfa'] = True

            # ============================================================
            # 规则 46: 检测URI跳转
            # ============================================================
            if b'/GoToR' in content:
                score += 5
                reasons.append('规则46: 检测到远程跳转')
                data['goto_remote'] = True

            # ============================================================
            # 规则 47: 检测邮件操作
            # ============================================================
            if b'/MailDoc' in content or b'/MailMsg' in content:
                score += 8
                reasons.append('规则47: 检测到邮件操作')
                data['mail_action'] = True

            # ============================================================
            # 规则 48: 检测声音/视频
            # ============================================================
            if b'/Sound' in content or b'/Movie' in content:
                score += 3
                reasons.append('规则48: 检测到多媒体')
                data['multimedia'] = True

            # ============================================================
            # 规则 49: 检测过滤器
            # ============================================================
            filters = []
            for f in [b'/FlateDecode', b'/ASCIIHexDecode', b'/ASCII85Decode',
                      b'/LZWDecode', b'/RunLengthDecode', b'/CCITTFaxDecode',
                      b'/JBIG2Decode', b'/DCTDecode']:
                if f in content:
                    filters.append(f.decode('ascii'))
            if len(filters) > 3:
                score += 3
                reasons.append(f'规则49: 检测到多种过滤器')
                data['filters'] = filters

            # ============================================================
            # 规则 50: 检测加密
            # ============================================================
            if b'/Encrypt' in content or b'/Crypt' in content:
                score += 3
                reasons.append('规则50: 检测到PDF加密')
                data['encrypt'] = True

            # ============================================================
            # 规则 51: 检测恶意JS关键词
            # ============================================================
            if b'/JavaScript' in content:
                # 提取JS内容
                js_pattern = re.compile(rb'/JavaScript\s*<<[^>]*>>\s*stream\s*(.*?)\s*endstream', re.DOTALL)
                js_matches = js_pattern.findall(content)
                for js in js_matches:
                    try:
                        # 尝试解码
                        decoded = zlib.decompress(js)
                        js_content = decoded.decode('utf-8', errors='replace').lower()
                        # 检测漏洞利用代码
                        exploit_indicators = [
                            'heap', 'spray', 'shellcode', 'nop', 'uaf',
                            'use after free', 'type confusion', 'buffer overflow',
                            'integer overflow', 'rop', 'ret2libc',
                            'addrof', 'fakeobj', 'jmp esp', 'call eax',
                            'payload', 'exploit', 'addressof',
                        ]
                        for indicator in exploit_indicators:
                            if indicator in js_content:
                                score += 10
                                reasons.append(f'规则51: PDF JS包含漏洞利用指示: {indicator}')
                                data['js_exploit'] = indicator
                                break
                    except Exception:
                        pass

        except Exception as e:
            score += 5
            reasons.append(f'PDF分析异常: {str(e)}')
            data['error'] = str(e)

        return min(score, 50.0), reasons, data

    # ============================================================
    # RTF 文档分析
    # ============================================================

    def _analyze_rtf(self, filepath: str) -> Tuple[float, List[str], Dict]:
        """分析RTF文档"""
        score = 0.0
        reasons = []
        data = {}

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # ============================================================
            # 规则 52: 检测嵌入式OLE对象
            # ============================================================
            # RTF中的OLE对象以{\object开头
            if b'\\object' in content:
                score += 8
                reasons.append('规则52: 检测到嵌入式OLE对象')
                data['ole_object'] = True

            # ============================================================
            # 规则 53: 检测嵌入式文件
            # ============================================================
            if b'\\objemb' in content or b'\\objlink' in content:
                score += 8
                reasons.append('规则53: 检测到嵌入式文件')
                data['embedded_file'] = True

            # ============================================================
            # 规则 54: 检测ActiveX
            # ============================================================
            if b'\\objocx' in content:
                score += 8
                reasons.append('规则54: 检测到ActiveX控件')
                data['activex'] = True

            # ============================================================
            # 规则 55: 检测自动执行
            # ============================================================
            if b'\\autolink' in content or b'\\autonum' in content:
                score += 3
                reasons.append('规则55: 检测到自动执行')
                data['auto_exec'] = True

            # ============================================================
            # 规则 56: 检测公式
            # ============================================================
            if b'\\objdata' in content:
                score += 3
                reasons.append('规则56: 检测到嵌入式数据')
                data['obj_data'] = True

            # ============================================================
            # 规则 57: 检测恶意内容
            # ============================================================
            if b'\\objhtml' in content:
                score += 5
                reasons.append('规则57: 检测到HTML内容')
                data['html_content'] = True

            # ============================================================
            # 规则 58: 检测文件大小异常
            # ============================================================
            if len(content) < 100:
                score += 3
                reasons.append(f'规则58: RTF文件大小异常小: {len(content)}字节')
                data['small_file'] = True

        except Exception as e:
            score += 5
            reasons.append(f'RTF分析异常: {str(e)}')
            data['error'] = str(e)

        return min(score, 30.0), reasons, data