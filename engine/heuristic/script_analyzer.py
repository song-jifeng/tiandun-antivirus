#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ScriptAnalyzer - 脚本文件启发式分析器
支持 PowerShell/JS/VBS/BAT/Python 脚本分析
"""

import os
import re
import base64
from typing import Tuple, List, Dict, Optional, Any


# Common malicious patterns
POWERSHELL_SUSPICIOUS_CMD = [
    'Invoke-Expression', 'IEX', 'Invoke-WebRequest', 'iwr',
    'Invoke-RestMethod', 'irm', 'Invoke-WmiMethod', 'Invoke-CimMethod',
    'Start-Process', 'New-Object Net.WebClient', 'DownloadFile',
    'DownloadString', '-enc', '-EncodedCommand', 'Bypass', '-Exec Bypass',
    '-WindowStyle Hidden', '-Window Hidden', '-W Hidden',
    '-NoProfile', '-NonInteractive', '-Nologo',
    'Add-MpPreference', 'Set-MpPreference', 'DisableRealtimeMonitoring',
    'AMSI', 'BypassAMS', 'AmsiUtils', 'amsi.dll',
    'New-Object -ComObject', 'Get-WmiObject Win32_Process',
    'Register-ScheduledJob', 'New-ScheduledTask', 'Register-ScheduledTask',
    'CreateThread', 'VirtualAlloc', 'VirtualProtect',
    'GetModuleHandle', 'GetProcAddress',
    'Reflection.Assembly', 'LoadFile', 'LoadFrom',
    'Net.Sockets.TCPClient', 'GetStream', 'System.IO.StreamWriter',
    'HttpWebRequest', 'WebClient', 'DownloadData', 'UploadFile',
    'GZipStream', 'DeflateStream', 'FromBase64String',
]

VBS_SUSPICIOUS_OBJECTS = [
    'CreateObject("WScript.Shell")', 'CreateObject("Scripting.FileSystemObject")',
    'CreateObject("MSXML2.XMLHTTP")', 'CreateObject("WinHttp.WinHttpRequest")',
    'CreateObject("Shell.Application")', 'CreateObject("ADODB.Stream")',
    'CreateObject("Word.Application")', 'CreateObject("Excel.Application")',
    'CreateObject("Outlook.Application")', 'CreateObject("InternetExplorer.Application")',
    'WScript.Run', 'Shell.Run', 'ShellExecute',
    'FileSystemObject', 'GetSpecialFolder',
    'RegRead', 'RegWrite', 'RegDelete',
]

JS_SUSPICIOUS_OBJECTS = [
    'ActiveXObject', 'WScript.Shell', 'Scripting.FileSystemObject',
    'ADODB.Stream', 'Shell.Application', 'MSXML2.XMLHTTP',
    'Microsoft.XMLHTTP', 'WinHttp.WinHttpRequest',
    'Unescape', 'Escape', 'fromCharCode', 'String.fromCharCode',
    'eval(', 'execScript', 'GetObject(',
    'new ActiveXObject', 'WScript.CreateObject',
    'new Function(', 'setTimeout', 'setInterval',
    'document.write(unescape', 'document.write(eval',
    'window.location', 'window.open', 'navigate',
]

PYTHON_SUSPICIOUS_PATTERNS = [
    'import os', 'import subprocess', 'import socket',
    'import ctypes', 'import win32api', 'import winreg',
    'import base64', 'import cryptography',
    'os.system', 'os.popen', 'subprocess.call',
    'subprocess.Popen', 'subprocess.run',
    'ctypes.windll', 'kernel32', 'ntdll', 'user32',
    'socket.connect', 'socket.bind', 'socket.listen',
    'base64.b64decode', 'base64.b64encode',
    'eval(', 'exec(', 'exec(compile(',
    'pickle.loads', 'marshal.loads',
    'ctypes.windll.kernel32.VirtualAlloc',
    'ctypes.windll.kernel32.CreateThread',
    'ctypes.windll.kernel32.WriteProcessMemory',
    'ctypes.windll.user32.SetWindowsHookEx',
    'ctypes.windll.user32.GetAsyncKeyState',
    'keyboard', 'mouse', 'pyautogui',
    'pyscreenshot', 'mss', 'PIL.ImageGrab',
    'win32clipboard', 'pyperclip',
]

BAT_SUSPICIOUS_PATTERNS = [
    'powershell', 'powershell.exe',
    'reg add', 'reg delete',
    'schtasks', 'schtasks.exe',
    'net user', 'net localgroup', 'net group',
    'net share', 'net use',
    'vssadmin delete shadows', 'wmic',
    'bcdedit', 'cipher', 'cacls', 'icacls',
    'del /f /s /q', 'rmdir /s /q',
    'format', 'diskpart', 'clean',
    'sc create', 'sc delete', 'sc config',
    'mshta', 'mshta.exe',
    'rundll32', 'rundll32.exe',
    'bitsadmin', 'bitsadmin.exe',
    'certutil', 'certutil.exe',
    'cscript', 'cscript.exe',
    'wscript', 'wscript.exe',
    'regsvr32', 'regsvr32.exe',
    'curl', 'curl.exe',
    'start /b', 'start /min',
    'timeout /t',
]


class ScriptAnalyzer:
    """
    Script file analyzer - detects malicious patterns in scripts.
    Supports: PowerShell, VBS, JavaScript, BAT, Python.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._url_pattern = re.compile(r'https?://[^\s\'"<>]+')
        self._b64_pattern = re.compile(r'[A-Za-z0-9+/=]{50,}')

    def analyze(self, filepath: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Analyze a script file for malicious patterns.
        Returns (risk_score, reasons, details).
        """
        score = 0.0
        reasons = []
        details = {}
        ext = os.path.splitext(filepath)[1].lower()

        if ext not in ('.ps1', '.psm1', '.psd1', '.vbs', '.vbe',
                       '.js', '.jse', '.wsf', '.wsh', '.bat', '.cmd',
                       '.py', '.pyw', '.pyc', '.pyo'):
            return 0.0, [], {'error': 'unsupported script type'}

        content = self._read_file(filepath)
        if content is None:
            return 0.0, [], {'error': 'cannot read file'}

        lower = content.lower()
        details['ext'] = ext
        details['size'] = len(content)

        # Obfuscation detection
        obf = self._detect_obfuscation(content, lower)
        if obf:
            score += obf['score']
            reasons.extend(obf['reasons'])
            details['obfuscation'] = obf['data']

        # Base64 detection
        b64 = self._detect_base64(content, lower)
        if b64:
            score += b64['score']
            reasons.extend(b64['reasons'])
            details['base64'] = b64['data']

        # Network detection
        net = self._detect_network(content, lower)
        if net:
            score += net['score']
            reasons.extend(net['reasons'])
            details['network'] = net['data']

        # Type-specific analysis
        if ext in ('.ps1', '.psm1', '.psd1'):
            s, r, d = self._analyze_ps(content, lower)
            score += s; reasons.extend(r); details['ps'] = d
        elif ext in ('.vbs', '.vbe'):
            s, r, d = self._analyze_vbs(content, lower)
            score += s; reasons.extend(r); details['vbs'] = d
        elif ext in ('.js', '.jse', '.wsf', '.wsh'):
            s, r, d = self._analyze_js(content, lower)
            score += s; reasons.extend(r); details['js'] = d
        elif ext in ('.bat', '.cmd'):
            s, r, d = self._analyze_bat(content, lower)
            score += s; reasons.extend(r); details['bat'] = d
        elif ext in ('.py', '.pyw', '.pyc', '.pyo'):
            s, r, d = self._analyze_py(content, lower)
            score += s; reasons.extend(r); details['py'] = d

        # Persistence detection
        persist = self._detect_persistence(content, lower)
        if persist:
            score += persist['score']
            reasons.extend(persist['reasons'])
            details['persistence'] = persist['data']

        # Anti-debug detection
        anti = self._detect_antidebug(content, lower)
        if anti:
            score += anti['score']
            reasons.extend(anti['reasons'])
            details['antidebug'] = anti['data']

        score = min(score, 100.0)
        return score, reasons, details

    def _read_file(self, path: str) -> Optional[str]:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception:
            try:
                with open(path, 'rb') as f:
                    return f.read().decode('utf-8', errors='replace')
            except Exception:
                return None

    def _detect_obfuscation(self, content: str, lower: str) -> Optional[Dict]:
        score = 0.0; reasons = []; data = {}
        # Variable substitution
        v = len(re.findall(r'\$[a-z_]\w*\s*=\s*\'[^\']{10,}\'', content))
        if v > 10: score += 5; reasons.append('Obfuscation: variable substitution')
        # String concatenation
        c = content.count(' + ') + content.count(' & ')
        if c > 20: score += 5; reasons.append(f'Obfuscation: string concat ({c})')
        # Char encoding
        if 'fromCharCode' in content or 'chr(' in lower:
            score += 8; reasons.append('Obfuscation: char encoding')
        # Escape sequences
        e = content.count('\\x') + content.count('\\u0')
        if e > 10: score += 5; reasons.append(f'Obfuscation: escape sequences ({e})')
        # Long lines
        l = sum(1 for line in content.split('\n') if len(line) > 500)
        if l > 3: score += 5; reasons.append('Obfuscation: long lines')
        if score > 0: return {'score': min(score, 20), 'reasons': reasons, 'data': data}
        return None

    def _detect_base64(self, content: str, lower: str) -> Optional[Dict]:
        score = 0.0; reasons = []; data = {}
        b = self._b64_pattern.findall(content)
        if b:
            score += 5 * min(len(b), 3)
            reasons.append(f'Base64: {len(b)} encoded strings')
            for s in b[:3]:
                try:
                    d = base64.b64decode(s)
                    if any(w in d.lower() for w in [b'http', b'powershell', b'eval']):
                        score += 5; reasons.append('Base64: decoded contains executable content')
                except Exception:
                    pass
            if len(b) > 5: score += 3; reasons.append('Base64: multiple layers')
        if score > 0: return {'score': min(score, 15), 'reasons': reasons, 'data': data}
        return None

    def _detect_network(self, content: str, lower: str) -> Optional[Dict]:
        score = 0.0; reasons = []; data = {}
        u = self._url_pattern.findall(content)
        if u: score += 3 * min(len(u), 5); reasons.append(f'Network: {len(u)} URLs')
        ips = [ip for ip in self._ip_pattern.findall(content) if self._is_valid_ip(ip)]
        if ips: score += 3 * min(len(ips), 3); reasons.append(f'Network: {len(ips)} IPs')
        if score > 0: return {'score': min(score, 15), 'reasons': reasons, 'data': data}
        return None

    def _detect_persistence(self, content: str, lower: str) -> Optional[Dict]:
        score = 0.0; reasons = []; data = {}
        patterns = [
            (r'schtasks', 'Scheduled Task', 8), (r'register-scheduled', 'Scheduled Task', 8),
            (r'startup', 'Startup', 6), (r'runonce', 'RunOnce', 6),
            (r'__EventFilter', 'WMI Event', 10), (r'ActiveScriptEventConsumer', 'WMI Event', 10),
            (r'sc create', 'Service Create', 8), (r'new-service', 'Service Create', 8),
            (r'boot\.exe|bcdedit', 'Boot Modification', 8),
            (r'winlogon', 'Winlogon', 8), (r'appinit', 'AppInit DLL', 8),
        ]
        for pat, desc, pts in patterns:
            if re.search(pat, lower):
                score += pts; reasons.append(f'Persistence: {desc}'); data[desc] = True
        if score > 0: return {'score': min(score, 25), 'reasons': reasons, 'data': data}
        return None

    def _detect_antidebug(self, content: str, lower: str) -> Optional[Dict]:
        score = 0.0; reasons = []; data = {}
        patterns = [
            (r'IsDebuggerPresent', 'Debugger Check', 5),
            (r'GetTickCount|QueryPerformanceCounter', 'Timing Check', 5),
            (r'vbox|vmware|virtualbox|qemu', 'VM Detection', 8),
            (r'sandbox|sandboxie', 'Sandbox Detection', 8),
            (r'NtGlobalFlag', 'PEB Flag', 6),
            (r'sleep.*\d+.*(?:ms|s)', 'Delay Evasion', 4),
        ]
        for pat, desc, pts in patterns:
            if re.search(pat, lower):
                score += pts; reasons.append(f'AntiDebug: {desc}'); data[desc] = True
        if score > 0: return {'score': min(score, 20), 'reasons': reasons, 'data': data}
        return None

    def _analyze_ps(self, content: str, lower: str) -> Tuple[float, List[str], Dict]:
        score = 0.0; reasons = []; data = {}
        cmds = [c for c in POWERSHELL_SUSPICIOUS_CMD if c.lower() in lower]
        if cmds: score += 5 * min(len(cmds), 5); reasons.append(f'PS: {len(cmds)} suspicious commands'); data['cmds'] = cmds[:10]
        if 'downloadstring' in lower and 'iex' in lower:
            score += 15; reasons.append('PS: download & execute'); data['download_exec'] = True
        if 'virtualalloc' in lower and 'createthread' in lower:
            score += 15; reasons.append('PS: shellcode execution'); data['shellcode'] = True
        if 'amsi' in lower or 'amsiutils' in lower:
            score += 10; reasons.append('PS: AMSI bypass'); data['amsi'] = True
        if '-enc' in content or '-encodedcommand' in lower:
            score += 10; reasons.append('PS: encoded command'); data['encoded'] = True
        if 'mimikatz' in lower:
            score += 15; reasons.append('PS: Mimikatz'); data['mimikatz'] = True
        if 'cobaltstrike' in lower or 'beacon' in lower:
            score += 12; reasons.append('PS: C2 framework'); data['c2'] = True
        return min(score, 50), reasons, data

    def _analyze_vbs(self, content: str, lower: str) -> Tuple[float, List[str], Dict]:
        score = 0.0; reasons = []; data = {}
        objs = [o for o in VBS_SUSPICIOUS_OBJECTS if o.lower() in lower]
        if objs: score += 5 * min(len(objs), 5); reasons.append(f'VBS: {len(objs)} suspicious objects'); data['objs'] = objs[:10]
        if 'xmlhttp' in lower or 'winhttp' in lower:
            score += 8; reasons.append('VBS: network request'); data['network'] = True
        if 'execute(' in lower or 'eval(' in lower:
            score += 5; reasons.append('VBS: dynamic exec'); data['dyn_exec'] = True
        if 'chr(' in lower and '&' in content:
            score += 5; reasons.append('VBS: obfuscation'); data['obfuscation'] = True
        if 'regread' in lower or 'regwrite' in lower:
            score += 5; reasons.append('VBS: registry op'); data['registry'] = True
        return min(score, 40), reasons, data

    def _analyze_js(self, content: str, lower: str) -> Tuple[float, List[str], Dict]:
        score = 0.0; reasons = []; data = {}
        objs = [o for o in JS_SUSPICIOUS_OBJECTS if o.lower() in lower]
        if objs: score += 5 * min(len(objs), 5); reasons.append(f'JS: {len(objs)} suspicious objects'); data['objs'] = objs[:10]
        ec = len(re.findall(r'eval\s*\(', lower))
        if ec > 2: score += 5 * min(ec, 5); reasons.append(f'JS: eval x{ec}'); data['eval'] = ec
        if 'document.write' in lower and ('unescape' in lower or 'eval' in lower):
            score += 8; reasons.append('JS: document.write obfuscation'); data['doc_write'] = True
        if 'fromcharcode' in lower:
            score += 5; reasons.append('JS: char code obfuscation'); data['charcode'] = True
        if 'heap' in lower and 'spray' in lower:
            score += 10; reasons.append('JS: heap spray'); data['heap_spray'] = True
        return min(score, 40), reasons, data

    def _analyze_bat(self, content: str, lower: str) -> Tuple[float, List[str], Dict]:
        score = 0.0; reasons = []; data = {}
        pats = [p for p in BAT_SUSPICIOUS_PATTERNS if p in lower]
        if pats: score += 3 * min(len(pats), 8); reasons.append(f'BAT: {len(pats)} suspicious patterns'); data['pats'] = pats[:10]
        if 'powershell' in lower: score += 8; reasons.append('BAT: calls PowerShell'); data['ps'] = True
        if 'reg add' in lower: score += 5; reasons.append('BAT: registry modify'); data['reg'] = True
        if 'schtasks' in lower: score += 8; reasons.append('BAT: scheduled task'); data['task'] = True
        if 'net user' in lower: score += 5; reasons.append('BAT: user management'); data['user'] = True
        if 'vssadmin' in lower or 'wmic' in lower:
            score += 5; reasons.append('BAT: system management'); data['sys'] = True
        if 'del /f /s /q' in lower: score += 8; reasons.append('BAT: mass delete'); data['delete'] = True
        if 'format' in lower or 'diskpart' in lower:
            score += 10; reasons.append('BAT: disk format'); data['format'] = True
        return min(score, 40), reasons, data

    def _analyze_py(self, content: str, lower: str) -> Tuple[float, List[str], Dict]:
        score = 0.0; reasons = []; data = {}
        pats = [p for p in PYTHON_SUSPICIOUS_PATTERNS if p in lower]
        if pats: score += 3 * min(len(pats), 8); reasons.append(f'PY: {len(pats)} suspicious patterns'); data['pats'] = pats[:10]
        if 'os.system' in lower or 'os.popen' in lower or 'subprocess' in lower:
            score += 8; reasons.append('PY: system exec'); data['exec'] = True
        if 'socket.bind' in lower or 'socket.listen' in lower:
            score += 8; reasons.append('PY: network bind'); data['bind'] = True
        if 'socket.connect' in lower: score += 5; reasons.append('PY: network connect'); data['connect'] = True
        if 'ctypes.windll' in lower or 'kernel32' in lower:
            score += 8; reasons.append('PY: Windows API'); data['api'] = True
        if 'virtualalloc' in lower or 'createthread' in lower:
            score += 12; reasons.append('PY: memory operation'); data['memory'] = True
        if 'keyboard' in lower or 'getasynckeystate' in lower:
            score += 10; reasons.append('PY: keylogger'); data['keylogger'] = True
        if 'pyscreenshot' in lower or 'mss' in lower or 'imagegrab' in lower:
            score += 8; reasons.append('PY: screenshot'); data['screenshot'] = True
        if 'win32clipboard' in lower or 'pyperclip' in lower:
            score += 5; reasons.append('PY: clipboard'); data['clipboard'] = True
        return min(score, 45), reasons, data

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            return all(0 <= p <= 255 for p in parts) and len(parts) == 4
        except Exception:
            return False