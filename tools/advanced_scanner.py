#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 高级安全扫描工具
包含内存扫描、注册表扫描、Rootkit检测等高级功能
"""
import os
import sys
import time
import json
import struct
import ctypes
from typing import Dict, List, Optional
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MemoryScanner:
    """内存扫描器"""

    @staticmethod
    def scan_process_memory(pid: int) -> Dict:
        """扫描进程内存"""
        result = {
            'pid': pid,
            'regions': 0,
            'suspicious': [],
            'strings_found': 0,
        }
        try:
            import psutil
            proc = psutil.Process(pid)
            result['name'] = proc.name()
            result['memory_info'] = {
                'rss': proc.memory_info().rss,
                'vms': proc.memory_info().vms,
            }
            # 扫描内存中的可疑字符串
            suspicious_patterns = [
                b'http://', b'https://', b'\\\\', b'.exe', b'.dll',
                b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                b'SetWindowsHookEx', b'CreateProcess', b'WinExec',
                b'ShellExecute', b'URLDownloadToFile', b'socket',
                b'connect', b'send', b'recv', b'encrypt', b'decrypt',
                b'password', b'keylog', b'ransom', b'bitcoin', b'wallet',
            ]
            try:
                for region in proc.memory_maps():
                    result['regions'] += 1
                    if region.path and '\\' in region.path:
                        for pattern in suspicious_patterns:
                            if pattern in region.path.encode():
                                result['suspicious'].append({
                                    'region': region.path,
                                    'pattern': pattern.decode('ascii', errors='replace'),
                                })
                                break
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def scan_all_processes() -> List[Dict]:
        """扫描所有进程内存"""
        results = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    result = MemoryScanner.scan_process_memory(proc.info['pid'])
                    if result['suspicious']:
                        results.append(result)
                except Exception:
                    pass
        except Exception:
            pass
        return results


class RegistryScanner:
    """注册表扫描器"""

    SUSPICIOUS_KEYS = [
        r'Software\Microsoft\Windows\CurrentVersion\Run',
        r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'Software\Microsoft\Windows\CurrentVersion\RunServices',
        r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        r'Software\Microsoft\Windows NT\CurrentVersion\Windows\Load',
        r'Software\Microsoft\Windows NT\CurrentVersion\Windows\Run',
        r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
        r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
        r'System\CurrentControlSet\Control\Session Manager\BootExecute',
        r'Software\Microsoft\Internet Explorer\Main\Start Page',
        r'Software\Microsoft\Internet Explorer\Main\Default_Page_URL',
    ]

    @staticmethod
    def scan_autoruns() -> List[Dict]:
        """扫描自动启动项"""
        results = []
        try:
            import winreg
            for key_path in RegistryScanner.SUSPICIOUS_KEYS:
                try:
                    hive = winreg.HKEY_LOCAL_MACHINE if key_path.startswith('System') or key_path.startswith('Software') else winreg.HKEY_CURRENT_USER
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if isinstance(value, str) and value.strip():
                                results.append({
                                    'key': key_path,
                                    'name': name,
                                    'value': value,
                                    'hive': 'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU',
                                })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        return results

    @staticmethod
    def scan_browser_plugins() -> List[Dict]:
        """扫描浏览器插件"""
        plugins = []
        try:
            import winreg
            # IE/Edge 插件
            paths = [
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Internet Explorer\Extensions'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Internet Explorer\Extensions'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Ext\Settings'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Ext\Settings'),
            ]
            for hive, key_path in paths:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            subkey = winreg.EnumKey(key, i)
                            plugins.append({
                                'key': f'{key_path}\\{subkey}',
                                'hive': 'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU',
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except Exception:
            pass
        return plugins


class RootkitDetector:
    """Rootkit 检测器"""

    @staticmethod
    def check_hidden_processes() -> List[Dict]:
        """检测隐藏进程"""
        hidden = []
        try:
            import psutil
            # 使用多种方法获取进程列表
            pids_psutil = set(proc.pid for proc in psutil.process_iter())
            pids_tasklist = set()
            import subprocess
            result = subprocess.run(
                'tasklist /FO CSV /NH',
                shell=True, capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        parts = line.split(',')
                        if len(parts) > 1:
                            pids_tasklist.add(int(parts[1].strip('"')))
                    except (ValueError, IndexError):
                        pass
            # 比较差异
            diff = pids_tasklist - pids_psutil
            if diff:
                for pid in diff:
                    hidden.append({
                        'pid': pid,
                        'detection_method': '进程列表差异',
                        'found_by': 'tasklist',
                    })
        except Exception:
            pass
        return hidden

    @staticmethod
    def check_hidden_services() -> List[Dict]:
        """检测隐藏服务"""
        hidden = []
        try:
            import subprocess
            # 使用SC查询
            result = subprocess.run(
                'sc query type= service state= all',
                shell=True, capture_output=True, text=True, timeout=10
            )
            known_services = set()
            for line in result.stdout.split('\n'):
                if 'SERVICE_NAME:' in line:
                    name = line.split(':', 1)[1].strip()
                    known_services.add(name)
            # 检查注册表中的服务
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r'System\CurrentControlSet\Services',
                                     0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(key, i)
                        if service_name not in known_services:
                            hidden.append({
                                'service_name': service_name,
                                'detection_method': '注册表中有但SC未列出',
                            })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass
        except Exception:
            pass
        return hidden

    @staticmethod
    def check_hidden_files(directory: str) -> List[Dict]:
        """检测隐藏文件"""
        hidden = []
        try:
            # 使用API和目录遍历对比
            for root, dirs, files in os.walk(directory):
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        # 检查隐藏属性
                        if sys.platform == 'win32':
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(fpath)
                            if attrs != -1 and attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                                hidden.append({
                                    'path': fpath,
                                    'attribute': 'hidden',
                                })
                    except Exception:
                        pass
                if len(hidden) > 100:
                    break
        except Exception:
            pass
        return hidden

    @staticmethod
    def check_ssdt_hooks() -> List[Dict]:
        """检查SSDT钩子 (概念验证)"""
        # 注意：实际SSDT检查需要内核级驱动
        return [{'note': 'SSDT钩子检测需要内核驱动支持'}]

    @staticmethod
    def run_all_checks() -> Dict:
        """运行所有Rootkit检测"""
        return {
            'hidden_processes': RootkitDetector.check_hidden_processes(),
            'hidden_services': RootkitDetector.check_hidden_services(),
            'hidden_files': RootkitDetector.check_hidden_files('C:\\'),
            'ssdt_hooks': RootkitDetector.check_ssdt_hooks(),
            'timestamp': time.time(),
        }


class BootkitDetector:
    """Bootkit 检测器"""

    @staticmethod
    def check_mbr() -> Dict:
        """检查MBR"""
        try:
            if sys.platform == 'win32':
                with open(r'\\.\PhysicalDrive0', 'rb') as f:
                    mbr = f.read(512)
                # 检查MBR签名
                if len(mbr) >= 512:
                    sig = struct.unpack_from('<H', mbr, 510)[0]
                    return {
                        'signature': f'0x{sig:04X}',
                        'valid': sig == 0xAA55,
                        'suspicious': False,
                    }
            return {'error': '无法读取MBR'}
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def check_boot_config() -> Dict:
        """检查启动配置"""
        try:
            import subprocess
            result = subprocess.run(
                'bcdedit /enum',
                shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            return {
                'has_unknown_entries': 'unknown' in output,
                'has_debug': 'debug' in output,
                'has_testsigning': 'testsigning' in output,
                'boot_config': result.stdout[:1000],
            }
        except Exception as e:
            return {'error': str(e)}


class NetworkThreatDetector:
    """网络威胁检测器"""

    @staticmethod
    def detect_suspicious_connections() -> List[Dict]:
        """检测可疑网络连接"""
        suspicious = []
        try:
            import psutil
            for conn in psutil.net_connections():
                if conn.raddr:
                    # 检查端口
                    suspicious_ports = {21, 23, 25, 135, 445, 3389, 5900, 6667, 6668, 6669}
                    if conn.raddr.port in suspicious_ports and conn.status == 'ESTABLISHED':
                        proc_name = ''
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except Exception:
                                pass
                        suspicious.append({
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'port': conn.raddr.port,
                            'status': conn.status,
                            'pid': conn.pid,
                            'process': proc_name,
                        })
        except Exception:
            pass
        return suspicious

    @staticmethod
    def detect_arp_spoofing() -> List[Dict]:
        """检测ARP欺骗"""
        alerts = []
        try:
            import subprocess
            result = subprocess.run(
                'arp -a',
                shell=True, capture_output=True, text=True, timeout=5
            )
            # 解析ARP表
            gateways = {}
            for line in result.stdout.split('\n'):
                if 'interface' in line.lower():
                    current_iface = line
                elif '.' in line and 'static' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1] if len(parts) > 1 else ''
                        if ip not in gateways:
                            gateways[ip] = mac
                        elif gateways[ip] != mac:
                            alerts.append({
                                'ip': ip,
                                'mac_1': gateways[ip],
                                'mac_2': mac,
                                'type': 'ARP欺骗',
                            })
        except Exception:
            pass
        return alerts


class BehavioralThreatDetector:
    """行为威胁检测器"""

    @staticmethod
    def detect_ransomware_behavior(process_name: str, file_operations: List[Dict]) -> Dict:
        """检测勒索软件行为"""
        score = 0
        reasons = []
        # 检测批量文件修改
        if len(file_operations) > 50:
            score += 30
            reasons.append(f"大量文件操作: {len(file_operations)}次")
        # 检测文件扩展名变更
        extensions = set(op.get('new_ext', '') for op in file_operations if 'new_ext' in op)
        if len(extensions) > 10:
            score += 30
            reasons.append(f"大量文件扩展名变更: {len(extensions)}种")
        # 检测勒索通知
        for op in file_operations:
            content = op.get('content', '')
            if any(kw in content.lower() for kw in ['encrypt', 'decrypt', 'bitcoin',
                                                     'ransom', 'payment', 'recover']):
                score += 40
                reasons.append("检测到勒索相关关键词")
                break
        return {
            'process': process_name,
            'risk_score': score,
            'risk_level': 'high' if score >= 70 else 'medium' if score >= 40 else 'low',
            'reasons': reasons,
        }

    @staticmethod
    def detect_miner_behavior(cpu_percent: float, memory_percent: float,
                               network_traffic: float) -> Dict:
        """检测挖矿病毒行为"""
        score = 0
        reasons = []
        if cpu_percent > 50:
            score += 30
            reasons.append(f"CPU使用率异常: {cpu_percent}%")
        if memory_percent > 30:
            score += 20
            reasons.append(f"内存使用率异常: {memory_percent}%")
        if network_traffic > 1000000:
            score += 20
            reasons.append(f"网络流量异常: {network_traffic} bytes/s")
        return {
            'risk_score': score,
            'risk_level': 'high' if score >= 50 else 'medium' if score >= 30 else 'low',
            'reasons': reasons,
        }


class IntegrityChecker:
    """完整性检查器"""

    @staticmethod
    def check_system_integrity() -> Dict:
        """检查系统完整性"""
        results = {}
        # 检查关键系统文件
        critical_files = [
            r'C:\Windows\System32\kernel32.dll',
            r'C:\Windows\System32\ntdll.dll',
            r'C:\Windows\System32\user32.dll',
            r'C:\Windows\System32\advapi32.dll',
        ]
        for fpath in critical_files:
            if os.path.exists(fpath):
                results[fpath] = {
                    'exists': True,
                    'size': os.path.getsize(fpath),
                    'modified': os.path.getmtime(fpath),
                }
            else:
                results[fpath] = {'exists': False, 'warning': '文件缺失'}
        # 检查Hosts文件
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        if os.path.exists(hosts_path):
            with open(hosts_path, 'r', encoding='utf-8') as f:
                content = f.read()
            suspicious_entries = []
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and '127.0.0.1' in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] not in ['localhost', 'localhost.localdomain']:
                        suspicious_entries.append(line)
            results['hosts_file'] = {
                'exists': True,
                'suspicious_entries': suspicious_entries,
                'suspicious_count': len(suspicious_entries),
            }
        return results


class VulnerabilityScanner:
    """漏洞扫描器"""

    @staticmethod
    def check_common_vulnerabilities() -> List[Dict]:
        """检查常见漏洞"""
        vulns = []
        # 检查SMBv1
        try:
            import subprocess
            result = subprocess.run(
                'sc query lanmanworkstation',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if 'RUNNING' in result.stdout:
                vulns.append({
                    'name': 'SMBv1可能已启用',
                    'risk': 'medium',
                    'description': 'SMBv1协议存在已知漏洞，建议禁用',
                    'remediation': '在Windows功能中禁用SMB 1.0/CIFS文件共享支持',
                })
        except Exception:
            pass
        # 检查远程桌面
        try:
            result = subprocess.run(
                'reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if '0x0' in result.stdout:
                vulns.append({
                    'name': '远程桌面已启用',
                    'risk': 'medium',
                    'description': '远程桌面可能暴露攻击面',
                    'remediation': '如不需要，请禁用远程桌面',
                })
        except Exception:
            pass
        # 检查自动登录
        try:
            result = subprocess.run(
                'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if 'DefaultUserName' in result.stdout:
                vulns.append({
                    'name': '自动登录已配置',
                    'risk': 'medium',
                    'description': '自动登录会降低系统安全性',
                    'remediation': '在用户账户设置中禁用自动登录',
                })
        except Exception:
            pass
        return vulns


class ExploitDetector:
    """漏洞利用检测器"""

    @staticmethod
    def check_common_exploit_techniques() -> List[Dict]:
        """检查常见漏洞利用技术"""
        findings = []
        # 检查DLL劫持
        dll_hijack_paths = [
            os.path.expanduser('~\\AppData\\Local\\Temp'),
            os.environ.get('TEMP', ''),
            os.getcwd(),
        ]
        for path in dll_hijack_paths:
            if path and os.path.exists(path):
                for f in os.listdir(path):
                    if f.lower().endswith('.dll') and not f.lower().startswith('ms'):
                        findings.append({
                            'type': 'DLL劫持',
                            'path': os.path.join(path, f),
                            'risk': 'medium',
                        })
        # 检查计划任务
        try:
            import subprocess
            result = subprocess.run(
                'schtasks /query /fo csv /v',
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if line.strip() and 'temp' in line.lower() or 'appdata' in line.lower():
                    findings.append({
                        'type': '可疑计划任务',
                        'task': line.split(',')[0].strip('"') if ',' in line else line,
                        'risk': 'low',
                    })
        except Exception:
            pass
        return findings