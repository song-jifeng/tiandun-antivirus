#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 安全工具集
"""
import os
import sys
import json
import time
import hashlib
import subprocess
from typing import Dict, List, Optional
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class NetworkTools:
    """网络工具集"""

    @staticmethod
    def check_port(host: str, port: int, timeout: int = 3) -> bool:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    @staticmethod
    def scan_ports(host: str, ports: List[int]) -> Dict[int, bool]:
        results = {}
        for port in ports:
            results[port] = NetworkTools.check_port(host, port)
        return results

    @staticmethod
    def dns_lookup(hostname: str) -> List[str]:
        try:
            import socket
            return list(set(
                addr[4][0] for addr in socket.getaddrinfo(hostname, 80)
            ))
        except Exception:
            return []

    @staticmethod
    def reverse_dns(ip: str) -> str:
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ''

    @staticmethod
    def get_public_ip() -> str:
        try:
            import requests
            return requests.get('https://api.ipify.org', timeout=5).text
        except Exception:
            return ''

    @staticmethod
    def ping(host: str, count: int = 4) -> Dict:
        try:
            import subprocess
            param = '-n' if sys.platform == 'win32' else '-c'
            result = subprocess.run(
                ['ping', param, str(count), host],
                capture_output=True, text=True, timeout=10
            )
            return {
                'host': host,
                'alive': result.returncode == 0,
                'output': result.stdout,
            }
        except Exception as e:
            return {'host': host, 'alive': False, 'error': str(e)}


class SystemTools:
    """系统工具集"""

    @staticmethod
    def get_system_info() -> Dict:
        info = {}
        try:
            import platform
            info['system'] = platform.system()
            info['release'] = platform.release()
            info['version'] = platform.version()
            info['machine'] = platform.machine()
            info['processor'] = platform.processor()
            info['hostname'] = platform.node()
        except Exception:
            pass
        try:
            import psutil
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_physical'] = psutil.cpu_count(logical=False)
            info['memory_total'] = psutil.virtual_memory().total
            info['memory_available'] = psutil.virtual_memory().available
            info['disk_total'] = psutil.disk_usage('/').total
            info['disk_free'] = psutil.disk_usage('/').free
            info['boot_time'] = psutil.boot_time()
        except Exception:
            pass
        return info

    @staticmethod
    def get_environment_variables() -> Dict[str, str]:
        return dict(os.environ)

    @staticmethod
    def get_running_services() -> List[Dict]:
        services = []
        try:
            result = subprocess.run(
                'sc query type= service state= all',
                shell=True, capture_output=True, text=True, timeout=10
            )
            current = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'SERVICE_NAME:' in line:
                    if current:
                        services.append(current)
                    current = {'name': line.split(':', 1)[1].strip()}
                elif 'DISPLAY_NAME:' in line:
                    current['display_name'] = line.split(':', 1)[1].strip()
                elif 'STATE' in line:
                    current['state'] = 'running' if 'RUNNING' in line else 'stopped'
                elif 'START_TYPE' in line:
                    current['start_type'] = ('auto' if 'AUTO' in line
                                            else 'manual' if 'DEMAND' in line
                                            else 'disabled')
            if current:
                services.append(current)
        except Exception:
            pass
        return services

    @staticmethod
    def get_scheduled_tasks() -> List[Dict]:
        tasks = []
        try:
            result = subprocess.run(
                'schtasks /query /fo csv /v',
                shell=True, capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.split('\n')[1:]
            for line in lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 3:
                        tasks.append({
                            'name': parts[0].strip('"'),
                            'next_run': parts[1].strip('"') if len(parts) > 1 else '',
                            'status': parts[2].strip('"') if len(parts) > 2 else '',
                        })
        except Exception:
            pass
        return tasks

    @staticmethod
    def get_installed_programs() -> List[Dict]:
        programs = []
        try:
            import winreg
            keys = [
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_CURRENT_USER,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
            ]
            for hive, key_path in keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(hive, f'{key_path}\\{subkey_name}')
                            try:
                                name, _, _ = winreg.QueryValueEx(subkey, 'DisplayName')
                                version, _, _ = winreg.QueryValueEx(subkey, 'DisplayVersion')
                                programs.append({
                                    'name': name,
                                    'version': version,
                                    'key': subkey_name,
                                })
                            except FileNotFoundError:
                                pass
                            winreg.CloseKey(subkey)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except Exception:
            pass
        return programs


class FileTools:
    """文件工具集"""

    @staticmethod
    def find_duplicates(directory: str) -> Dict[str, List[str]]:
        hashes = {}
        for root, _, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, 'rb') as fh:
                        file_hash = hashlib.md5(fh.read(65536)).hexdigest()
                    if file_hash not in hashes:
                        hashes[file_hash] = []
                    hashes[file_hash].append(fpath)
                except Exception:
                    pass
        return {h: paths for h, paths in hashes.items() if len(paths) > 1}

    @staticmethod
    def find_large_files(directory: str, min_size_mb: int = 100) -> List[Dict]:
        large_files = []
        min_size = min_size_mb * 1024 * 1024
        for root, _, files in os.walk(directory):
            for f in files:
                try:
                    fpath = os.path.join(root, f)
                    size = os.path.getsize(fpath)
                    if size >= min_size:
                        large_files.append({
                            'path': fpath,
                            'size': size,
                            'size_mb': round(size / (1024 * 1024), 1),
                            'modified': os.path.getmtime(fpath),
                        })
                except Exception:
                    pass
        return sorted(large_files, key=lambda x: x['size'], reverse=True)

    @staticmethod
    def batch_rename(directory: str, pattern: str, replacement: str,
                    dry_run: bool = True) -> List[Dict]:
        results = []
        for f in os.listdir(directory):
            if pattern in f:
                new_name = f.replace(pattern, replacement)
                old_path = os.path.join(directory, f)
                new_path = os.path.join(directory, new_name)
                results.append({
                    'old': f,
                    'new': new_name,
                    'renamed': False if dry_run else None,
                })
                if not dry_run:
                    try:
                        os.rename(old_path, new_path)
                        results[-1]['renamed'] = True
                    except Exception:
                        results[-1]['renamed'] = False
        return results


class SecurityTools:
    """安全工具集"""

    @staticmethod
    def check_file_integrity(filepath: str, known_hash: str = '',
                            hash_type: str = 'md5') -> Dict:
        result = {'file': filepath, 'exists': os.path.exists(filepath)}
        if not result['exists']:
            return result
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            if hash_type == 'md5':
                result['hash'] = hashlib.md5(data).hexdigest()
            elif hash_type == 'sha256':
                result['hash'] = hashlib.sha256(data).hexdigest()
            else:
                result['hash'] = hashlib.sha1(data).hexdigest()
            if known_hash:
                result['match'] = result['hash'] == known_hash.lower()
        except Exception as e:
            result['error'] = str(e)
        return result

    @staticmethod
    def verify_signature(filepath: str) -> Dict:
        result = {'file': filepath, 'signed': False}
        try:
            if sys.platform == 'win32':
                output = subprocess.run(
                    ['signtool', 'verify', '/v', '/pa', filepath],
                    capture_output=True, text=True, timeout=10
                )
                result['signed'] = 'SignTool Error' not in output.stdout
                result['output'] = output.stdout[:500]
        except Exception:
            result['error'] = 'signtool not available'
        return result

    @staticmethod
    def check_password_strength(password: str) -> Dict:
        score = 0
        feedback = []
        if len(password) >= 8:
            score += 20
        else:
            feedback.append('密码长度至少8位')
        if any(c.isupper() for c in password):
            score += 20
        else:
            feedback.append('需要大写字母')
        if any(c.islower() for c in password):
            score += 20
        else:
            feedback.append('需要小写字母')
        if any(c.isdigit() for c in password):
            score += 20
        else:
            feedback.append('需要数字')
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            score += 20
        else:
            feedback.append('需要特殊字符')
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        level = ('very_weak' if score < 40 else 'weak' if score < 60
                else 'medium' if score < 80 else 'strong' if score < 100
                else 'very_strong')
        return {
            'score': score,
            'level': level,
            'feedback': feedback,
        }


class EncodingTools:
    """编码工具集"""

    @staticmethod
    def detect_encoding(filepath: str) -> str:
        import chardet
        try:
            with open(filepath, 'rb') as f:
                raw = f.read(min(65536, os.path.getsize(filepath)))
            result = chardet.detect(raw)
            return result.get('encoding', 'unknown')
        except Exception:
            return 'unknown'

    @staticmethod
    def convert_encoding(filepath: str, from_enc: str, to_enc: str,
                        output_path: str = None) -> bool:
        try:
            with open(filepath, 'r', encoding=from_enc, errors='replace') as f:
                content = f.read()
            output = output_path or filepath + '.converted'
            with open(output, 'w', encoding=to_enc) as f:
                f.write(content)
            return True
        except Exception:
            return False

    @staticmethod
    def base64_encode(data: str) -> str:
        import base64
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> str:
        import base64
        try:
            return base64.b64decode(data).decode('utf-8', errors='replace')
        except Exception:
            return ''

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        try:
            return bytes.fromhex(data).decode('utf-8', errors='replace')
        except Exception:
            return ''


class LogAnalyzer:
    """日志分析工具"""

    @staticmethod
    def analyze_log_file(filepath: str) -> Dict:
        analysis = {
            'file': filepath,
            'total_lines': 0,
            'error_lines': 0,
            'warning_lines': 0,
            'info_lines': 0,
            'debug_lines': 0,
            'top_errors': [],
            'top_ips': [],
            'timeline': {},
        }
        error_counts = Counter()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    analysis['total_lines'] += 1
                    if ' ERROR ' in line or '|ERROR' in line:
                        analysis['error_lines'] += 1
                        error_counts[line.strip()[:100]] += 1
                    elif ' WARN ' in line or '|WARN' in line:
                        analysis['warning_lines'] += 1
                    elif ' INFO ' in line or '|INFO' in line:
                        analysis['info_lines'] += 1
                    elif ' DEBUG ' in line or '|DEBUG' in line:
                        analysis['debug_lines'] += 1
            analysis['top_errors'] = error_counts.most_common(10)
        except Exception as e:
            analysis['error'] = str(e)
        return analysis


class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def generate_html_report(title: str, sections: List[Dict]) -> str:
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 40px; color: #333; }}
h1 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px; }}
h2 {{ color: #333; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background-color: #f8f9fa; font-weight: bold; }}
tr:hover {{ background-color: #f1f3f4; }}
.safe {{ color: #34a853; }}
.warning {{ color: #fbbc04; }}
.danger {{ color: #ea4335; }}
.card {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.summary {{ display: flex; gap: 20px; }}
.summary-item {{ flex: 1; text-align: center; padding: 20px; background: white;
                border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.summary-value {{ font-size: 32px; font-weight: bold; color: #1a73e8; }}
.summary-label {{ font-size: 14px; color: #5f6368; margin-top: 5px; }}
</style>
</head>
<body>
<h1>🛡️ {title}</h1>
<p>生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
'''
        for section in sections:
            html += '<div class="card">'
            html += f'<h2>{section.get("title", "")}</h2>'
            content = section.get('content', '')
            if isinstance(content, list):
                if content and isinstance(content[0], dict):
                    html += '<table><tr>'
                    for key in content[0].keys():
                        html += f'<th>{key}</th>'
                    html += '</tr>'
                    for row in content:
                        html += '<tr>'
                        for key in row.keys():
                            html += f'<td>{row[key]}</td>'
                        html += '</tr>'
                    html += '</table>'
                else:
                    html += '<ul>'
                    for item in content:
                        html += f'<li>{item}</li>'
                    html += '</ul>'
            else:
                html += f'<p>{content}</p>'
            html += '</div>'
        html += '</body></html>'
        return html

    @staticmethod
    def save_report(report: str, filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            return True
        except Exception:
            return False


class DataValidator:
    """数据验证工具"""

    @staticmethod
    def validate_email(email: str) -> bool:
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_ip(ip: str) -> bool:
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def validate_url(url: str) -> bool:
        import re
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))

    @staticmethod
    def validate_hex_string(hex_str: str) -> bool:
        try:
            bytes.fromhex(hex_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hash(hash_str: str) -> bool:
        valid_lengths = {32, 40, 64, 128}
        return (len(hash_str) in valid_lengths
                and all(c in '0123456789abcdef' for c in hash_str.lower()))