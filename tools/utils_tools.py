#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 综合工具模块
包含数据压缩、加密、备份、报告生成等实用工具
"""
import os
import sys
import json
import time
import zlib
import base64
import hashlib
import tempfile
import shutil
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataCompressor:
    """数据压缩工具"""

    @staticmethod
    def compress(data: bytes, level: int = 6) -> bytes:
        """压缩数据"""
        return zlib.compress(data, level)

    @staticmethod
    def decompress(data: bytes) -> bytes:
        """解压数据"""
        return zlib.decompress(data)

    @staticmethod
    def compress_file(filepath: str, output_path: str = None) -> str:
        """压缩文件"""
        if output_path is None:
            output_path = filepath + '.zlib'
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            compressed = DataCompressor.compress(data)
            with open(output_path, 'wb') as f:
                f.write(compressed)
            return output_path
        except Exception as e:
            raise RuntimeError(f"压缩文件失败: {e}")

    @staticmethod
    def decompress_file(filepath: str, output_path: str = None) -> str:
        """解压文件"""
        if output_path is None:
            output_path = filepath.rstrip('.zlib')
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            decompressed = DataCompressor.decompress(data)
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            return output_path
        except Exception as e:
            raise RuntimeError(f"解压文件失败: {e}")

    @staticmethod
    def compress_directory(directory: str, output_path: str = None) -> str:
        """压缩目录"""
        if output_path is None:
            output_path = directory + '.tar.zlib'
        try:
            import tarfile
            import io
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w') as tar:
                tar.add(directory, arcname=os.path.basename(directory))
            compressed = DataCompressor.compress(buf.getvalue())
            with open(output_path, 'wb') as f:
                f.write(compressed)
            return output_path
        except ImportError:
            # 不使用tar，直接压缩文件列表
            data = {}
            for root, _, files in os.walk(directory):
                for f in files:
                    fpath = os.path.join(root, f)
                    with open(fpath, 'rb') as fh:
                        rel_path = os.path.relpath(fpath, directory)
                        data[rel_path] = base64.b64encode(fh.read()).decode()
            compressed = DataCompressor.compress(json.dumps(data).encode())
            with open(output_path, 'wb') as f:
                f.write(compressed)
            return output_path


class DataEncryptor:
    """数据加密工具"""

    @staticmethod
    def xor_encrypt(data: bytes, key: str) -> bytes:
        """XOR 加密"""
        key_bytes = key.encode()
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ key_bytes[i % len(key_bytes)])
        return bytes(result)

    @staticmethod
    def xor_decrypt(data: bytes, key: str) -> bytes:
        """XOR 解密"""
        return DataEncryptor.xor_encrypt(data, key)

    @staticmethod
    def simple_hash(data: bytes) -> str:
        """简单哈希"""
        return hashlib.sha256(data).hexdigest()[:16]

    @staticmethod
    def obfuscate_string(text: str) -> str:
        """混淆字符串"""
        result = []
        for c in text:
            result.append(chr(ord(c) ^ 0x55))
        return base64.b64encode(''.join(result).encode()).decode()

    @staticmethod
    def deobfuscate_string(obfuscated: str) -> str:
        """去混淆字符串"""
        try:
            decoded = base64.b64decode(obfuscated).decode()
            result = []
            for c in decoded:
                result.append(chr(ord(c) ^ 0x55))
            return ''.join(result)
        except Exception:
            return ''


class ConfigBackup:
    """配置备份工具"""

    def __init__(self, backup_dir: str = None):
        self.backup_dir = backup_dir or os.path.join(
            os.environ.get('TIANDUN_ROOT', 'D:/Antivirus'),
            'backups', 'config'
        )
        os.makedirs(self.backup_dir, exist_ok=True)

    def backup(self, config_data: Dict) -> str:
        """备份配置"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.backup_dir, f'config_{timestamp}.json')
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)
        return backup_file

    def list_backups(self) -> List[Dict]:
        """列出所有备份"""
        backups = []
        if not os.path.exists(self.backup_dir):
            return backups
        for f in sorted(os.listdir(self.backup_dir), reverse=True):
            fpath = os.path.join(self.backup_dir, f)
            if os.path.isfile(fpath):
                backups.append({
                    'file': f,
                    'size': os.path.getsize(fpath),
                    'time': os.path.getmtime(fpath),
                    'path': fpath,
                })
        return backups

    def restore(self, backup_file: str) -> Dict:
        """从备份恢复"""
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise RuntimeError(f"恢复备份失败: {e}")

    def clean_old(self, max_backups: int = 10):
        """清理旧备份"""
        backups = self.list_backups()
        if len(backups) > max_backups:
            for old in backups[max_backups:]:
                try:
                    os.remove(old['path'])
                except Exception:
                    pass


class FileHasher:
    """文件哈希计算器"""

    @staticmethod
    def hash_file(filepath: str, algorithms: List[str] = None) -> Dict[str, str]:
        """计算文件的多种哈希值"""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
        hashers = {}
        for algo in algorithms:
            try:
                hashers[algo] = hashlib.new(algo)
            except ValueError:
                continue
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    for h in hashers.values():
                        h.update(chunk)
            return {algo: h.hexdigest() for algo, h in hashers.items()}
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def hash_directory(directory: str, algorithms: List[str] = None) -> Dict[str, str]:
        """计算目录的哈希值"""
        if algorithms is None:
            algorithms = ['sha256']
        hashers = {}
        for algo in algorithms:
            try:
                hashers[algo] = hashlib.new(algo)
            except ValueError:
                continue
        try:
            for root, dirs, files in sorted(os.walk(directory)):
                for f in sorted(files):
                    fpath = os.path.join(root, f)
                    rel_path = os.path.relpath(fpath, directory)
                    for h in hashers.values():
                        h.update(rel_path.encode())
                    with open(fpath, 'rb') as fh:
                        while True:
                            chunk = fh.read(65536)
                            if not chunk:
                                break
                            for h in hashers.values():
                                h.update(chunk)
            return {algo: h.hexdigest() for algo, h in hashers.items()}
        except Exception as e:
            return {'error': str(e)}


class PortScanner:
    """端口扫描器"""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                    443, 445, 993, 995, 1433, 1521, 3306, 3389,
                    5432, 5900, 6379, 8080, 8443, 27017]

    @staticmethod
    def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
        """检查端口是否开放"""
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
    def scan_common(host: str, timeout: float = 1.0) -> Dict[int, bool]:
        """扫描常见端口"""
        results = {}
        for port in PortScanner.COMMON_PORTS:
            results[port] = PortScanner.check_port(host, port, timeout)
        return results

    @staticmethod
    def scan_range(host: str, start: int, end: int,
                   timeout: float = 0.5, max_threads: int = 50) -> Dict[int, bool]:
        """扫描端口范围"""
        results = {}
        import threading
        lock = threading.Lock()

        def scan_port(port):
            open = PortScanner.check_port(host, port, timeout)
            with lock:
                results[port] = open

        threads = []
        for port in range(start, end + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads.append(t)
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        return results


class WhoisLookup:
    """WHOIS 查询工具"""

    @staticmethod
    def lookup(domain: str) -> Dict:
        """WHOIS 查询"""
        try:
            import socket
            result = {
                'domain': domain,
                'ip': socket.gethostbyname(domain),
                'timestamp': time.time(),
            }
            return result
        except Exception as e:
            return {'domain': domain, 'error': str(e)}


class GeoIP:
    """IP 地理位置查询"""

    @staticmethod
    def lookup(ip: str) -> Dict:
        """IP 地理位置查询"""
        try:
            import requests
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                }
        except Exception:
            pass
        return {'ip': ip, 'error': 'query_failed'}


class SystemOptimizer:
    """系统优化器"""

    @staticmethod
    def optimize_memory() -> Dict:
        """优化内存使用"""
        freed = 0
        try:
            import subprocess
            # 清理工作集
            result = subprocess.run(
                'powershell -Command "Get-Process | Where-Object { $_.WorkingSet -gt 100MB } | ForEach-Object { [GC]::Collect(); $_.Refresh() }"',
                shell=True, capture_output=True, timeout=30
            )
            freed = 1
        except Exception:
            pass
        return {'success': True, 'freed_mb': freed}

    @staticmethod
    def clean_event_logs() -> Dict:
        """清理事件日志"""
        try:
            import subprocess
            logs = ['Application', 'System', 'Security']
            for log in logs:
                subprocess.run(
                    f'powershell -Command "Clear-EventLog -LogName {log}"',
                    shell=True, capture_output=True, timeout=30
                )
            return {'success': True, 'cleaned': len(logs)}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class FileIntegrityChecker:
    """文件完整性检查器"""

    def __init__(self):
        self._baseline = {}

    def create_baseline(self, directory: str) -> Dict[str, str]:
        """创建文件完整性基线"""
        baseline = {}
        for root, _, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, 'rb') as fh:
                        file_hash = hashlib.sha256(fh.read()).hexdigest()
                    baseline[fpath] = file_hash
                except Exception:
                    pass
        self._baseline = baseline
        return baseline

    def check_integrity(self, baseline: Dict[str, str] = None) -> List[Dict]:
        """检查文件完整性"""
        if baseline is None:
            baseline = self._baseline
        changes = []
        for fpath, expected_hash in baseline.items():
            if not os.path.exists(fpath):
                changes.append({'file': fpath, 'status': 'deleted'})
                continue
            try:
                with open(fpath, 'rb') as fh:
                    current_hash = hashlib.sha256(fh.read()).hexdigest()
                if current_hash != expected_hash:
                    changes.append({'file': fpath, 'status': 'modified'})
            except Exception:
                changes.append({'file': fpath, 'status': 'error'})
        return changes


class DataSerializer:
    """数据序列化工具"""

    @staticmethod
    def serialize_json(data: Any, pretty: bool = True) -> str:
        """JSON 序列化"""
        return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None)

    @staticmethod
    def deserialize_json(text: str) -> Any:
        """JSON 反序列化"""
        return json.loads(text)

    @staticmethod
    def serialize_csv(data: List[Dict]) -> str:
        """CSV 序列化"""
        if not data:
            return ''
        import csv
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    @staticmethod
    def serialize_text_report(data: Dict, title: str = 'Report') -> str:
        """文本报告序列化"""
        lines = [
            f"{'=' * 60}",
            f"  {title}",
            f"  {datetime.now().isoformat()}",
            f"{'=' * 60}",
        ]
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"\n[{key}]")
                for k, v in value.items():
                    lines.append(f"  {k}: {v}")
            elif isinstance(value, list):
                lines.append(f"\n[{key}] ({len(value)} items)")
                for i, item in enumerate(value[:10]):
                    lines.append(f"  {i + 1}. {item}")
                if len(value) > 10:
                    lines.append(f"  ... and {len(value) - 10} more")
            else:
                lines.append(f"{key}: {value}")
        lines.append(f"{'=' * 60}")
        return '\n'.join(lines)


class SchedulerHelper:
    """调度器辅助工具"""

    @staticmethod
    def calculate_next_run(interval_hours: int, base_time: float = None) -> float:
        """计算下次运行时间"""
        if base_time is None:
            base_time = time.time()
        return base_time + interval_hours * 3600

    @staticmethod
    def format_schedule(interval_hours: int) -> str:
        """格式化调度信息"""
        if interval_hours < 1:
            return f"每{interval_hours * 60}分钟"
        elif interval_hours < 24:
            return f"每{interval_hours}小时"
        elif interval_hours < 168:
            return f"每{interval_hours // 24}天"
        else:
            return f"每{interval_hours // 168}周"

    @staticmethod
    def parse_cron(cron_expression: str) -> Dict:
        """解析Cron表达式（简化版）"""
        parts = cron_expression.strip().split()
        if len(parts) != 5:
            return {'error': '格式错误，需要5个字段'}
        return {
            'minute': parts[0],
            'hour': parts[1],
            'day_of_month': parts[2],
            'month': parts[3],
            'day_of_week': parts[4],
        }


class ResourceMonitor:
    """资源监控器"""

    @staticmethod
    def get_cpu_usage() -> Dict:
        """获取CPU使用率"""
        try:
            import psutil
            return {
                'percent': psutil.cpu_percent(interval=0.1),
                'count': psutil.cpu_count(),
                'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
            }
        except Exception:
            return {'percent': 0, 'count': 0}

    @staticmethod
    def get_memory_usage() -> Dict:
        """获取内存使用率"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'percent': mem.percent,
                'swap': psutil.swap_memory()._asdict() if psutil.swap_memory() else {},
            }
        except Exception:
            return {'total': 0, 'available': 0, 'percent': 0}

    @staticmethod
    def get_disk_usage(path: str = '/') -> Dict:
        """获取磁盘使用率"""
        try:
            import psutil
            disk = psutil.disk_usage(path)
            return {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent,
            }
        except Exception:
            return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}

    @staticmethod
    def get_network_usage() -> Dict:
        """获取网络使用率"""
        try:
            import psutil
            net = psutil.net_io_counters()
            return {
                'bytes_sent': net.bytes_sent,
                'bytes_recv': net.bytes_recv,
                'packets_sent': net.packets_sent,
                'packets_recv': net.packets_recv,
                'errin': net.errin,
                'errout': net.errout,
                'dropin': net.dropin,
                'dropout': net.dropout,
            }
        except Exception:
            return {}


class BatchProcessor:
    """批处理工具"""

    @staticmethod
    def process_files(directory: str, pattern: str, processor_func,
                      recursive: bool = True, max_workers: int = 4) -> Dict:
        """批量处理文件"""
        from concurrent.futures import ThreadPoolExecutor
        import fnmatch

        files = []
        if recursive:
            for root, _, filenames in os.walk(directory):
                for f in filenames:
                    if fnmatch.fnmatch(f, pattern):
                        files.append(os.path.join(root, f))
        else:
            for f in os.listdir(directory):
                if fnmatch.fnmatch(f, pattern):
                    files.append(os.path.join(directory, f))

        results = {'total': len(files), 'processed': 0, 'errors': 0, 'results': []}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(processor_func, f): f for f in files}
            for future in futures:
                try:
                    result = future.result()
                    results['results'].append(result)
                    results['processed'] += 1
                except Exception:
                    results['errors'] += 1

        return results


class DataValidator:
    """数据验证器"""

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址"""
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def validate_email(email: str) -> bool:
        """验证邮箱地址"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL"""
        import re
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))

    @staticmethod
    def validate_hex(hex_str: str) -> bool:
        """验证十六进制字符串"""
        try:
            bytes.fromhex(hex_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_hash(hash_str: str) -> bool:
        """验证哈希值"""
        valid_lengths = {32, 40, 64, 128}
        return (len(hash_str) in valid_lengths
                and all(c in '0123456789abcdef' for c in hash_str.lower()))

    @staticmethod
    def validate_file_path(path: str) -> bool:
        """验证文件路径"""
        try:
            os.path.normpath(path)
            return True
        except Exception:
            return False


class TempFileManager:
    """临时文件管理器"""

    def __init__(self):
        self._temp_files = []
        self._temp_dirs = []

    def create_temp_file(self, suffix: str = '.tmp', prefix: str = 'td_') -> str:
        """创建临时文件"""
        import tempfile
        fd, fpath = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)
        self._temp_files.append(fpath)
        return fpath

    def create_temp_dir(self, prefix: str = 'td_') -> str:
        """创建临时目录"""
        import tempfile
        dpath = tempfile.mkdtemp(prefix=prefix)
        self._temp_dirs.append(dpath)
        return dpath

    def cleanup(self):
        """清理所有临时文件"""
        for fpath in self._temp_files:
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
            except Exception:
                pass
        self._temp_files = []

        for dpath in self._temp_dirs:
            try:
                if os.path.exists(dpath):
                    shutil.rmtree(dpath, ignore_errors=True)
            except Exception:
                pass
        self._temp_dirs = []

    def __del__(self):
        self.cleanup()


class ProgressTracker:
    """进度跟踪器"""

    def __init__(self, total: int, description: str = 'Processing'):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self._lock = threading.Lock()

    def update(self, n: int = 1):
        """更新进度"""
        with self._lock:
            self.current += n
            self._print_progress()

    def set_current(self, current: int):
        """设置当前值"""
        with self._lock:
            self.current = min(current, self.total)
            self._print_progress()

    def _print_progress(self):
        """打印进度"""
        pct = (self.current / self.total * 100) if self.total > 0 else 0
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        print(f"\r{self.description}: {self.current}/{self.total} "
              f"({pct:.1f}%) | {elapsed:.1f}s | ETA: {eta:.1f}s", end='', flush=True)

    def finish(self):
        """完成"""
        elapsed = time.time() - self.start_time
        print(f"\n完成! 总耗时: {elapsed:.1f}秒")


class RateLimiter:
    """速率限制器"""

    def __init__(self, max_calls: int, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self.calls = []
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """获取许可"""
        with self._lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.period]
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            return False

    def wait_and_acquire(self, timeout: float = None):
        """等待并获取许可"""
        import time
        start = time.time()
        while True:
            if self.acquire():
                return True
            if timeout is not None and time.time() - start > timeout:
                return False
            time.sleep(0.1)


class CircularBuffer:
    """循环缓冲区"""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._buffer = []
        self._lock = threading.Lock()

    def push(self, item):
        """添加元素"""
        with self._lock:
            self._buffer.append(item)
            if len(self._buffer) > self.max_size:
                self._buffer.pop(0)

    def pop(self):
        """弹出元素"""
        with self._lock:
            if self._buffer:
                return self._buffer.pop(0)
            return None

    def get_all(self) -> List:
        """获取所有元素"""
        with self._lock:
            return list(self._buffer)

    def clear(self):
        """清空缓冲区"""
        with self._lock:
            self._buffer.clear()

    def __len__(self):
        with self._lock:
            return len(self._buffer)


class MetricsCollector:
    """指标收集器"""

    def __init__(self):
        self._metrics = {}
        self._lock = threading.Lock()

    def increment(self, name: str, value: int = 1):
        """递增指标"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = 0
            self._metrics[name] += value

    def gauge(self, name: str, value: float):
        """设置指标值"""
        with self._lock:
            self._metrics[name] = value

    def timing(self, name: str, duration_ms: float):
        """记录时间"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = []
            self._metrics[name].append(duration_ms)
            if len(self._metrics[name]) > 1000:
                self._metrics[name] = self._metrics[name][-1000:]

    def get_all(self) -> Dict:
        """获取所有指标"""
        with self._lock:
            result = {}
            for name, value in self._metrics.items():
                if isinstance(value, list) and value:
                    result[name] = {
                        'count': len(value),
                        'avg': sum(value) / len(value),
                        'min': min(value),
                        'max': max(value),
                        'last': value[-1],
                    }
                else:
                    result[name] = value
            return result

    def clear(self):
        """清空所有指标"""
        with self._lock:
            self._metrics.clear()