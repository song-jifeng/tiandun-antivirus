#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 通用工具函数
"""
import os
import re
import sys
import time
import json
import struct
import base64
import shutil
import fnmatch
import hashlib
import tempfile
import threading
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Set, Callable
from datetime import datetime, timedelta

# ============================================================
# 路径工具
# ============================================================
class PathUtil:
    """路径相关工具函数"""

    COMMON_SYSTEM_PATHS = [
        'C:\\Windows', 'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
        'C:\\Program Files', 'C:\\Program Files (x86)',
        'C:\\ProgramData', 'C:\\Users',
    ]

    @staticmethod
    def normalize(path: str) -> str:
        """规范化路径"""
        return os.path.normpath(os.path.abspath(path))

    @staticmethod
    def is_system_path(path: str) -> bool:
        """判断是否为系统路径"""
        path = PathUtil.normalize(path).lower()
        for sp in PathUtil.COMMON_SYSTEM_PATHS:
            if path.startswith(sp.lower()):
                return True
        return False

    @staticmethod
    def is_hidden(path: str) -> bool:
        """判断是否为隐藏文件/目录"""
        try:
            attrs = os.stat(path).st_file_attributes
            return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            return os.path.basename(path).startswith('.')

    @staticmethod
    def get_drives() -> List[str]:
        """获取所有可用驱动器"""
        drives = []
        if sys.platform == 'win32':
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drives.append(f'{chr(65 + i)}:\\')
        else:
            for p in ['/']:
                if os.path.exists(p):
                    drives.append(p)
        return drives

    @staticmethod
    def get_common_dirs() -> List[str]:
        """获取需要扫描的常见目录"""
        dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.environ.get('APPDATA', ''),
            os.environ.get('LOCALAPPDATA', ''),
            os.environ.get('PROGRAMDATA', ''),
            os.environ.get('USERPROFILE', ''),
            os.environ.get('PUBLIC', ''),
            'C:\\Windows\\Temp',
            'C:\\Windows\\System32\\drivers\\etc',
        ]
        if os.environ.get('HOMEDRIVE') and os.environ.get('HOMEPATH'):
            dirs.append(os.environ['HOMEDRIVE'] + os.environ['HOMEPATH'])
        return [d for d in dirs if d and os.path.exists(d)]

    @staticmethod
    def get_desktop_path() -> str:
        """获取桌面路径"""
        return os.path.join(os.environ.get('USERPROFILE', 'C:'), 'Desktop')

    @staticmethod
    def get_downloads_path() -> str:
        """获取下载文件夹路径"""
        return os.path.join(os.environ.get('USERPROFILE', 'C:'), 'Downloads')

    @staticmethod
    def get_startup_paths() -> List[str]:
        """获取所有启动项路径"""
        paths = []
        # 当前用户启动文件夹
        startup = os.path.join(
            os.environ.get('APPDATA', ''),
            'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        )
        if os.path.exists(startup):
            paths.append(startup)
        # 所有用户启动文件夹
        common_startup = os.path.join(
            os.environ.get('PROGRAMDATA', ''),
            'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        )
        if os.path.exists(common_startup):
            paths.append(common_startup)
        # 注册表启动项
        paths.append('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
        paths.append('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
        return paths


# ============================================================
# 文件工具
# ============================================================
class FileUtil:
    """文件操作工具函数"""

    @staticmethod
    def get_size_str(size_bytes: int) -> str:
        """获取可读的文件大小字符串"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def get_time_str(timestamp: float) -> str:
        """获取可读的时间字符串"""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def safe_delete(path: str) -> bool:
        """安全删除文件（覆盖后再删除）"""
        try:
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            # 覆盖文件内容
            if size > 0:
                with open(path, 'wb') as f:
                    f.write(os.urandom(min(size, 1024 * 1024)))  # 最多覆盖1MB
                if size > 1024 * 1024:
                    with open(path, 'wb') as f:
                        f.truncate(0)
            os.remove(path)
            return True
        except Exception:
            return False

    @staticmethod
    def safe_move(src: str, dst: str) -> bool:
        """安全移动文件"""
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            return True
        except Exception:
            return False

    @staticmethod
    def safe_copy(src: str, dst: str) -> bool:
        """安全复制文件"""
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            return True
        except Exception:
            return False

    @staticmethod
    def get_file_attributes(path: str) -> Dict[str, Any]:
        """获取文件属性"""
        attrs = {}
        try:
            stat = os.stat(path)
            attrs['size'] = stat.st_size
            attrs['created'] = stat.st_ctime
            attrs['modified'] = stat.st_mtime
            attrs['accessed'] = stat.st_atime
            attrs['is_dir'] = os.path.isdir(path)
            attrs['is_file'] = os.path.isfile(path)
            attrs['is_hidden'] = PathUtil.is_hidden(path)
            attrs['extension'] = os.path.splitext(path)[1].lower()
            if sys.platform == 'win32':
                attrs['attributes'] = stat.st_file_attributes
        except Exception:
            pass
        return attrs

    @staticmethod
    def is_binary(filepath: str, sample_size: int = 8192) -> bool:
        """判断文件是否为二进制文件"""
        try:
            with open(filepath, 'rb') as f:
                sample = f.read(sample_size)
            return b'\x00' in sample
        except Exception:
            return True

    @staticmethod
    def read_file_safe(filepath: str, mode: str = 'rb',
                       max_size: int = 10 * 1024 * 1024) -> Optional[bytes]:
        """安全读取文件（带大小限制）"""
        try:
            size = os.path.getsize(filepath)
            if size > max_size:
                return None
            with open(filepath, mode) as f:
                return f.read()
        except Exception:
            return None

    @staticmethod
    def list_files(directory: str, pattern: str = '*',
                   recursive: bool = True) -> List[str]:
        """列出目录中的文件"""
        files = []
        try:
            if recursive:
                for root, _, filenames in os.walk(directory):
                    for f in filenames:
                        if fnmatch.fnmatch(f, pattern):
                            files.append(os.path.join(root, f))
            else:
                for f in os.listdir(directory):
                    fpath = os.path.join(directory, f)
                    if os.path.isfile(fpath) and fnmatch.fnmatch(f, pattern):
                        files.append(fpath)
        except Exception:
            pass
        return files


# ============================================================
# 进程工具
# ============================================================
class ProcessUtil:
    """进程操作工具函数"""

    @staticmethod
    def get_process_list() -> List[Dict[str, Any]]:
        """获取进程列表"""
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username',
                                              'cpu_percent', 'memory_percent',
                                              'create_time', 'status']):
                try:
                    pinfo = proc.info
                    if pinfo['exe']:
                        processes.append(pinfo)
                except Exception:
                    pass
        except ImportError:
            # 使用 wmic 作为后备
            try:
                output = subprocess.check_output(
                    'wmic process get ProcessId,Name,ExecutablePath /format:csv',
                    shell=True, timeout=5
                ).decode('utf-8', errors='replace')
                for line in output.strip().split('\n')[1:]:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        processes.append({
                            'pid': int(parts[1]) if parts[1].strip().isdigit() else 0,
                            'name': parts[2].strip() if len(parts) > 2 else '',
                            'exe': parts[0].strip() if len(parts) > 0 else '',
                        })
            except Exception:
                pass
        return processes

    @staticmethod
    def kill_process(pid: int) -> bool:
        """终止进程"""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True
        except Exception:
            try:
                subprocess.run(f'taskkill /F /PID {pid}', shell=True,
                             capture_output=True, timeout=5)
                return True
            except Exception:
                return False

    @staticmethod
    def is_process_running(pid: int) -> bool:
        """检查进程是否在运行"""
        try:
            import psutil
            return psutil.pid_exists(pid)
        except Exception:
            try:
                subprocess.run(f'taskkill /PID {pid} /F 2>nul', shell=True,
                             capture_output=True, timeout=2)
                return False
            except Exception:
                return True

    @staticmethod
    def get_process_path(pid: int) -> str:
        """获取进程路径"""
        try:
            import psutil
            return psutil.Process(pid).exe()
        except Exception:
            return ''

    @staticmethod
    def get_process_by_name(name: str) -> List[int]:
        """根据进程名查找PID"""
        pids = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and name.lower() in proc.info['name'].lower():
                        pids.append(proc.info['pid'])
                except Exception:
                    pass
        except Exception:
            pass
        return pids


# ============================================================
# 服务工具
# ============================================================
class ServiceUtil:
    """Windows 服务操作工具"""

    @staticmethod
    def get_services() -> List[Dict[str, Any]]:
        """获取所有服务列表"""
        services = []
        try:
            output = subprocess.check_output(
                'sc query type= service state= all',
                shell=True, timeout=10
            ).decode('utf-8', errors='replace')
            # 解析 sc query 输出
            current = {}
            for line in output.split('\n'):
                line = line.strip()
                if 'SERVICE_NAME:' in line:
                    if current:
                        services.append(current)
                    current = {'name': line.split(':', 1)[1].strip()}
                elif 'DISPLAY_NAME:' in line:
                    current['display_name'] = line.split(':', 1)[1].strip()
                elif 'STATE' in line:
                    if 'RUNNING' in line:
                        current['state'] = 'running'
                    elif 'STOPPED' in line:
                        current['state'] = 'stopped'
                    else:
                        current['state'] = 'unknown'
                elif 'START_TYPE' in line:
                    if 'AUTO' in line:
                        current['start_type'] = 'auto'
                    elif 'DEMAND' in line:
                        current['start_type'] = 'manual'
                    elif 'DISABLED' in line:
                        current['start_type'] = 'disabled'
                    else:
                        current['start_type'] = 'unknown'
            if current:
                services.append(current)
        except Exception:
            pass
        return services

    @staticmethod
    def stop_service(name: str) -> bool:
        """停止服务"""
        try:
            subprocess.run(f'net stop "{name}" /y', shell=True,
                         capture_output=True, timeout=10)
            return True
        except Exception:
            return False

    @staticmethod
    def delete_service(name: str) -> bool:
        """删除服务"""
        try:
            subprocess.run(f'sc delete "{name}"', shell=True,
                         capture_output=True, timeout=10)
            return True
        except Exception:
            return False

    @staticmethod
    def disable_service(name: str) -> bool:
        """禁用服务"""
        try:
            subprocess.run(f'sc config "{name}" start= disabled',
                         shell=True, capture_output=True, timeout=10)
            return True
        except Exception:
            return False


# ============================================================
# 注册表工具
# ============================================================
class RegistryUtil:
    """注册表操作工具"""

    HIVE_MAP = {
        'HKCR': 0x80000000,  # HKEY_CLASSES_ROOT
        'HKCU': 0x80000001,  # HKEY_CURRENT_USER
        'HKLM': 0x80000002,  # HKEY_LOCAL_MACHINE
        'HKU':  0x80000003,  # HKEY_USERS
        'HKCC': 0x80000005,  # HKEY_CURRENT_CONFIG
    }

    @staticmethod
    def parse_key(full_key: str) -> Tuple[int, str]:
        """解析完整注册表路径为 hive 和子键"""
        for hive_name, hive_value in RegistryUtil.HIVE_MAP.items():
            if full_key.upper().startswith(hive_name):
                subkey = full_key[len(hive_name):].strip('\\')
                return hive_value, subkey
        return RegistryUtil.HIVE_MAP['HKLM'], full_key

    @staticmethod
    def get_value(key_path: str, value_name: str = '') -> Optional[str]:
        """获取注册表值"""
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                return str(value)
        except Exception:
            return None

    @staticmethod
    def set_value(key_path: str, value_name: str, value: str,
                  value_type: int = 1) -> bool:
        """设置注册表值 (1=REG_SZ, 2=REG_EXPAND_SZ, 3=REG_BINARY, 4=REG_DWORD)"""
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            # 尝试打开，不存在则创建
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE)
            except FileNotFoundError:
                key = winreg.CreateKey(hive, subkey)
            with key:
                winreg.SetValueEx(key, value_name, 0, value_type, value)
            return True
        except Exception:
            return False

    @staticmethod
    def delete_value(key_path: str, value_name: str) -> bool:
        """删除注册表值"""
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, value_name)
            return True
        except Exception:
            return False

    @staticmethod
    def delete_key(key_path: str) -> bool:
        """删除注册表键"""
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            winreg.DeleteKey(hive, subkey)
            return True
        except Exception:
            return False

    @staticmethod
    def enum_keys(key_path: str) -> List[str]:
        """枚举子键"""
        keys = []
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        keys.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return keys

    @staticmethod
    def enum_values(key_path: str) -> List[Tuple[str, Any, int]]:
        """枚举值"""
        values = []
        try:
            import winreg
            hive, subkey = RegistryUtil.parse_key(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, typ = winreg.EnumValue(key, i)
                        values.append((name, value, typ))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return values

    @staticmethod
    def get_startup_entries() -> List[Dict[str, str]]:
        """获取所有启动项"""
        entries = []
        startup_paths = [
            (0x80000001, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (0x80000001, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (0x80000002, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (0x80000002, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (0x80000002, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
            (0x80000002, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]
        try:
            import winreg
            for hive, subkey in startup_paths:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                entries.append({
                                    'name': name,
                                    'value': str(value),
                                    'key': f'{hive}\\{subkey}'
                                })
                                i += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue
        except Exception:
            pass
        return entries


# ============================================================
# 网络工具
# ============================================================
class NetworkUtil:
    """网络操作工具"""

    @staticmethod
    def get_connections() -> List[Dict[str, Any]]:
        """获取网络连接"""
        try:
            import psutil
            conns = []
            for conn in psutil.net_connections():
                conns.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid,
                })
            return conns
        except Exception:
            return []

    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        """获取网络接口"""
        try:
            import psutil
            ifaces = []
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    ifaces.append({
                        'name': name,
                        'address': addr.address,
                        'family': str(addr.family),
                        'netmask': addr.netmask,
                    })
            return ifaces
        except Exception:
            return []

    @staticmethod
    def test_connection(host: str = '8.8.8.8', port: int = 53, timeout: int = 3) -> bool:
        """测试网络连接"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False


# ============================================================
# 字符串工具
# ============================================================
class StringUtil:
    """字符串操作工具"""

    @staticmethod
    def hexdump(data: bytes, length: int = 16) -> str:
        """生成十六进制转储"""
        result = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(f'{i:08x}  {hex_part:<48}  {ascii_part}')
        return '\n'.join(result)

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """从二进制数据中提取可打印字符串"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_length:
            strings.append(''.join(current))
        return strings

    @staticmethod
    def mask_sensitive(data: str, visible_chars: int = 4) -> str:
        """脱敏处理"""
        if len(data) <= visible_chars:
            return '*' * len(data)
        return data[:visible_chars] + '*' * (len(data) - visible_chars)

    @staticmethod
    def truncate(text: str, max_length: int = 100, suffix: str = '...') -> str:
        """截断字符串"""
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix


# ============================================================
# 时间工具
# ============================================================
class TimeUtil:
    """时间工具"""

    @staticmethod
    def now() -> float:
        return time.time()

    @staticmethod
    def now_str() -> str:
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def format_duration(seconds: float) -> str:
        """格式化持续时间"""
        if seconds < 60:
            return f'{seconds:.1f}秒'
        elif seconds < 3600:
            return f'{seconds / 60:.1f}分钟'
        elif seconds < 86400:
            return f'{seconds / 3600:.1f}小时'
        else:
            return f'{seconds / 86400:.1f}天'

    @staticmethod
    def format_timestamp(ts: float) -> str:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def time_ago(ts: float) -> str:
        """获取相对时间描述"""
        diff = time.time() - ts
        if diff < 60:
            return '刚刚'
        elif diff < 3600:
            return f'{int(diff / 60)}分钟前'
        elif diff < 86400:
            return f'{int(diff / 3600)}小时前'
        elif diff < 2592000:
            return f'{int(diff / 86400)}天前'
        elif diff < 31536000:
            return f'{int(diff / 2592000)}个月前'
        else:
            return f'{int(diff / 31536000)}年前'


# ============================================================
# 系统信息
# ============================================================
class SystemInfo:
    """系统信息收集"""

    @staticmethod
    def get_all() -> Dict[str, Any]:
        """获取完整系统信息"""
        info = {
            'os': SystemInfo.get_os_info(),
            'cpu': SystemInfo.get_cpu_info(),
            'memory': SystemInfo.get_memory_info(),
            'disk': SystemInfo.get_disk_info(),
            'processes': len(ProcessUtil.get_process_list()),
            'boot_time': SystemInfo.get_boot_time(),
        }
        return info

    @staticmethod
    def get_os_info() -> Dict[str, str]:
        """获取操作系统信息"""
        try:
            import platform
            return {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
            }
        except Exception:
            return {'system': 'Unknown'}

    @staticmethod
    def get_cpu_info() -> Dict[str, Any]:
        """获取CPU信息"""
        info = {}
        try:
            import psutil
            info['count'] = psutil.cpu_count()
            info['physical_count'] = psutil.cpu_count(logical=False)
            info['percent'] = psutil.cpu_percent(interval=0.1)
            info['freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
            return info
        except Exception:
            return {'count': 0}

    @staticmethod
    def get_memory_info() -> Dict[str, Any]:
        """获取内存信息"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            total = mem.total
            # 某些环境下 psutil 可能返回 0，尝试用 ctypes 获取
            if total == 0:
                try:
                    import ctypes
                    from ctypes import wintypes
                    class MEMORYSTATUSEX(ctypes.Structure):
                        _fields_ = [
                            ('dwLength', ctypes.c_ulong),
                            ('dwMemoryLoad', ctypes.c_ulong),
                            ('ullTotalPhys', ctypes.c_ulonglong),
                            ('ullAvailPhys', ctypes.c_ulonglong),
                            ('ullTotalPageFile', ctypes.c_ulonglong),
                            ('ullAvailPageFile', ctypes.c_ulonglong),
                            ('ullTotalVirtual', ctypes.c_ulonglong),
                            ('ullAvailVirtual', ctypes.c_ulonglong),
                            ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                        ]
                    mem_status = MEMORYSTATUSEX()
                    mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
                        total = mem_status.ullTotalPhys
                except Exception:
                    pass
            return {
                'total': total,
                'available': mem.available,
                'percent': mem.percent,
                'used': mem.used,
                'free': mem.free,
            }
        except Exception:
            return {'total': 0, 'available': 0}

    @staticmethod
    def get_disk_info() -> List[Dict[str, Any]]:
        """获取磁盘信息"""
        disks = []
        try:
            import psutil
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                    })
                except Exception:
                    disks.append({
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                    })
        except Exception:
            pass
        return disks

    @staticmethod
    def get_boot_time() -> float:
        """获取系统启动时间"""
        try:
            import psutil
            return psutil.boot_time()
        except Exception:
            return 0.0


# ============================================================
# 定时器
# ============================================================
class IntervalTimer:
    """定时器工具 - 支持暂停、恢复、动态调整间隔"""

    def __init__(self, interval: float, callback: Callable, name: str = 'timer'):
        self.interval = interval
        self.callback = callback
        self.name = name
        self._running = False
        self._paused = False
        self._thread = None
        self._event = threading.Event()
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._paused = False
            self._event.clear()
            self._thread = threading.Thread(target=self._run, name=self.name, daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False
            self._event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def pause(self):
        with self._lock:
            self._paused = True

    def resume(self):
        with self._lock:
            self._paused = False
            self._event.set()

    def set_interval(self, interval: float):
        with self._lock:
            self.interval = interval

    def _run(self):
        while self._running:
            if self._paused:
                self._event.wait(1)
                continue
            try:
                self.callback()
            except Exception:
                pass
            self._event.wait(self.interval)


# ============================================================
# 版本号
# ============================================================
class Version:
    """版本号比较"""

    @staticmethod
    def parse(version_str: str) -> Tuple[int, ...]:
        """解析版本号字符串"""
        parts = version_str.strip().split('.')
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                # 提取数字部分
                num = ''
                for c in p:
                    if c.isdigit():
                        num += c
                    else:
                        break
                result.append(int(num) if num else 0)
        return tuple(result)

    @staticmethod
    def compare(v1: str, v2: str) -> int:
        """比较两个版本号，返回 -1/0/1"""
        p1 = Version.parse(v1)
        p2 = Version.parse(v2)
        max_len = max(len(p1), len(p2))
        p1 = p1 + (0,) * (max_len - len(p1))
        p2 = p2 + (0,) * (max_len - len(p2))
        for a, b in zip(p1, p2):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0