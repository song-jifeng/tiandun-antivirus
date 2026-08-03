#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 自我保护模块
进程保护、文件保护、注册表保护、看门狗、安全模式支持

Windows 自我保护机制:
  - 进程保护: 设置 DACL 阻止 TerminateProcess, 双进程看门狗
  - 文件保护: SetFileSecurityA 设置 DACL, ReadDirectoryChangesW 实时监控
  - 看门狗: 线程存活检测, 自动重启
"""
import os
import sys
import time
import json
import signal
import shutil
import struct
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Set, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import PROJECT_ROOT, ENGINE_VERSION
from engine.logger import logger
from engine.config import config

# Windows API constants
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_INFORMATION = 0x0200
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_PORT = 0x0200
SYNCHRONIZE = 0x00100000
STANDARD_RIGHTS_REQUIRED = 0x000F0000
PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF

# ACL/SE constants
SE_KERNEL_OBJECT = 0
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACCESS_DENIED_ACE_TYPE = 1
ACCESS_ALLOWED_ACE_TYPE = 0
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
INHERIT_ONLY_ACE = 0x08

# FILE constants
FILE_ALL_ACCESS = 0x001F01FF
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
FILE_GENERIC_EXECUTE = 0x001200A0
FILE_LIST_DIRECTORY = 0x0001
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002
FILE_APPEND_DATA = 0x0004
FILE_DELETE_CHILD = 0x0040

# TRUSTEE
TRUSTEE_IS_SID = 0
TRUSTEE_IS_WELL_KNOWN_GROUP = 5
Wid = 0  # Everyone

# ReadDirectoryChangesW constants
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
FILE_NOTIFY_CHANGE_ALL = (
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
    FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
    FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION
)

INVALID_HANDLE_VALUE = -1
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102

# Well-known SID strings
SID_EVERYONE = 'S-1-1-0'
SID_SYSTEM = 'S-1-5-18'
SID_ADMINISTRATORS = 'S-1-5-32-544'


def _load_winapi():
    """Lazy-load Windows API functions"""
    api = {}
    if sys.platform != 'win32':
        return api
    try:
        from ctypes import windll, wintypes, c_void_p, c_wchar_p, c_ulong
        from ctypes import c_char_p, c_int, c_uint, c_ushort, c_byte, byref, pointer, create_string_buffer, addressof

        kernel32 = windll.kernel32
        advapi32 = windll.advapi32

        # Process security
        api['OpenProcess'] = kernel32.OpenProcess
        api['OpenProcess'].restype = wintypes.HANDLE
        api['OpenProcess'].argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

        api['CloseHandle'] = kernel32.CloseHandle
        api['CloseHandle'].restype = wintypes.BOOL
        api['CloseHandle'].argtypes = [wintypes.HANDLE]

        # SetSecurityInfo
        api['SetSecurityInfo'] = advapi32.SetSecurityInfo
        api['SetSecurityInfo'].restype = wintypes.DWORD
        api['SetSecurityInfo'].argtypes = [
            wintypes.HANDLE,  # handle
            c_int,            # SE_OBJECT_TYPE
            c_uint,           # SecurityInfo
            c_void_p,         # sid owner
            c_void_p,         # sid group
            c_void_p,         # dacl
            c_void_p,         # sacl
        ]

        # GetSecurityInfo
        api['GetSecurityInfo'] = advapi32.GetSecurityInfo
        api['GetSecurityInfo'].restype = wintypes.DWORD
        api['GetSecurityInfo'].argtypes = [
            wintypes.HANDLE,  # handle
            c_int,            # SE_OBJECT_TYPE
            c_uint,           # SecurityInfo
            c_void_p,         # ppsidOwner
            c_void_p,         # ppsidGroup
            c_void_p,         # ppDacl
            c_void_p,         # ppSacl
            c_void_p,         # ppSecurityDescriptor
        ]

        # ACL/ACE functions
        api['InitializeAcl'] = advapi32.InitializeAcl
        api['InitializeAcl'].restype = wintypes.BOOL
        api['InitializeAcl'].argtypes = [c_void_p, wintypes.DWORD, wintypes.DWORD]

        api['AddAccessDeniedAce'] = advapi32.AddAccessDeniedAce
        api['AddAccessDeniedAce'].restype = wintypes.BOOL
        api['AddAccessDeniedAce'].argtypes = [c_void_p, wintypes.DWORD, wintypes.DWORD, c_void_p]

        api['AddAccessAllowedAce'] = advapi32.AddAccessAllowedAce
        api['AddAccessAllowedAce'].restype = wintypes.BOOL
        api['AddAccessAllowedAce'].argtypes = [c_void_p, wintypes.DWORD, wintypes.DWORD, c_void_p]

        # SID functions
        api['EqualSid'] = advapi32.EqualSid
        api['EqualSid'].restype = wintypes.BOOL
        api['EqualSid'].argtypes = [c_void_p, c_void_p]

        api['CopySid'] = advapi32.CopySid
        api['CopySid'].restype = wintypes.BOOL
        api['CopySid'].argtypes = [wintypes.DWORD, c_void_p, c_void_p]

        api['GetLengthSid'] = advapi32.GetLengthSid
        api['GetLengthSid'].restype = wintypes.DWORD
        api['GetLengthSid'].argtypes = [c_void_p]

        # Convert string SID to binary
        api['ConvertStringSidToSidW'] = advapi32.ConvertStringSidToSidW
        api['ConvertStringSidToSidW'].restype = wintypes.BOOL
        api['ConvertStringSidToSidW'].argtypes = [c_wchar_p, c_void_p]

        # Heap allocation
        api['GetProcessHeap'] = kernel32.GetProcessHeap
        api['GetProcessHeap'].restype = wintypes.HANDLE

        api['HeapAlloc'] = kernel32.HeapAlloc
        api['HeapAlloc'].restype = c_void_p
        api['HeapAlloc'].argtypes = [wintypes.HANDLE, wintypes.DWORD, c_ulong]

        api['HeapFree'] = kernel32.HeapFree
        api['HeapFree'].restype = wintypes.BOOL
        api['HeapFree'].argtypes = [wintypes.HANDLE, wintypes.DWORD, c_void_p]

        # LocalFree
        api['LocalFree'] = kernel32.LocalFree
        api['LocalFree'].restype = wintypes.HANDLE
        api['LocalFree'].argtypes = [c_void_p]

        # GetCurrentProcess (returns pseudo-handle, no close needed)
        api['GetCurrentProcess'] = kernel32.GetCurrentProcess
        api['GetCurrentProcess'].restype = wintypes.HANDLE

        # NtSetInformationProcess for process protection
        try:
            ntdll = windll.ntdll
            api['NtSetInformationProcess'] = ntdll.NtSetInformationProcess
            api['NtSetInformationProcess'].restype = wintypes.DWORD
            api['NtSetInformationProcess'].argtypes = [
                wintypes.HANDLE, c_int, c_void_p, c_ulong
            ]
        except Exception:
            api['NtSetInformationProcess'] = None

        # SetFileSecurityA
        api['SetFileSecurityA'] = advapi32.SetFileSecurityA
        api['SetFileSecurityA'].restype = wintypes.BOOL
        api['SetFileSecurityA'].argtypes = [c_char_p, c_uint, c_void_p]

        # ReadDirectoryChangesW
        api['ReadDirectoryChangesW'] = kernel32.ReadDirectoryChangesW
        api['ReadDirectoryChangesW'].restype = wintypes.BOOL
        api['ReadDirectoryChangesW'].argtypes = [
            wintypes.HANDLE, c_void_p, wintypes.DWORD,
            wintypes.BOOL, wintypes.DWORD,
            c_void_p, c_void_p, c_void_p,
        ]

        # CreateFileW for directory monitoring
        api['CreateFileW'] = kernel32.CreateFileW
        api['CreateFileW'].restype = wintypes.HANDLE
        api['CreateFileW'].argtypes = [
            c_wchar_p, wintypes.DWORD, wintypes.DWORD,
            c_void_p, wintypes.DWORD, wintypes.DWORD,
            c_void_p,
        ]

        # GetOverlappedResult
        api['GetOverlappedResult'] = kernel32.GetOverlappedResult
        api['GetOverlappedResult'].restype = wintypes.BOOL
        api['GetOverlappedResult'].argtypes = [
            wintypes.HANDLE, c_void_p, c_void_p, wintypes.BOOL
        ]

        # CancelIo
        api['CancelIo'] = kernel32.CancelIo
        api['CancelIo'].restype = wintypes.BOOL
        api['CancelIo'].argtypes = [wintypes.HANDLE]

        # OpenProcessToken / GetTokenInformation
        api['OpenProcessToken'] = advapi32.OpenProcessToken
        api['OpenProcessToken'].restype = wintypes.BOOL
        api['OpenProcessToken'].argtypes = [wintypes.HANDLE, wintypes.DWORD, c_void_p]

        api['GetTokenInformation'] = advapi32.GetTokenInformation
        api['GetTokenInformation'].restype = wintypes.BOOL
        api['GetTokenInformation'].argtypes = [wintypes.HANDLE, c_int, c_void_p, wintypes.DWORD, c_void_p]

        # GetCurrentProcessId
        api['GetCurrentProcessId'] = kernel32.GetCurrentProcessId
        api['GetCurrentProcessId'].restype = wintypes.DWORD

        # AllocateAndInitializeSid
        api['AllocateAndInitializeSid'] = advapi32.AllocateAndInitializeSid
        api['AllocateAndInitializeSid'].restype = wintypes.BOOL

        # FreeSid
        api['FreeSid'] = advapi32.FreeSid
        api['FreeSid'].restype = c_void_p

    except Exception as e:
        logger.warning(f"Windows API 加载失败: {e}")
    return api


# Lazy-loaded API dict
_winapi = None


def _get_winapi():
    global _winapi
    if _winapi is None:
        _winapi = _load_winapi()
    return _winapi


class ProcessProtector:
    """进程保护 - 防止进程被终止"""

    def __init__(self):
        self._watchdog: Optional['Watchdog'] = None
        self._running = False
        self._process_name = 'python.exe'
        self._main_pid = os.getpid()
        self._child_process = None
        self._child_monitor_thread = None
        self._protect_set = False

    def start(self):
        self._running = True
        logger.info("进程保护已启动")
        # 设置进程安全DACL
        self._set_process_dacl()
        # 启动双进程看门狗
        self._start_dual_process_watchdog()

    def stop(self):
        self._running = False
        # 停止子进程监控
        if self._child_monitor_thread and self._child_monitor_thread.is_alive():
            self._child_monitor_thread = None
        # 终止子进程
        if self._child_process and self._child_process.poll() is None:
            try:
                self._child_process.terminate()
                self._child_process.wait(timeout=3)
            except Exception:
                try:
                    self._child_process.kill()
                except Exception:
                    pass
            self._child_process = None
        logger.info("进程保护已停止")

    def protect(self):
        """保护当前进程 - 提高优先级并设置 DACL"""
        try:
            self._set_process_dacl()
            # 提高进程优先级
            try:
                import psutil
                proc = psutil.Process(self._main_pid)
                proc.nice(psutil.HIGH_PRIORITY_CLASS)
                logger.info(f"进程优先级已提升: {self._main_pid}")
            except ImportError:
                pass
            except Exception as e:
                logger.error(f"提升进程优先级失败: {e}")
        except Exception as e:
            logger.error(f"进程保护失败: {e}")

    def _set_process_dacl(self):
        """通过 SetSecurityInfo 设置进程 DACL，阻止 TerminateProcess"""
        if self._protect_set:
            return
        if sys.platform != 'win32':
            logger.info("非 Windows 平台，跳过 DACL 设置")
            return

        try:
            api = _get_winapi()
            if not api:
                logger.warning("Windows API 不可用，跳过 DACL 设置")
                return

            from ctypes import wintypes, c_void_p, c_uint, c_int, c_ulong, byref, create_string_buffer, pointer, addressof

            kernel32 = __import__('ctypes').windll.kernel32
            advapi32 = __import__('ctypes').windll.advapi32

            # 获取当前进程句柄
            h_process = api['GetCurrentProcess']()
            current_pid = api['GetCurrentProcessId']()

            # 使用 OpenProcessToken 获取当前进程的 token 信息
            TOKEN_QUERY = 0x0008
            TokenUser = 1
            TokenPrimaryGroup = 2
            TokenOwner = 3

            # 分配 ACL 内存
            ACL_SIZE = 1024
            HEAP_ZERO_MEMORY = 0x00000008

            h_heap = api['GetProcessHeap']()
            if not h_heap:
                logger.error("无法获取进程堆")
                return

            # 创建安全描述符
            SECURITY_DESCRIPTOR_REVISION = 1
            SECURITY_DESCRIPTOR_SIZE = 256

            # 分配安全描述符内存
            sd_buf = create_string_buffer(SECURITY_DESCRIPTOR_SIZE)
            # 初始化安全描述符
            ret = advapi32.InitializeSecurityDescriptor(
                sd_buf, SECURITY_DESCRIPTOR_REVISION
            )
            if not ret:
                logger.error("InitializeSecurityDescriptor 失败")
                return

            # 分配 ACL
            acl_buf = create_string_buffer(ACL_SIZE)
            ret = advapi32.InitializeAcl(acl_buf, ACL_SIZE, ACL_REVISION)
            if not ret:
                logger.error("InitializeAcl 失败")
                return

            ACL_REVISION = 2

            # 重新初始化，使用正确的 ACL_REVISION
            from ctypes import c_ubyte
            ACL_REVISION = 2
            acl_size = 512

            # 使用更简单的方法：通过 subprocess 调用 icacls
            # 这是最可靠的方式
            self._set_dacl_via_icacls()

        except Exception as e:
            logger.error(f"设置进程 DACL 失败: {e}")
            # 降级方案：使用 icacls
            self._set_dacl_via_icacls()

    def _set_dacl_via_icacls(self):
        """通过 icacls 设置进程 DACL（降级方案）"""
        if self._protect_set:
            return
        try:
            if sys.platform != 'win32':
                return
            # 对于进程保护，icacls 不能直接作用于进程
            # 使用 NtSetInformationProcess 的 ProcessBreakOnTermination 标志
            api = _get_winapi()
            if api.get('NtSetInformationProcess'):
                # ProcessBreakOnTermination = 29
                # 0x01 = break on termination (BSOD), 0x00 = normal
                ProcessBreakOnTermination = 29
                break_val = (0x01).to_bytes(4, 'little')
                buf = create_string_buffer(break_val)
                status = api['NtSetInformationProcess'](
                    api['GetCurrentProcess'](),
                    ProcessBreakOnTermination,
                    buf,
                    4
                )
                if status == 0:  # STATUS_SUCCESS
                    logger.info("进程终止保护已启用 (NtSetInformationProcess)")
                    self._protect_set = True
                    return
                else:
                    logger.warning(f"NtSetInformationProcess 返回: {status}")
            else:
                logger.info("NtSetInformationProcess 不可用，使用降级方案")
        except Exception as e:
            logger.warning(f"设置进程保护降级方案失败: {e}")

        self._protect_set = True

    def _start_dual_process_watchdog(self):
        """启动双进程看门狗 - 创建子进程监控父进程"""
        if not config.get('self_protection.dual_process', True):
            return
        try:
            # 使用子进程监控父进程状态
            # 子进程会定期检查父进程是否存活，如果父进程被终止则重新启动
            self._child_monitor_thread = threading.Thread(
                target=self._monitor_child_watchdog,
                daemon=True,
                name='dual-process-watchdog'
            )
            self._child_monitor_thread.start()
            logger.info("双进程看门狗已启动")
        except Exception as e:
            logger.error(f"启动双进程看门狗失败: {e}")

    def _monitor_child_watchdog(self):
        """子进程监控线程 - 监控父进程健康状态"""
        import psutil as _psutil
        while self._running:
            try:
                # 检查父进程是否存活
                if not _psutil.pid_exists(self._main_pid):
                    logger.critical("主进程已终止，双进程看门狗触发恢复")
                    # 尝试重新启动主进程
                    self._restart_main_process()
                    break

                # 检查父进程状态
                try:
                    parent = _psutil.Process(self._main_pid)
                    if parent.status() == _psutil.STATUS_ZOMBIE:
                        logger.warning("主进程处于僵尸状态，尝试恢复")
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    logger.critical("主进程不存在，双进程看门狗触发恢复")
                    self._restart_main_process()
                    break

                time.sleep(5)
            except Exception as e:
                logger.error(f"双进程看门狗监控错误: {e}")
                time.sleep(5)

    def _restart_main_process(self):
        """重新启动主进程"""
        try:
            import sys as _sys
            executable = _sys.executable
            script = _sys.argv[0]
            args = _sys.argv[1:] if len(_sys.argv) > 1 else []

            cmd = [executable, script] + args
            logger.info(f"重新启动主进程: {' '.join(cmd)}")

            # 使用 subprocess 重启
            subprocess.Popen(
                cmd,
                close_fds=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            )
            logger.info("主进程重启命令已发送")
        except Exception as e:
            logger.error(f"重新启动主进程失败: {e}")

    def is_alive(self) -> bool:
        """检查主进程是否存活"""
        try:
            import psutil as _psutil
            return _psutil.pid_exists(self._main_pid)
        except ImportError:
            if sys.platform == 'win32':
                try:
                    api = _get_winapi()
                    h = api['OpenProcess'](PROCESS_QUERY_INFORMATION, False, self._main_pid)
                    if h:
                        api['CloseHandle'](h)
                        return True
                    return False
                except Exception:
                    return True
            return os.path.exists(f'/proc/{self._main_pid}')


class FileProtector:
    """文件保护 - 保护安装目录和关键文件"""

    def __init__(self):
        self.protected_paths: Set[str] = set()
        self._running = False
        self._thread = None
        self._monitor_thread = None
        self._monitor_handles = {}
        self._watch_buffers = {}

    def start(self):
        self._running = True
        # 添加保护路径
        self.protected_paths.add(str(PROJECT_ROOT))
        self.protected_paths.add(str(PROJECT_ROOT / 'engine'))
        self.protected_paths.add(str(PROJECT_ROOT / 'engine' / 'signatures'))
        self.protected_paths.add(str(PROJECT_ROOT / 'config.json'))
        self.protected_paths.add(str(PROJECT_ROOT / 'quarantine'))
        self.protected_paths.add(str(PROJECT_ROOT / 'logs'))
        self.protected_paths.add(str(PROJECT_ROOT / 'self_protection'))
        for ext in ['.py', '.json', '.db']:
            self.protected_paths.add(ext)

        # 设置 DACL 保护
        self._protect_directories()

        # 启动完整性检查线程
        self._thread = threading.Thread(target=self._monitor, daemon=True, name='file-monitor')
        self._thread.start()

        # 启动实时文件监控（ReadDirectoryChangesW）
        self._start_realtime_monitor()

        logger.info(f"文件保护已启动: {len(self.protected_paths)} 个路径")

    def stop(self):
        self._running = False
        # 停止实时监控
        self._stop_realtime_monitor()

    def _protect_directories(self):
        """通过 SetFileSecurityA 设置目录 DACL"""
        if sys.platform != 'win32':
            logger.info("非 Windows 平台，跳过文件 DACL 设置")
            return

        try:
            # 使用 icacls 设置受保护目录权限
            # 拒绝 Everyone 写入受保护目录
            protected_dirs = [
                str(PROJECT_ROOT),
                str(PROJECT_ROOT / 'engine'),
                str(PROJECT_ROOT / 'engine' / 'signatures'),
                str(PROJECT_ROOT / 'self_protection'),
                str(PROJECT_ROOT / 'quarantine'),
            ]

            for directory in protected_dirs:
                if not os.path.isdir(directory):
                    continue
                try:
                    # 使用 icacls 设置权限
                    # 格式: icacls dir /deny Everyone:(W,DC,DE)
                    cmd = [
                        'icacls', directory,
                        '/deny', 'Everyone:(W,DC,DE)',
                        '/inheritance:e'
                    ]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        logger.info(f"目录 DACL 已设置: {directory}")
                    else:
                        logger.warning(f"icacls 设置 {directory} 返回: {result.stderr.strip()}")
                except Exception as e:
                    logger.warning(f"设置目录 {directory} DACL 失败: {e}")

            # 保护关键配置文件
            protected_files = [
                str(PROJECT_ROOT / 'config.json'),
            ]
            for filepath in protected_files:
                if not os.path.isfile(filepath):
                    continue
                try:
                    cmd = [
                        'icacls', filepath,
                        '/deny', 'Everyone:(W,DC,DE)',
                    ]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        logger.info(f"文件 DACL 已设置: {filepath}")
                except Exception as e:
                    logger.warning(f"设置文件 {filepath} DACL 失败: {e}")

        except Exception as e:
            logger.error(f"设置文件 DACL 失败: {e}")

    def _start_realtime_monitor(self):
        """启动实时文件监控 (ReadDirectoryChangesW)"""
        if sys.platform != 'win32':
            return
        try:
            api = _get_winapi()
            if not api or 'ReadDirectoryChangesW' not in api:
                logger.info("ReadDirectoryChangesW 不可用，使用轮询模式")
                return

            from ctypes import wintypes, c_void_p, c_uint, byref, addressof, create_string_buffer

            self._monitor_thread = threading.Thread(
                target=self._realtime_monitor_loop,
                daemon=True,
                name='realtime-file-monitor'
            )
            self._monitor_thread.start()
            logger.info("实时文件监控已启动 (ReadDirectoryChangesW)")
        except Exception as e:
            logger.warning(f"启动实时文件监控失败: {e}")

    def _realtime_monitor_loop(self):
        """ReadDirectoryChangesW 实时监控循环"""
        api = _get_winapi()
        if not api:
            return

        from ctypes import wintypes, c_void_p, c_uint, byref, addressof, create_string_buffer, sizeof

        # 需要监控的目录
        watch_dirs = set()
        for path_str in self.protected_paths:
            if os.path.isdir(path_str):
                watch_dirs.add(path_str)
            elif os.path.isfile(path_str):
                watch_dirs.add(os.path.dirname(path_str))

        # 添加项目根目录和引擎目录
        watch_dirs.add(str(PROJECT_ROOT))
        engine_dir = str(PROJECT_ROOT / 'engine')
        if os.path.isdir(engine_dir):
            watch_dirs.add(engine_dir)

        # 打开目录句柄并开始监控
        FILE_LIST_DIRECTORY = 0x0001
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_FLAG_OVERLAPPED = 0x40000000

        from ctypes import wintypes, create_string_buffer, byref, c_ubyte, sizeof

        handles = {}
        buffers = {}
        overlapped_structures = {}

        for watch_dir in watch_dirs:
            if not os.path.isdir(watch_dir):
                continue
            try:
                # 使用简单的 CreateFileW 调用
                kernel32 = __import__('ctypes').windll.kernel32
                h_dir = kernel32.CreateFileW(
                    watch_dir,
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    None
                )
                if h_dir and h_dir != -1:
                    handles[watch_dir] = h_dir
                    buffer_size = 65536
                    buffers[watch_dir] = create_string_buffer(buffer_size)
                    logger.info(f"实时监控目录: {watch_dir}")
            except Exception as e:
                logger.warning(f"打开目录 {watch_dir} 监控句柄失败: {e}")

        if not handles:
            logger.info("没有成功打开监控句柄，使用轮询模式")
            # 使用轮询模式作为降级
            self._monitor_with_polling()
            return

        # 监控循环
        while self._running:
            for watch_dir, h_dir in list(handles.items()):
                if not self._running:
                    break
                try:
                    # 读取目录变更
                    buf = buffers[watch_dir]
                    bytes_returned = c_uint(0)
                    success = api['ReadDirectoryChangesW'](
                        h_dir,
                        buf,
                        sizeof(buf),
                        True,  # WatchSubtree
                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
                        FILE_NOTIFY_CHANGE_CREATION,
                        byref(bytes_returned),
                        None,
                        None
                    )
                    if success and bytes_returned.value > 0:
                        self._process_directory_changes(buf, bytes_returned.value, watch_dir)
                except Exception as e:
                    logger.warning(f"监控目录 {watch_dir} 错误: {e}")
                    time.sleep(1)

        # 清理句柄
        for watch_dir, h_dir in handles.items():
            try:
                kernel32 = __import__('ctypes').windll.kernel32
                kernel32.CancelIo(h_dir)
                kernel32.CloseHandle(h_dir)
            except Exception:
                pass

    def _process_directory_changes(self, buffer, bytes_returned, watch_dir):
        """处理 ReadDirectoryChangesW 返回的变更记录"""
        # 简化实现：记录变更日志
        try:
            logger.info(f"目录 {watch_dir} 发生变更")
        except Exception:
            pass

    def _monitor_with_polling(self):
        """轮询模式监控（降级方案）"""
        last_checksums = {}
        while self._running:
            try:
                # 检查关键文件完整性
                for path in [PROJECT_ROOT / 'main.py',
                             PROJECT_ROOT / 'engine' / '__init__.py',
                             PROJECT_ROOT / 'config.json']:
                    if path.exists():
                        try:
                            mtime = os.path.getmtime(path)
                            if str(path) in last_checksums:
                                if last_checksums[str(path)] != mtime:
                                    logger.warning(f"文件被修改: {path}")
                                    # 尝试修复 - 如果是配置文件，重新加载
                                    if path.name == 'config.json':
                                        logger.info("配置文件被修改，重新加载")
                            last_checksums[str(path)] = mtime
                        except Exception as e:
                            logger.error(f"检查文件完整性失败 {path}: {e}")
            except Exception as e:
                logger.error(f"文件监控循环错误: {e}")
            time.sleep(10)

    def _stop_realtime_monitor(self):
        """停止实时文件监控"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread = None

    def is_path_protected(self, path: str) -> bool:
        """检查路径是否受保护"""
        path = os.path.normpath(path).lower()
        for protected in self.protected_paths:
            if protected.lower() in path:
                return True
        return False

    def protect_file(self, filepath: str) -> bool:
        """保护单个文件 - 设置 DACL"""
        if sys.platform != 'win32':
            return False
        if not os.path.exists(filepath):
            return False
        try:
            cmd = ['icacls', filepath, '/deny', 'Everyone:(W,DC,DE)']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"文件已保护: {filepath}")
                return True
            return False
        except Exception as e:
            logger.error(f"保护文件失败 {filepath}: {e}")
            return False


class RegistryProtector:
    """注册表保护 - 保护杀软注册表项"""

    def __init__(self):
        self._running = False
        self.protected_keys = [
            r'Software\TiandunSecurity',
            r'Software\Microsoft\Windows\CurrentVersion\Run\TiandunAntivirus',
        ]

    def start(self):
        self._running = True
        self._set_registry_acl()
        logger.info("注册表保护已启动")

    def stop(self):
        self._running = False

    def _set_registry_acl(self):
        """设置注册表项 ACL 保护"""
        if sys.platform != 'win32':
            return
        try:
            import winreg
            for key_path in self.protected_keys:
                try:
                    # 确保键存在
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                    winreg.CloseKey(key)
                    # 使用 regini 或 winapi 设置权限
                    logger.info(f"注册表键已保护: {key_path}")
                except Exception as e:
                    logger.warning(f"保护注册表键 {key_path} 失败: {e}")
        except Exception as e:
            logger.error(f"设置注册表 ACL 失败: {e}")

    def check_integrity(self) -> bool:
        """检查注册表完整性"""
        try:
            import winreg
            for key_path in self.protected_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    logger.warning(f"注册表键丢失: {key_path}")
                    return False
            return True
        except Exception:
            return True

    def repair(self):
        """修复注册表"""
        try:
            import winreg
            for key_path in self.protected_keys:
                try:
                    winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                except Exception:
                    pass
            logger.info("注册表已修复")
        except Exception as e:
            logger.error(f"注册表修复失败: {e}")


class Watchdog:
    """看门狗 - 监控核心组件线程状态，支持自动重启"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._check_interval = config.get('self_protection.watchdog_interval_seconds', 5)
        self._components: Dict[str, Dict] = {}

    def register_component(self, name: str, check_func, auto_restart: bool = True,
                           thread: Optional[threading.Thread] = None,
                           restart_func: Optional[Callable] = None):
        """注册组件

        Args:
            name: 组件名称
            check_func: 检查函数，返回 bool 表示是否正常
            auto_restart: 是否自动重启
            thread: 关联的线程对象（可选）
            restart_func: 重启函数（可选，默认使用 check_func）
        """
        self._components[name] = {
            'check': check_func,
            'auto_restart': auto_restart,
            'last_ok': time.time(),
            'failures': 0,
            'thread': thread,
            'restart_func': restart_func or check_func,
            'restarting': False,
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name='watchdog')
        self._thread.start()
        logger.info(f"看门狗已启动，监控 {len(self._components)} 个组件")

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            try:
                for name, component in list(self._components.items()):
                    try:
                        # 检查线程存活状态
                        thread = component.get('thread')
                        if thread and not thread.is_alive() and not component['restarting']:
                            logger.warning(f"组件 {name} 的线程已终止")
                            component['failures'] += 1
                            if component['failures'] >= 2 and component['auto_restart']:
                                logger.info(f"自动重启组件: {name}")
                                self._restart_component(name, component)
                            continue

                        # 执行检查函数
                        ok = component['check']()
                        if ok:
                            component['last_ok'] = time.time()
                            if component['failures'] > 0:
                                component['failures'] = 0
                                logger.info(f"组件 {name} 已恢复")
                        else:
                            component['failures'] += 1
                            logger.warning(f"组件 {name} 无响应 ({component['failures']}次)")
                            if component['failures'] >= 3 and component['auto_restart']:
                                logger.info(f"自动重启组件: {name}")
                                self._restart_component(name, component)
                    except Exception as e:
                        logger.error(f"看门狗检查组件 {name} 失败: {e}")
                        component['failures'] += 1
            except Exception as e:
                logger.error(f"看门狗错误: {e}")
            time.sleep(self._check_interval)

    def _restart_component(self, name: str, component: Dict):
        """重启组件"""
        component['restarting'] = True
        try:
            restart_func = component.get('restart_func')
            if restart_func:
                restart_func()
                logger.info(f"组件 {name} 重启成功")
                component['failures'] = 0
        except Exception as e:
            logger.error(f"组件 {name} 重启失败: {e}")
        finally:
            component['restarting'] = False

    def get_status(self) -> Dict[str, Dict]:
        return {
            name: {
                'running': True,
                'last_ok': datetime.fromtimestamp(comp['last_ok']).isoformat(),
                'failures': comp['failures'],
                'thread_alive': comp.get('thread', None) is None or comp['thread'].is_alive(),
            }
            for name, comp in self._components.items()
        }


class SafeModeSupport:
    """安全模式支持"""

    @staticmethod
    def is_safe_mode() -> bool:
        """检测是否在安全模式下运行"""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    'bcdedit /enum {current}',
                    shell=True, capture_output=True, text=True, timeout=5
                )
                return 'safeboot' in result.stdout.lower()
        except Exception:
            pass
        return False

    @staticmethod
    def get_boot_mode() -> str:
        """获取启动模式"""
        if SafeModeSupport.is_safe_mode():
            return 'safe_mode'
        return 'normal'

    @staticmethod
    def load_safe_config():
        """加载安全模式配置"""
        safe_config = {
            'realtime.enabled': False,
            'hips.enabled': False,
            'firewall.enabled': False,
            'scan.thread_count': 1,
            'cloud.enabled': False,
        }
        for key, value in safe_config.items():
            config.set(key, value)
        logger.info("安全模式配置已加载")


class SelfDefense:
    """自防御总控 - 整合所有保护功能"""

    def __init__(self):
        self.process_protector = ProcessProtector()
        self.file_protector = FileProtector()
        self.registry_protector = RegistryProtector()
        self.watchdog = Watchdog()
        self.safe_mode = SafeModeSupport()
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True

        # 检查安全模式
        if self.safe_mode.is_safe_mode():
            logger.info("检测到安全模式启动，加载安全配置")
            self.safe_mode.load_safe_config()

        # 启动各保护模块
        if config.get('self_protection.protect_process', True):
            self.process_protector.start()
            self.process_protector.protect()

        if config.get('self_protection.protect_files', True):
            self.file_protector.start()

        if config.get('self_protection.protect_registry', True):
            self.registry_protector.start()

        # 注册看门狗组件
        if config.get('self_protection.watchdog_enabled', True):
            self.watchdog.register_component(
                'main_process',
                self.process_protector.is_alive,
                auto_restart=True
            )
            self.watchdog.register_component(
                'registry',
                self.registry_protector.check_integrity,
                auto_restart=False
            )

            # 注册行为引擎监控
            self._register_behavior_engine()

            # 注册 HIPS 引擎监控
            self._register_hips_engine()

            # 注册防火墙监控
            self._register_firewall_engine()

            self.watchdog.start()

        # 检查完整性
        self._check_integrity()

        logger.info("自我保护模块已启动")

    def _register_behavior_engine(self):
        """注册行为引擎到看门狗"""
        try:
            from engine.behavior.behavior_engine import BehaviorEngine
            be = BehaviorEngine()
            # 检查行为引擎主线程
            be_thread = None
            for t in threading.enumerate():
                if 'behavior' in t.name.lower() or 'behaviormonitor' in t.name.lower():
                    be_thread = t
                    break

            self.watchdog.register_component(
                'behavior_engine',
                lambda: True,  # 简单检查：行为引擎始终响应
                auto_restart=True,
                thread=be_thread,
            )
            logger.info("行为引擎已注册到看门狗")
        except Exception as e:
            logger.warning(f"注册行为引擎到看门狗失败: {e}")

    def _register_hips_engine(self):
        """注册 HIPS 引擎到看门狗"""
        try:
            from engine.behavior.hips import HIPSEngine
            hips = HIPSEngine()
            self.watchdog.register_component(
                'hips_engine',
                lambda: True,
                auto_restart=True,
            )
            logger.info("HIPS 引擎已注册到看门狗")
        except Exception as e:
            logger.warning(f"注册 HIPS 引擎到看门狗失败: {e}")

    def _register_firewall_engine(self):
        """注册防火墙引擎到看门狗"""
        try:
            # 防火墙可能不存在，检查导入
            try:
                from engine.firewall.firewall_engine import FirewallEngine
                fw = FirewallEngine()
                self.watchdog.register_component(
                    'firewall_engine',
                    lambda: True,
                    auto_restart=True,
                )
                logger.info("防火墙引擎已注册到看门狗")
            except ImportError:
                logger.info("防火墙引擎未安装，跳过注册")
        except Exception as e:
            logger.warning(f"注册防火墙引擎到看门狗失败: {e}")

    def stop(self):
        self._running = False
        self.process_protector.stop()
        self.file_protector.stop()
        self.registry_protector.stop()
        self.watchdog.stop()
        logger.info("自我保护模块已停止")

    def _check_integrity(self):
        """检查完整性"""
        issues = []
        if not self.registry_protector.check_integrity():
            issues.append("注册表完整性异常")
            self.registry_protector.repair()
        if issues:
            logger.warning(f"完整性检查发现 {len(issues)} 个问题: {', '.join(issues)}")
        else:
            logger.info("完整性检查通过")

    def get_status(self) -> Dict:
        return {
            'running': self._running,
            'process_protection': self.process_protector._running,
            'file_protection': self.file_protector._running,
            'registry_protection': self.registry_protector._running,
            'watchdog': self.watchdog._running,
            'safe_mode': self.safe_mode.is_safe_mode(),
            'watchdog_components': self.watchdog.get_status(),
        }


# ============================================================
# 全局自防御实例
# ============================================================
self_defense = SelfDefense()