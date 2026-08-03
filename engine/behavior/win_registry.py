#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - Windows Registry API ctypes 封装
提供 RegOpenKeyEx / RegNotifyChangeKeyValue / RegEnumValue / RegDeleteValue 等底层操作
"""
import ctypes
from ctypes import wintypes
import threading
from typing import Dict, List, Optional, Callable, Tuple, Any

# ============================================================
# 预定义 HKEY 句柄
# ============================================================
HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003
HKEY_CURRENT_CONFIG = 0x80000005

HIVE_NAMES = {
    HKEY_CLASSES_ROOT: 'HKCR',
    HKEY_CURRENT_USER: 'HKCU',
    HKEY_LOCAL_MACHINE: 'HKLM',
    HKEY_USERS: 'HKU',
    HKEY_CURRENT_CONFIG: 'HKCC',
}

# ============================================================
# 访问权限
# ============================================================
KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_CREATE_LINK = 0x0020
KEY_WOW64_32KEY = 0x0200
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_RES = 0x0300
KEY_READ = 0x20019
KEY_WRITE = 0x20006
KEY_EXECUTE = 0x20019
KEY_ALL_ACCESS = 0xF003F

# ============================================================
# 通知过滤器
# ============================================================
REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008

# ============================================================
# 值类型
# ============================================================
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11
REG_QWORD_LITTLE_ENDIAN = 11

REG_TYPE_NAMES = {
    REG_NONE: 'NONE',
    REG_SZ: 'SZ',
    REG_EXPAND_SZ: 'EXPAND_SZ',
    REG_BINARY: 'BINARY',
    REG_DWORD: 'DWORD',
    REG_DWORD_BIG_ENDIAN: 'DWORD_BIG_ENDIAN',
    REG_MULTI_SZ: 'MULTI_SZ',
    REG_QWORD: 'QWORD',
}

# ============================================================
# 错误码
# ============================================================
ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_MORE_DATA = 234
ERROR_NO_MORE_ITEMS = 259

# ============================================================
# 等待常量
# ============================================================
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF

# ============================================================
# 进程权限
# ============================================================
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
SYNCHRONIZE = 0x00100000

# ============================================================
# 文件属性
# ============================================================
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_NORMAL = 0x00000080

# ============================================================
# 加载 DLL
# ============================================================
_advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# ============================================================
# 注册表函数定义
# ============================================================

_RegOpenKeyEx = _advapi32.RegOpenKeyExW
_RegOpenKeyEx.argtypes = [
    wintypes.HKEY,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,  # REGSAM (access mask) - use DWORD for compatibility
    ctypes.POINTER(wintypes.HKEY),
]
_RegOpenKeyEx.restype = wintypes.LONG

_RegCloseKey = _advapi32.RegCloseKey
_RegCloseKey.argtypes = [wintypes.HKEY]
_RegCloseKey.restype = wintypes.LONG

_RegNotifyChangeKeyValue = _advapi32.RegNotifyChangeKeyValue
_RegNotifyChangeKeyValue.argtypes = [
    wintypes.HKEY,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.BOOL,
]
_RegNotifyChangeKeyValue.restype = wintypes.LONG

_RegEnumValueW = _advapi32.RegEnumValueW
_RegEnumValueW.argtypes = [
    wintypes.HKEY,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,  # LPBYTE -> LPVOID for compatibility
    ctypes.POINTER(wintypes.DWORD),
]
_RegEnumValueW.restype = wintypes.LONG

_RegQueryValueExW = _advapi32.RegQueryValueExW
_RegQueryValueExW.argtypes = [
    wintypes.HKEY,
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,  # LPBYTE -> LPVOID for compatibility
    ctypes.POINTER(wintypes.DWORD),
]
_RegQueryValueExW.restype = wintypes.LONG

_RegDeleteValueW = _advapi32.RegDeleteValueW
_RegDeleteValueW.argtypes = [wintypes.HKEY, wintypes.LPCWSTR]
_RegDeleteValueW.restype = wintypes.LONG

_RegEnumKeyExW = _advapi32.RegEnumKeyExW
_RegEnumKeyExW.argtypes = [
    wintypes.HKEY,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.FILETIME),
]
_RegEnumKeyExW.restype = wintypes.LONG

# ============================================================
# Kernel32 函数定义
# ============================================================

_CreateEventW = _kernel32.CreateEventW
_CreateEventW.argtypes = [
    ctypes.c_void_p,  # LPSECURITY_ATTRIBUTES - use void_p for compatibility
    wintypes.BOOL,
    wintypes.BOOL,
    wintypes.LPCWSTR,
]
_CreateEventW.restype = wintypes.HANDLE

_WaitForSingleObject = _kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_WaitForSingleObject.restype = wintypes.DWORD

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_OpenProcess = _kernel32.OpenProcess
_OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_OpenProcess.restype = wintypes.HANDLE

_TerminateProcess = _kernel32.TerminateProcess
_TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_TerminateProcess.restype = wintypes.BOOL

_SetFileAttributesW = _kernel32.SetFileAttributesW
_SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
_SetFileAttributesW.restype = wintypes.BOOL

# ============================================================
# 工具函数
# ============================================================

def hive_name(hive: int) -> str:
    """返回 HKEY 的友好名称"""
    return HIVE_NAMES.get(hive, f'0x{hive:08X}')


def format_key_path(hive: int, sub_key: str) -> str:
    """返回完整的注册表路径字符串"""
    return f"{hive_name(hive)}\\{sub_key}"


def open_reg_key(hive: int, sub_key: str,
                 access: int = KEY_READ | KEY_NOTIFY) -> Optional[int]:
    """打开注册表键，返回句柄，失败返回 None"""
    handle = wintypes.HKEY(0)
    ret = _RegOpenKeyEx(hive, sub_key, 0, access, ctypes.byref(handle))
    if ret == ERROR_SUCCESS:
        return handle.value
    return None


def close_reg_key(handle: int) -> bool:
    """关闭注册表键句柄"""
    if handle:
        return _RegCloseKey(handle) == ERROR_SUCCESS
    return True


def create_event(manual_reset: bool = False,
                 initial_state: bool = False,
                 name: str = None) -> Optional[int]:
    """创建 Windows 事件对象，返回句柄"""
    sec_attr = None
    handle = _CreateEventW(sec_attr, manual_reset, initial_state, name)
    if handle:
        return handle
    return None


def close_handle(handle: int) -> bool:
    """关闭内核对象句柄"""
    if handle:
        return _CloseHandle(handle)
    return True


def wait_for_object(handle: int, timeout_ms: int = INFINITE) -> int:
    """等待内核对象信号"""
    return _WaitForSingleObject(handle, timeout_ms)


def enum_values(handle: int) -> Dict[str, Tuple[int, Any]]:
    """枚举注册表键下的所有值，返回 {name: (type, data)} 字典"""
    values = {}
    index = 0
    while True:
        name_buf_size = wintypes.DWORD(1024)
        name_buf = ctypes.create_unicode_buffer(1024)
        type_buf = wintypes.DWORD(0)
        data_buf_size = wintypes.DWORD(4096)
        data_buf = ctypes.create_string_buffer(4096)

        ret = _RegEnumValueW(
            handle, index,
            name_buf, ctypes.byref(name_buf_size),
            None, ctypes.byref(type_buf),
            ctypes.byref(data_buf), ctypes.byref(data_buf_size),
        )
        if ret == ERROR_NO_MORE_ITEMS:
            break
        if ret == ERROR_SUCCESS:
            name = name_buf.value
            data_raw = data_buf.raw[:data_buf_size.value]
            type_val = type_buf.value
            # Decode based on type
            if type_val == REG_SZ or type_val == REG_EXPAND_SZ:
                try:
                    decoded = data_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
                except Exception:
                    decoded = data_raw.hex()
            elif type_val == REG_DWORD or type_val == REG_DWORD_LITTLE_ENDIAN:
                decoded = int.from_bytes(data_raw[:4], 'little')
            elif type_val == REG_QWORD:
                decoded = int.from_bytes(data_raw[:8], 'little')
            elif type_val == REG_MULTI_SZ:
                try:
                    decoded = data_raw.decode('utf-16-le', errors='replace').rstrip('\x00').split('\x00')
                except Exception:
                    decoded = []
            elif type_val == REG_BINARY:
                decoded = data_raw.hex()
            else:
                decoded = data_raw.hex()
            values[name] = (type_val, decoded)
        index += 1
    return values


def query_value(handle: int, value_name: str) -> Optional[Tuple[int, Any]]:
    """查询单个注册表值"""
    type_buf = wintypes.DWORD(0)
    data_buf_size = wintypes.DWORD(0)
    # First call to get size
    ret = _RegQueryValueExW(handle, value_name, None, ctypes.byref(type_buf), None, ctypes.byref(data_buf_size))
    if ret == ERROR_FILE_NOT_FOUND:
        return None
    if ret != ERROR_SUCCESS and ret != ERROR_MORE_DATA:
        return None
    data_buf = ctypes.create_string_buffer(data_buf_size.value)
    ret = _RegQueryValueExW(handle, value_name, None, ctypes.byref(type_buf), data_buf, ctypes.byref(data_buf_size))
    if ret != ERROR_SUCCESS:
        return None
    data_raw = data_buf.raw[:data_buf_size.value]
    type_val = type_buf.value
    if type_val == REG_SZ or type_val == REG_EXPAND_SZ:
        try:
            decoded = data_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            decoded = data_raw.hex()
    elif type_val == REG_DWORD or type_val == REG_DWORD_LITTLE_ENDIAN:
        decoded = int.from_bytes(data_raw[:4], 'little')
    elif type_val == REG_QWORD:
        decoded = int.from_bytes(data_raw[:8], 'little')
    else:
        decoded = data_raw.hex()
    return (type_val, decoded)


def delete_value(handle: int, value_name: str) -> bool:
    """删除注册表值"""
    return _RegDeleteValueW(handle, value_name) == ERROR_SUCCESS


def open_process(pid: int, access: int = PROCESS_TERMINATE) -> Optional[int]:
    """打开进程，返回句柄"""
    handle = _OpenProcess(access, False, pid)
    if handle:
        return handle
    return None


def terminate_process(handle: int, exit_code: int = 1) -> bool:
    """终止进程"""
    return _TerminateProcess(handle, exit_code) == 1


def kill_process(pid: int) -> bool:
    """通过 PID 终止进程（便捷方法）"""
    handle = open_process(pid)
    if handle:
        try:
            return terminate_process(handle)
        finally:
            close_handle(handle)
    return False


def set_file_readonly(filepath: str) -> bool:
    """设置文件为只读属性"""
    return _SetFileAttributesW(filepath, FILE_ATTRIBUTE_READONLY) == 1


def set_file_normal(filepath: str) -> bool:
    """移除文件只读属性"""
    return _SetFileAttributesW(filepath, FILE_ATTRIBUTE_NORMAL) == 1


# ============================================================
# 注册表监控器
# ============================================================

class RegistryChangeWatcher:
    """
    对单个注册表键进行实时监控。
    使用 RegNotifyChangeKeyValue 异步等待，不轮询。
    """

    def __init__(self, hive: int, sub_key: str,
                 on_change: Optional[Callable[[str, str, str, str], None]] = None,
                 filter_flags: int = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                 watch_subtree: bool = True,
                 poll_interval: float = 0.5):
        """
        :param hive: HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER 等
        :param sub_key: 子键路径
        :param on_change: 回调函数，参数为 (hive_name, sub_key, action, value_name)
        :param filter_flags: REG_NOTIFY_CHANGE_* 的组合
        :param watch_subtree: 是否监控子键
        :param poll_interval: 等待超时后重试间隔（秒）
        """
        self.hive = hive
        self.sub_key = sub_key
        self.hive_name_str = hive_name(hive)
        self.full_path = format_key_path(hive, sub_key)
        self.on_change = on_change
        self.filter_flags = filter_flags
        self.watch_subtree = watch_subtree
        self.poll_interval = poll_interval

        self._key_handle: Optional[int] = None
        self._event_handle: Optional[int] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._prev_snapshot: Dict[str, Tuple[int, Any]] = {}

    def start(self) -> bool:
        """启动监控"""
        if self._running:
            return True

        self._key_handle = open_reg_key(self.hive, self.sub_key)
        if self._key_handle is None:
            return False

        self._event_handle = create_event(manual_reset=True)
        if self._event_handle is None:
            close_reg_key(self._key_handle)
            self._key_handle = None
            return False

        # 初始化快照
        self._prev_snapshot = enum_values(self._key_handle)

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """停止监控"""
        self._running = False
        if self._event_handle:
            # 设置事件以唤醒等待
            _kernel32.SetEvent(self._event_handle)
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        if self._event_handle:
            close_handle(self._event_handle)
            self._event_handle = None
        if self._key_handle:
            close_reg_key(self._key_handle)
            self._key_handle = None

    def _monitor_loop(self):
        """监控循环"""
        while self._running:
            if not self._key_handle:
                break

            # 注册异步通知
            ret = _RegNotifyChangeKeyValue(
                self._key_handle,
                self.watch_subtree,
                self.filter_flags,
                self._event_handle,
                True,  # 异步
            )
            if ret != ERROR_SUCCESS:
                break

            # 等待事件（带超时，以便检查 _running 标志）
            wait_ret = wait_for_object(self._event_handle, int(self.poll_interval * 1000))

            if not self._running:
                break

            if wait_ret == WAIT_OBJECT_0:
                # 事件被信号触发，说明注册表发生了变化
                self._detect_changes()
                # 重置事件，准备下一次通知
                _kernel32.ResetEvent(self._event_handle)

    def _detect_changes(self):
        """检测注册表变化并触发回调"""
        try:
            current_snapshot = enum_values(self._key_handle)
            # 检查新增或修改的值
            for name, value in current_snapshot.items():
                if name not in self._prev_snapshot:
                    self._fire_change('create', name)
                elif self._prev_snapshot[name] != value:
                    self._fire_change('set', name)

            # 检查删除的值
            for name in self._prev_snapshot:
                if name not in current_snapshot:
                    self._fire_change('delete', name)

            self._prev_snapshot = current_snapshot
        except Exception:
            pass

    def _fire_change(self, action: str, value_name: str):
        """触发回调"""
        if self.on_change:
            try:
                self.on_change(self.hive_name_str, self.sub_key, action, value_name)
            except Exception:
                pass


class RegistryMonitorEngine:
    """
    多键注册表监控引擎。
    同时监控多个注册表键，统一收集事件。
    """

    def __init__(self):
        self._watchers: List[RegistryChangeWatcher] = []
        self._events: List[Dict] = []
        self._lock = threading.Lock()
        self._running = False

    def add_watch(self, hive: int, sub_key: str,
                  filter_flags: int = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET) -> bool:
        """添加监控目标"""
        watcher = RegistryChangeWatcher(
            hive=hive, sub_key=sub_key,
            on_change=self._on_registry_change,
            filter_flags=filter_flags,
        )
        if self._running:
            if not watcher.start():
                return False
        self._watchers.append(watcher)
        return True

    def start(self):
        """启动所有监控器"""
        self._running = True
        for watcher in self._watchers:
            watcher.start()

    def stop(self):
        """停止所有监控器"""
        self._running = False
        for watcher in self._watchers:
            watcher.stop()

    def _on_registry_change(self, hive_name: str, sub_key: str, action: str, value_name: str):
        """注册表变化回调"""
        with self._lock:
            self._events.append({
                'hive': hive_name,
                'key': sub_key,
                'action': action,
                'value': value_name,
                'timestamp': __import__('time').time(),
            })

    def get_events(self) -> List[Dict]:
        """获取所有待处理事件"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events