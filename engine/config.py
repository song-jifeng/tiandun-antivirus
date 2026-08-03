#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 配置管理系统
支持多层级配置：默认配置 → 用户配置 → 命令行参数
"""
import os
import json
import copy
import threading, time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ============================================================
# 默认配置
# ============================================================
DEFAULT_CONFIG = {
    # ============================================================
    # 通用设置
    # ============================================================
    'general': {
        'language': 'zh_CN',
        'auto_start': False,           # 开机自启
        'minimize_to_tray': True,      # 最小化到托盘
        'show_notifications': True,    # 显示通知
        'sound_enabled': False,        # 声音提示
        'theme': 'auto',               # 主题: auto/light/dark
        'check_update': True,          # 检查更新
        'update_interval_hours': 24,    # 更新检查间隔
    },

    # ============================================================
    # 实时防护设置
    # ============================================================
    'realtime': {
        'enabled': True,               # 实时防护总开关
        'file_monitor': True,          # 文件监控
        'process_monitor': True,       # 进程监控
        'registry_monitor': True,      # 注册表监控
        'network_monitor': True,       # 网络监控
        'usb_scan': True,              # USB 自动扫描
        'download_scan': True,         # 下载文件扫描
        'office_macro_scan': True,     # Office 宏扫描
        'email_scan': True,            # 邮件扫描
        'script_scan': True,           # 脚本扫描
        'monitor_level': 'normal',     # 监控级别: low/normal/high
        'scan_on_write': True,         # 写入时扫描
        'scan_on_read': False,         # 读取时扫描
        'scan_on_execute': True,       # 执行时扫描
        'monitor_extensions': [        # 监控的文件扩展名
            'exe', 'dll', 'sys', 'com', 'bat', 'cmd', 'ps1', 'vbs',
            'js', 'vbe', 'jse', 'wsf', 'wsh', 'msi', 'msp',
            'scr', 'pif', 'cpl', 'drv', 'ocx', 'ax',
            'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm',
            'zip', 'rar', '7z', 'cab', 'gz', 'bz2',
            'pdf', 'swf', 'hta', 'jar',
        ],
        'exclude_paths': [],           # 排除路径
        'exclude_extensions': [],      # 排除扩展名
        'exclude_processes': [],       # 排除进程
    },

    # ============================================================
    # 扫描设置
    # ============================================================
    'scan': {
        'quick_paths': [               # 快速扫描路径
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\Users',
            'C:\\Windows\\Temp',
            os.environ.get('TEMP', 'C:\\Temp'),
            os.environ.get('APPDATA', 'C:\\Users\\Default\\AppData\\Roaming'),
            os.environ.get('LOCALAPPDATA', 'C:\\Users\\Default\\AppData\\Local'),
            os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
        ],
        'max_file_size_mb': 200,        # 最大扫描文件大小(MB)
        'archive_scan': True,           # 扫描压缩包
        'archive_depth': 3,             # 压缩包递归深度
        'heuristic_level': 'medium',    # 启发式级别: low/medium/high
        'cpu_priority': 'low',          # CPU优先级: low/normal/high
        'scan_timeout_seconds': 300,    # 单文件扫描超时
        'thread_count': 4,              # 扫描线程数
        'delete_to_quarantine': True,   # 删除前先隔离
        'auto_clean': False,            # 自动清理
        'auto_clean_level': 'low',      # 自动清理的最低威胁等级
    },

    # ============================================================
    # 云查杀设置
    # ============================================================
    'cloud': {
        'enabled': True,               # 云查杀总开关
        'server_url': 'https://cloud.tiandun.security/api/scan',
        'timeout_seconds': 10,
        'cache_size': 10000,           # 缓存条目数
        'cache_ttl_hours': 24,
        'offline_mode': False,         # 离线模式
        'privacy_mode': True,          # 隐私模式(不发送文件内容)
        'send_hash_only': True,        # 仅发送哈希值
        'max_retries': 3,
    },

    # ============================================================
    # HIPS 设置
    # ============================================================
    'hips': {
        'enabled': True,
        'level': 'normal',             # 级别: low/normal/high/paranoid
        'monitor_process_create': True,
        'monitor_process_terminate': True,
        'monitor_file_write': True,
        'monitor_file_delete': True,
        'monitor_registry_write': True,
        'monitor_registry_delete': True,
        'monitor_dll_inject': True,
        'monitor_network_connect': True,
        'monitor_service_install': True,
        'monitor_driver_load': True,
        'monitor_scheduled_task': True,
        'monitor_startup': True,
        'block_unknown': False,         # 阻止未知行为
        'auto_allow_signed': True,      # 自动允许签名程序
        'whitelist': [],                # 白名单
        'blacklist': [],                # 黑名单
    },

    # ============================================================
    # 自我保护设置
    # ============================================================
    'self_protection': {
        'enabled': True,
        'protect_process': True,       # 进程保护
        'protect_files': True,         # 文件保护
        'protect_registry': True,      # 注册表保护
        'protect_drivers': True,       # 驱动保护
        'safe_mode_protection': True,  # 安全模式保护
        'watchdog_enabled': True,      # 看门狗
        'watchdog_interval_seconds': 5,
        'dual_process': True,          # 双进程保护
        'backup_config': True,         # 配置备份
    },

    # ============================================================
    # 清理修复设置
    # ============================================================
    'cleanup': {
        'auto_cleanup': False,
        'backup_before_clean': True,   # 清理前备份
        'restore_point': True,         # 创建系统还原点
        'clean_registry': True,        # 清理注册表
        'clean_services': True,        # 清理服务
        'clean_tasks': True,           # 清理计划任务
        'clean_startup': True,         # 清理启动项
        'repair_hosts': True,          # 修复hosts文件
        'repair_association': True,    # 修复文件关联
        'repair_browser': True,        # 修复浏览器设置
        'max_quarantine_size_mb': 1024,
        'quarantine_retention_days': 30,
    },

    # ============================================================
    # 防火墙设置
    # ============================================================
    'firewall': {
        'enabled': True,
        'mode': 'auto',                # 模式: auto/manual/off
        'block_incoming': True,
        'block_outgoing': False,
        'log_all_connections': False,
        'alert_on_unknown': True,      # 未知连接弹窗提醒
        'ransomware_honeypot': True,   # 勒索软件诱捕
        'honeypot_paths': [],          # 诱捕路径
        'intrusion_detection': True,   # 入侵检测
        'port_scan_detection': True,   # 端口扫描检测
        'dns_protection': True,        # DNS保护
        'arp_protection': False,       # ARP保护
        'whitelist_apps': [],          # 白名单应用
        'blocklist_apps': [],          # 黑名单应用
        'blocklist_ips': [],           # 黑名单IP
        'blocklist_ports': [],         # 黑名单端口
    },

    # ============================================================
    # 日志设置
    # ============================================================
    'logging': {
        'level': 'info',               # 日志级别: debug/info/warning/error
        'max_size_mb': 50,             # 日志文件最大大小
        'max_files': 10,               # 日志文件最大数量
        'log_scan_results': True,
        'log_threats': True,
        'log_performance': True,
        'log_errors': True,
        'log_to_file': True,
        'log_to_console': False,
    },
}

# ============================================================
# 配置管理器
# ============================================================
class ConfigManager:
    """配置管理器 - 线程安全，支持多层配置合并"""

    def __init__(self, config_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._config_path = config_path or str(
            Path(os.environ.get('TIANDUN_ROOT', 'D:/Antivirus')) / 'config.json'
        )
        self._config = self._deep_copy(DEFAULT_CONFIG)
        self._user_config = {}
        self._loaded = False
        self._watch_thread = None
        self._watch_running = False
        self._last_mtime = 0
        self._on_change_callbacks = {}  # key -> [callbacks]
        self._load()

    def _load(self):
        """加载用户配置"""
        try:
            self._config_path = os.environ.get('TIANDUN_CONFIG', self._config_path)
            if os.path.exists(self._config_path):
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    self._user_config = json.load(f)
                self._merge(self._config, self._user_config)
                self._loaded = True
        except Exception as e:
            print(f"[Config] 加载配置失败: {e}")

    def save(self):
        """保存用户配置到文件"""
        with self._lock:
            try:
                config_dir = os.path.dirname(self._config_path)
                os.makedirs(config_dir, exist_ok=True)
                # 仅保存用户修改过的配置（与默认配置不同的部分）
                diff = self._compute_diff(DEFAULT_CONFIG, self._config)
                with open(self._config_path, 'w', encoding='utf-8') as f:
                    json.dump(diff, f, ensure_ascii=False, indent=2)
                return True
            except Exception as e:
                print(f"[Config] 保存配置失败: {e}")
                return False

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值，支持点号分隔的路径，如 'realtime.enabled'"""
        with self._lock:
            parts = key.split('.')
            value = self._config
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                    if value is None:
                        return default
                else:
                    return default
            return value

    def set(self, key: str, value: Any):
        """设置配置值，支持点号分隔的路径"""
        with self._lock:
            parts = key.split('.')
            target = self._config
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]
            target[parts[-1]] = value

    def get_all(self) -> Dict:
        """获取完整配置（深拷贝）"""
        with self._lock:
            return self._deep_copy(self._config)

    def reset(self):
        """重置为默认配置"""
        with self._lock:
            self._config = self._deep_copy(DEFAULT_CONFIG)
            self._user_config = {}
            self.save()

    def _deep_copy(self, data: Dict) -> Dict:
        return copy.deepcopy(data)

    def _merge(self, base: Dict, override: Dict):
        """递归合并配置"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge(base[key], value)
            else:
                base[key] = value

    def _compute_diff(self, base: Dict, current: Dict) -> Dict:
        """计算当前配置与默认配置的差异"""
        diff = {}
        for key, value in current.items():
            if key in base:
                if isinstance(value, dict) and isinstance(base[key], dict):
                    nested_diff = self._compute_diff(base[key], value)
                    if nested_diff:
                        diff[key] = nested_diff
                elif value != base[key]:
                    diff[key] = value
            else:
                diff[key] = value
        return diff

    @property
    def config_path(self) -> str:
        return self._config_path

    @config_path.setter
    def config_path(self, path: str):
        self._config_path = path
        self._load()

    def start_watch(self, interval: float = 5.0):
        if self._watch_running:
            return
        self._watch_running = True
        self._last_mtime = self._get_config_mtime()
        self._watch_thread = threading.Thread(target=self._watch_loop, args=(interval,), daemon=True)
        self._watch_thread.start()

    def stop_watch(self):
        self._watch_running = False

    def on_change(self, key: str, callback):
        if key not in self._on_change_callbacks:
            self._on_change_callbacks[key] = []
        self._on_change_callbacks[key].append(callback)

    def _get_config_mtime(self):
        config_path = self._config_path
        if config_path and os.path.exists(config_path):
            return os.path.getmtime(config_path)
        return 0

    def _watch_loop(self, interval: float):
        while self._watch_running:
            try:
                mtime = self._get_config_mtime()
                if mtime > self._last_mtime:
                    self._last_mtime = mtime
                    self._reload_config()
                time.sleep(interval)
            except Exception:
                time.sleep(interval)

    def _reload_config(self):
        try:
            config_path = self._config_path
            if config_path and os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    new_config = json.load(f)
                # Merge new config
                self._merge_config(self._config, new_config)
                # Fire callbacks
                for key, callbacks in self._on_change_callbacks.items():
                    if self._config_deep_get(self._config, key) is not None:
                        for cb in callbacks:
                            try:
                                cb(key, self._config_deep_get(self._config, key))
                            except Exception:
                                pass
        except Exception:
            pass

    def _config_deep_get(self, config, key):
        parts = key.split('.')
        current = config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _merge_config(self, base, overlay):
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value


# ============================================================
# 全局配置实例
# ============================================================
config = ConfigManager()