# 天盾 Antivirus API 参考文档

## 1. 核心API

### 1.1 引擎模块 (engine)

#### ScanEngine 类

所有扫描引擎的基类。

```python
class ScanEngine:
    def __init__(self, name: str, enabled: bool = True)
    def scan(self, filepath: str) -> Optional[ThreatInfo]
    def scan_batch(self, filepaths: List[str]) -> List[ThreatInfo]
    def get_stats(self) -> Dict
    def reset_stats(self)
```

**属性：**
- `name`: 引擎名称
- `enabled`: 是否启用

**方法：**
- `scan(filepath)`: 扫描单个文件，返回威胁信息或None
- `scan_batch(filepaths)`: 批量扫描
- `get_stats()`: 获取引擎统计信息
- `reset_stats()`: 重置统计信息

#### ThreatInfo 类

威胁信息结构。

```python
class ThreatInfo:
    def __init__(self, file_path: str, threat_type: str = ThreatType.UNKNOWN,
                 threat_name: str = '', scan_engine: str = 'unknown',
                 threat_level: int = ThreatLevel.MEDIUM,
                 result: int = ScanResult.MALICIOUS)
    def to_dict() -> Dict
    @classmethod def from_dict(data: Dict) -> ThreatInfo
```

**属性：**
- `file_path`: 文件路径
- `file_name`: 文件名
- `file_size`: 文件大小
- `md5`: MD5哈希
- `sha1`: SHA1哈希
- `sha256`: SHA256哈希
- `threat_type`: 威胁类型
- `threat_name`: 威胁名称
- `scan_engine`: 检测引擎
- `threat_level`: 威胁等级
- `result`: 扫描结果
- `timestamp`: 检测时间
- `details`: 详细信息
- `processed`: 是否已处理

#### HashUtil 类

哈希计算工具。

```python
class HashUtil:
    @staticmethod def md5_file(filepath: str) -> str
    @staticmethod def sha1_file(filepath: str) -> str
    @staticmethod def sha256_file(filepath: str) -> str
    @staticmethod def compute_all(filepath: str) -> Tuple[str, str, str]
```

#### ScanResult 常量

```python
ScanResult.CLEAN = 0        # 安全
ScanResult.SUSPICIOUS = 1   # 可疑
ScanResult.MALICIOUS = 2    # 恶意
ScanResult.ERROR = -1       # 错误
ScanResult.UNKNOWN = -2     # 未知
```

#### ThreatType 常量

```python
ThreatType.VIRUS = 'virus'           # 传统病毒
ThreatType.WORM = 'worm'             # 蠕虫
ThreatType.TROJAN = 'trojan'         # 木马
ThreatType.RANSOMWARE = 'ransomware' # 勒索病毒
ThreatType.SPYWARE = 'spyware'       # 间谍软件
ThreatType.ADWARE = 'adware'         # 广告软件
ThreatType.ROOTKIT = 'rootkit'       # Rootkit
ThreatType.KEYLOGGER = 'keylogger'   # 键盘记录器
ThreatType.MINER = 'miner'           # 挖矿病毒
ThreatType.DOWNLOADER = 'downloader' # 下载器
ThreatType.BACKDOOR = 'backdoor'     # 后门
ThreatType.HEURISTIC = 'heuristic'   # 启发式检测
ThreatType.BEHAVIOR = 'behavior'     # 行为检测
ThreatType.UNKNOWN = 'unknown'       # 未知
```

#### ThreatLevel 常量

```python
ThreatLevel.CRITICAL = 5  # 严重
ThreatLevel.HIGH = 4      # 高危
ThreatLevel.MEDIUM = 3    # 中等
ThreatLevel.LOW = 2       # 低危
ThreatLevel.INFO = 1      # 信息
ThreatLevel.NONE = 0      # 无害
```

### 1.2 配置模块 (engine.config)

#### ConfigManager 类

```python
class ConfigManager:
    def __init__(self, config_path: Optional[str] = None)
    def get(key: str, default: Any = None) -> Any
    def set(key: str, value: Any)
    def get_all() -> Dict
    def save() -> bool
    def reset()
```

**使用示例：**
```python
from engine.config import config

# 获取配置
lang = config.get('general.language')
enabled = config.get('realtime.enabled')

# 设置配置
config.set('scan.thread_count', 8)
config.save()
```

### 1.3 日志模块 (engine.logger)

#### Logger 类

```python
class Logger:
    def __init__(self, name: str = 'tiandun', log_dir: Optional[str] = None)
    def debug(msg: str)
    def info(msg: str)
    def warning(msg: str)
    def error(msg: str)
    def critical(msg: str)
    def exception(msg: str)
    def log_struct(level: int, event: str, data: Dict)
    def log_scan_result(filepath: str, result: str, engine: str, ...)
    def log_threat(threat_info: Dict)
    def log_performance(operation: str, duration_ms: float, ...)
```

### 1.4 通用工具 (engine.common)

#### PathUtil 类

```python
class PathUtil:
    @staticmethod def normalize(path: str) -> str
    @staticmethod def is_system_path(path: str) -> bool
    @staticmethod def is_hidden(path: str) -> bool
    @staticmethod def get_drives() -> List[str]
    @staticmethod def get_common_dirs() -> List[str]
    @staticmethod def get_desktop_path() -> str
    @staticmethod def get_downloads_path() -> str
    @staticmethod def get_startup_paths() -> List[str]
```

#### FileUtil 类

```python
class FileUtil:
    @staticmethod def get_size_str(size_bytes: int) -> str
    @staticmethod def get_time_str(timestamp: float) -> str
    @staticmethod def safe_delete(path: str) -> bool
    @staticmethod def safe_move(src: str, dst: str) -> bool
    @staticmethod def safe_copy(src: str, dst: str) -> bool
    @staticmethod def get_file_attributes(path: str) -> Dict
    @staticmethod def is_binary(filepath: str) -> bool
    @staticmethod def read_file_safe(filepath: str, ...) -> Optional[bytes]
    @staticmethod def list_files(directory: str, ...) -> List[str]
```

#### ProcessUtil 类

```python
class ProcessUtil:
    @staticmethod def get_process_list() -> List[Dict]
    @staticmethod def kill_process(pid: int) -> bool
    @staticmethod def is_process_running(pid: int) -> bool
    @staticmethod def get_process_path(pid: int) -> str
    @staticmethod def get_process_by_name(name: str) -> List[int]
```

#### RegistryUtil 类

```python
class RegistryUtil:
    @staticmethod def get_value(key_path: str, value_name: str = '') -> Optional[str]
    @staticmethod def set_value(key_path: str, value_name: str, value: str, ...) -> bool
    @staticmethod def delete_value(key_path: str, value_name: str) -> bool
    @staticmethod def delete_key(key_path: str) -> bool
    @staticmethod def enum_keys(key_path: str) -> List[str]
    @staticmethod def enum_values(key_path: str) -> List[Tuple]
    @staticmethod def get_startup_entries() -> List[Dict]
```

#### NetworkUtil 类

```python
class NetworkUtil:
    @staticmethod def get_connections() -> List[Dict]
    @staticmethod def get_interfaces() -> List[Dict]
    @staticmethod def test_connection(host: str = '8.8.8.8', ...) -> bool
```

## 2. 扫描模块

### 2.1 Scanner 类

```python
class Scanner:
    def __init__(self)
    def scan_file(filepath: str, callback: Optional[ScanCallback] = None) -> List[ThreatInfo]
    def scan(paths: List[str], mode: str = ScanMode.QUICK, callback: Optional[ScanCallback] = None) -> ScanReport
    def quick_scan(callback: Optional[ScanCallback] = None) -> ScanReport
    def full_scan(callback: Optional[ScanCallback] = None) -> ScanReport
    def custom_scan(paths: List[str], callback: Optional[ScanCallback] = None) -> ScanReport
    def get_engine_stats() -> List[Dict]
```

### 2.2 ScanReport 类

```python
class ScanReport:
    def __init__(self, scan_mode: str = ScanMode.CUSTOM)
    def add_threat(threat: ThreatInfo)
    def add_error(filepath: str, error: str)
    def finish()
    def to_dict() -> Dict
    def to_json(indent: int = 2) -> str
    def summary() -> str
```

**属性：**
- `scan_mode`: 扫描模式
- `start_time`: 开始时间
- `end_time`: 结束时间
- `total_files`: 总文件数
- `scanned_files`: 已扫描文件数
- `threats_found`: 发现的威胁列表
- `errors`: 错误列表

### 2.3 ScanCallback 类

```python
class ScanCallback:
    def __init__(self)
    def cancel()
    def is_cancelled() -> bool
```

**回调属性：**
- `on_file_start`: 开始扫描文件时的回调
- `on_file_complete`: 完成扫描文件时的回调
- `on_threat_found`: 发现威胁时的回调
- `on_progress`: 进度更新回调
- `on_error`: 错误回调

## 3. 签名引擎

### 3.1 SignatureEngine 类

```python
class SignatureEngine(ScanEngine):
    def __init__(self)
    def scan(filepath: str) -> Optional[ThreatInfo]
    def load_signatures()
    def reload()
```

### 3.2 SignatureDatabase 类

```python
class SignatureDatabase:
    def __init__(self)
    def load(path: str)
    def save(path: str)
    def search(hash_value: str) -> Optional[Dict]
    def add_signature(signature: Dict)
    def remove_signature(hash_value: str)
    def get_stats() -> Dict
    def get_version() -> str
```

## 4. 启发式引擎

### 4.1 HeuristicEngine 类

```python
class HeuristicEngine(ScanEngine):
    def __init__(self)
    def scan(filepath: str) -> Optional[ThreatInfo]
```

### 4.2 PEAnalyzer 类

```python
class PEAnalyzer:
    def analyze(filepath: str) -> Tuple[float, List[str]]
```

### 4.3 ScriptAnalyzer 类

```python
class ScriptAnalyzer:
    def analyze(filepath: str) -> Tuple[float, List[str]]
```

### 4.4 DocumentAnalyzer 类

```python
class DocumentAnalyzer:
    def analyze(filepath: str) -> Tuple[float, List[str]]
```

## 5. 行为引擎

### 5.1 BehaviorEngine 类

```python
class BehaviorEngine(ScanEngine):
    def __init__(self)
    def start()
    def stop()
    def scan(filepath: str) -> Optional[ThreatInfo]
```

### 5.2 HIPSEngine 类

```python
class HIPSEngine:
    def __init__(self)
    def start()
    def stop()
    def get_stats() -> Dict
```

## 6. 云查杀引擎

### 6.1 CloudEngine 类

```python
class CloudEngine(ScanEngine):
    def __init__(self)
    def scan(filepath: str) -> Optional[ThreatInfo]
    def get_stats() -> Dict
```

## 7. 自我保护

### 7.1 SelfDefense 类

```python
class SelfDefense:
    def __init__(self)
    def start()
    def stop()
    def get_status() -> Dict
```

## 8. 清理修复

### 8.1 QuarantineManager 类

```python
class QuarantineManager:
    def __init__(self)
    def quarantine(filepath: str, threat_info: Optional[ThreatInfo] = None) -> bool
    def restore(quarantine_id: str, restore_path: Optional[str] = None) -> bool
    def delete(quarantine_id: str) -> bool
    def clean_expired()
    def get_all() -> List[Dict]
    def get_stats() -> Dict
```

### 8.2 MalwareRemover 类

```python
class MalwareRemover:
    def remove(threat: ThreatInfo) -> Dict
```

### 8.3 SystemRepair 类

```python
class SystemRepair:
    @staticmethod def repair_hosts() -> Dict
    @staticmethod def repair_file_associations() -> Dict
    @staticmethod def repair_browser_settings() -> Dict
    @staticmethod def repair_system_files() -> Dict
    @staticmethod def repair_network() -> Dict
    @staticmethod def repair_all() -> Dict
```

## 9. 防火墙

### 9.1 FirewallEngine 类

```python
class FirewallEngine:
    def __init__(self)
    def start()
    def stop()
    def add_rule(rule: FirewallRule)
    def remove_rule(rule_id: str)
    def get_rules() -> List[Dict]
    def get_stats() -> Dict
```

### 9.2 Honeypot 类

```python
class Honeypot:
    def __init__(self)
    def start()
    def stop()
    def get_alerts() -> List[Dict]
    def get_stats() -> Dict
```

## 10. 工具集

### 10.1 FileAnalyzer 类

```python
class FileAnalyzer:
    @staticmethod def analyze(filepath: str) -> Dict
    @staticmethod def export_report(result: Dict, fmt: str = 'json') -> str
```

### 10.2 ProcessExplorer 类

```python
class ProcessExplorer:
    @staticmethod def get_processes() -> List[Dict]
    @staticmethod def get_process_info(pid: int) -> Dict
    @staticmethod def kill_process(pid: int) -> bool
    @staticmethod def suspend_process(pid: int) -> bool
    @staticmethod def resume_process(pid: int) -> bool
```

## 11. 事件与回调

### 11.1 事件类型

```python
# 扫描事件
EVENT_SCAN_START = 'scan_start'
EVENT_SCAN_COMPLETE = 'scan_complete'
EVENT_THREAT_FOUND = 'threat_found'
EVENT_THREAT_CLEANED = 'threat_cleaned'

# 防护事件
EVENT_PROTECTION_ENABLED = 'protection_enabled'
EVENT_PROTECTION_DISABLED = 'protection_disabled'
EVENT_HIPS_BLOCK = 'hips_block'

# 系统事件
EVENT_UPDATE_AVAILABLE = 'update_available'
EVENT_SERVICE_START = 'service_start'
EVENT_SERVICE_STOP = 'service_stop'
```

## 12. 错误码

| 错误码 | 说明 | 处理方式 |
|--------|------|---------|
| E001 | 文件不存在 | 检查文件路径 |
| E002 | 权限不足 | 以管理员身份运行 |
| E003 | 文件被占用 | 关闭文件后重试 |
| E004 | 磁盘空间不足 | 清理磁盘空间 |
| E005 | 网络连接失败 | 检查网络连接 |
| E006 | 服务未启动 | 启动服务 |
| E007 | 配置错误 | 重置配置文件 |
| E008 | 内存不足 | 关闭其他程序 |
| E009 | 超时 | 增加超时时间 |
| E010 | 未知错误 | 查看日志详情 |