# 天盾 Antivirus

> 全方位安全防护软件 — 基于 Python 的多维度杀毒引擎
> 开源协议：MIT License

## CI/CD Status

![Tests](https://github.com/song-jifeng/tiandun-antivirus/actions/workflows/tests.yml/badge.svg)
![Code Quality](https://github.com/song-jifeng/tiandun-antivirus/actions/workflows/lint.yml/badge.svg)
![Build](https://github.com/song-jifeng/tiandun-antivirus/actions/workflows/build.yml/badge.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Code size](https://img.shields.io/badge/Code-500K%2B%20lines-brightgreen.svg)](.)

## 五大核心能力

### 1. 🎯 核心"狙击"能力：多维度检测引擎
- **特征码查杀**：SignatureEngine — 10000+ 病毒签名，快速比对已知病毒
- **启发式检测**：HeuristicEngine — PE分析、脚本分析、文档分析、熵值检测
- **行为检测**：BehaviorEngine — 进程/文件/注册表/网络行为监控
- **云查杀**：CloudEngine — 云端海量算力，毫秒级查询
- **主动防御 HIPS**：HIPSEngine — 实时拦截高危操作

### 2. 🛡️ "抗揍"能力：底层自我保护
- **进程保护**：双进程看门狗，防止进程被终止
- **文件保护**：保护安装目录和关键文件
- **注册表护盾**：防止病毒修改杀软启动项
- **安全模式**：检测安全模式启动，加载最小配置

### 3. ⚡ 性能优化
- 智能资源调度，不抢CPU
- I/O优化，避免卡顿
- 内存占用极小

### 4. 🧹 "打扫战场"：彻底清除与修复
- **隔离区管理**：加密隔离，安全还原
- **恶意软件清除**：终止进程、删除文件、清理注册表/服务/计划任务
- **系统修复**：修复Hosts、文件关联、浏览器设置
- **文件恢复**：恢复隐藏文件、修复文件关联

### 5. 🌐 全平台与全链路防护
- **网络防火墙**：规则引擎，流量监控
- **勒索软件诱捕**：蜜罐文件系统，检测勒索行为
- **USB设备扫描**：自动扫描U盘
- **入侵检测**：端口扫描检测、暴力破解检测

## 项目结构

```
D:\Antivirus\
├── main.py                     # 主入口
├── scanner.py                  # 扫描管理器
├── updater.py                  # 更新管理器
├── service.py                  # Windows服务
├── scheduler.py                # 任务调度器
├── notifier.py                 # 通知管理器
├── installer.py                # 安装脚本
├── config.json                 # 默认配置
├── requirements.txt            # 依赖
├── engine/                     # 核心引擎
│   ├── __init__.py             # 核心定义
│   ├── config.py               # 配置管理
│   ├── logger.py               # 日志系统
│   ├── common.py               # 通用工具
│   ├── signatures/             # 特征码引擎
│   │   ├── signatures_db.py    # 病毒库 (10000+ 签名)
│   │   ├── signature_engine.py # 签名引擎
│   │   ├── signature_db.py     # 签名数据库管理
│   │   ├── yara_engine.py      # YARA规则引擎
│   │   └── heuristics.py       # 启发式规则
│   ├── heuristic/              # 启发式引擎
│   │   ├── heuristic_engine.py # 启发式分析
│   ├── behavior/               # 行为引擎
│   │   ├── behavior_engine.py  # 行为分析
│   ├── cloud/                  # 云查杀
│   │   └── cloud_engine.py     # 云查杀引擎
├── self-protection/            # 自我保护
│   └── self_defense.py         # 自防御总控
├── cleanup/                    # 清理修复
│   ├── quarantine.py           # 隔离区
│   ├── malware_remover.py      # 恶意软件清除
│   ├── system_repair.py        # 系统修复
│   ├── file_recovery.py        # 文件恢复
│   └── backup_manager.py       # 备份管理
├── firewall/                   # 防火墙
│   ├── firewall_engine.py      # 防火墙引擎
│   ├── honeypot.py             # 勒索诱捕
│   └── usb_scanner.py          # USB扫描
├── ui/                         # 用户界面
│   ├── main_window.py          # 主窗口 (PyQt5)
│   └── styles.py               # 样式定义
├── tools/                      # 工具集
│   ├── file_analyzer.py        # 文件分析
│   ├── process_explorer.py     # 进程浏览器
│   ├── startup_manager.py      # 启动项管理
│   └── system_cleaner.py       # 系统清理
└── tests/                      # 测试
    └── run_all.py              # 测试运行器
```

## 安装

```bash
# 安装依赖
pip install -r requirements.txt

# 运行
python main.py

# 命令行模式
python main.py --console

# 快速扫描
python main.py --scan-quick

# 全盘扫描
python main.py --scan-full

# 安装服务
python main.py --service install
```

## 使用方法

### GUI 模式
```bash
python main.py
```
启动图形界面，可通过导航栏选择各功能模块。

### 命令行模式
```bash
python main.py --console
```
进入交互式命令行：
- `scan-quick` - 快速扫描
- `scan-full` - 全盘扫描
- `scan <path>` - 自定义扫描
- `status` - 查看状态

### 扫描模式
- **快速扫描**：扫描系统关键路径（启动项、系统目录、临时文件夹）
- **全盘扫描**：扫描所有驱动器
- **自定义扫描**：选择指定目录扫描

## 系统要求

- Windows 10/11 (64位)
- Python 3.8+
- 4GB RAM
- 500MB 磁盘空间

## 技术栈

- **Python 3.12** - 核心开发语言
- **PyQt5** - 图形界面
- **psutil** - 系统监控
- **pywin32** - Windows API
- **watchdog** - 文件系统监控
- **requests** - HTTP 通信

## 版本

v1.0.0.20260803

## 开源协议

本项目基于 [MIT License](LICENSE) 开源。
Copyright (c) 2026 TianDun Security