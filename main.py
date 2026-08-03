#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 主入口
"""
import os
import sys
import time
import json
import signal
import argparse
import threading
from pathlib import Path
from typing import Optional

# 确保项目根目录在路径中
_PROJECT_ROOT = os.environ.get('TIANDUN_ROOT', 'D:/Antivirus')
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
os.environ['TIANDUN_ROOT'] = _PROJECT_ROOT


def _fix_console_encoding():
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


from engine import ENGINE_VERSION, PROJECT_ROOT
from engine.logger import logger
from engine.config import config
from scanner import scanner
from notifier import notifier


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='天盾 Antivirus - 全方位安全防护',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
示例:
  %(prog)s                          # 启动GUI界面
  %(prog)s --scan-quick             # 快速扫描
  %(prog)s --scan-full              # 全盘扫描
  %(prog)s --scan-path C:\\Users    # 自定义路径扫描
  %(prog)s --service install        # 安装Windows服务
  %(prog)s --service start          # 启动服务
  %(prog)s --console                # 命令行模式
  %(prog)s --version                # 显示版本信息
        '''
    )
    parser.add_argument('--scan-quick', action='store_true', help='执行快速扫描')
    parser.add_argument('--scan-full', action='store_true', help='执行全盘扫描')
    parser.add_argument('--scan-path', type=str, help='扫描指定路径')
    parser.add_argument('--service', choices=['install', 'uninstall', 'start', 'stop'],
                       help='Windows服务管理')
    parser.add_argument('--console', action='store_true', help='命令行模式（无GUI）')
    parser.add_argument('--daemon', action='store_true', help='守护进程模式')
    parser.add_argument('--version', action='store_true', help='显示版本信息')
    return parser.parse_args()


def check_single_instance():
    """检查单实例运行"""
    try:
        import win32event
        import win32api
        import winerror
        mutex_name = 'Global\\TiandunAntivirus-{7E8B5C3A-2F1D-4E9A-8B6C-5D4E3F2A1B0C}'
        mutex = win32event.CreateMutex(None, False, mutex_name)
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            logger.warning("天盾 Antivirus 已在运行")
            return False
        return True
    except Exception:
        return True


def check_admin():
    """检查管理员权限"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def init_environment():
    """初始化环境"""
    # 创建必要的目录
    dirs = [
        PROJECT_ROOT / 'logs',
        PROJECT_ROOT / 'quarantine',
        PROJECT_ROOT / 'engine' / 'signatures',
        PROJECT_ROOT / 'engine' / 'heuristic',
        PROJECT_ROOT / 'engine' / 'behavior',
        PROJECT_ROOT / 'engine' / 'cloud',
        PROJECT_ROOT / 'self-protection',
        PROJECT_ROOT / 'cleanup',
        PROJECT_ROOT / 'firewall',
        PROJECT_ROOT / 'ui',
        PROJECT_ROOT / 'tools',
        PROJECT_ROOT / 'tests',
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    logger.info(f"天盾 Antivirus v{ENGINE_VERSION} 初始化")
    logger.info(f"项目目录: {PROJECT_ROOT}")
    logger.info(f"Python版本: {sys.version}")


def run_scan(args):
    """运行扫描"""
    from engine import ScanCallback

    callback = ScanCallback()

    def on_threat(threat):
        print(f"  [发现威胁] {threat.file_name} - {threat.threat_name}")
        notifier.threat_alert(threat.threat_name, threat.file_path, threat.threat_level)

    def on_progress(current, total):
        pct = (current / total * 100) if total > 0 else 0
        print(f"\r  扫描进度: {current}/{total} ({pct:.1f}%)", end='', flush=True)

    def on_error(filepath, error):
        print(f"\n  [错误] {filepath}: {error}")

    callback.on_threat_found = on_threat
    callback.on_progress = on_progress
    callback.on_error = on_error

    if args.scan_quick:
        print("开始快速扫描系统关键路径...")
        report = scanner.quick_scan(callback)
    elif args.scan_full:
        print("开始全盘扫描...")
        report = scanner.full_scan(callback)
    elif args.scan_path:
        path = args.scan_path
        if not os.path.exists(path):
            print(f"路径不存在: {path}")
            return 1
        print(f"开始扫描: {path}")
        report = scanner.custom_scan([path], callback)
    else:
        return 0

    print("\n")
    print(report.summary())
    notifier.scan_complete(report.scanned_files, report.threat_count, report.duration)
    return 1 if report.threat_count > 0 else 0


def run_service(action: str):
    """管理Windows服务"""
    try:
        from service import TiandunService
        if action == 'install':
            TiandunService.install()
            print("服务安装成功")
        elif action == 'uninstall':
            TiandunService.uninstall()
            print("服务卸载成功")
        elif action == 'start':
            TiandunService.start()
            print("服务启动成功")
        elif action == 'stop':
            TiandunService.stop()
            print("服务停止成功")
        return 0
    except Exception as e:
        print(f"服务操作失败: {e}")
        return 1


def run_console():
    """命令行交互模式"""
    print(f"\n{'='*60}")
    print(f"  天盾 Antivirus v{ENGINE_VERSION} - 命令行模式")
    print(f"{'='*60}")
    print("  可用命令:")
    print("    scan-quick   - 快速扫描")
    print("    scan-full    - 全盘扫描")
    print("    scan <path>  - 自定义扫描")
    print("    status       - 查看状态")
    print("    help         - 帮助")
    print("    quit/exit    - 退出")
    print(f"{'='*60}\n")

    while True:
        try:
            cmd = input('tiandun> ').strip().lower()
            if cmd in ('quit', 'exit', 'q'):
                break
            elif cmd == 'scan-quick':
                args = argparse.Namespace(scan_quick=True, scan_full=False, scan_path=None)
                run_scan(args)
            elif cmd == 'scan-full':
                args = argparse.Namespace(scan_quick=False, scan_full=True, scan_path=None)
                run_scan(args)
            elif cmd.startswith('scan '):
                path = cmd[5:].strip()
                if path:
                    args = argparse.Namespace(scan_quick=False, scan_full=False, scan_path=path)
                    run_scan(args)
                else:
                    print("请指定路径: scan <path>")
            elif cmd == 'status':
                print(f"引擎版本: {ENGINE_VERSION}")
                stats = scanner.get_engine_stats()
                for s in stats:
                    print(f"  {s['name']}: {'启用' if s['enabled'] else '禁用'} "
                          f"(扫描: {s['stats']['scanned']}, 检测: {s['stats']['detected']})")
            elif cmd == 'help':
                print("可用命令: scan-quick, scan-full, scan <path>, status, help, quit")
            else:
                print(f"未知命令: {cmd}")
        except KeyboardInterrupt:
            print("\n")
            break
        except Exception as e:
            print(f"错误: {e}")


def main():
    """主入口"""
    _fix_console_encoding()
    args = parse_args()

    # 版本信息
    if args.version:
        print(f"天盾 Antivirus v{ENGINE_VERSION}")
        print(f"签名库版本: {config.get('signature_version', '2026.08.03')}")
        print(f"构建日期: 2026-08-03")
        return 0

    # 初始化
    init_environment()

    # 服务模式
    if args.service:
        return run_service(args.service)

    # 扫描模式
    if args.scan_quick or args.scan_full or args.scan_path:
        return run_scan(args)

    # 命令行模式
    if args.console:
        return run_console()

    # 守护进程模式
    if args.daemon:
        logger.info("启动守护进程模式")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("守护进程停止")
        return 0

    # 默认启动GUI
    try:
        from ui.main_window import MainWindow
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt

        # 高DPI支持
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

        app = QApplication(sys.argv)
        app.setApplicationName('天盾 Antivirus')
        app.setApplicationVersion(ENGINE_VERSION)
        app.setOrganizationName('TianDun Security')

        window = MainWindow()
        window.show()

        logger.info("GUI 界面启动完成")
        return app.exec_()
    except ImportError as e:
        logger.error(f"无法加载GUI模块: {e}")
        logger.info("PyQt5未安装，自动切换到命令行模式")
        print("PyQt5未安装，自动切换到命令行模式")
        return run_console()
    except Exception as e:
        logger.error(f"启动失败: {e}")
        print(f"启动失败: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())