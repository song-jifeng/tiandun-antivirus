#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 主窗口
"""
import os
import sys
import time
import json
import threading
from typing import Optional, Dict, Any
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QStackedWidget, QFrame, QListWidget, QListWidgetItem,
    QApplication, QSystemTrayIcon, QMenu, QAction, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QCheckBox, QComboBox, QDateEdit, QLineEdit, QTextEdit, QGroupBox,
    QTabWidget, QSplitter, QScrollArea, QFileDialog, QButtonGroup,
    QRadioButton, QSizePolicy, QSpacerItem, QSlider, QSpinBox,
    QStyleFactory, QGridLayout, QFormLayout
)
from PyQt5.QtCore import (
    QDate, Qt, QTimer, pyqtSignal, QThread, QSize, QPropertyAnimation,
    QEasingCurve, QRect, QPoint, QMutex
)
from PyQt5.QtGui import (
    QIcon, QFont, QPixmap, QColor, QPalette, QPainter,
    QLinearGradient, QBrush, QPen, QFontDatabase
)

# 导入项目模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import ENGINE_VERSION, PROJECT_ROOT, ScanResult, ThreatLevel
from engine.logger import logger
from engine.config import config
from scanner import scanner
from notifier import notifier
from updater import updater

from cleanup.quarantine import QuarantineManager

from .styles import Colors, Fonts, LIGHT_STYLE, DARK_STYLE, get_style


# ============================================================
# 扫描工作线程
# ============================================================
class ScanWorker(QThread):
    """扫描工作线程"""
    progress = pyqtSignal(int, int)
    file_scanned = pyqtSignal(str, int)
    threat_found = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str, str)

    def __init__(self, scan_mode: str, paths=None):
        super().__init__()
        self.scan_mode = scan_mode
        self.paths = paths or []
        self._report = None

    def run(self):
        try:
            from engine import ScanCallback
            callback = ScanCallback()

            callback.on_progress = lambda c, t: self.progress.emit(c, t)
            callback.on_threat_found = lambda t: self.threat_found.emit(t.to_dict())
            callback.on_error = lambda f, e: self.error.emit(f, e)

            if self.scan_mode == 'quick':
                self._report = scanner.quick_scan(callback)
            elif self.scan_mode == 'full':
                self._report = scanner.full_scan(callback)
            elif self.scan_mode == 'custom' and self.paths:
                self._report = scanner.custom_scan(self.paths, callback)
            else:
                self._report = scanner.quick_scan(callback)

            self.finished.emit(self._report.to_dict() if self._report else {})
        except Exception as e:
            self.error.emit('scan_error', str(e))

    def cancel(self):
        from engine import ScanCallback
        # 设置取消标志
        pass


# ============================================================
# 导航按钮
# ============================================================
class NavButton(QPushButton):
    """导航按钮"""
    def __init__(self, text: str, icon: str = '', page_index: int = 0):
        super().__init__(text)
        self.page_index = page_index
        self.setCheckable(True)
        self.setFixedHeight(48)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet('''
            QPushButton {
                text-align: left;
                padding: 12px 20px;
                border: none;
                border-radius: 0;
                font-size: 14px;
                background-color: transparent;
                color: #5f6368;
            }
            QPushButton:checked {
                background-color: #e8f0fe;
                color: #1a73e8;
                font-weight: bold;
                border-left: 3px solid #1a73e8;
            }
            QPushButton:hover:!checked {
                background-color: #f1f3f4;
            }
        ''')
        # 暗色主题覆盖
        self._dark_style = '''
            QPushButton {
                text-align: left;
                padding: 12px 20px;
                border: none;
                border-radius: 0;
                font-size: 14px;
                background-color: transparent;
                color: #9aa0a6;
            }
            QPushButton:checked {
                background-color: #0f3460;
                color: #4a9afa;
                font-weight: bold;
                border-left: 3px solid #4a9afa;
            }
            QPushButton:hover:!checked {
                background-color: #2a2a4a;
            }
        '''


# ============================================================
# 主窗口
# ============================================================
class MainWindow(QMainWindow):
    """天盾 Antivirus 主窗口"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f'天盾 Antivirus v{ENGINE_VERSION}')
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        # 状态
        self._current_theme = config.get('general.theme', 'light')
        self._is_dark = self._current_theme == 'dark'
        self._scan_worker = None
        self._protection_enabled = config.get('realtime.enabled', True)

        # 隔离区管理器
        self.quarantine_mgr = QuarantineManager()

        # 初始化UI
        self._init_ui()
        self._init_tray()
        self._apply_theme()

        # 定时器
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._update_status)
        self._status_timer.start(5000)

        logger.info("主窗口初始化完成")

    def _init_ui(self):
        """初始化UI"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ============================================================
        # 左侧导航栏
        # ============================================================
        nav_widget = QFrame()
        nav_widget.setFixedWidth(200)
        nav_widget.setObjectName('navWidget')
        nav_layout = QVBoxLayout(nav_widget)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(0)

        # Logo
        logo_label = QLabel('🛡️ 天盾')
        logo_label.setObjectName('titleLabel')
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setFixedHeight(60)
        nav_layout.addWidget(logo_label)

        nav_layout.addWidget(self._separator())

        # 导航按钮
        self.nav_buttons = []
        nav_items = [
            ('🏠 首页', 0),
            ('🔍 病毒扫描', 1),
            ('🛡️ 实时防护', 2),
            ('🔥 防火墙', 3),
            ('📦 隔离区', 4),
            ('📋 日志', 5),
            ('⚙️ 设置', 6),
        ]

        self.nav_btn_group = QButtonGroup()
        self.nav_btn_group.setExclusive(True)

        for i, (text, page) in enumerate(nav_items):
            btn = NavButton(text, page_index=page)
            self.nav_buttons.append(btn)
            self.nav_btn_group.addButton(btn, page)
            nav_layout.addWidget(btn)

        nav_layout.addStretch()

        # 版本信息
        version_label = QLabel(f'v{ENGINE_VERSION}')
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet('color: #9aa0a6; font-size: 11px; padding: 8px;')
        nav_layout.addWidget(version_label)

        # ============================================================
        # 右侧内容区
        # ============================================================
        content_widget = QFrame()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)

        # 标题栏
        header = QFrame()
        header.setFixedHeight(50)
        header.setObjectName('header')
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)

        self.page_title = QLabel('首页')
        self.page_title.setFont(Fonts.HEADING)
        header_layout.addWidget(self.page_title)

        header_layout.addStretch()

        # 防护状态指示
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(12, 12)
        header_layout.addWidget(self.status_indicator)

        self.status_label = QLabel('防护已开启')
        self.status_label.setFont(Fonts.SMALL)
        header_layout.addWidget(self.status_label)

        # 最小化/关闭按钮
        self.minimize_btn = QPushButton('─')
        self.minimize_btn.setFixedSize(36, 36)
        self.minimize_btn.clicked.connect(self.showMinimized)
        self.minimize_btn.setObjectName('headerBtn')
        header_layout.addWidget(self.minimize_btn)

        self.close_btn = QPushButton('✕')
        self.close_btn.setFixedSize(36, 36)
        self.close_btn.clicked.connect(self.hide)
        self.close_btn.setObjectName('headerBtn')
        header_layout.addWidget(self.close_btn)

        content_layout.addWidget(header)

        # 页面栈
        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack)

        # 创建各页面
        self.pages = []
        self.pages.append(self._create_dashboard())
        self.pages.append(self._create_scan_page())
        self.pages.append(self._create_realtime_page())
        self.pages.append(self._create_firewall_page())
        # 隔离区、日志、设置页面
        self.pages.append(self._create_quarantine_page())
        self.pages.append(self._create_log_page())
        self.pages.append(self._create_settings_page())

        for page in self.pages:
            self.stack.addWidget(page)

        # 连接导航
        self.nav_btn_group.buttonClicked.connect(self._on_nav_clicked)
        self.nav_buttons[0].setChecked(True)

        # 添加到主布局
        main_layout.addWidget(nav_widget)
        main_layout.addWidget(content_widget, 1)

    def _separator(self) -> QFrame:
        """分隔线"""
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet('background-color: #dadce0;')
        return sep

    def _on_nav_clicked(self, btn):
        """导航点击"""
        self.stack.setCurrentIndex(btn.page_index)
        page_names = ['首页', '病毒扫描', '实时防护', '防火墙', '隔离区', '日志', '设置']
        if btn.page_index < len(page_names):
            self.page_title.setText(page_names[btn.page_index])

    def _apply_theme(self):
        """应用主题"""
        style = get_style(self._is_dark)
        self.setStyleSheet(style)
        # 更新导航按钮样式
        for btn in self.nav_buttons:
            btn.setStyleSheet(btn._dark_style if self._is_dark else '''
                QPushButton {
                    text-align: left; padding: 12px 20px; border: none;
                    border-radius: 0; font-size: 14px;
                    background-color: transparent; color: #5f6368;
                }
                QPushButton:checked {
                    background-color: #e8f0fe; color: #1a73e8;
                    font-weight: bold; border-left: 3px solid #1a73e8;
                }
                QPushButton:hover:!checked { background-color: #f1f3f4; }
            ''')

    def _init_tray(self):
        """初始化系统托盘"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip(f'天盾 Antivirus v{ENGINE_VERSION}')

        tray_menu = QMenu()
        show_action = tray_menu.addAction('显示主界面')
        show_action.triggered.connect(self.showNormal)
        scan_action = tray_menu.addAction('快速扫描')
        scan_action.triggered.connect(lambda: self._start_scan('quick'))
        tray_menu.addSeparator()
        quit_action = tray_menu.addAction('退出')
        quit_action.triggered.connect(QApplication.quit)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason):
        """托盘图标点击"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def closeEvent(self, event):
        """关闭事件 - 最小化到托盘"""
        if config.get('general.minimize_to_tray', True):
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                '天盾 Antivirus',
                '程序已最小化到系统托盘',
                QSystemTrayIcon.Information,
                2000
            )
        else:
            event.accept()

    # ============================================================
    # 首页仪表盘
    # ============================================================
    def _create_dashboard(self) -> QWidget:
        """创建首页仪表盘"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 安全状态卡片
        status_card = QFrame()
        status_card.setObjectName('card')
        status_layout = QHBoxLayout(status_card)

        # 安全状态图标
        self.shield_label = QLabel('🛡️')
        self.shield_label.setFont(QFont('Segoe UI', 48))
        status_layout.addWidget(self.shield_label)

        # 安全状态文字
        status_text = QVBoxLayout()
        self.safety_title = QLabel('您的系统安全')
        self.safety_title.setObjectName('safeLabel')
        status_text.addWidget(self.safety_title)

        self.safety_desc = QLabel('实时防护已开启，系统运行正常')
        self.safety_desc.setFont(Fonts.SMALL)
        self.safety_desc.setStyleSheet('color: #5f6368;')
        status_text.addWidget(self.safety_desc)

        status_layout.addLayout(status_text)
        status_layout.addStretch()

        # 快速操作按钮
        quick_scan_btn = QPushButton('🔍 快速扫描')
        quick_scan_btn.setObjectName('btnSuccess')
        quick_scan_btn.setFixedSize(140, 44)
        quick_scan_btn.clicked.connect(lambda: self._start_scan('quick'))
        status_layout.addWidget(quick_scan_btn)

        full_scan_btn = QPushButton('📀 全盘扫描')
        full_scan_btn.setFixedSize(140, 44)
        full_scan_btn.clicked.connect(lambda: self._start_scan('full'))
        status_layout.addWidget(full_scan_btn)

        layout.addWidget(status_card)

        # 统计卡片
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(16)

        stats_data = [
            ('🔍', '扫描文件', '0', 'total_scanned'),
            ('⚠️', '发现威胁', '0', 'total_threats'),
            ('📦', '隔离项目', '0', 'quarantined'),
            ('🛡️', '拦截攻击', '0', 'blocked'),
        ]

        self.stats_labels = {}
        for icon, title, value, key in stats_data:
            card = QFrame()
            card.setObjectName('statsCard')
            card.setFixedHeight(120)
            cl = QVBoxLayout(card)
            cl.setAlignment(Qt.AlignCenter)

            icon_label = QLabel(icon)
            icon_label.setFont(QFont('Segoe UI', 28))
            icon_label.setAlignment(Qt.AlignCenter)
            cl.addWidget(icon_label)

            value_label = QLabel(value)
            value_label.setFont(QFont('Segoe UI', 24, QFont.Bold))
            value_label.setAlignment(Qt.AlignCenter)
            value_label.setStyleSheet('color: #1a73e8;')
            cl.addWidget(value_label)
            self.stats_labels[key] = value_label

            title_label = QLabel(title)
            title_label.setAlignment(Qt.AlignCenter)
            title_label.setStyleSheet('color: #5f6368; font-size: 12px;')
            cl.addWidget(title_label)

            stats_layout.addWidget(card)

        layout.addLayout(stats_layout)

        # 最近活动
        activity_card = QFrame()
        activity_card.setObjectName('card')
        activity_layout = QVBoxLayout(activity_card)

        activity_title = QLabel('最近活动')
        activity_title.setFont(Fonts.SUBHEADING)
        activity_layout.addWidget(activity_title)

        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(200)
        self.activity_log.setFont(Fonts.MONO)
        self.activity_log.setStyleSheet('border: none; background: transparent;')
        activity_layout.addWidget(self.activity_log)

        layout.addWidget(activity_card)
        layout.addStretch()

        return page

    # ============================================================
    # 病毒扫描页面
    # ============================================================
    def _create_scan_page(self) -> QWidget:
        """创建扫描页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 扫描模式选择
        mode_card = QFrame()
        mode_card.setObjectName('card')
        mode_layout = QVBoxLayout(mode_card)

        mode_title = QLabel('选择扫描模式')
        mode_title.setFont(Fonts.SUBHEADING)
        mode_layout.addWidget(mode_title)

        mode_buttons = QHBoxLayout()
        mode_buttons.setSpacing(12)

        self.quick_scan_btn = QPushButton('⚡ 快速扫描')
        self.quick_scan_btn.setObjectName('btnSuccess')
        self.quick_scan_btn.setFixedSize(160, 60)
        self.quick_scan_btn.clicked.connect(lambda: self._start_scan('quick'))
        mode_buttons.addWidget(self.quick_scan_btn)

        self.full_scan_btn = QPushButton('📀 全盘扫描')
        self.full_scan_btn.setFixedSize(160, 60)
        self.full_scan_btn.clicked.connect(lambda: self._start_scan('full'))
        mode_buttons.addWidget(self.full_scan_btn)

        self.custom_scan_btn = QPushButton('📁 自定义扫描')
        self.custom_scan_btn.setObjectName('btnSecondary')
        self.custom_scan_btn.setFixedSize(160, 60)
        self.custom_scan_btn.clicked.connect(self._custom_scan)
        mode_buttons.addWidget(self.custom_scan_btn)

        mode_layout.addLayout(mode_buttons)
        layout.addWidget(mode_card)

        # 扫描进度
        progress_card = QFrame()
        progress_card.setObjectName('card')
        progress_layout = QVBoxLayout(progress_card)

        progress_header = QHBoxLayout()
        self.scan_status_label = QLabel('就绪 - 点击上方按钮开始扫描')
        self.scan_status_label.setFont(Fonts.SUBHEADING)
        progress_header.addWidget(self.scan_status_label)

        self.cancel_scan_btn = QPushButton('取消扫描')
        self.cancel_scan_btn.setObjectName('btnDanger')
        self.cancel_scan_btn.setFixedSize(100, 32)
        self.cancel_scan_btn.setVisible(False)
        self.cancel_scan_btn.clicked.connect(self._cancel_scan)
        progress_header.addWidget(self.cancel_scan_btn)

        progress_layout.addLayout(progress_header)

        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setFixedHeight(8)
        progress_layout.addWidget(self.scan_progress)

        self.scan_info = QLabel('')
        self.scan_info.setFont(Fonts.SMALL)
        self.scan_info.setStyleSheet('color: #5f6368;')
        progress_layout.addWidget(self.scan_info)

        layout.addWidget(progress_card)

        # 扫描结果
        result_card = QFrame()
        result_card.setObjectName('card')
        result_layout = QVBoxLayout(result_card)

        result_title = QLabel('扫描结果')
        result_title.setFont(Fonts.SUBHEADING)
        result_layout.addWidget(result_title)

        self.scan_result_table = QTableWidget()
        self.scan_result_table.setColumnCount(5)
        self.scan_result_table.setHorizontalHeaderLabels(['文件', '威胁', '类型', '等级', '操作'])
        self.scan_result_table.horizontalHeader().setStretchLastSection(True)
        self.scan_result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_result_table.verticalHeader().setVisible(False)
        self.scan_result_table.setAlternatingRowColors(True)
        self.scan_result_table.setSelectionBehavior(QTableWidget.SelectRows)
        result_layout.addWidget(self.scan_result_table)

        layout.addWidget(result_card, 1)

        return page

    # ============================================================
    # 实时防护页面
    # ============================================================
    def _create_realtime_page(self) -> QWidget:
        """创建实时防护页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 防护总开关
        switch_card = QFrame()
        switch_card.setObjectName('card')
        switch_layout = QHBoxLayout(switch_card)

        switch_icon = QLabel('🛡️')
        switch_icon.setFont(QFont('Segoe UI', 36))
        switch_layout.addWidget(switch_icon)

        switch_text = QVBoxLayout()
        self.protection_title = QLabel('实时防护')
        self.protection_title.setFont(Fonts.HEADING)
        switch_text.addWidget(self.protection_title)
        self.protection_desc = QLabel('实时监控文件、进程、注册表和网络活动')
        self.protection_desc.setStyleSheet('color: #5f6368;')
        switch_text.addWidget(self.protection_desc)
        switch_layout.addLayout(switch_text)

        switch_layout.addStretch()

        self.protection_switch = QPushButton('关闭防护')
        self.protection_switch.setObjectName('btnDanger')
        self.protection_switch.setFixedSize(120, 40)
        self.protection_switch.clicked.connect(self._toggle_protection)
        switch_layout.addWidget(self.protection_switch)

        layout.addWidget(switch_card)

        # 防护模块
        modules_card = QFrame()
        modules_card.setObjectName('card')
        modules_layout = QVBoxLayout(modules_card)

        modules_title = QLabel('防护模块')
        modules_title.setFont(Fonts.SUBHEADING)
        modules_layout.addWidget(modules_title)

        self.protection_modules = {}
        modules = [
            ('file_monitor', '📁 文件监控', '监控文件创建、修改、删除操作', True),
            ('process_monitor', '⚙️ 进程监控', '监控进程创建、注入、提权行为', True),
            ('registry_monitor', '📝 注册表监控', '监控注册表关键项变更', True),
            ('network_monitor', '🌐 网络监控', '监控网络连接和流量', True),
            ('usb_scan', '💾 USB扫描', '自动扫描USB存储设备', True),
            ('office_macro_scan', '📄 Office宏扫描', '扫描Office文档中的宏代码', True),
        ]

        for key, name, desc, default in modules:
            module_frame = QFrame()
            module_frame.setObjectName('statsCard')
            ml = QHBoxLayout(module_frame)

            ml.addWidget(QLabel(name))
            ml.addWidget(QLabel(desc))
            ml.addStretch()

            cb = QCheckBox()
            cb.setChecked(config.get(f'realtime.{key}', default))
            cb.toggled.connect(lambda checked, k=key: config.set(f'realtime.{k}', checked))
            ml.addWidget(cb)
            self.protection_modules[key] = cb

            modules_layout.addWidget(module_frame)

        layout.addWidget(modules_card)

        # 排除列表
        exclude_card = QFrame()
        exclude_card.setObjectName('card')
        exclude_layout = QVBoxLayout(exclude_card)

        exclude_title = QLabel('排除列表')
        exclude_title.setFont(Fonts.SUBHEADING)
        exclude_layout.addWidget(exclude_title)

        exclude_input = QHBoxLayout()
        self.exclude_path_input = QLineEdit()
        self.exclude_path_input.setPlaceholderText('输入要排除的路径...')
        exclude_input.addWidget(self.exclude_path_input)

        add_exclude_btn = QPushButton('添加')
        add_exclude_btn.setFixedSize(80, 36)
        exclude_input.addWidget(add_exclude_btn)

        exclude_layout.addLayout(exclude_input)

        self.exclude_list = QListWidget()
        self.exclude_list.setMaximumHeight(100)
        exclude_layout.addWidget(self.exclude_list)

        layout.addWidget(exclude_card)
        layout.addStretch()

        return page

    # ============================================================
    # 防火墙页面
    # ============================================================
    def _create_firewall_page(self) -> QWidget:
        """创建防火墙页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 防火墙状态
        fw_card = QFrame()
        fw_card.setObjectName('card')
        fw_layout = QHBoxLayout(fw_card)

        fw_icon = QLabel('🔥')
        fw_icon.setFont(QFont('Segoe UI', 36))
        fw_layout.addWidget(fw_icon)

        fw_text = QVBoxLayout()
        fw_title = QLabel('网络防火墙')
        fw_title.setFont(Fonts.HEADING)
        fw_text.addWidget(fw_title)
        fw_desc = QLabel('监控网络流量，阻止恶意连接')
        fw_desc.setStyleSheet('color: #5f6368;')
        fw_text.addWidget(fw_desc)
        fw_layout.addLayout(fw_text)

        fw_layout.addStretch()

        self.fw_switch = QPushButton('关闭防火墙')
        self.fw_switch.setObjectName('btnDanger')
        self.fw_switch.setFixedSize(120, 40)
        fw_layout.addWidget(self.fw_switch)

        layout.addWidget(fw_card)

        # 防火墙规则
        rules_card = QFrame()
        rules_card.setObjectName('card')
        rules_layout = QVBoxLayout(rules_card)

        rules_title = QLabel('防火墙规则')
        rules_title.setFont(Fonts.SUBHEADING)
        rules_layout.addWidget(rules_title)

        self.fw_rules_table = QTableWidget()
        self.fw_rules_table.setColumnCount(5)
        self.fw_rules_table.setHorizontalHeaderLabels(['规则名称', '方向', '协议', '端口', '操作'])
        self.fw_rules_table.horizontalHeader().setStretchLastSection(True)
        self.fw_rules_table.verticalHeader().setVisible(False)
        rules_layout.addWidget(self.fw_rules_table)

        layout.addWidget(rules_card)

        # 诱捕系统
        honeypot_card = QFrame()
        honeypot_card.setObjectName('card')
        honeypot_layout = QHBoxLayout(honeypot_card)

        hp_icon = QLabel('🎯')
        hp_icon.setFont(QFont('Segoe UI', 24))
        honeypot_layout.addWidget(hp_icon)

        hp_text = QVBoxLayout()
        hp_title = QLabel('勒索软件诱捕系统')
        hp_title.setFont(Fonts.SUBHEADING)
        hp_text.addWidget(hp_title)
        hp_desc = QLabel('在关键目录放置蜜罐文件，监控勒索软件行为')
        hp_desc.setStyleSheet('color: #5f6368;')
        hp_text.addWidget(hp_desc)
        honeypot_layout.addLayout(hp_text)

        honeypot_layout.addStretch()
        hp_status = QLabel('✅ 运行中')
        hp_status.setStyleSheet('color: #34a853; font-weight: bold;')
        honeypot_layout.addWidget(hp_status)

        layout.addWidget(honeypot_card)
        layout.addStretch()

        return page

    # ============================================================
    # 设置页面
    # ============================================================
    def _create_settings_page(self) -> QWidget:
        """创建设置页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 通用设置
        general_card = QFrame()
        general_card.setObjectName('card')
        gl = QVBoxLayout(general_card)

        general_title = QLabel('通用设置')
        general_title.setFont(Fonts.SUBHEADING)
        gl.addWidget(general_title)

        # 开机自启
        auto_start_layout = QHBoxLayout()
        auto_start_layout.addWidget(QLabel('开机自动启动'))
        auto_start_layout.addStretch()
        self.auto_start_cb = QCheckBox()
        self.auto_start_cb.setChecked(False)
        auto_start_layout.addWidget(self.auto_start_cb)
        gl.addLayout(auto_start_layout)

        # 主题
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel('界面主题'))
        theme_layout.addStretch()
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(['跟随系统', '亮色', '暗色'])
        self.theme_combo.setCurrentIndex(0)
        self.theme_combo.currentTextChanged.connect(self._on_theme_changed)
        theme_layout.addWidget(self.theme_combo)
        gl.addLayout(theme_layout)

        # 通知
        notify_layout = QHBoxLayout()
        notify_layout.addWidget(QLabel('显示通知'))
        notify_layout.addStretch()
        self.notify_cb = QCheckBox()
        self.notify_cb.setChecked(True)
        notify_layout.addWidget(self.notify_cb)
        gl.addLayout(notify_layout)

        layout.addWidget(general_card)

        # 扫描设置
        scan_card = QFrame()
        scan_card.setObjectName('card')
        sl = QVBoxLayout(scan_card)

        scan_title = QLabel('扫描设置')
        scan_title.setFont(Fonts.SUBHEADING)
        sl.addWidget(scan_title)

        # 线程数
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel('扫描线程数'))
        thread_layout.addStretch()
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 16)
        self.thread_spin.setValue(4)
        thread_layout.addWidget(self.thread_spin)
        sl.addLayout(thread_layout)

        # 最大文件大小
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel('最大文件大小 (MB)'))
        size_layout.addStretch()
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(10, 1000)
        self.max_size_spin.setValue(200)
        self.max_size_spin.setSuffix(' MB')
        size_layout.addWidget(self.max_size_spin)
        sl.addLayout(size_layout)

        # 启发式级别
        heuristic_layout = QHBoxLayout()
        heuristic_layout.addWidget(QLabel('启发式分析级别'))
        heuristic_layout.addStretch()
        self.heuristic_combo = QComboBox()
        self.heuristic_combo.addItems(['低', '中', '高'])
        self.heuristic_combo.setCurrentIndex(1)
        heuristic_layout.addWidget(self.heuristic_combo)
        sl.addLayout(heuristic_layout)

        layout.addWidget(scan_card)

        # 关于
        about_card = QFrame()
        about_card.setObjectName('card')
        al = QVBoxLayout(about_card)

        about_title = QLabel(f'关于天盾 Antivirus')
        about_title.setFont(Fonts.SUBHEADING)
        al.addWidget(about_title)

        al.addWidget(QLabel(f'版本: {ENGINE_VERSION}'))
        al.addWidget(QLabel(f'引擎版本: {ENGINE_VERSION}'))
        al.addWidget(QLabel('构建日期: 2026-08-03'))
        al.addWidget(QLabel('© 2026 TianDun Security. All rights reserved.'))

        # 保存设置按钮
        save_btn = QPushButton('💾 保存设置')
        save_btn.setObjectName('btnSuccess')
        save_btn.setFixedSize(140, 40)
        save_btn.clicked.connect(self._save_settings)
        al.addWidget(save_btn)

        layout.addWidget(about_card)
        layout.addStretch()

        return page

    # ============================================================
    # 占位页面
    # ============================================================
    def _create_placeholder_page(self, title: str, desc: str) -> QWidget:
        """创建占位页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignCenter)

        icon_label = QLabel('🚧')
        icon_label.setFont(QFont('Segoe UI', 64))
        icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setFont(Fonts.HEADING)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        desc_label = QLabel(desc)
        desc_label.setStyleSheet('color: #5f6368;')
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)

        return page

    # ============================================================
    # 隔离区页面方法
    # ============================================================
    def _create_quarantine_page(self) -> QWidget:
        """创建隔离区管理页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        # 标题栏
        title_bar = QHBoxLayout()
        title_label = QLabel('📦 隔离区管理')
        title_label.setFont(Fonts.HEADING)
        title_bar.addWidget(title_label)
        title_bar.addStretch()

        refresh_btn = QPushButton('🔄 刷新')
        refresh_btn.setObjectName('btnSecondary')
        refresh_btn.setFixedSize(100, 36)
        refresh_btn.clicked.connect(self._refresh_quarantine)
        title_bar.addWidget(refresh_btn)
        layout.addLayout(title_bar)

        # 分割器 - 表格 + 详情面板
        splitter = QSplitter(Qt.Horizontal)

        # 表格容器
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(6)
        self.quarantine_table.setHorizontalHeaderLabels(['原始路径', '文件名', '隔离日期', '大小', '威胁名称', '状态'])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.quarantine_table.verticalHeader().setVisible(False)
        self.quarantine_table.setAlternatingRowColors(True)
        self.quarantine_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.quarantine_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.quarantine_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.quarantine_table.customContextMenuRequested.connect(self._show_quarantine_context_menu)
        self.quarantine_table.itemSelectionChanged.connect(self._on_quarantine_selection_changed)
        self.quarantine_table.setSortingEnabled(True)
        table_layout.addWidget(self.quarantine_table)

        splitter.addWidget(table_container)

        # 详情面板
        self.quarantine_details_panel = QFrame()
        self.quarantine_details_panel.setObjectName('card')
        self.quarantine_details_panel.setFixedWidth(300)
        details_layout = QVBoxLayout(self.quarantine_details_panel)

        details_header = QHBoxLayout()
        details_title = QLabel('详细信息')
        details_title.setFont(Fonts.SUBHEADING)
        details_header.addWidget(details_title)
        details_header.addStretch()

        close_details_btn = QPushButton('✕')
        close_details_btn.setFixedSize(28, 28)
        close_details_btn.setObjectName('btnSecondary')
        close_details_btn.clicked.connect(lambda: self.quarantine_details_panel.setVisible(False))
        details_header.addWidget(close_details_btn)
        details_layout.addLayout(details_header)

        # 详情字段
        self.detail_labels = {}
        detail_fields = [
            ('original_path', '原始路径'),
            ('file_name', '文件名'),
            ('md5', 'MD5'),
            ('sha256', 'SHA256'),
            ('threat_name', '威胁名称'),
            ('threat_type', '威胁类型'),
            ('threat_level', '威胁等级'),
            ('quarantine_time', '隔离时间'),
            ('file_size', '文件大小'),
            ('scan_engine', '扫描引擎'),
            ('status', '状态'),
        ]

        for key, label in detail_fields:
            row = QHBoxLayout()
            name_label = QLabel(f'{label}:')
            name_label.setStyleSheet('color: #5f6368; font-size: 12px;')
            name_label.setFixedWidth(80)
            row.addWidget(name_label)

            value_label = QLabel('-')
            value_label.setWordWrap(True)
            value_label.setStyleSheet('font-size: 12px;')
            row.addWidget(value_label, 1)
            details_layout.addLayout(row)
            self.detail_labels[key] = value_label

        details_layout.addStretch()

        # 详情面板操作按钮
        self.detail_restore_btn = QPushButton('↩️ 恢复文件')
        self.detail_restore_btn.setObjectName('btnSuccess')
        self.detail_restore_btn.clicked.connect(self._restore_selected)
        details_layout.addWidget(self.detail_restore_btn)

        self.detail_delete_btn = QPushButton('🗑️ 永久删除')
        self.detail_delete_btn.setObjectName('btnDanger')
        self.detail_delete_btn.clicked.connect(self._delete_selected)
        details_layout.addWidget(self.detail_delete_btn)

        self.quarantine_details_panel.setVisible(False)
        splitter.addWidget(self.quarantine_details_panel)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        # 底部操作栏
        action_bar = QHBoxLayout()

        self.q_restore_btn = QPushButton('↩️ 恢复选中')
        self.q_restore_btn.setObjectName('btnSuccess')
        self.q_restore_btn.setFixedSize(120, 36)
        self.q_restore_btn.clicked.connect(self._restore_selected)
        action_bar.addWidget(self.q_restore_btn)

        self.q_delete_btn = QPushButton('🗑️ 永久删除')
        self.q_delete_btn.setObjectName('btnDanger')
        self.q_delete_btn.setFixedSize(120, 36)
        self.q_delete_btn.clicked.connect(self._delete_selected)
        action_bar.addWidget(self.q_delete_btn)

        empty_btn = QPushButton('清空隔离区')
        empty_btn.setObjectName('btnDanger')
        empty_btn.setFixedSize(120, 36)
        empty_btn.clicked.connect(self._empty_quarantine)
        action_bar.addWidget(empty_btn)

        action_bar.addStretch()

        self.quarantine_status_label = QLabel('共 0 项，总大小 0 B')
        self.quarantine_status_label.setStyleSheet('color: #5f6368; font-size: 12px;')
        action_bar.addWidget(self.quarantine_status_label)

        layout.addLayout(action_bar)

        return page

    def _refresh_quarantine(self):
        """刷新隔离区列表"""
        try:
            items = self.quarantine_mgr.get_all()
            self.quarantine_table.setRowCount(0)

            total_size = 0
            for item in items:
                row = self.quarantine_table.rowCount()
                self.quarantine_table.insertRow(row)

                # 原始路径
                path_item = QTableWidgetItem(item.get('original_path', ''))
                path_item.setData(Qt.UserRole, item.get('id', ''))
                self.quarantine_table.setItem(row, 0, path_item)
                # 文件名
                self.quarantine_table.setItem(row, 1, QTableWidgetItem(item.get('file_name', '')))
                # 隔离日期
                q_time = item.get('quarantine_time', 0)
                date_str = datetime.fromtimestamp(q_time).strftime('%Y-%m-%d %H:%M:%S') if q_time else '-'
                self.quarantine_table.setItem(row, 2, QTableWidgetItem(date_str))
                # 大小
                size = item.get('file_size', 0)
                total_size += size
                self.quarantine_table.setItem(row, 3, QTableWidgetItem(self._format_size(size)))
                # 威胁名称
                threat_name = item.get('threat_name', '') or '-'
                self.quarantine_table.setItem(row, 4, QTableWidgetItem(threat_name))
                # 状态
                status = '已恢复' if item.get('restored') else '已隔离'
                status_item = QTableWidgetItem(status)
                if item.get('restored'):
                    status_item.setForeground(QColor('#34a853'))
                else:
                    status_item.setForeground(QColor('#ea4335'))
                self.quarantine_table.setItem(row, 5, status_item)

            # 更新状态
            count = len(items)
            self.quarantine_status_label.setText(f'共 {count} 项，总大小 {self._format_size(total_size)}')

            # 更新仪表盘统计
            self._update_stats()

        except Exception as e:
            logger.error(f"刷新隔离区失败: {e}")

    def _show_quarantine_context_menu(self, pos):
        """显示右键菜单"""
        item = self.quarantine_table.itemAt(pos)
        if not item:
            return

        menu = QMenu()

        restore_action = QAction('↩️ 恢复文件', self)
        restore_action.triggered.connect(self._restore_selected)
        menu.addAction(restore_action)

        delete_action = QAction('🗑️ 永久删除', self)
        delete_action.triggered.connect(self._delete_selected)
        menu.addAction(delete_action)

        menu.addSeparator()

        details_action = QAction('📋 查看详情', self)
        details_action.triggered.connect(self._show_quarantine_details)
        menu.addAction(details_action)

        menu.exec_(self.quarantine_table.viewport().mapToGlobal(pos))

    def _on_quarantine_selection_changed(self):
        """隔离区选择变化"""
        selected = self._get_selected_quarantine_ids()
        has_selection = len(selected) > 0
        single_selection = len(selected) == 1

        self.q_restore_btn.setEnabled(has_selection)
        self.q_delete_btn.setEnabled(has_selection)
        self.detail_restore_btn.setEnabled(has_selection)
        self.detail_delete_btn.setEnabled(has_selection)

        if single_selection:
            self._update_quarantine_details(selected[0])
            self.quarantine_details_panel.setVisible(True)
        else:
            self.quarantine_details_panel.setVisible(False)

    def _update_quarantine_details(self, qid: str):
        """更新隔离区详情面板"""
        try:
            items = self.quarantine_mgr.get_all()
            info = None
            for i in items:
                if i.get('id') == qid:
                    info = i
                    break

            if info:
                self.detail_labels['original_path'].setText(info.get('original_path', '-'))
                self.detail_labels['file_name'].setText(info.get('file_name', '-'))
                md5_val = info.get('md5', '-')
                self.detail_labels['md5'].setText(md5_val[:32] + '...' if len(md5_val) > 32 else md5_val)
                sha256_val = info.get('sha256', '-')
                self.detail_labels['sha256'].setText(sha256_val[:16] + '...' if len(sha256_val) > 16 else sha256_val)
                self.detail_labels['threat_name'].setText(info.get('threat_name', '-') or '-')
                self.detail_labels['threat_type'].setText(info.get('threat_type', '-') or '-')
                level = info.get('threat_level', 0)
                level_names = {5: '严重', 4: '高危', 3: '中等', 2: '低危', 1: '信息', 0: '未知'}
                self.detail_labels['threat_level'].setText(level_names.get(level, '未知'))
                q_time = info.get('quarantine_time', 0)
                date_str = datetime.fromtimestamp(q_time).strftime('%Y-%m-%d %H:%M:%S') if q_time else '-'
                self.detail_labels['quarantine_time'].setText(date_str)
                self.detail_labels['file_size'].setText(self._format_size(info.get('file_size', 0)))
                self.detail_labels['scan_engine'].setText(info.get('scan_engine', '-') or '-')
                status = '已恢复' if info.get('restored') else '已隔离'
                self.detail_labels['status'].setText(status)
        except Exception as e:
            logger.error(f"更新隔离详情失败: {e}")

    def _get_selected_quarantine_ids(self) -> list:
        """获取选中行的隔离ID列表"""
        ids = []
        for item in self.quarantine_table.selectedItems():
            if item.column() == 0:
                qid = item.data(Qt.UserRole)
                if qid:
                    ids.append(qid)
        return list(set(ids))

    def _restore_selected(self):
        """恢复选中文件"""
        ids = self._get_selected_quarantine_ids()
        if not ids:
            QMessageBox.information(self, '提示', '请先选择要恢复的文件')
            return

        reply = QMessageBox.question(
            self, '确认恢复',
            f'确定要恢复选中的 {len(ids)} 个文件吗？\n文件将恢复到原始路径。',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        success = 0
        for qid in ids:
            if self.quarantine_mgr.restore(qid):
                success += 1

        QMessageBox.information(self, '恢复结果', f'成功恢复 {success}/{len(ids)} 个文件')
        self._refresh_quarantine()

    def _delete_selected(self):
        """永久删除选中文件"""
        ids = self._get_selected_quarantine_ids()
        if not ids:
            QMessageBox.information(self, '提示', '请先选择要删除的文件')
            return

        reply = QMessageBox.warning(
            self, '确认删除',
            f'确定要永久删除选中的 {len(ids)} 个文件吗？\n此操作不可恢复！',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        success = 0
        for qid in ids:
            if self.quarantine_mgr.delete(qid):
                success += 1

        QMessageBox.information(self, '删除结果', f'成功删除 {success}/{len(ids)} 个文件')
        self._refresh_quarantine()

    def _empty_quarantine(self):
        """清空隔离区"""
        items = self.quarantine_mgr.get_all()
        if not items:
            QMessageBox.information(self, '提示', '隔离区已为空')
            return

        reply = QMessageBox.warning(
            self, '确认清空',
            f'确定要清空隔离区吗？\n将永久删除所有 {len(items)} 个隔离文件！\n此操作不可恢复！',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        success = 0
        for item in items:
            if self.quarantine_mgr.delete(item.get('id', '')):
                success += 1

        QMessageBox.information(self, '清空结果', f'成功清空 {success}/{len(items)} 个文件')
        self._refresh_quarantine()

    def _show_quarantine_details(self):
        """显示详情（通过右键菜单）"""
        ids = self._get_selected_quarantine_ids()
        if len(ids) == 1:
            self._update_quarantine_details(ids[0])
            self.quarantine_details_panel.setVisible(True)

    # ============================================================
    # 日志页面方法
    # ============================================================
    def _create_log_page(self) -> QWidget:
        """创建日志查看页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(12)

        # 标题栏
        title_bar = QHBoxLayout()
        title_label = QLabel('📋 日志查看')
        title_label.setFont(Fonts.HEADING)
        title_bar.addWidget(title_label)
        title_bar.addStretch()

        export_btn = QPushButton('📥 导出')
        export_btn.setObjectName('btnSecondary')
        export_btn.setFixedSize(80, 36)
        export_btn.clicked.connect(self._export_logs)
        title_bar.addWidget(export_btn)

        refresh_btn = QPushButton('🔄 刷新')
        refresh_btn.setObjectName('btnSecondary')
        refresh_btn.setFixedSize(80, 36)
        refresh_btn.clicked.connect(self._refresh_logs)
        title_bar.addWidget(refresh_btn)
        layout.addLayout(title_bar)

        # 筛选栏
        filter_bar = QFrame()
        filter_bar.setObjectName('card')
        filter_layout = QVBoxLayout(filter_bar)
        filter_layout.setSpacing(8)

        # 第一行：级别筛选
        level_layout = QHBoxLayout()
        level_layout.addWidget(QLabel('日志级别:'))
        level_layout.setSpacing(4)

        self.log_level_checks = {}
        for level_name in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            cb = QCheckBox(level_name)
            cb.setChecked(True)
            cb.stateChanged.connect(self._on_log_filter_changed)
            level_layout.addWidget(cb)
            self.log_level_checks[level_name] = cb

        level_layout.addStretch()
        filter_layout.addLayout(level_layout)

        # 第二行：模块、日期范围、搜索
        filter_row2 = QHBoxLayout()

        filter_row2.addWidget(QLabel('模块:'))
        self.log_module_combo = QComboBox()
        self.log_module_combo.addItems(['全部', 'Scanner', 'Monitor', 'Firewall', 'Cloud', 'System'])
        self.log_module_combo.currentTextChanged.connect(self._on_log_filter_changed)
        filter_row2.addWidget(self.log_module_combo)

        filter_row2.addSpacing(16)
        filter_row2.addWidget(QLabel('从:'))
        self.log_date_from = QDateEdit()
        self.log_date_from.setCalendarPopup(True)
        self.log_date_from.setDate(QDate(2000, 1, 1))
        self.log_date_from.dateChanged.connect(self._on_log_filter_changed)
        filter_row2.addWidget(self.log_date_from)

        filter_row2.addWidget(QLabel('到:'))
        self.log_date_to = QDateEdit()
        self.log_date_to.setCalendarPopup(True)
        self.log_date_to.setDate(QDate.currentDate())
        self.log_date_to.dateChanged.connect(self._on_log_filter_changed)
        filter_row2.addWidget(self.log_date_to)

        filter_row2.addSpacing(16)
        self.log_search_input = QLineEdit()
        self.log_search_input.setPlaceholderText('搜索日志...')
        self.log_search_input.setFixedWidth(200)
        self.log_search_input.returnPressed.connect(self._on_log_filter_changed)
        filter_row2.addWidget(self.log_search_input)

        search_btn = QPushButton('🔍')
        search_btn.setFixedSize(36, 36)
        search_btn.clicked.connect(self._on_log_filter_changed)
        filter_row2.addWidget(search_btn)

        filter_layout.addLayout(filter_row2)
        layout.addWidget(filter_bar)

        # 日志表格
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(5)
        self.log_table.setHorizontalHeaderLabels(['时间', '级别', '模块', '来源', '消息'])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.log_table, 1)

        # 底部操作栏
        action_bar = QHBoxLayout()

        clear_btn = QPushButton('🗑️ 清空日志')
        clear_btn.setObjectName('btnDanger')
        clear_btn.setFixedSize(120, 36)
        clear_btn.clicked.connect(self._clear_logs)
        action_bar.addWidget(clear_btn)

        export_btn2 = QPushButton('📥 导出日志')
        export_btn2.setObjectName('btnSecondary')
        export_btn2.setFixedSize(120, 36)
        export_btn2.clicked.connect(self._export_logs)
        action_bar.addWidget(export_btn2)

        action_bar.addStretch()

        self.log_auto_refresh_cb = QCheckBox('自动刷新')
        self.log_auto_refresh_cb.setChecked(True)
        self.log_auto_refresh_cb.stateChanged.connect(self._toggle_auto_refresh)
        action_bar.addWidget(self.log_auto_refresh_cb)

        action_bar.addWidget(QLabel('间隔:'))
        self.log_refresh_interval = QComboBox()
        self.log_refresh_interval.addItems(['1s', '5s', '10s', '30s'])
        self.log_refresh_interval.setCurrentIndex(1)  # 5s default
        self.log_refresh_interval.currentTextChanged.connect(self._on_refresh_interval_changed)
        action_bar.addWidget(self.log_refresh_interval)

        self.log_count_label = QLabel('共 0 条日志')
        self.log_count_label.setStyleSheet('color: #5f6368; font-size: 12px;')
        action_bar.addWidget(self.log_count_label)

        layout.addLayout(action_bar)

        # 自动刷新定时器
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self._refresh_logs)
        self.log_timer.start(5000)

        # 存储解析的日志
        self.log_records = []

        # 初始加载
        self._refresh_logs()

        return page

    def _refresh_logs(self):
        """刷新日志"""
        self.log_records = self._parse_log_file()
        self._apply_log_filters()

    def _on_log_filter_changed(self):
        """日志筛选条件变化"""
        self._apply_log_filters()

    def _apply_log_filters(self):
        """应用日志筛选"""
        # 获取筛选条件
        enabled_levels = set()
        for name, cb in self.log_level_checks.items():
            if cb.isChecked():
                enabled_levels.add(name)

        module_filter = self.log_module_combo.currentText()
        date_from = self.log_date_from.date()
        date_to = self.log_date_to.date()
        search_text = self.log_search_input.text().strip().lower()

        filtered = []
        for record in self.log_records:
            # 级别筛选
            if record['level'] not in enabled_levels:
                continue

            # 模块筛选
            if module_filter != '全部':
                module_map = {
                    'Scanner': 'scanner',
                    'Monitor': 'monitor',
                    'Firewall': 'firewall',
                    'Cloud': 'cloud',
                    'System': 'tiandun',
                }
                expected = module_map.get(module_filter, module_filter.lower())
                if expected not in record['module'].lower():
                    continue

            # 日期筛选
            try:
                record_date = QDate.fromString(record['timestamp'].split(' ')[0], 'yyyy-MM-dd')
                if record_date < date_from or record_date > date_to:
                    continue
            except Exception:
                pass

            # 搜索文本筛选
            if search_text:
                if (search_text not in record['message'].lower()
                        and search_text not in record['module'].lower()):
                    continue

            filtered.append(record)

        # 更新表格
        self.log_table.setRowCount(0)
        for record in filtered:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)

            self.log_table.setItem(row, 0, QTableWidgetItem(record['timestamp']))

            level_item = QTableWidgetItem(record['level'])
            # 颜色编码
            if record['level'] == 'ERROR':
                level_item.setForeground(QColor('#ffffff'))
                level_item.setBackground(QColor('#ea4335'))
            elif record['level'] == 'CRITICAL':
                level_item.setForeground(QColor('#ffffff'))
                level_item.setBackground(QColor('#d93025'))
            elif record['level'] == 'WARNING':
                level_item.setForeground(QColor('#1a1a1a'))
                level_item.setBackground(QColor('#fdd663'))
            elif record['level'] == 'INFO':
                level_item.setForeground(QColor('#1a73e8'))
            elif record['level'] == 'DEBUG':
                level_item.setForeground(QColor('#5f6368'))
            self.log_table.setItem(row, 1, level_item)

            self.log_table.setItem(row, 2, QTableWidgetItem(record['module']))
            self.log_table.setItem(row, 3, QTableWidgetItem(record.get('source', '')))
            self.log_table.setItem(row, 4, QTableWidgetItem(record['message']))

        self.log_count_label.setText(f'共 {len(filtered)} 条日志 (总 {len(self.log_records)} 条)')

    def _export_logs(self):
        """导出日志"""
        filtered = []
        for row in range(self.log_table.rowCount()):
            filtered.append({
                'timestamp': self.log_table.item(row, 0).text() if self.log_table.item(row, 0) else '',
                'level': self.log_table.item(row, 1).text() if self.log_table.item(row, 1) else '',
                'module': self.log_table.item(row, 2).text() if self.log_table.item(row, 2) else '',
                'source': self.log_table.item(row, 3).text() if self.log_table.item(row, 3) else '',
                'message': self.log_table.item(row, 4).text() if self.log_table.item(row, 4) else '',
            })

        if not filtered:
            QMessageBox.information(self, '提示', '没有日志可导出')
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, '导出日志', 'logs_export',
            'CSV 文件 (*.csv);;JSON 文件 (*.json)'
        )

        if not file_path:
            return

        try:
            if file_path.endswith('.csv'):
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['时间', '级别', '模块', '来源', '消息'])
                    for record in filtered:
                        writer.writerow([
                            record['timestamp'], record['level'],
                            record['module'], record['source'], record['message']
                        ])
            elif file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(filtered, f, ensure_ascii=False, indent=2)

            QMessageBox.information(self, '导出成功', f'日志已导出到 {file_path}')
        except Exception as e:
            QMessageBox.critical(self, '导出失败', f'导出日志失败: {e}')

    def _clear_logs(self):
        """清空日志"""
        reply = QMessageBox.warning(
            self, '确认清空',
            '确定要清空所有日志吗？\n此操作将删除日志文件内容！',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        try:
            log_path = os.path.join(PROJECT_ROOT, 'logs', 'tiandun.log')
            if os.path.exists(log_path):
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write('')

            error_log_path = os.path.join(PROJECT_ROOT, 'logs', 'tiandun.error.log')
            if os.path.exists(error_log_path):
                with open(error_log_path, 'w', encoding='utf-8') as f:
                    f.write('')

            self.log_records = []
            self._apply_log_filters()
            QMessageBox.information(self, '清空成功', '日志已清空')
            self.add_activity('📋 日志已清空')
        except Exception as e:
            QMessageBox.critical(self, '清空失败', f'清空日志失败: {e}')

    def _toggle_auto_refresh(self, state):
        """切换自动刷新"""
        if state:
            interval_text = self.log_refresh_interval.currentText()
            interval_ms = int(interval_text.replace('s', '')) * 1000
            self.log_timer.start(interval_ms)
        else:
            self.log_timer.stop()

    def _on_refresh_interval_changed(self, text: str):
        """刷新间隔变化"""
        if self.log_auto_refresh_cb.isChecked():
            interval_ms = int(text.replace('s', '')) * 1000
            self.log_timer.start(interval_ms)

    def _parse_log_file(self) -> list:
        """解析日志文件"""
        records = []
        log_path = os.path.join(PROJECT_ROOT, 'logs', 'tiandun.log')

        if not os.path.exists(log_path):
            return records

        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            # 从后向前解析（最新在前）
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue

                parts = line.split(' | ', 3)
                if len(parts) >= 4:
                    records.append({
                        'timestamp': parts[0].strip(),
                        'level': parts[1].strip(),
                        'module': parts[2].strip(),
                        'source': '',
                        'message': parts[3].strip(),
                    })
                elif len(parts) == 3:
                    records.append({
                        'timestamp': parts[0].strip(),
                        'level': parts[1].strip(),
                        'module': '',
                        'source': '',
                        'message': parts[2].strip(),
                    })

                # 限制记录数量
                if len(records) >= 10000:
                    break

        except Exception as e:
            logger.error(f"解析日志文件失败: {e}")

        return records

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """格式化文件大小"""
        if size_bytes < 1024:
            return f'{size_bytes} B'
        elif size_bytes < 1024 * 1024:
            return f'{size_bytes / 1024:.1f} KB'
        elif size_bytes < 1024 * 1024 * 1024:
            return f'{size_bytes / 1024 / 1024:.1f} MB'
        else:
            return f'{size_bytes / 1024 / 1024 / 1024:.2f} GB'

    # ============================================================
    # 功能方法
    # ============================================================
    def _start_scan(self, mode: str):
        """开始扫描"""
        if self._scan_worker and self._scan_worker.isRunning():
            return

        self._scan_worker = ScanWorker(mode)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.threat_found.connect(self._on_threat_found)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)

        # 更新UI
        self.scan_status_label.setText(f'正在{mode}扫描...')
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.cancel_scan_btn.setVisible(True)
        self.quick_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)
        self.scan_result_table.setRowCount(0)

        self._scan_worker.start()
        logger.info(f"开始{mode}扫描")

    def _cancel_scan(self):
        """取消扫描"""
        if self._scan_worker:
            self._scan_worker.cancel()
            self._scan_worker.terminate()
            self._scan_worker.wait()
            self._on_scan_finished({})

    def _custom_scan(self):
        """自定义扫描"""
        path = QFileDialog.getExistingDirectory(self, '选择扫描目录')
        if path:
            self._scan_worker = ScanWorker('custom', [path])
            self._scan_worker.progress.connect(self._on_scan_progress)
            self._scan_worker.threat_found.connect(self._on_threat_found)
            self._scan_worker.finished.connect(self._on_scan_finished)
            self._scan_worker.error.connect(self._on_scan_error)
            self._scan_worker.start()

    def _on_scan_progress(self, current: int, total: int):
        """扫描进度更新"""
        if total > 0:
            pct = int(current / total * 100)
            self.scan_progress.setValue(pct)
            self.scan_info.setText(f'扫描中: {current}/{total} 文件 ({pct}%)')

    def _on_threat_found(self, threat: dict):
        """发现威胁"""
        row = self.scan_result_table.rowCount()
        self.scan_result_table.insertRow(row)

        self.scan_result_table.setItem(row, 0, QTableWidgetItem(threat.get('file_name', '')))
        self.scan_result_table.setItem(row, 1, QTableWidgetItem(threat.get('threat_name', '')))
        self.scan_result_table.setItem(row, 2, QTableWidgetItem(threat.get('threat_type', '')))
        level = threat.get('threat_level', 0)
        level_names = {5: '严重', 4: '高危', 3: '中等', 2: '低危', 1: '信息'}
        self.scan_result_table.setItem(row, 3, QTableWidgetItem(level_names.get(level, '未知')))

        action_btn = QPushButton('隔离')
        action_btn.setObjectName('btnDanger')
        action_btn.setFixedSize(60, 28)
        self.scan_result_table.setCellWidget(row, 4, action_btn)

        # 更新统计
        self._update_stats()

    def _on_scan_finished(self, report: dict):
        """扫描完成"""
        self.scan_status_label.setText('扫描完成')
        self.scan_progress.setVisible(False)
        self.cancel_scan_btn.setVisible(False)
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)

        threats = len(report.get('threats', [])) if report else 0
        scanned = report.get('scanned_files', 0) if report else 0
        self.scan_info.setText(f'扫描完成: {scanned} 文件, {threats} 威胁')

        if threats > 0:
            self.add_activity(f'⚠️ 扫描完成，发现 {threats} 个威胁')
        else:
            self.add_activity(f'✅ 扫描完成，未发现威胁 ({scanned} 文件)')

        self._update_stats()

    def _on_scan_error(self, filepath: str, error: str):
        """扫描错误"""
        self.scan_info.setText(f'错误: {error}')

    def _toggle_protection(self):
        """切换防护状态"""
        self._protection_enabled = not self._protection_enabled
        if self._protection_enabled:
            self.protection_switch.setText('关闭防护')
            self.protection_switch.setObjectName('btnDanger')
            self.protection_title.setText('实时防护 - 已开启')
            self.status_label.setText('防护已开启')
            self.status_indicator.setStyleSheet(
                'background-color: #34a853; border-radius: 6px;'
            )
            self.add_activity('🛡️ 实时防护已开启')
        else:
            self.protection_switch.setText('开启防护')
            self.protection_switch.setObjectName('btnSuccess')
            self.protection_title.setText('实时防护 - 已关闭')
            self.status_label.setText('防护已关闭')
            self.status_indicator.setStyleSheet(
                'background-color: #ea4335; border-radius: 6px;'
            )
            self.add_activity('⚠️ 实时防护已关闭')

        config.set('realtime.enabled', self._protection_enabled)
        # 刷新样式
        self.setStyleSheet(self.styleSheet())

    def _on_theme_changed(self, theme: str):
        """主题切换"""
        self._is_dark = theme == '暗色'
        self._apply_theme()

    def _save_settings(self):
        """保存设置"""
        config.set('general.auto_start', self.auto_start_cb.isChecked())
        config.set('general.show_notifications', self.notify_cb.isChecked())
        config.set('scan.thread_count', self.thread_spin.value())
        config.set('scan.max_file_size_mb', self.max_size_spin.value())
        config.save()
        self.add_activity('⚙️ 设置已保存')
        QMessageBox.information(self, '设置', '设置已保存成功')

    def _update_status(self):
        """定时更新状态"""
        self._update_stats()

    def _update_stats(self):
        """更新统计信息"""
        try:
            stats = scanner.get_engine_stats()
            total_scanned = sum(s['stats']['scanned'] for s in stats)
            total_detected = sum(s['stats']['detected'] for s in stats)

            if 'total_scanned' in self.stats_labels:
                self.stats_labels['total_scanned'].setText(str(total_scanned))
            if 'total_threats' in self.stats_labels:
                self.stats_labels['total_threats'].setText(str(total_detected))
            if 'quarantined' in self.stats_labels:
                try:
                    q_stats = self.quarantine_mgr.get_stats()
                    self.stats_labels['quarantined'].setText(str(q_stats['total_items']))
                except Exception:
                    pass
        except Exception:
            pass

    def add_activity(self, message: str):
        """添加活动日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.activity_log.append(f'[{timestamp}] {message}')

    def _update_protection_status(self):
        """更新防护状态"""
        # 从配置读取
        pass


# ============================================================
# 应用入口
# ============================================================
def run_app():
    """运行GUI应用"""
    app = QApplication(sys.argv)
    app.setApplicationName('天盾 Antivirus')
    app.setApplicationVersion(ENGINE_VERSION)
    app.setOrganizationName('TianDun Security')

    # 设置字体
    font = QFont('Microsoft YaHei', 9)
    app.setFont(font)

    window = MainWindow()
    window.show()

    # 添加启动日志
    window.add_activity(f'🛡️ 天盾 Antivirus v{ENGINE_VERSION} 启动')

    return app.exec_()