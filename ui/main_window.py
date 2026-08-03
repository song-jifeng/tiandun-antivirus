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
    QCheckBox, QComboBox, QLineEdit, QTextEdit, QGroupBox,
    QTabWidget, QSplitter, QScrollArea, QFileDialog, QButtonGroup,
    QRadioButton, QSizePolicy, QSpacerItem, QSlider, QSpinBox,
    QStyleFactory, QGridLayout, QFormLayout
)
from PyQt5.QtCore import (
    Qt, QTimer, pyqtSignal, QThread, QSize, QPropertyAnimation,
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
        self.pages.append(self._create_placeholder_page('📦 隔离区', '隔离区管理功能'))
        self.pages.append(self._create_placeholder_page('📋 日志', '日志查看功能'))
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