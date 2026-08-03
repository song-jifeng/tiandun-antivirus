#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - UI 样式定义
"""
from PyQt5.QtGui import QColor, QPalette, QFont

# ============================================================
# 颜色方案
# ============================================================
class Colors:
    # 主色调
    PRIMARY = '#1a73e8'
    PRIMARY_DARK = '#1557b0'
    PRIMARY_LIGHT = '#4a9afa'

    # 安全色
    SAFE = '#34a853'
    SAFE_LIGHT = '#81c995'

    # 警告色
    WARNING = '#fbbc04'
    WARNING_LIGHT = '#fdd663'

    # 危险色
    DANGER = '#ea4335'
    DANGER_LIGHT = '#f28b82'

    # 信息色
    INFO = '#4285f4'
    INFO_LIGHT = '#8ab4f8'

    # 文字色
    TEXT_PRIMARY = '#202124'
    TEXT_SECONDARY = '#5f6368'
    TEXT_DISABLED = '#9aa0a6'

    # 背景色
    BG_PRIMARY = '#ffffff'
    BG_SECONDARY = '#f8f9fa'
    BG_TERTIARY = '#e8eaed'

    # 暗色主题
    DARK_BG_PRIMARY = '#1a1a2e'
    DARK_BG_SECONDARY = '#16213e'
    DARK_BG_TERTIARY = '#0f3460'
    DARK_TEXT_PRIMARY = '#e8eaed'
    DARK_TEXT_SECONDARY = '#9aa0a6'
    DARK_CARD = '#1e1e3a'
    DARK_BORDER = '#2a2a4a'


# ============================================================
# 字体
# ============================================================
class Fonts:
    FAMILY = 'Microsoft YaHei, Segoe UI, sans-serif'
    TITLE = QFont(FAMILY, 18, QFont.Bold)
    HEADING = QFont(FAMILY, 14, QFont.Bold)
    SUBHEADING = QFont(FAMILY, 12, QFont.Medium)
    BODY = QFont(FAMILY, 10)
    SMALL = QFont(FAMILY, 9)
    MONO = QFont('Consolas, Courier New', 10)


# ============================================================
# 亮色主题样式表
# ============================================================
LIGHT_STYLE = '''
QMainWindow, QWidget {
    background-color: #f8f9fa;
    color: #202124;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QPushButton {
    background-color: #1a73e8;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 20px;
    font-size: 13px;
    font-weight: bold;
    min-height: 36px;
}
QPushButton:hover {
    background-color: #1557b0;
}
QPushButton:pressed {
    background-color: #0d47a1;
}
QPushButton:disabled {
    background-color: #c4c7cc;
    color: #9aa0a6;
}

QPushButton#btnDanger {
    background-color: #ea4335;
}
QPushButton#btnDanger:hover {
    background-color: #d33426;
}

QPushButton#btnSuccess {
    background-color: #34a853;
}
QPushButton#btnSuccess:hover {
    background-color: #2d9249;
}

QPushButton#btnSecondary {
    background-color: #e8eaed;
    color: #202124;
}
QPushButton#btnSecondary:hover {
    background-color: #d2d5d9;
}

QLabel#titleLabel {
    font-size: 22px;
    font-weight: bold;
    color: #1a73e8;
}

QLabel#statusLabel {
    font-size: 14px;
    font-weight: bold;
}

QLabel#safeLabel {
    color: #34a853;
    font-size: 16px;
    font-weight: bold;
}

QLabel#dangerLabel {
    color: #ea4335;
    font-size: 16px;
    font-weight: bold;
}

QFrame#card {
    background-color: white;
    border: 1px solid #e8eaed;
    border-radius: 12px;
    padding: 16px;
}

QFrame#card:hover {
    border-color: #1a73e8;
}

QFrame#statsCard {
    background-color: white;
    border: 1px solid #e8eaed;
    border-radius: 8px;
    padding: 12px;
}

QListWidget, QTableWidget, QTreeWidget {
    background-color: white;
    border: 1px solid #dadce0;
    border-radius: 8px;
    outline: none;
}
QListWidget::item, QTableWidget::item, QTreeWidget::item {
    padding: 8px;
    border-bottom: 1px solid #f1f3f4;
}
QListWidget::item:selected, QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #e8f0fe;
    color: #1a73e8;
}
QListWidget::item:hover, QTableWidget::item:hover, QTreeWidget::item:hover {
    background-color: #f1f3f4;
}

QHeaderView::section {
    background-color: #f8f9fa;
    color: #5f6368;
    border: none;
    border-bottom: 2px solid #dadce0;
    padding: 10px;
    font-weight: bold;
}

QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: white;
    border: 1px solid #dadce0;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #1a73e8;
    border-width: 2px;
}

QComboBox {
    background-color: white;
    border: 1px solid #dadce0;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
    min-height: 20px;
}
QComboBox:focus {
    border-color: #1a73e8;
}
QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QCheckBox, QRadioButton {
    spacing: 8px;
    font-size: 13px;
}
QCheckBox::indicator, QRadioButton::indicator {
    width: 18px;
    height: 18px;
}

QScrollBar:vertical {
    background-color: #f1f3f4;
    width: 12px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background-color: #c4c7cc;
    border-radius: 6px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #9aa0a6;
}

QTabWidget::pane {
    border: 1px solid #dadce0;
    border-radius: 8px;
    background-color: white;
}
QTabBar::tab {
    padding: 10px 20px;
    font-size: 13px;
    border: none;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected {
    color: #1a73e8;
    border-bottom: 2px solid #1a73e8;
}
QTabBar::tab:hover {
    color: #1557b0;
    background-color: #f1f3f4;
}

QProgressBar {
    border: none;
    border-radius: 4px;
    background-color: #e8eaed;
    text-align: center;
    font-size: 12px;
    min-height: 8px;
}
QProgressBar::chunk {
    background-color: #1a73e8;
    border-radius: 4px;
}

QGroupBox {
    font-size: 13px;
    font-weight: bold;
    border: 1px solid #dadce0;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    padding: 0 8px;
}
'''


# ============================================================
# 暗色主题样式表
# ============================================================
DARK_STYLE = '''
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e8eaed;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
}

QPushButton {
    background-color: #1a73e8;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 20px;
    font-size: 13px;
    font-weight: bold;
    min-height: 36px;
}
QPushButton:hover {
    background-color: #4a9afa;
}
QPushButton:pressed {
    background-color: #0d47a1;
}
QPushButton:disabled {
    background-color: #3a3a5a;
    color: #6a6a8a;
}

QPushButton#btnDanger {
    background-color: #ea4335;
}

QPushButton#btnSuccess {
    background-color: #34a853;
}

QPushButton#btnSecondary {
    background-color: #2a2a4a;
    color: #e8eaed;
}

QLabel#titleLabel {
    color: #4a9afa;
}

QLabel#safeLabel {
    color: #34a853;
}

QLabel#dangerLabel {
    color: #ea4335;
}

QFrame#card {
    background-color: #1e1e3a;
    border: 1px solid #2a2a4a;
    border-radius: 12px;
    padding: 16px;
}
QFrame#card:hover {
    border-color: #1a73e8;
}

QFrame#statsCard {
    background-color: #1e1e3a;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    padding: 12px;
}

QListWidget, QTableWidget, QTreeWidget {
    background-color: #1e1e3a;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    color: #e8eaed;
}
QListWidget::item, QTableWidget::item, QTreeWidget::item {
    border-bottom: 1px solid #2a2a4a;
}
QListWidget::item:selected, QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #0f3460;
    color: #4a9afa;
}
QListWidget::item:hover, QTableWidget::item:hover, QTreeWidget::item:hover {
    background-color: #2a2a4a;
}

QHeaderView::section {
    background-color: #16213e;
    color: #9aa0a6;
    border-bottom: 2px solid #2a2a4a;
}

QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #1e1e3a;
    color: #e8eaed;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    padding: 8px 12px;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #1a73e8;
}

QComboBox {
    background-color: #1e1e3a;
    color: #e8eaed;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    padding: 8px 12px;
}
QComboBox:focus {
    border-color: #1a73e8;
}
QComboBox QAbstractItemView {
    background-color: #1e1e3a;
    color: #e8eaed;
    selection-background-color: #0f3460;
}

QCheckBox, QRadioButton {
    spacing: 8px;
    color: #e8eaed;
}

QScrollBar:vertical {
    background-color: #16213e;
    width: 12px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background-color: #3a3a5a;
    border-radius: 6px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #5a5a7a;
}

QTabWidget::pane {
    border: 1px solid #2a2a4a;
    background-color: #1e1e3a;
}
QTabBar::tab {
    padding: 10px 20px;
    color: #9aa0a6;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected {
    color: #4a9afa;
    border-bottom: 2px solid #4a9afa;
}
QTabBar::tab:hover {
    color: #e8eaed;
    background-color: #2a2a4a;
}

QProgressBar {
    border: none;
    border-radius: 4px;
    background-color: #2a2a4a;
    text-align: center;
    font-size: 12px;
    min-height: 8px;
}
QProgressBar::chunk {
    background-color: #1a73e8;
    border-radius: 4px;
}

QGroupBox {
    font-size: 13px;
    font-weight: bold;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    color: #e8eaed;
}
QGroupBox::title {
    subcontrol-origin: margin;
    padding: 0 8px;
}
'''


def get_style(is_dark: bool = False) -> str:
    """获取主题样式"""
    return DARK_STYLE if is_dark else LIGHT_STYLE