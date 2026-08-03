# 天盾 Antivirus 编码规范与开发指南

## 1. 编码规范

### 1.1 Python 编码规范

本项目遵循 PEP 8 编码规范，主要规则如下：

**缩进：**
- 使用4个空格进行缩进
- 不使用Tab键

**行长度：**
- 最大行长度：100个字符
- 超出时使用括号、反斜杠或隐式续行

**空行：**
- 顶级定义之间空两行
- 方法定义之间空一行

**导入：**
- 标准库导入
- 第三方库导入
- 本地库导入
- 每组之间空一行

**命名规范：**
- 类名：CapWords 约定
- 函数名：小写加下划线
- 变量名：小写加下划线
- 常量名：大写加下划线
- 私有属性：前导下划线

### 1.2 文档字符串规范

所有模块、类、函数必须有文档字符串：

```python
def function(param1: str, param2: int) -> bool:
    """函数功能描述。

    Args:
        param1: 参数1描述
        param2: 参数2描述

    Returns:
        返回值描述

    Raises:
        ValueError: 异常情况描述
    """
    pass
```

### 1.3 类型注解

所有函数参数和返回值必须使用类型注解：

```python
from typing import List, Optional, Dict, Tuple

def scan_file(filepath: str) -> Optional[ThreatInfo]:
    ...
```

## 2. 代码结构规范

### 2.1 模块结构

每个模块文件应遵循以下结构：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块简短描述

详细描述模块功能、使用方法和注意事项
"""
import os
import sys
from typing import List, Optional

# 全局常量
CONSTANT_VALUE = 42

# 异常类
class CustomError(Exception):
    pass

# 工具函数
def utility_function():
    pass

# 主要类
class MainClass:
    def __init__(self):
        pass
    
    def public_method(self):
        pass
    
    def _private_method(self):
        pass
```

### 2.2 异常处理

```python
try:
    result = risky_operation()
except FileNotFoundError as e:
    logger.error(f"文件不存在: {e}")
    return None
except PermissionError as e:
    logger.error(f"权限不足: {e}")
    raise
except Exception as e:
    logger.exception(f"未知错误: {e}")
    return None
else:
    return result
finally:
    cleanup()
```

### 2.3 日志记录

```python
from engine.logger import logger

logger.debug("调试信息")      # 开发调试
logger.info("操作信息")       # 正常运行
logger.warning("警告信息")    # 潜在问题
logger.error("错误信息")      # 运行时错误
logger.critical("严重错误")   # 系统崩溃
logger.exception("异常信息")  # 带堆栈追踪
```

## 3. 测试规范

### 3.1 单元测试

```python
import unittest

class TestFeature(unittest.TestCase):
    def setUp(self):
        """测试前准备"""
        pass
    
    def tearDown(self):
        """测试后清理"""
        pass
    
    def test_normal_case(self):
        """正常情况测试"""
        self.assertEqual(result, expected)
    
    def test_edge_case(self):
        """边界情况测试"""
        self.assertIsNone(result)
    
    def test_error_case(self):
        """异常情况测试"""
        with self.assertRaises(ValueError):
            function()
```

### 3.2 测试覆盖要求

- 核心引擎：90%+
- 工具函数：80%+
- UI组件：60%+
- 集成测试：关键路径全覆盖

## 4. 文档规范

### 4.1 代码注释

```python
# 这是行注释
x = 1  # 行尾注释

def function():
    """文档字符串，描述函数功能"""
    # 实现细节注释
    pass
```

### 4.2 README 规范

每个模块应有README或文档说明：
- 功能描述
- 使用方法
- 依赖关系
- 示例代码

## 5. Git 工作流

### 5.1 分支策略

- main: 主分支，保持稳定
- develop: 开发分支
- feature/*: 功能分支
- fix/*: 修复分支
- release/*: 发布分支

### 5.2 提交信息格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

类型: feat/fix/docs/style/refactor/test/chore

### 5.3 代码审查检查清单

- [ ] 代码符合PEP 8规范
- [ ] 包含完整文档字符串
- [ ] 包含类型注解
- [ ] 异常处理完善
- [ ] 日志记录完整
- [ ] 单元测试覆盖
- [ ] 无安全漏洞
- [ ] 性能达标

## 6. 安全编码规范

### 6.1 输入验证

```python
def validate_input(data: str) -> bool:
    """验证输入数据"""
    if not data or len(data) > 1024:
        return False
    # 防止路径遍历
    if '..' in data or '/' in data:
        return False
    return True
```

### 6.2 路径安全

```python
def safe_path_join(base: str, *paths: str) -> str:
    """安全路径拼接"""
    result = os.path.normpath(os.path.join(base, *paths))
    if not result.startswith(os.path.normpath(base)):
        raise ValueError("路径遍历检测")
    return result
```

### 6.3 命令注入防护

```python
import subprocess

def safe_execute(command: List[str]) -> subprocess.CompletedProcess:
    """安全执行命令"""
    # 使用列表而不是字符串
    return subprocess.run(
        command,
        capture_output=True,
        timeout=30,
        shell=False  # 禁用shell
    )
```

## 7. 依赖管理

### 7.1 依赖声明

在 requirements.txt 中声明所有依赖：

```
PyQt5>=5.15.0
psutil>=5.9.0
pywin32>=305
watchdog>=3.0.0
requests>=2.28.0
aiohttp>=3.8.0
```

### 7.2 依赖安全

- 定期检查依赖漏洞
- 使用固定版本号
- 最小化依赖数量
- 审计第三方代码

## 8. 构建与部署

### 8.1 开发环境

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 8.2 打包

```bash
# 安装PyInstaller
pip install pyinstaller

# 打包
pyinstaller --onefile --windowed --name "TiandunAntivirus" main.py

# 输出: dist/TiandunAntivirus.exe
```

### 8.3 持续集成

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -r requirements.txt
      - run: python -m pytest tests/
```

## 9. 调试技巧

### 9.1 日志调试

```python
# 启用调试日志
import logging
logging.basicConfig(level=logging.DEBUG)

# 使用性能计时器
with logger.timer("操作名称"):
    risky_operation()
```

### 9.2 性能分析

```python
import cProfile
import pstats

# 性能分析
cProfile.run('function()', 'profile.stats')
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(20)
```

## 10. 常见问题

### 10.1 导入错误

```
问题: ModuleNotFoundError: No module named 'engine'
解决: 确保项目根目录在 sys.path 中
```

### 10.2 编码问题

```
问题: UnicodeEncodeError: 'gbk' codec can't encode character
解决: 设置环境变量 PYTHONIOENCODING=utf-8
```

### 10.3 权限问题

```
问题: PermissionError: [Errno 13] Permission denied
解决: 以管理员身份运行
```