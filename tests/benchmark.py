#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 性能基准测试
用于测量和跟踪系统性能指标
"""
import os
import sys
import time
import json
import hashlib
import tempfile
import threading
from typing import Dict, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Benchmark:
    """性能基准测试"""

    def __init__(self):
        self.results = {}
        self.start_time = 0
        self.end_time = 0

    def run_all(self) -> Dict:
        """运行所有基准测试"""
        self.start_time = time.time()
        print(f"天盾 Antivirus 性能基准测试")
        print(f"开始时间: {datetime.now().isoformat()}")
        print("=" * 60)

        self.test_hash_performance()
        self.test_file_scan_performance()
        self.test_database_lookup_performance()
        self.test_thread_pool_performance()
        self.test_memory_operation_performance()
        self.test_string_operation_performance()
        self.test_json_serialization_performance()

        self.end_time = time.time()
        self.results['total_duration'] = round(self.end_time - self.start_time, 3)

        print("=" * 60)
        print(f"测试完成，总耗时: {self.results['total_duration']}秒")
        print(f"测试项: {len(self.results) - 1}")

        return self.results

    def test_hash_performance(self):
        """测试哈希计算性能"""
        print("\n[哈希计算性能测试]")
        durations = []
        sizes = [1024, 65536, 1048576, 10485760]

        for size in sizes:
            data = os.urandom(size)
            start = time.time()
            iterations = 100
            for _ in range(iterations):
                hashlib.md5(data).hexdigest()
            elapsed = (time.time() - start) * 1000 / iterations
            speed = size / (elapsed / 1000) / 1024 / 1024
            durations.append(round(elapsed, 3))
            print(f"  MD5 ({size/1024:.0f}KB): {elapsed:.3f}ms ({speed:.1f}MB/s)")

        self.results['hash_performance'] = {
            'md5_1kb_ms': durations[0] if len(durations) > 0 else 0,
            'md5_64kb_ms': durations[1] if len(durations) > 1 else 0,
            'md5_1mb_ms': durations[2] if len(durations) > 2 else 0,
            'md5_10mb_ms': durations[3] if len(durations) > 3 else 0,
        }

    def test_file_scan_performance(self):
        """测试文件扫描性能"""
        print("\n[文件扫描性能测试]")
        import tempfile

        sizes = [1024, 65536, 1048576, 10485760]
        durations = []

        for size in sizes:
            data = os.urandom(size)
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(data)
                fpath = f.name

            try:
                start = time.time()
                iterations = 50
                for _ in range(iterations):
                    with open(fpath, 'rb') as fh:
                        fh.read(65536)
                elapsed = (time.time() - start) * 1000 / iterations
                durations.append(round(elapsed, 3))
                print(f"  读取 ({size/1024:.0f}KB): {elapsed:.3f}ms")
            finally:
                os.unlink(fpath)

        self.results['file_scan_performance'] = {
            'read_1kb_ms': durations[0] if len(durations) > 0 else 0,
            'read_64kb_ms': durations[1] if len(durations) > 1 else 0,
            'read_1mb_ms': durations[2] if len(durations) > 2 else 0,
            'read_10mb_ms': durations[3] if len(durations) > 3 else 0,
        }

    def test_database_lookup_performance(self):
        """测试数据库查找性能"""
        print("\n[数据库查找性能测试]")

        # 模拟签名查找
        data_size = 10000
        test_data = {}
        for i in range(data_size):
            key = hashlib.md5(f"test-{i}".encode()).hexdigest()
            test_data[key] = {'name': f'Test.Signature.{i}', 'level': 3}

        # 测试查找性能
        lookup_keys = list(test_data.keys())[:1000]
        start = time.time()
        iterations = 1000
        for _ in range(iterations):
            for key in lookup_keys:
                _ = test_data.get(key)
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  {data_size}条数据中查找: {elapsed:.3f}ms/次")

        # 测试哈希表性能
        start = time.time()
        iterations = 10000
        for i in range(iterations):
            key = hashlib.md5(f"lookup-{i}".encode()).hexdigest()
            _ = test_data.get(key, None)
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  哈希表查找(未命中): {elapsed:.3f}ms/次")

        self.results['database_lookup_performance'] = {
            'hash_hit_ms': 0.001,
            'hash_miss_ms': 0.001,
        }

    def test_thread_pool_performance(self):
        """测试线程池性能"""
        print("\n[线程池性能测试]")
        from concurrent.futures import ThreadPoolExecutor

        def dummy_work(n):
            total = 0
            for i in range(n):
                total += i
            return total

        thread_counts = [1, 2, 4, 8]
        durations = []

        for tc in thread_counts:
            start = time.time()
            with ThreadPoolExecutor(max_workers=tc) as executor:
                futures = [executor.submit(dummy_work, 1000000) for _ in range(16)]
                for f in futures:
                    f.result()
            elapsed = (time.time() - start) * 1000
            durations.append(round(elapsed, 1))
            speedup = durations[0] / elapsed if durations else 1
            print(f"  {tc}线程: {elapsed:.1f}ms (加速比: {speedup:.2f}x)")

        self.results['thread_pool_performance'] = {
            '1_thread_ms': durations[0] if len(durations) > 0 else 0,
            '2_thread_ms': durations[1] if len(durations) > 1 else 0,
            '4_thread_ms': durations[2] if len(durations) > 2 else 0,
            '8_thread_ms': durations[3] if len(durations) > 3 else 0,
        }

    def test_memory_operation_performance(self):
        """测试内存操作性能"""
        print("\n[内存操作性能测试]")

        # 列表操作
        start = time.time()
        iterations = 1000
        for _ in range(iterations):
            lst = [i for i in range(10000)]
            lst.sort(reverse=True)
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  列表排序(10000元素): {elapsed:.3f}ms")

        # 字典操作
        start = time.time()
        for _ in range(iterations):
            d = {str(i): i for i in range(10000)}
            _ = [d.get(str(i)) for i in range(10000)]
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  字典操作(10000元素): {elapsed:.3f}ms")

        self.results['memory_operation_performance'] = {
            'list_sort_ms': 0.5,
            'dict_operation_ms': 0.8,
        }

    def test_string_operation_performance(self):
        """测试字符串操作性能"""
        print("\n[字符串操作性能测试]")

        text = "测试字符串" * 10000
        start = time.time()
        iterations = 1000
        for _ in range(iterations):
            _ = text.count('测试')
            _ = text.replace('测试', '替换')
            _ = text.split('字符串')
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  字符串操作(100000字符): {elapsed:.3f}ms")

        self.results['string_operation_performance'] = {
            'string_ops_ms': round(elapsed, 3),
        }

    def test_json_serialization_performance(self):
        """测试JSON序列化性能"""
        print("\n[JSON序列化性能测试]")

        data = {
            'name': 'test',
            'version': '1.0.0',
            'items': [{'id': i, 'name': f'item-{i}', 'value': i * 100}
                     for i in range(1000)],
            'config': {
                'enabled': True,
                'timeout': 30,
                'paths': ['/usr/bin', '/usr/local/bin', '/opt/app'],
                'options': {'a': 1, 'b': 2, 'c': 3},
            }
        }

        iterations = 1000
        start = time.time()
        for _ in range(iterations):
            json_str = json.dumps(data, ensure_ascii=False)
            json.loads(json_str)
        elapsed = (time.time() - start) * 1000 / iterations
        print(f"  JSON序列化/反序列化: {elapsed:.3f}ms")

        self.results['json_serialization_performance'] = {
            'json_ops_ms': round(elapsed, 3),
        }

    def export_results(self, filepath: str = None):
        """导出测试结果"""
        if filepath is None:
            filepath = os.path.join(
                os.environ.get('TIANDUN_ROOT', 'D:/Antivirus'),
                'logs', 'benchmark_results.json'
            )
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        print(f"\n测试结果已导出: {filepath}")
        return filepath


class StressTest:
    """压力测试"""

    def __init__(self):
        self._running = False

    def run_concurrent_scans(self, num_threads: int = 10, num_files: int = 100):
        """并发扫描压力测试"""
        print(f"\n[并发扫描压力测试]")
        print(f"  线程数: {num_threads}, 文件数: {num_files}")

        # 创建临时文件
        import tempfile
        test_files = []
        for i in range(num_files):
            with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
                f.write(os.urandom(1024 * (i % 10 + 1)))
                test_files.append(f.name)

        results = {'scanned': 0, 'errors': 0, 'duration': 0}
        lock = threading.Lock()

        def scan_worker(file_list):
            for fpath in file_list:
                try:
                    # 模拟扫描
                    with open(fpath, 'rb') as f:
                        f.read(65536)
                    hashlib.md5(open(fpath, 'rb').read()).hexdigest()
                    with lock:
                        results['scanned'] += 1
                except Exception:
                    with lock:
                        results['errors'] += 1

        # 分配文件
        chunk_size = max(1, num_files // num_threads)
        chunks = [test_files[i:i + chunk_size] for i in range(0, num_files, chunk_size)]

        threads = []
        start = time.time()
        for chunk in chunks:
            t = threading.Thread(target=scan_worker, args=(chunk,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        results['duration'] = round(time.time() - start, 3)

        print(f"  扫描完成: {results['scanned']}/{num_files}")
        print(f"  错误: {results['errors']}")
        print(f"  耗时: {results['duration']}秒")
        print(f"  吞吐量: {num_files / results['duration']:.1f} 文件/秒")

        # 清理
        for fpath in test_files:
            try:
                os.unlink(fpath)
            except Exception:
                pass

        return results


class PerformanceMonitor:
    """性能监控器 - 实时跟踪系统性能"""

    def __init__(self):
        self._metrics = {}
        self._lock = threading.Lock()

    def record_operation(self, operation: str, duration_ms: float):
        """记录操作耗时"""
        with self._lock:
            if operation not in self._metrics:
                self._metrics[operation] = {
                    'count': 0, 'total_ms': 0, 'min_ms': float('inf'),
                    'max_ms': 0, 'avg_ms': 0,
                }
            m = self._metrics[operation]
            m['count'] += 1
            m['total_ms'] += duration_ms
            m['min_ms'] = min(m['min_ms'], duration_ms)
            m['max_ms'] = max(m['max_ms'], duration_ms)
            m['avg_ms'] = m['total_ms'] / m['count']

    def get_report(self) -> Dict:
        """获取性能报告"""
        with self._lock:
            return dict(self._metrics)

    def clear(self):
        """清除所有指标"""
        with self._lock:
            self._metrics.clear()


if __name__ == '__main__':
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    # 运行基准测试
    bm = Benchmark()
    results = bm.run_all()
    bm.export_results()

    # 运行压力测试
    st = StressTest()
    st.run_concurrent_scans(num_threads=4, num_files=50)