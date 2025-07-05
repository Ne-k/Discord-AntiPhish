"""
Optimization package for the Discord Anti-Phishing Bot

This package contains:
- memory_manager: Memory usage optimization and leak prevention
- performance: Performance monitoring and async optimization utilities  
- cache: Advanced caching systems with LRU and multi-level support
- engine: Optimized anti-phishing engine with all optimizations integrated
"""

from .cache import (
    result_cache, domain_cache_phishing, domain_cache_malware,
    domain_cache_adguard, domain_cache_piracy
)
from .engine import optimized_engine
from .memory_manager import memory_manager
from .performance import performance_monitor, task_pool, connection_pool, async_timed, timed

__all__ = [
    'memory_manager',
    'performance_monitor',
    'task_pool',
    'connection_pool',
    'async_timed',
    'timed',
    'result_cache',
    'domain_cache_phishing',
    'domain_cache_malware',
    'domain_cache_adguard',
    'domain_cache_piracy',
    'optimized_engine'
]
