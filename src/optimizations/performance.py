"""
Performance optimization utilities for the Discord bot
"""
import asyncio
import logging
import time
import weakref
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Any, Callable, Optional

try:
    from src.core.config import get_user_agent
except ImportError:
    # Fallback if config module is not available
    def get_user_agent(service: str = 'performance') -> str:
        return "Nek_ng Anti Phish"

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Monitor and track performance metrics"""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.slow_operations = deque(maxlen=100)
        self.error_counts = defaultdict(int)
        self.start_time = time.time()

    def track_timing(self, operation: str, duration: float):
        """Track operation timing"""
        self.metrics[operation].append({
            'duration': duration,
            'timestamp': time.time()
        })

        # Keep only last 1000 entries per operation
        if len(self.metrics[operation]) > 1000:
            self.metrics[operation] = self.metrics[operation][-1000:]

        # Track slow operations (>2 seconds)
        if duration > 2.0:
            self.slow_operations.append({
                'operation': operation,
                'duration': duration,
                'timestamp': time.time()
            })

    def track_error(self, operation: str):
        """Track error occurrences"""
        self.error_counts[operation] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        stats = {
            'uptime_seconds': time.time() - self.start_time,
            'operations': {},
            'slow_operations': list(self.slow_operations),
            'error_counts': dict(self.error_counts)
        }

        for operation, timings in self.metrics.items():
            if not timings:
                continue

            durations = [t['duration'] for t in timings]
            stats['operations'][operation] = {
                'count': len(durations),
                'avg_duration': sum(durations) / len(durations),
                'min_duration': min(durations),
                'max_duration': max(durations),
                'recent_count': len([t for t in timings if time.time() - t['timestamp'] < 3600])
            }

        return stats


def async_timed(operation_name: Optional[str] = None):
    """Decorator to time async operations"""

    def decorator(func: Callable):
        name = operation_name or f"{func.__module__}.{func.__name__}"

        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                performance_monitor.track_error(name)
                raise
            finally:
                duration = time.time() - start_time
                performance_monitor.track_timing(name, duration)

        return wrapper

    return decorator


def timed(operation_name: Optional[str] = None):
    """Decorator to time sync operations"""

    def decorator(func: Callable):
        name = operation_name or f"{func.__module__}.{func.__name__}"

        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                performance_monitor.track_error(name)
                raise
            finally:
                duration = time.time() - start_time
                performance_monitor.track_timing(name, duration)

        return wrapper

    return decorator


class AsyncTaskPool:
    """Manage a pool of async tasks with concurrency limits"""

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks = weakref.WeakSet()

    async def run_task(self, coro):
        """Run a task with concurrency limiting"""
        async with self.semaphore:
            task = asyncio.create_task(coro)
            self.active_tasks.add(task)
            try:
                return await task
            finally:
                # Task will be automatically removed from WeakSet when it's done
                pass

    def get_active_count(self) -> int:
        """Get number of active tasks"""
        return len(self.active_tasks)


class BatchProcessor:
    """Process items in batches with configurable delays"""

    def __init__(self, batch_size: int = 10, delay_seconds: float = 1.0):
        self.batch_size = batch_size
        self.delay_seconds = delay_seconds
        self.queue = asyncio.Queue()
        self._processor_task = None
        self._running = False

    async def add_item(self, item: Any):
        """Add item to processing queue"""
        await self.queue.put(item)

    async def start(self, processor_func: Callable):
        """Start batch processing"""
        if self._running:
            return

        self._running = True
        self._processor_task = asyncio.create_task(
            self._process_batches(processor_func)
        )

    async def stop(self):
        """Stop batch processing"""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

    async def _process_batches(self, processor_func: Callable):
        """Process items in batches"""
        while self._running:
            try:
                batch = []

                # Collect batch items
                for _ in range(self.batch_size):
                    try:
                        item = await asyncio.wait_for(
                            self.queue.get(), timeout=self.delay_seconds
                        )
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break

                # Process batch if we have items
                if batch:
                    try:
                        await processor_func(batch)
                    except Exception as e:
                        logger.error(f"Error processing batch: {e}")

                # Small delay between batches
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
                await asyncio.sleep(1.0)


class ConnectionPool:
    """Manage HTTP connection pooling"""

    def __init__(self, max_connections: int = 50, max_per_host: int = 10):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self._session = None

    async def get_session(self):
        """Get or create HTTP session with optimized settings"""
        if self._session is None or self._session.closed:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                limit_per_host=self.max_per_host,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )

            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": get_user_agent('performance')}
            )

        return self._session

    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()


# Global instances
performance_monitor = PerformanceMonitor()
task_pool = AsyncTaskPool(max_concurrent=20)
connection_pool = ConnectionPool()
