"""
Memory Manager for optimizing memory usage and preventing memory leaks
"""
import asyncio
import gc
import logging
import psutil
import weakref
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class MemoryManager:
    """Manages memory usage and prevents memory leaks"""

    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_mb = max_memory_mb
        self.process = psutil.Process()
        self.last_gc_time = datetime.now()
        self.gc_interval = timedelta(minutes=5)
        self.memory_warnings = defaultdict(int)
        self._cleanup_task = None
        self._weak_references = weakref.WeakSet()

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics"""
        memory_info = self.process.memory_info()
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'percent': self.process.memory_percent(),
            'available_mb': psutil.virtual_memory().available / 1024 / 1024
        }

    def should_force_gc(self) -> bool:
        """Check if we should force garbage collection"""
        memory_usage = self.get_memory_usage()
        time_since_gc = datetime.now() - self.last_gc_time

        return (
                memory_usage['rss_mb'] > self.max_memory_mb * 0.8 or
                time_since_gc > self.gc_interval
        )

    def force_gc(self) -> Dict[str, int]:
        """Force garbage collection and return statistics"""
        before_objects = len(gc.get_objects())

        # Force collection in all generations
        collected = []
        for generation in range(3):
            collected.append(gc.collect(generation))

        after_objects = len(gc.get_objects())
        self.last_gc_time = datetime.now()

        stats = {
            'objects_before': before_objects,
            'objects_after': after_objects,
            'objects_collected': before_objects - after_objects,
            'generation_0': collected[0],
            'generation_1': collected[1],
            'generation_2': collected[2]
        }

        logger.debug(f"Garbage collection stats: {stats}")
        return stats

    def register_cleanup_target(self, obj: Any):
        """Register an object for cleanup tracking"""
        self._weak_references.add(obj)

    def check_memory_threshold(self) -> bool:
        """Check if memory usage exceeds threshold"""
        memory_usage = self.get_memory_usage()
        if memory_usage['rss_mb'] > self.max_memory_mb:
            self.memory_warnings['threshold_exceeded'] += 1
            logger.warning(
                f"Memory usage ({memory_usage['rss_mb']:.1f}MB) exceeds "
                f"threshold ({self.max_memory_mb}MB). Warning #{self.memory_warnings['threshold_exceeded']}"
            )
            return True
        return False

    async def start_monitoring(self):
        """Start memory monitoring task"""
        if self._cleanup_task and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._memory_monitor_loop())
        logger.info("Memory monitoring started")

    async def stop_monitoring(self):
        """Stop memory monitoring task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Memory monitoring stopped")

    async def _memory_monitor_loop(self):
        """Memory monitoring loop"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                # Check memory usage
                memory_usage = self.get_memory_usage()

                # Force GC if needed
                if self.should_force_gc():
                    stats = self.force_gc()
                    logger.info(
                        f"Automatic GC: freed {stats['objects_collected']} objects, "
                        f"memory: {memory_usage['rss_mb']:.1f}MB"
                    )

                # Check memory threshold
                self.check_memory_threshold()

                # Log memory stats every 10 minutes
                if datetime.now().minute % 10 == 0:
                    logger.info(f"Memory usage: {memory_usage['rss_mb']:.1f}MB ({memory_usage['percent']:.1f}%)")

            except Exception as e:
                logger.error(f"Error in memory monitor: {e}")
                await asyncio.sleep(30)  # Wait before retrying


# Global memory manager instance
memory_manager = MemoryManager()
