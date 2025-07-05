"""
User attempt tracking system for Discord anti-phishing bot.
Tracks user attempts in memory with periodic cleanup and cooldown resets.
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict
from typing import Dict, Set, Any

logger = logging.getLogger(__name__)


class UserAttemptTracker:
    """Tracks user attempts per guild with automatic cleanup and cooldown"""

    def __init__(self, cooldown_hours: float = 1.0):
        # Structure: {guild_id: {user_id: {'attempts': int, 'last_attempt': timestamp}}}
        self._attempts: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(lambda: defaultdict(dict))
        self._lock = threading.Lock()
        self.cooldown_seconds = cooldown_hours * 3600
        self._cleanup_task = None
        self._running = False

    def start_cleanup_task(self):
        """Start the periodic cleanup task"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._running = True
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            logger.info("User attempt tracker cleanup task started")

    def stop_cleanup_task(self):
        """Stop the periodic cleanup task"""
        self._running = False
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            logger.info("User attempt tracker cleanup task stopped")

    async def _periodic_cleanup(self):
        """Periodic cleanup task that runs every 30 minutes"""
        while self._running:
            try:
                await asyncio.sleep(1800)  # 30 minutes
                self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")

    def add_attempt(self, guild_id: int, user_id: int) -> int:
        """
        Add an attempt for a user in a guild.
        Returns the total number of attempts for this user.
        """
        with self._lock:
            current_time = time.time()

            # Initialize guild if needed
            if guild_id not in self._attempts:
                self._attempts[guild_id] = defaultdict(dict)

            # Get or initialize user data
            user_data = self._attempts[guild_id][user_id]

            # Check if we need to reset due to cooldown
            if 'last_attempt' in user_data:
                time_since_last = current_time - user_data['last_attempt']
                if time_since_last >= self.cooldown_seconds:
                    # Reset attempts after cooldown
                    user_data['attempts'] = 0
                    logger.info(f"Reset attempts for user {user_id} in guild {guild_id} after cooldown")

            # Increment attempts
            user_data['attempts'] = user_data.get('attempts', 0) + 1
            user_data['last_attempt'] = current_time

            attempts = int(user_data['attempts'])
            logger.info(f"User {user_id} in guild {guild_id} now has {attempts} attempts")
            return attempts

    def get_attempts(self, guild_id: int, user_id: int) -> int:
        """Get the current number of attempts for a user in a guild"""
        with self._lock:
            if guild_id not in self._attempts:
                return 0

            user_data = self._attempts[guild_id].get(user_id, {})
            if not user_data:
                return 0

            # Check if attempts should be reset due to cooldown
            current_time = time.time()
            if 'last_attempt' in user_data:
                time_since_last = current_time - user_data['last_attempt']
                if time_since_last >= self.cooldown_seconds:
                    # Reset attempts after cooldown
                    user_data['attempts'] = 0
                    user_data['last_attempt'] = current_time
                    return 0

            return int(user_data.get('attempts', 0))

    def reset_user_attempts(self, guild_id: int, user_id: int):
        """Manually reset a user's attempts"""
        with self._lock:
            if guild_id in self._attempts and user_id in self._attempts[guild_id]:
                self._attempts[guild_id][user_id]['attempts'] = 0
                self._attempts[guild_id][user_id]['last_attempt'] = time.time()
                logger.info(f"Manually reset attempts for user {user_id} in guild {guild_id}")

    def reset_guild_attempts(self, guild_id: int):
        """Reset all attempts for a guild"""
        with self._lock:
            if guild_id in self._attempts:
                self._attempts[guild_id].clear()
                logger.info(f"Reset all attempts for guild {guild_id}")

    def cleanup_expired(self):
        """Remove expired attempt records"""
        with self._lock:
            current_time = time.time()
            expired_count = 0

            for guild_id in list(self._attempts.keys()):
                guild_data = self._attempts[guild_id]

                for user_id in list(guild_data.keys()):
                    user_data = guild_data[user_id]
                    if 'last_attempt' in user_data:
                        time_since_last = current_time - user_data['last_attempt']
                        if time_since_last >= (self.cooldown_seconds * 2):
                            del guild_data[user_id]
                            expired_count += 1

                if not guild_data:
                    del self._attempts[guild_id]

            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired attempt records")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about tracked attempts"""
        with self._lock:
            total_guilds = len(self._attempts)
            total_users = sum(len(guild_data) for guild_data in self._attempts.values())

            current_time = time.time()
            active_users = 0

            for guild_data in self._attempts.values():
                for user_data in guild_data.values():
                    if 'last_attempt' in user_data:
                        time_since_last = current_time - user_data['last_attempt']
                        if time_since_last < self.cooldown_seconds:
                            active_users += 1

            return {
                'total_guilds': total_guilds,
                'total_users': total_users,
                'active_users': active_users,
                'cooldown_hours': self.cooldown_seconds / 3600
            }


# Global instance
user_attempt_tracker = UserAttemptTracker(cooldown_hours=1.0)


# Convenience functions
def add_user_attempt(guild_id: int, user_id: int) -> int:
    """Add an attempt for a user and return total attempts"""
    return user_attempt_tracker.add_attempt(guild_id, user_id)


def get_user_attempts(guild_id: int, user_id: int) -> int:
    """Get current attempts for a user"""
    return user_attempt_tracker.get_attempts(guild_id, user_id)


def reset_user_attempts(guild_id: int, user_id: int):
    """Reset attempts for a user"""
    user_attempt_tracker.reset_user_attempts(guild_id, user_id)


def reset_guild_attempts(guild_id: int):
    """Reset attempts for all users in a guild"""
    user_attempt_tracker.reset_guild_attempts(guild_id)


def get_attempt_stats() -> Dict[str, Any]:
    """Get attempt tracking statistics"""
    return user_attempt_tracker.get_stats()


def start_attempt_tracking():
    """Start the attempt tracking system"""
    user_attempt_tracker.start_cleanup_task()


def stop_attempt_tracking():
    """Stop the attempt tracking system"""
    user_attempt_tracker.stop_cleanup_task()
