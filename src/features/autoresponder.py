"""
Autoresponder module for Discord Anti-Phishing Bot
Handles pattern matching and automated responses to messages
"""
import discord
import logging
import re
from typing import Optional, Dict, Any

from guild_config import (
    get_autoresponder_rules,
    check_autoresponder_cooldown,
    set_autoresponder_cooldown
)
from src.core.config import config

logger = logging.getLogger(__name__)


class AutoresponderEngine:
    """Engine for processing autoresponder rules and generating responses"""

    def __init__(self):
        self.compiled_patterns = {}  # Cache for compiled regex patterns

    def _compile_pattern(self, pattern: str, case_sensitive: bool = False) -> re.Pattern:
        """Compile and cache regex patterns"""
        cache_key = f"{pattern}_{case_sensitive}"
        if cache_key not in self.compiled_patterns:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                self.compiled_patterns[cache_key] = re.compile(pattern, flags)
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {e}")
                # Return a pattern that never matches
                self.compiled_patterns[cache_key] = re.compile(r'(?!.*)', flags)
        return self.compiled_patterns[cache_key]

    def _matches_pattern(self, message_content: str, rule: Dict[str, Any]) -> bool:
        """Check if message content matches a rule pattern"""
        trigger_pattern = rule['trigger_pattern']
        is_regex = rule['is_regex']
        case_sensitive = rule['case_sensitive']

        if is_regex:
            # Use regex matching
            try:
                pattern = self._compile_pattern(trigger_pattern, case_sensitive)
                return bool(pattern.search(message_content))
            except Exception as e:
                logger.error(f"Error matching regex pattern '{trigger_pattern}': {e}")
                return False
        else:
            # Simple substring matching
            content = message_content if case_sensitive else message_content.lower()
            pattern = trigger_pattern if case_sensitive else trigger_pattern.lower()
            return pattern in content

    async def process_message(self, message: discord.Message) -> Optional[str]:
        """
        Process a message against autoresponder rules
        Returns response message if a rule matches, None otherwise
        """
        if not config.AUTORESPONDER_ENABLED:
            return None

        if not message.guild:
            return None

        # Skip bot messages
        if message.author.bot:
            return None

        # Get autoresponder rules for this guild
        rules = get_autoresponder_rules(message.guild.id)
        if not rules:
            return None

        logger.debug(f"Processing message against {len(rules)} autoresponder rules in guild {message.guild.name}")

        # Check each rule in order
        for rule in rules:
            if not rule['is_enabled']:
                continue

            # Check if pattern matches
            if self._matches_pattern(message.content, rule):
                logger.info(f"Autoresponder rule '{rule['rule_name']}' matched in guild {message.guild.name}")

                # Check cooldown
                if check_autoresponder_cooldown(
                        message.guild.id,
                        message.author.id,
                        rule['id'],
                        config.AUTORESPONDER_COOLDOWN
                ):
                    logger.debug(f"User {message.author} is on cooldown for rule '{rule['rule_name']}'")
                    continue

                # Set cooldown
                set_autoresponder_cooldown(message.guild.id, message.author.id, rule['id'])

                # Return the response message (first matching rule wins)
                return rule['response_message']

        return None

    def validate_rule(self, trigger_pattern: str, is_regex: bool, case_sensitive: bool = False) -> tuple[bool, str]:
        """
        Validate an autoresponder rule
        Returns (is_valid, error_message)
        """
        if not trigger_pattern.strip():
            return False, "Trigger pattern cannot be empty"

        if len(trigger_pattern) > 500:
            return False, "Trigger pattern is too long (max 500 characters)"

        if is_regex:
            try:
                # Test compile the regex
                flags = 0 if case_sensitive else re.IGNORECASE
                re.compile(trigger_pattern, flags)
            except re.error as e:
                return False, f"Invalid regex pattern: {e}"

        return True, ""

    def validate_response(self, response_message: str) -> tuple[bool, str]:
        """
        Validate a response message
        Returns (is_valid, error_message)
        """
        if not response_message.strip():
            return False, "Response message cannot be empty"

        if len(response_message) > config.AUTORESPONDER_MAX_RESPONSE_LENGTH:
            return False, f"Response message is too long (max {config.AUTORESPONDER_MAX_RESPONSE_LENGTH} characters)"

        return True, ""


# Global autoresponder engine instance
autoresponder_engine = AutoresponderEngine()
