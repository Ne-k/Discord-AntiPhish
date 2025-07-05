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
    set_autoresponder_cooldown,
    get_guild_autoresponder_use_embeds,
    get_guild_autoresponder_use_reply,
    get_guild_autoresponder_embed_config
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

    async def process_message(self, message: discord.Message) -> Optional[Dict[str, Any]]:
        """
        Process a message against autoresponder rules
        Returns response data if a rule matches, None otherwise
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

                # Get guild settings for response format
                use_embeds = get_guild_autoresponder_use_embeds(message.guild.id)
                use_reply = get_guild_autoresponder_use_reply(message.guild.id)
                embed_config = get_guild_autoresponder_embed_config(message.guild.id)

                # Return the response data (first matching rule wins)
                return {
                    'message': rule['response_message'],
                    'use_embeds': use_embeds,
                    'use_reply': use_reply,
                    'rule_name': rule['rule_name'],
                    'embed_config': embed_config,
                    'is_json_embed': self._is_json_embed_format(rule['response_message'])
                }

        return None

    def _is_json_embed_format(self, response: str) -> bool:
        """Check if response is JSON embed format"""
        response = response.strip()
        
        # Must start with { and end with }
        if not (response.startswith('{') and response.endswith('}')):
            return False
        
        try:
            import json
            data = json.loads(response)
            
            # Must be a dictionary
            if not isinstance(data, dict):
                return False
            
            # Check for common embed fields
            embed_fields = ['title', 'description', 'color', 'footer', 'author', 'fields', 'thumbnail', 'image']
            has_embed_field = any(field in data for field in embed_fields)
            
            return has_embed_field
            
        except (json.JSONDecodeError, TypeError):
            return False

    def _create_embed_from_json(self, json_data: str, rule_name: str, embed_config: Dict[str, Any]) -> discord.Embed:
        """Create a Discord embed from JSON data"""
        import json
        
        try:
            data = json.loads(json_data)
        except:
            # Fallback to simple embed with the raw content
            return self._create_guild_configured_embed(json_data, rule_name, embed_config)
        
        # Get basic properties from JSON, use guild config as fallback
        title = data.get('title', embed_config.get('title', ''))
        description = data.get('description', '')
        color_str = data.get('color', embed_config.get('color', 'blue'))
        
        # Parse color
        color = discord.Color.blue()  # Default
        try:
            if isinstance(color_str, str):
                color_str = color_str.lower()
                if color_str == 'red':
                    color = discord.Color.red()
                elif color_str == 'green':
                    color = discord.Color.green()
                elif color_str == 'yellow':
                    color = discord.Color.yellow()
                elif color_str == 'purple':
                    color = discord.Color.purple()
                elif color_str == 'orange':
                    color = discord.Color.orange()
                elif color_str.startswith('#'):
                    color = discord.Color(int(color_str[1:], 16))
            elif isinstance(color_str, int):
                color = discord.Color(color_str)
        except:
            color = discord.Color.blue()  # Fallback
        
        # Create embed
        embed = discord.Embed(
            title=title,
            description=description,
            color=color
        )
        
        # Add fields if present
        if 'fields' in data and isinstance(data['fields'], list):
            for field in data['fields'][:25]:  # Discord limit
                if isinstance(field, dict) and 'name' in field and 'value' in field:
                    embed.add_field(
                        name=field['name'],
                        value=field['value'],
                        inline=field.get('inline', False)
                    )
        
        # Add footer if explicitly provided in JSON
        if 'footer' in data:
            footer = data['footer']
            if isinstance(footer, str):
                embed.set_footer(text=footer)
            elif isinstance(footer, dict) and 'text' in footer:
                embed.set_footer(
                    text=footer['text'],
                    icon_url=footer.get('icon_url') or None
                )
        # Use guild custom footer if configured and no footer in JSON
        elif embed_config.get('custom_footer'):
            embed.set_footer(text=embed_config['custom_footer'])
        # No automatic footer - user must specify if they want one
        
        # Add author if present
        if 'author' in data:
            author = data['author']
            if isinstance(author, str):
                embed.set_author(name=author)
            elif isinstance(author, dict) and 'name' in author:
                embed.set_author(
                    name=author['name'],
                    url=author.get('url') or None,
                    icon_url=author.get('icon_url') or None
                )
        
        # Add thumbnail if present
        if 'thumbnail' in data and isinstance(data['thumbnail'], str):
            try:
                embed.set_thumbnail(url=data['thumbnail'])
            except:
                pass  # Invalid URL
        
        # Add image if present
        if 'image' in data and isinstance(data['image'], str):
            try:
                embed.set_image(url=data['image'])
            except:
                pass  # Invalid URL
        
        return embed

    def _create_guild_configured_embed(self, message: str, rule_name: str, embed_config: Dict[str, Any]) -> discord.Embed:
        """Create an embed using guild configuration"""
        # Use guild-configured title or no title
        title = embed_config.get('title', '') if embed_config.get('title') else None
        
        # Parse guild-configured color
        color_str = embed_config.get('color', 'blue')
        color = discord.Color.blue()  # Default
        try:
            if isinstance(color_str, str) and color_str:
                color_str = color_str.lower()
                if color_str == 'red':
                    color = discord.Color.red()
                elif color_str == 'green':
                    color = discord.Color.green()
                elif color_str == 'yellow':
                    color = discord.Color.yellow()
                elif color_str == 'purple':
                    color = discord.Color.purple()
                elif color_str == 'orange':
                    color = discord.Color.orange()
                elif color_str.startswith('#'):
                    color = discord.Color(int(color_str[1:], 16))
        except:
            color = discord.Color.blue()  # Fallback
        
        # Create embed
        embed = discord.Embed(
            title=title,
            description=message,
            color=color
        )
        
        # Add custom footer if configured
        if embed_config.get('custom_footer'):
            embed.set_footer(text=embed_config['custom_footer'])
        # No automatic footer - clean appearance
        
        return embed

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
