import discord
import logging
from datetime import datetime, timezone
from discord.ext import commands


class EventHandler:
    """Handles Discord events"""

    def __init__(self, bot):
        self.bot = bot
        self.logger = logging.getLogger(__name__)
        self.setup_events()

    def setup_events(self):
        """Register all event handlers"""

        @self.bot.event
        async def on_ready():
            await self.on_ready()

        @self.bot.event
        async def on_guild_remove(guild):
            await self.on_guild_remove(guild)

        @self.bot.event
        async def on_member_join(member):
            await self.on_member_join(member)

        @self.bot.event
        async def on_member_remove(member):
            await self.on_member_remove(member)

        @self.bot.event
        async def on_message(message):
            await self.on_message(message)

        @self.bot.event
        async def on_message_delete(message):
            await self.on_message_delete(message)

        @self.bot.event
        async def on_message_edit(before, after):
            await self.on_message_edit(before, after)

    async def on_ready(self):
        """Called when the bot is ready"""
        self.logger.info(f"Bot is ready! Logged in as {self.bot.user}")
        self.logger.info(f"Bot ID: {self.bot.user.id}")
        self.logger.info(f"Connected to {len(self.bot.guilds)} guilds")

        # Set bot status
        activity = discord.Game(name="with slash commands!")
        await self.bot.change_presence(status=discord.Status.online, activity=activity)

    async def on_guild_remove(self, guild):
        """Called when the bot is removed from a guild"""
        self.logger.info(f"Removed from guild: {guild.name} (ID: {guild.id})")

    async def on_member_join(self, member):
        """Called when a member joins a guild"""
        self.logger.info(f"Member joined {member.guild.name}: {member} (ID: {member.id})")

    async def on_member_remove(self, member):
        """Called when a member leaves a guild"""
        self.logger.info(f"Member left {member.guild.name}: {member} (ID: {member.id})")

    async def on_message(self, message):
        """Called when a message is sent"""
        if message.author.bot:
            return

        await self.bot.process_commands(message)

    async def on_message_delete(self, message):
        """Called when a message is deleted"""
        if message.author.bot:
            return

        self.logger.info(
            f"Message deleted in {message.guild.name if message.guild else 'DM'}: {message.content[:50]}...")

    async def on_message_edit(self, before, after):
        """Called when a message is edited"""
        if before.author.bot:
            return

        # Only log if content actually changed
        if before.content != after.content:
            self.logger.info(f"Message edited in {before.guild.name if before.guild else 'DM'}")
            self.logger.info(f"Before: {before.content[:50]}...")
            self.logger.info(f"After: {after.content[:50]}...")
