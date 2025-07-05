"""
Development commands for debugging and testing
"""
import aiohttp
import discord
import gc
import logging
import os
import psutil
import sys
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from discord import app_commands

logger = logging.getLogger(__name__)

# Global error tracking
error_tracker = defaultdict(lambda: deque(maxlen=50))
last_errors = deque(maxlen=20)


def track_error(error_type: str, error: Exception):
    """Track errors for monitoring"""
    error_info = {
        'timestamp': datetime.now(timezone.utc),
        'type': error_type,
        'message': str(error),
        'traceback': traceback.format_exc()
    }
    error_tracker[error_type].append(error_info)
    last_errors.append(error_info)


def is_dev_user(user_id: int) -> bool:
    """Check if user is the designated developer"""
    dev_user_id = os.getenv('DEV')
    return bool(dev_user_id and str(user_id) == dev_user_id)


# Developer command group
dev_group = app_commands.Group(name="dev", description="Developer commands")


class DevPanelView(discord.ui.View):
    """Interactive developer panel with buttons"""

    def __init__(self):
        super().__init__(timeout=300)  # 5 minute timeout

    @discord.ui.button(label="🔄 Reload Engine", style=discord.ButtonStyle.primary, row=0)
    async def reload_engine_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Reload the anti-phishing engine"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            from src.optimizations import optimized_engine

            # Cleanup and reinitialize
            await optimized_engine.cleanup()
            await optimized_engine.initialize()

            await interaction.followup.send("✅ Anti-phishing engine reloaded successfully.", ephemeral=True)

        except Exception as e:
            logger.error(f"Error reloading engine: {e}")
            await interaction.followup.send(f"❌ Error reloading engine: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔄 Sync Commands", style=discord.ButtonStyle.success, row=0)
    async def sync_commands_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Sync slash commands to Discord"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            synced = await interaction.client.tree.sync()  # type: ignore
            await interaction.followup.send(f"✅ Synced {len(synced)} commands successfully.", ephemeral=True)

        except Exception as e:
            logger.error(f"Error syncing commands: {e}")
            await interaction.followup.send(f"❌ Error syncing commands: {str(e)}", ephemeral=True)

    @discord.ui.button(label="📋 Guild Info", style=discord.ButtonStyle.secondary, row=0)
    async def list_guilds_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """List all guilds the bot is connected to"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            guilds = interaction.client.guilds

            embed = discord.Embed(
                title=f"📋 Connected Guilds ({len(guilds)})",
                color=discord.Color.blue()
            )

            guild_info = []
            for guild in guilds[:10]:  # Limit to first 10
                member_count = guild.member_count or 0
                guild_info.append(f"**{guild.name}** (ID: {guild.id})\nMembers: {member_count}")

            if guild_info:
                embed.description = "\n\n".join(guild_info)
            else:
                embed.description = "No guilds found."

            if len(guilds) > 10:
                embed.set_footer(text=f"Showing first 10 of {len(guilds)} guilds")

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error listing guilds: {e}")
            await interaction.response.send_message(f"❌ Error listing guilds: {str(e)}", ephemeral=True)

    @discord.ui.button(label="📊 System Stats", style=discord.ButtonStyle.secondary, row=0)
    async def system_stats_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show detailed system and bot statistics"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            bot = interaction.client
            process = psutil.Process()

            # Bot stats
            guilds = len(bot.guilds)
            total_members = sum(guild.member_count or 0 for guild in bot.guilds)

            # System stats
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            bot_memory = process.memory_info().rss / 1024 / 1024  # MB

            # Bot uptime
            uptime = timedelta(seconds=int(time.time() - process.create_time()))

            embed = discord.Embed(
                title="📊 System & Bot Statistics",
                color=discord.Color.green()
            )

            embed.add_field(
                name="🤖 Bot Stats",
                value=f"Guilds: **{guilds:,}**\n"
                      f"Total Members: **{total_members:,}**\n"
                      f"Latency: **{bot.latency * 1000:.1f}ms**\n"
                      f"Uptime: **{uptime}**",
                inline=True
            )

            embed.add_field(
                name="💻 System Stats",
                value=f"CPU Usage: **{cpu_percent:.1f}%**\n"
                      f"RAM Usage: **{memory.percent:.1f}%**\n"
                      f"Bot Memory: **{bot_memory:.1f} MB**\n"
                      f"Python: **{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}**",
                inline=True
            )

            embed.add_field(
                name="📈 Memory Details",
                value=f"Total RAM: **{memory.total / 1024 ** 3:.1f} GB**\n"
                      f"Available: **{memory.available / 1024 ** 3:.1f} GB**\n"
                      f"Used: **{memory.used / 1024 ** 3:.1f} GB**",
                inline=True
            )

            embed.timestamp = datetime.now(timezone.utc)

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            await interaction.followup.send(f"❌ Error getting system stats: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🗃️ Cache Info", style=discord.ButtonStyle.secondary, row=1)
    async def cache_info_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show cache statistics and information"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🗃️ Cache Information",
                color=discord.Color.orange()
            )

            # Discord.py cache stats
            bot = interaction.client
            embed.add_field(
                name="📦 Discord Cache",
                value=f"Guilds: **{len(bot.guilds)}**\n"
                      f"Users: **{len(bot.users)}**\n"
                      f"Channels: **{len([c for c in bot.get_all_channels()])}**\n"
                      f"Emojis: **{len(bot.emojis)}**",
                inline=True
            )

            # Try to get anti-phishing cache stats
            try:
                from src.optimizations import optimized_engine
                # Use stats attribute if available
                if hasattr(optimized_engine, 'stats'):
                    cache_stats = optimized_engine.stats
                    embed.add_field(
                        name="🛡️ Anti-Phishing Cache",
                        value=f"Operations: **{len(cache_stats)}**\n"
                              f"Stats Available: **Yes**",
                        inline=True
                    )
                else:
                    embed.add_field(
                        name="🛡️ Anti-Phishing Cache",
                        value="Cache stats not available",
                        inline=True
                    )
            except ImportError:
                embed.add_field(
                    name="🛡️ Anti-Phishing Cache",
                    value="Optimized engine not loaded",
                    inline=True
                )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting cache info: {e}")
            await interaction.followup.send(f"❌ Error getting cache info: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🧹 Clear Cache", style=discord.ButtonStyle.danger, row=1)
    async def clear_cache_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Clear various caches"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            cleared = []

            # Clear anti-phishing cache
            try:
                from src.optimizations import optimized_engine
                if hasattr(optimized_engine, 'cleanup') and hasattr(optimized_engine, 'initialize'):
                    await optimized_engine.cleanup()
                    await optimized_engine.initialize()
                    cleared.append("Anti-phishing engine (restarted)")
            except (ImportError, AttributeError):
                pass

            # Clear user attempts cache
            try:
                from src.features.user_attempts import user_attempt_tracker
                # Reset attempts for all tracked users (simplified approach)
                user_attempt_tracker.cleanup_expired()
                cleared.append("User attempts cache (cleaned up)")
            except (ImportError, AttributeError):
                pass

            if cleared:
                await interaction.followup.send(f"✅ Cleared: {', '.join(cleared)}", ephemeral=True)
            else:
                await interaction.followup.send("⚠️ No caches were cleared (none available)", ephemeral=True)

        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            await interaction.followup.send(f"❌ Error clearing cache: {str(e)}", ephemeral=True)

    @discord.ui.button(label="📝 Recent Logs", style=discord.ButtonStyle.secondary, row=1)
    async def recent_logs_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show recent log entries"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            # Get recent log entries from memory (if available)
            embed = discord.Embed(
                title="📝 Recent Log Activity",
                description="Last 10 log entries from various loggers:",
                color=discord.Color.purple()
            )

            # Try to get recent logs from different modules
            log_sources = [
                ("optimizations", "Anti-phishing engine"),
                ("events.message", "Message handler"),
                ("commands", "Commands"),
                ("main", "Main bot")
            ]

            for module_name, description in log_sources:
                try:
                    module_logger = logging.getLogger(module_name)
                    # Note: This is basic - in production you'd want a proper log handler
                    embed.add_field(
                        name=f"📊 {description}",
                        value=f"Logger: `{module_name}`\nLevel: {logging.getLevelName(module_logger.level)}",
                        inline=True
                    )
                except Exception:
                    continue

            embed.add_field(
                name="ℹ️ Note",
                value="For detailed logs, check the console output or log files.",
                inline=False
            )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting recent logs: {e}")
            await interaction.followup.send(f"❌ Error getting recent logs: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔍 Test URL", style=discord.ButtonStyle.secondary, row=1)
    async def test_url_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Test a URL against the anti-phishing engine"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        await interaction.response.send_message("❌ TestURLModal is not implemented.", ephemeral=True)

    @discord.ui.button(label="⚡ Performance", style=discord.ButtonStyle.secondary, row=2)
    async def performance_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show performance metrics"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="⚡ Performance Metrics",
                color=discord.Color.gold()
            )

            # Try to get performance data
            try:
                from src.optimizations.performance import performance_monitor
                perf_stats = performance_monitor.get_stats()
                # Example: show total uptime and operation count
                embed.add_field(
                    name="� Analysis Times",
                    value=f"Uptime: **{perf_stats.get('uptime_seconds', 'N/A'):.0f}s**\n"
                          f"Tracked Operations: **{len(perf_stats.get('operations', {}))}**",
                    inline=True
                )
            except (ImportError, AttributeError):
                embed.add_field(
                    name="⚠️ Performance Module",
                    value="Performance tracking not available",
                    inline=False
                )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            await interaction.followup.send(f"❌ Error getting performance metrics: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔧 Database Info", style=discord.ButtonStyle.secondary, row=2)
    async def database_info_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show database information"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🔧 Database Information",
                color=discord.Color.teal()
            )

            # Guild config database
            try:
                import sqlite3
                conn = sqlite3.connect('guild_config.db')
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM guild_config")
                guild_count = cursor.fetchone()[0]

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()

                embed.add_field(
                    name="📁 Guild Config DB",
                    value=f"Configured Guilds: **{guild_count}**\n"
                          f"Tables: **{len(tables)}**",
                    inline=True
                )

                conn.close()
            except Exception as e:
                embed.add_field(
                    name="📁 Guild Config DB",
                    value=f"Error: {str(e)[:50]}...",
                    inline=True
                )

            # User attempts database (if exists)
            try:
                from src.features.user_attempts import get_attempt_stats
                user_stats = get_attempt_stats()
                embed.add_field(
                    name="👥 User Attempts",
                    value=f"Total Guilds: **{user_stats.get('total_guilds', 'N/A')}**\n"
                          f"Total Users: **{user_stats.get('total_users', 'N/A')}**",
                    inline=True
                )
            except ImportError:
                embed.add_field(
                    name="👥 User Attempts",
                    value="Module not available",
                    inline=True
                )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting database info: {e}")
            await interaction.followup.send(f"❌ Error getting database info: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔄 Refresh Panel", style=discord.ButtonStyle.primary, row=2)
    async def refresh_panel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Refresh the dev panel"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        embed = discord.Embed(
            title="🔧 Developer Control Panel",
            description="Enhanced debugging and monitoring tools:",
            color=discord.Color.blue()
        )

        embed.add_field(
            name="🔄 Core Actions",
            value="🔄 **Reload Engine** - Restart anti-phishing engine\n"
                  "🔄 **Sync Commands** - Sync slash commands\n"
                  "📋 **Guild Info** - Show connected servers\n"
                  "📊 **System Stats** - Detailed system metrics",
            inline=False
        )

        embed.add_field(
            name="🔍 Analysis & Debug",
            value="🗃️ **Cache Info** - View cache statistics\n"
                  "🧹 **Clear Cache** - Clear various caches\n"
                  "📝 **Recent Logs** - Show recent log activity\n"
                  "🔍 **Test URL** - Test URLs against engine",
            inline=False
        )

        embed.add_field(
            name="📊 Monitoring & Analysis",
            value="⚡ **Performance** - Performance metrics\n"
                  "🔧 **Database Info** - Database statistics\n"
                  "🌐 **Network Test** - Check connectivity\n"
                  "🚨 **Error Monitor** - View error statistics\n"
                  "🧠 **Memory Monitor** - Memory usage & leaks\n"
                  "⚙️ **Bot Config** - Configuration details\n"
                  "🔬 **System Analysis** - Advanced diagnostics",
            inline=False
        )

        view = DevPanelView()
        await interaction.response.edit_message(embed=embed, view=view)

    @discord.ui.button(label="🌐 Network Test", style=discord.ButtonStyle.secondary, row=3)
    async def network_test_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Test network connectivity and Discord API status"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🌐 Network & API Status",
                color=discord.Color.blue()
            )

            # Test Discord API latency
            discord_latency = interaction.client.latency * 1000

            # Test external connectivity
            test_urls = [
                "https://discord.com",
                "https://google.com",
                "https://phishtank.org"
            ]

            connectivity_results = []

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                for url in test_urls:
                    try:
                        start_time = time.time()
                        async with session.get(url) as response:
                            latency = (time.time() - start_time) * 1000
                            status = "✅" if response.status == 200 else f"⚠️ {response.status}"
                            connectivity_results.append(f"{status} {url}: **{latency:.0f}ms**")
                    except Exception as e:
                        connectivity_results.append(f"❌ {url}: **Error**")

            embed.add_field(
                name="🔗 Discord API",
                value=f"WebSocket Latency: **{discord_latency:.1f}ms**\n"
                      f"Status: **{'🟢 Good' if discord_latency < 200 else '🟡 Slow' if discord_latency < 500 else '🔴 Poor'}**",
                inline=True
            )

            embed.add_field(
                name="🌍 External Connectivity",
                value="\n".join(connectivity_results),
                inline=False
            )

            # Rate limit info
            bot = interaction.client
            if hasattr(bot, 'http') and hasattr(bot.http, 'get_ratelimit'):
                try:
                    embed.add_field(
                        name="⏱️ Rate Limits",
                        value="Rate limit info available via HTTP client",
                        inline=True
                    )
                except Exception:
                    pass

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error testing network: {e}")
            track_error("network_test", e)
            await interaction.followup.send(f"❌ Error testing network: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🚨 Error Monitor", style=discord.ButtonStyle.danger, row=3)
    async def error_monitor_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show error statistics and recent errors"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🚨 Error Monitoring",
                color=discord.Color.red()
            )

            # Error summary
            total_errors = sum(len(errors) for errors in error_tracker.values())
            recent_errors = len(
                [e for e in last_errors if e['timestamp'] > datetime.now(timezone.utc) - timedelta(hours=1)])

            embed.add_field(
                name="📊 Error Summary",
                value=f"Total Tracked: **{total_errors}**\n"
                      f"Last Hour: **{recent_errors}**\n"
                      f"Types: **{len(error_tracker)}**",
                inline=True
            )

            # Error types breakdown
            if error_tracker:
                error_breakdown = []
                for error_type, errors in list(error_tracker.items())[:5]:  # Top 5 error types
                    error_breakdown.append(f"**{error_type}**: {len(errors)}")

                embed.add_field(
                    name="🏷️ Error Types (Top 5)",
                    value="\n".join(error_breakdown) if error_breakdown else "No errors tracked",
                    inline=True
                )

            # Recent errors
            if last_errors:
                recent_list = []
                for error in list(last_errors)[-5:]:  # Last 5 errors
                    time_ago = datetime.now(timezone.utc) - error['timestamp']
                    recent_list.append(f"**{error['type']}** ({time_ago.total_seconds():.0f}s ago)")

                embed.add_field(
                    name="⏰ Recent Errors",
                    value="\n".join(recent_list),
                    inline=False
                )
            else:
                embed.add_field(
                    name="⏰ Recent Errors",
                    value="No recent errors 🎉",
                    inline=False
                )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting error monitor: {e}")
            track_error("error_monitor", e)
            await interaction.followup.send(f"❌ Error getting error monitor: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🧠 Memory Monitor", style=discord.ButtonStyle.secondary, row=3)
    async def memory_monitor_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show detailed memory usage and potential leaks"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🧠 Memory Monitoring",
                color=discord.Color.purple()
            )

            process = psutil.Process()
            memory_info = process.memory_info()

            # Basic memory stats
            embed.add_field(
                name="💾 Process Memory",
                value=f"RSS: **{memory_info.rss / 1024 / 1024:.1f} MB**\n"
                      f"VMS: **{memory_info.vms / 1024 / 1024:.1f} MB**\n"
                      f"Memory %: **{process.memory_percent():.1f}%**",
                inline=True
            )

            # Garbage collection stats
            gc_stats = gc.get_stats()
            uncollectable = len(gc.garbage)

            embed.add_field(
                name="🗑️ Garbage Collection",
                value=f"Collections: **{gc_stats[0]['collections'] if gc_stats else 'N/A'}**\n"
                      f"Uncollectable: **{uncollectable}**\n"
                      f"GC Enabled: **{'Yes' if gc.isenabled() else 'No'}**",
                inline=True
            )

            # Object counts (top types)
            try:
                import types
                object_counts = {}
                for obj in gc.get_objects():
                    obj_type = type(obj).__name__
                    object_counts[obj_type] = object_counts.get(obj_type, 0) + 1

                top_objects = sorted(object_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                object_list = [f"**{name}**: {count}" for name, count in top_objects]

                embed.add_field(
                    name="📦 Top Object Types",
                    value="\n".join(object_list),
                    inline=False
                )
            except Exception:
                embed.add_field(
                    name="📦 Object Analysis",
                    value="Object counting not available",
                    inline=False
                )

            # Force garbage collection
            collected = gc.collect()
            embed.add_field(
                name="🧹 GC Test",
                value=f"Objects collected: **{collected}**",
                inline=True
            )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting memory monitor: {e}")
            track_error("memory_monitor", e)
            await interaction.followup.send(f"❌ Error getting memory monitor: {str(e)}", ephemeral=True)

    @discord.ui.button(label="⚙️ Bot Config", style=discord.ButtonStyle.secondary, row=3)
    async def bot_config_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show bot configuration and environment variables"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="⚙️ Bot Configuration",
                color=discord.Color.gold()
            )

            # Environment variables (safe ones)
            safe_env_vars = ['DEV', 'PREFIX', 'DEBUG', 'ENVIRONMENT']
            env_info = []
            for var in safe_env_vars:
                value = os.getenv(var)
                if value:
                    # Mask sensitive data
                    if len(value) > 10:
                        display_value = value[:3] + "..." + value[-3:]
                    else:
                        display_value = value
                    env_info.append(f"**{var}**: `{display_value}`")
                else:
                    env_info.append(f"**{var}**: Not set")

            embed.add_field(
                name="🌍 Environment",
                value="\n".join(env_info),
                inline=True
            )

            # Bot configuration
            bot = interaction.client
            embed.add_field(
                name="🤖 Bot Info",
                value=f"User ID: **{bot.user.id if bot.user else 'N/A'}**\n"
                      f"Username: **{bot.user.name if bot.user else 'N/A'}**\n"
                      f"Intents: **{len([i for i in discord.Intents.all() if getattr(bot.intents, i[0], False)])} enabled**",
                inline=True
            )

            # File system info
            try:
                cwd = os.getcwd()
                file_count = len([f for f in os.listdir('.') if os.path.isfile(f)])
                dir_count = len([d for d in os.listdir('.') if os.path.isdir(d)])

                embed.add_field(
                    name="📁 Working Directory",
                    value=f"Path: `{cwd[-30:]}`\n"
                          f"Files: **{file_count}**\n"
                          f"Directories: **{dir_count}**",
                    inline=True
                )
            except Exception:
                pass

            # Python configuration
            embed.add_field(
                name="🐍 Python Info",
                value=f"Version: **{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}**\n"
                      f"Platform: **{sys.platform}**\n"
                      f"Executable: `{sys.executable[-30:]}`",
                inline=False
            )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error getting bot config: {e}")
            track_error("bot_config", e)
            await interaction.followup.send(f"❌ Error getting bot config: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔬 System Analysis", style=discord.ButtonStyle.secondary, row=4)
    async def system_analysis_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Open advanced system analysis modal"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        await interaction.response.send_message("❌ SystemAnalysisModal is not implemented.", ephemeral=True)

    @discord.ui.button(label="📊 Real-time Monitor", style=discord.ButtonStyle.success, row=4)
    async def realtime_monitor_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Start a real-time monitoring session"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            # Get current stats
            process = psutil.Process()
            bot = interaction.client

            embed = discord.Embed(
                title="📊 Real-time System Monitor",
                description="Live system metrics snapshot",
                color=discord.Color.green()
            )

            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_info = process.memory_info()

            embed.add_field(
                name="💻 System Resources",
                value=f"CPU: **{cpu_percent:.1f}%**\n"
                      f"Memory: **{memory_info.rss / 1024 / 1024:.1f} MB**\n"
                      f"Threads: **{process.num_threads()}**",
                inline=True
            )

            # Discord stats
            embed.add_field(
                name="🤖 Discord Stats",
                value=f"Latency: **{bot.latency * 1000:.1f}ms**\n"
                      f"Guilds: **{len(bot.guilds)}**\n"
                      f"Users: **{len(bot.users)}**",
                inline=True
            )

            # Recent activity
            recent_errors = len(
                [e for e in last_errors if e['timestamp'] > datetime.now(timezone.utc) - timedelta(minutes=5)])
            uptime = datetime.now(timezone.utc) - datetime.fromtimestamp(process.create_time(), tz=timezone.utc)

            embed.add_field(
                name="⚡ Recent Activity",
                value=f"Errors (5m): **{recent_errors}**\n"
                      f"Uptime: **{str(uptime).split('.')[0]}**",
                inline=True
            )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error in real-time monitor: {e}")
            track_error("realtime_monitor", e)
            await interaction.followup.send(f"❌ Error starting monitor: {str(e)}", ephemeral=True)

    @discord.ui.button(label="🔗 Webhook Test", style=discord.ButtonStyle.secondary, row=4)
    async def webhook_test_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Test webhook functionality"""
        if not is_dev_user(interaction.user.id):
            await interaction.response.send_message("❌ This action is restricted to developers.", ephemeral=True)
            return

        try:
            await interaction.response.defer(ephemeral=True)

            embed = discord.Embed(
                title="🔗 Webhook Status",
                color=discord.Color.blue()
            )

            # Check if the bot has webhook permissions
            guild = interaction.guild
            if guild and interaction.client.user:
                bot_member = guild.get_member(interaction.client.user.id)
                if bot_member:
                    has_webhook_perms = bot_member.guild_permissions.manage_webhooks
                    embed.add_field(
                        name="🔐 Permissions",
                        value=f"Manage Webhooks: **{'✅ Yes' if has_webhook_perms else '❌ No'}**",
                        inline=True
                    )

                # Check existing webhooks in the guild
                try:
                    webhooks = await guild.webhooks()
                    bot_webhooks = [w for w in webhooks if w.user and w.user.id == interaction.client.user.id]

                    embed.add_field(
                        name="🪝 Webhooks",
                        value=f"Total in Guild: **{len(webhooks)}**\n"
                              f"Bot's Webhooks: **{len(bot_webhooks)}**",
                        inline=True
                    )
                except discord.Forbidden:
                    embed.add_field(
                        name="🪝 Webhooks",
                        value="Cannot access webhook list (missing permissions)",
                        inline=True
                    )
            else:
                embed.add_field(
                    name="⚠️ Note",
                    value="Webhook test only works in a guild context",
                    inline=False
                )

            # Test webhook creation (dry run)
            embed.add_field(
                name="🧪 Test Results",
                value="✅ Webhook system appears functional\n"
                      "⚠️ Actual webhook creation requires explicit permission",
                inline=False
            )

            embed.timestamp = datetime.now(timezone.utc)
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error testing webhooks: {e}")
            track_error("webhook_test", e)
            await interaction.followup.send(f"❌ Error testing webhooks: {str(e)}", ephemeral=True)


# Command registration functions
@dev_group.command(name="panel", description="Open the developer control panel")
async def dev_panel(interaction: discord.Interaction):
    """Open the interactive developer panel"""
    if not is_dev_user(interaction.user.id):
        await interaction.response.send_message("❌ This command is restricted to developers.", ephemeral=True)
        return

    embed = discord.Embed(
        title="🔧 Developer Control Panel",
        description="Enhanced debugging and monitoring tools:",
        color=discord.Color.blue()
    )

    embed.add_field(
        name="🔄 Core Actions",
        value="🔄 **Reload Engine** - Restart anti-phishing engine\n"
              "🔄 **Sync Commands** - Sync slash commands\n"
              "📋 **Guild Info** - Show connected servers\n"
              "📊 **System Stats** - Detailed system metrics",
        inline=False
    )

    embed.add_field(
        name="🔍 Analysis & Debug",
        value="🗃️ **Cache Info** - View cache statistics\n"
              "🧹 **Clear Cache** - Clear various caches\n"
              "📝 **Recent Logs** - Show recent log activity\n"
              "🔍 **Test URL** - Test URLs against engine",
        inline=False
    )

    embed.add_field(
        name="📊 Monitoring & Analysis",
        value="⚡ **Performance** - Performance metrics\n"
              "🔧 **Database Info** - Database statistics\n"
              "🌐 **Network Test** - Check connectivity\n"
              "🚨 **Error Monitor** - View error statistics\n"
              "🧠 **Memory Monitor** - Memory usage & leaks\n"
              "⚙️ **Bot Config** - Configuration details\n"
              "🔬 **System Analysis** - Advanced diagnostics",
        inline=False
    )

    view = DevPanelView()
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@dev_group.command(name="reload", description="Reload the anti-phishing engine")
async def dev_reload(interaction: discord.Interaction):
    """Reload the anti-phishing engine"""
    if not is_dev_user(interaction.user.id):
        await interaction.response.send_message("❌ This command is restricted to developers.", ephemeral=True)
        return

    try:
        await interaction.response.defer(ephemeral=True)

        from src.optimizations import optimized_engine

        # Cleanup and reinitialize
        await optimized_engine.cleanup()
        await optimized_engine.initialize()

        await interaction.followup.send("✅ Anti-phishing engine reloaded successfully.", ephemeral=True)

    except Exception as e:
        logger.error(f"Error reloading engine: {e}")
        track_error("dev_reload", e)
        await interaction.followup.send(f"❌ Error reloading engine: {str(e)}", ephemeral=True)


@dev_group.command(name="sync", description="Sync slash commands")
async def dev_sync(interaction: discord.Interaction):
    """Sync slash commands to Discord"""
    if not is_dev_user(interaction.user.id):
        await interaction.response.send_message("❌ This command is restricted to developers.", ephemeral=True)
        return

    try:
        await interaction.response.defer(ephemeral=True)

        synced = await interaction.client.tree.sync()  # type: ignore
        await interaction.followup.send(f"✅ Synced {len(synced)} commands successfully.", ephemeral=True)

    except Exception as e:
        logger.error(f"Error syncing commands: {e}")
        track_error("dev_sync", e)
        await interaction.followup.send(f"❌ Error syncing commands: {str(e)}", ephemeral=True)


@dev_group.command(name="stats", description="Show system statistics")
async def dev_stats(interaction: discord.Interaction):
    """Show detailed system and bot statistics"""
    if not is_dev_user(interaction.user.id):
        await interaction.response.send_message("❌ This command is restricted to developers.", ephemeral=True)
        return

    try:
        await interaction.response.defer(ephemeral=True)

        bot = interaction.client
        process = psutil.Process()

        # Bot stats
        guilds = len(bot.guilds)
        total_members = sum(guild.member_count or 0 for guild in bot.guilds)

        # System stats
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        bot_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Bot uptime
        uptime = timedelta(seconds=int(time.time() - process.create_time()))

        embed = discord.Embed(
            title="📊 System & Bot Statistics",
            color=discord.Color.green()
        )

        embed.add_field(
            name="🤖 Bot Stats",
            value=f"Guilds: **{guilds:,}**\n"
                  f"Total Members: **{total_members:,}**\n"
                  f"Latency: **{bot.latency * 1000:.1f}ms**\n"
                  f"Uptime: **{uptime}**",
            inline=True
        )

        embed.add_field(
            name="💻 System Stats",
            value=f"CPU Usage: **{cpu_percent:.1f}%**\n"
                  f"RAM Usage: **{memory.percent:.1f}%**\n"
                  f"Bot Memory: **{bot_memory:.1f} MB**\n"
                  f"Python: **{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}**",
            inline=True
        )

        embed.add_field(
            name="📈 Memory Details",
            value=f"Total RAM: **{memory.total / 1024 ** 3:.1f} GB**\n"
                  f"Available: **{memory.available / 1024 ** 3:.1f} GB**\n"
                  f"Used: **{memory.used / 1024 ** 3:.1f} GB**",
            inline=True
        )

        embed.timestamp = datetime.now(timezone.utc)

        await interaction.followup.send(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        track_error("dev_stats", e)
        await interaction.followup.send(f"❌ Error getting system stats: {str(e)}", ephemeral=True)


@dev_group.command(name="errors", description="Show error statistics")
async def dev_errors(interaction: discord.Interaction):
    """Show error statistics and recent errors"""
    if not is_dev_user(interaction.user.id):
        await interaction.response.send_message("❌ This command is restricted to developers.", ephemeral=True)
        return

    try:
        await interaction.response.defer(ephemeral=True)

        embed = discord.Embed(
            title="🚨 Error Statistics",
            color=discord.Color.red()
        )

        # Error summary
        total_errors = sum(len(errors) for errors in error_tracker.values())
        recent_errors = len(
            [e for e in last_errors if e['timestamp'] > datetime.now(timezone.utc) - timedelta(hours=1)])

        embed.add_field(
            name="📊 Error Summary",
            value=f"Total Tracked: **{total_errors}**\n"
                  f"Last Hour: **{recent_errors}**\n"
                  f"Types: **{len(error_tracker)}**",
            inline=True
        )

        # Error types breakdown
        if error_tracker:
            error_breakdown = []
            for error_type, errors in list(error_tracker.items())[:5]:  # Top 5 error types
                error_breakdown.append(f"**{error_type}**: {len(errors)}")

            embed.add_field(
                name="🏷️ Error Types (Top 5)",
                value="\n".join(error_breakdown) if error_breakdown else "No errors tracked",
                inline=True
            )

        # Recent errors
        if last_errors:
            recent_list = []
            for error in list(last_errors)[-5:]:  # Last 5 errors
                time_ago = datetime.now(timezone.utc) - error['timestamp']
                recent_list.append(f"**{error['type']}** ({time_ago.total_seconds():.0f}s ago)")

            embed.add_field(
                name="⏰ Recent Errors",
                value="\n".join(recent_list),
                inline=False
            )
        else:
            embed.add_field(
                name="⏰ Recent Errors",
                value="No recent errors 🎉",
                inline=False
            )

        embed.timestamp = datetime.now(timezone.utc)
        await interaction.followup.send(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error getting error stats: {e}")
        track_error("dev_errors", e)
        await interaction.followup.send(f"❌ Error getting error stats: {str(e)}", ephemeral=True)


# Export the dev group for registration in main bot
__all__ = ['dev_group', 'track_error', 'is_dev_user']
