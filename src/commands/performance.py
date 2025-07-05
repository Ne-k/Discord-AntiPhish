"""
Performance command for monitoring bot performance
"""
import discord
import logging
import os
import psutil
from datetime import datetime, timezone
from discord import app_commands

logger = logging.getLogger(__name__)


@app_commands.command(name="performance", description="View bot performance metrics")
@app_commands.default_permissions(administrator=True)
async def performance_command(interaction: discord.Interaction):
    """Display performance metrics"""
    try:
        await interaction.response.defer()

        # Get process info
        process = psutil.Process(os.getpid())

        # Memory usage
        memory_info = process.memory_info()
        memory_mb = round(memory_info.rss / 1024 / 1024, 2)

        # CPU usage
        cpu_percent = process.cpu_percent()

        # Uptime
        create_time = datetime.fromtimestamp(process.create_time(), tz=timezone.utc)
        uptime = datetime.now(timezone.utc) - create_time
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds

        embed = discord.Embed(
            title="📊 Performance Metrics",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )

        embed.add_field(name="Memory Usage", value=f"{memory_mb} MB", inline=True)
        embed.add_field(name="CPU Usage", value=f"{cpu_percent}%", inline=True)
        embed.add_field(name="Uptime", value=uptime_str, inline=True)

        # Bot-specific metrics
        embed.add_field(name="Guilds", value=len(interaction.client.guilds), inline=True)
        embed.add_field(name="Latency", value=f"{round(interaction.client.latency * 1000)}ms", inline=True)

        # Performance monitor stats if available
        try:
            from optimizations.performance import performance_monitor
            stats = performance_monitor.get_stats()

            if stats:
                embed.add_field(
                    name="Operation Stats",
                    value=f"Total Operations: {stats.get('total_operations', 0)}\nErrors: {stats.get('total_errors', 0)}",
                    inline=False
                )
        except:
            pass

        await interaction.followup.send(embed=embed)

    except Exception as e:
        logger.error(f"Error in performance command: {e}")
        await interaction.followup.send("❌ Error retrieving performance metrics.", ephemeral=True)


@app_commands.command(name="memory-stats", description="View detailed memory statistics")
@app_commands.default_permissions(administrator=True)
async def memory_stats_command(interaction: discord.Interaction):
    """Display memory statistics"""
    try:
        await interaction.response.defer()

        try:
            from optimizations.memory_manager import memory_manager
            stats = getattr(memory_manager, 'get_memory_stats', lambda: {})()
        except:
            stats = {}

        embed = discord.Embed(
            title="🧠 Memory Statistics",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )

        # Basic process memory info
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        memory_mb = round(memory_info.rss / 1024 / 1024, 2)

        embed.add_field(
            name="Process Memory",
            value=f"{memory_mb} MB",
            inline=True
        )

        if stats:
            embed.add_field(
                name="Cache Memory",
                value=f"{stats.get('cache_memory_mb', 0):.2f} MB",
                inline=True
            )

            embed.add_field(
                name="Usage Percentage",
                value=f"{stats.get('usage_percentage', 0):.1f}%",
                inline=True
            )
        else:
            embed.add_field(
                name="Advanced Stats",
                value="Memory manager not available",
                inline=False
            )

        await interaction.followup.send(embed=embed)

    except Exception as e:
        logger.error(f"Error in memory stats command: {e}")
        await interaction.followup.send("❌ Error retrieving memory statistics.", ephemeral=True)


# Export the commands
__all__ = ['performance_command', 'memory_stats_command']
