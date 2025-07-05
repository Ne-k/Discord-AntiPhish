"""
Ping command for checking bot responsiveness
"""
import discord
import logging
import time
from discord import app_commands

logger = logging.getLogger(__name__)


@app_commands.command(name="ping", description="Check bot latency and responsiveness")
async def ping_command(interaction: discord.Interaction):
    """Simple ping command to check bot responsiveness"""
    try:
        start_time = time.perf_counter()
        await interaction.response.defer()
        end_time = time.perf_counter()

        latency = round((end_time - start_time) * 1000)
        websocket_latency = round(interaction.client.latency * 1000)

        embed = discord.Embed(
            title="🏓 Pong!",
            color=discord.Color.green()
        )
        embed.add_field(name="Response Time", value=f"{latency}ms", inline=True)
        embed.add_field(name="WebSocket Latency", value=f"{websocket_latency}ms", inline=True)

        await interaction.followup.send(embed=embed)

    except Exception as e:
        logger.error(f"Error in ping command: {e}")
        if not interaction.response.is_done():
            await interaction.response.send_message("❌ An error occurred while checking ping.", ephemeral=True)
        else:
            await interaction.followup.send("❌ An error occurred while checking ping.", ephemeral=True)


# Export the command
__all__ = ['ping_command']
