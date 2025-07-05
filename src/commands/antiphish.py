"""
Anti-phishing command module
Contains commands for managing anti-phishing features
"""
import discord
import logging
from discord import app_commands

logger = logging.getLogger(__name__)


@app_commands.command(name="antiphish-stats", description="View anti-phishing statistics and cache info")
@app_commands.default_permissions(administrator=True)
async def antiphish_stats_command(interaction: discord.Interaction):
    """Show anti-phishing statistics"""
    try:
        await interaction.response.defer()

        from optimizations import optimized_engine

        embed = discord.Embed(
            title="🛡️ Anti-Phishing Statistics",
            color=discord.Color.blue()
        )

        # Engine status
        embed.add_field(
            name="Engine Status",
            value=f"Initialized: {'✅' if optimized_engine._initialized else '❌'}",
            inline=True
        )

        # Statistics
        stats = optimized_engine.stats
        embed.add_field(
            name="Analyses Performed",
            value=f"{stats.get('total_analyses', 0):,}",
            inline=True
        )

        # Cache info if available
        try:
            from optimizations.cache import domain_cache_adguard, domain_cache_piracy
            adguard_size = len(getattr(domain_cache_adguard, '_domains', []))
            piracy_size = len(getattr(domain_cache_piracy, '_domains', []))
            embed.add_field(
                name="Cache Sizes",
                value=f"AdGuard: {adguard_size:,}\nPiracy: {piracy_size:,}",
                inline=True
            )
        except:
            embed.add_field(name="Cache Sizes", value="N/A", inline=True)

        await interaction.followup.send(embed=embed)

    except Exception as e:
        logger.error(f"Error in antiphish stats command: {e}")
        await interaction.followup.send("❌ Error retrieving anti-phishing statistics.", ephemeral=True)


@app_commands.command(name="check-link", description="Check if a link is potentially malicious")
@app_commands.describe(url="The URL to check for threats")
async def check_link_command(interaction: discord.Interaction, url: str):
    """Check a link for threats"""
    try:
        await interaction.response.defer(ephemeral=True)

        from optimizations import optimized_engine

        guild_settings = {
            'anti_phish': True,
            'anti_malware': True,
            'anti_piracy': True
        }

        analysis = await optimized_engine.analyze_content(url, guild_settings)

        embed = discord.Embed(
            title="🔍 Link Analysis Results",
            color=discord.Color.red() if analysis['is_threat'] else discord.Color.green()
        )

        status = "🚨 THREAT DETECTED" if analysis['is_threat'] else "✅ SAFE"
        embed.add_field(name="Status", value=status, inline=False)

        if analysis['domains']:
            embed.add_field(name="Domains Found", value=", ".join(analysis['domains'][:3]), inline=False)

        if analysis['sources']:
            embed.add_field(name="Detection Sources", value="\n".join(analysis['sources'][:3]), inline=False)

        embed.add_field(name="Checked URL", value=f"`{url[:100]}{'...' if len(url) > 100 else ''}`", inline=False)

        await interaction.followup.send(embed=embed)

    except Exception as e:
        logger.error(f"Error in check link command: {e}")
        await interaction.followup.send("❌ Error checking the link.", ephemeral=True)


# Export the commands
__all__ = ['antiphish_stats_command', 'check_link_command']
