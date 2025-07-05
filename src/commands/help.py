"""
Help command for the Discord bot
"""
import discord
import logging
import os
from discord import app_commands
from discord.ext import commands

logger = logging.getLogger(__name__)


@app_commands.command(name="help", description="Show help information about the bot")
async def help_command(interaction: discord.Interaction):
    """Display help information"""
    try:
        embed = discord.Embed(
            title="🤖 Bot Help",
            description="Anti-phishing Discord bot :3",
            color=discord.Color.blue()
        )

        # Dynamically get registered commands
        bot = interaction.client
        # Type check and get commands from the app commands tree
        try:
            commands = getattr(bot, 'tree', None)
            if commands:
                commands = commands.get_commands()
            else:
                commands = []
        except:
            commands = []

        # Categorize commands
        admin_commands = []
        utility_commands = []
        performance_commands = []
        dev_commands = []

        for cmd in commands:
            if isinstance(cmd, discord.app_commands.Group):
                # Handle command groups
                if cmd.name == "settings":
                    admin_commands.append(f"• `/{cmd.name}` - Configure bot settings")
                elif cmd.name == "dev":
                    dev_commands.append(f"• `/{cmd.name}` - Developer commands")
                else:
                    utility_commands.append(f"• `/{cmd.name}` - {cmd.description}")
            else:
                # Handle individual commands
                if cmd.name in ["antiphish-stats", "test-detection"]:
                    admin_commands.append(f"• `/{cmd.name}` - {cmd.description}")
                elif cmd.name in ["performance", "memory-stats"]:
                    performance_commands.append(f"• `/{cmd.name}` - {cmd.description}")
                elif cmd.name in ["ping", "check-link", "help"]:
                    utility_commands.append(f"• `/{cmd.name}` - {cmd.description}")
                else:
                    utility_commands.append(f"• `/{cmd.name}` - {cmd.description}")

        # Add command fields if they have content
        if admin_commands:
            embed.add_field(
                name="⚙️ Admin Commands",
                value="\n".join(admin_commands),
                inline=False
            )

        if utility_commands:
            embed.add_field(
                name="🔧 Utility Commands",
                value="\n".join(utility_commands),
                inline=False
            )

        if performance_commands:
            embed.add_field(
                name="📊 Performance",
                value="\n".join(performance_commands),
                inline=False
            )

        # Only show dev commands to the DEV user specified in environment
        if dev_commands:
            try:
                dev_user_id = os.getenv('DEV')
                if dev_user_id and str(interaction.user.id) == dev_user_id:
                    embed.add_field(
                        name="🔧 Developer Commands",
                        value="\n".join(dev_commands),
                        inline=False
                    )
            except:
                pass  # Skip if we can't get DEV environment variable

        embed.add_field(
            name="� Tips",
            value="• Use `/settings view` to see current server configuration\n• Commands with permissions may only be visible to admins\n• Report false positives using the button that appears after detections",
            inline=False
        )

        embed.set_footer(text=f"Total Commands: {len(commands)} | Use /settings to configure protection")

        await interaction.response.send_message(embed=embed)

    except Exception as e:
        logger.error(f"Error in help command: {e}")
        await interaction.response.send_message("❌ Error displaying help information.", ephemeral=True)


# Export the command
__all__ = ['help_command']
