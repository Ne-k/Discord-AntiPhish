"""
Error handling events for the Discord bot
"""
import discord
import logging
import traceback
from discord.ext import commands

logger = logging.getLogger(__name__)


async def on_app_command_error(bot, interaction: discord.Interaction, error):
    """Handle slash command errors"""
    try:
        if isinstance(error, discord.app_commands.MissingPermissions):
            perms = ', '.join(error.missing_permissions)
            message = f"❌ You don't have permission to use this command. Required: `{perms}`"

        elif isinstance(error, discord.app_commands.BotMissingPermissions):
            perms = ', '.join(error.missing_permissions)
            message = f"❌ I don't have permission to do that. Required: `{perms}`"

        elif isinstance(error, discord.app_commands.CommandOnCooldown):
            message = f"❌ Command is on cooldown. Try again in {error.retry_after:.2f} seconds."

        elif isinstance(error, discord.app_commands.CommandNotFound):
            return  # Ignore command not found errors

        else:
            logger.error(f"Unhandled app command error: {error}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            message = "❌ An unexpected error occurred while processing the command."

        # Send error message
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in error handler: {e}")


async def on_command_error(bot, ctx, error):
    """Handle traditional command errors"""
    try:
        if isinstance(error, commands.CommandNotFound):
            return  # Ignore command not found errors

        elif isinstance(error, commands.MissingRequiredArgument):
            await ctx.send(f"❌ Missing required argument: `{error.param}`")

        elif isinstance(error, commands.BadArgument):
            await ctx.send(f"❌ Invalid argument provided: {error}")

        elif isinstance(error, commands.MissingPermissions):
            perms = ', '.join(error.missing_permissions)
            await ctx.send(f"❌ You don't have permission to use this command. Required: `{perms}`")

        elif isinstance(error, commands.BotMissingPermissions):
            perms = ', '.join(error.missing_permissions)
            await ctx.send(f"❌ I don't have permission to do that. Required: `{perms}`")

        elif isinstance(error, commands.CommandOnCooldown):
            await ctx.send(f"❌ Command is on cooldown. Try again in {error.retry_after:.2f} seconds.")

        else:
            logger.error(f"Unhandled command error: {error}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            await ctx.send("❌ An unexpected error occurred while processing the command.")

    except Exception as e:
        logger.error(f"Error in command error handler: {e}")


# Export the functions
__all__ = ['on_app_command_error', 'on_command_error']
