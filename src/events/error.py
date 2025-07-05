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

        elif isinstance(error, discord.HTTPException):
            if error.code == 10062:  # Unknown interaction
                logger.warning(f"Unknown interaction error: {error}")
                message = "❌ Interaction expired or bot was restarted. Please try the command again."
            elif error.code == 40060:  # Interaction has already been acknowledged
                logger.warning(f"Interaction already acknowledged: {error}")
                return  # Can't respond to already acknowledged interaction
            else:
                logger.error(f"Discord HTTP error: {error}")
                message = f"❌ Discord API error: {error}. Please try again in a moment."

        else:
            logger.error(f"Unhandled app command error: {error}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            message = "❌ An unexpected error occurred while processing the command."

        # Send error message
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException as send_error:
            if send_error.code == 10062:  # Unknown interaction - can't respond
                logger.warning("Could not send error response - interaction expired")
            else:
                logger.error(f"Failed to send error response: {send_error}")

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
