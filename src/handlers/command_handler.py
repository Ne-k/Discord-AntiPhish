import discord
import logging
from discord.ext import commands


class CommandHandler:
    """Handles command registration and processing"""

    def __init__(self, bot):
        self.bot = bot
        self.logger = logging.getLogger(__name__)

    async def handle_command_error(self, ctx, error):
        """Global command error handler"""
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
            self.logger.error(f"Unhandled command error: {error}")
            await ctx.send("❌ An unexpected error occurred while processing the command.")

    async def handle_app_command_error(self, interaction: discord.Interaction, error):
        """Global slash command error handler"""
        if isinstance(error, discord.app_commands.MissingPermissions):
            perms = ', '.join(error.missing_permissions)
            message = f"❌ You don't have permission to use this command. Required: `{perms}`"

        elif isinstance(error, discord.app_commands.BotMissingPermissions):
            perms = ', '.join(error.missing_permissions)
            message = f"❌ I don't have permission to do that. Required: `{perms}`"

        elif isinstance(error, discord.app_commands.CommandOnCooldown):
            message = f"❌ Command is on cooldown. Try again in {error.retry_after:.2f} seconds."

        else:
            self.logger.error(f"Unhandled app command error: {error}")
            message = "❌ An unexpected error occurred while processing the command."

        # Send error message
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)

    def setup_error_handlers(self):
        """Set up global error handlers"""

        @self.bot.event
        async def on_command_error(ctx, error):
            await self.handle_command_error(ctx, error)

        @self.bot.tree.error
        async def on_app_command_error(interaction: discord.Interaction, error):
            await self.handle_app_command_error(interaction, error)
