"""
Ready event handler for Discord anti-phishing bot
Handles bot ready events
"""
import logging

logger = logging.getLogger(__name__)


async def on_ready(bot):
    """Handle bot ready event"""
    try:
        logger.info(f"Bot {bot.user.name} is ready and online!")
        logger.info(f"Bot ID: {bot.user.id}")
        logger.info(f"Connected to {len(bot.guilds)} guilds")

    except Exception as e:
        logger.error(f"Error in on_ready: {e}")


async def on_disconnect(bot):
    """Handle bot disconnect event"""
    logger.warning("Bot disconnected from Discord")


async def on_resumed(bot):
    """Handle bot resume event"""
    logger.info("Bot connection resumed")
