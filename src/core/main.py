import asyncio
import discord
import importlib
import logging
import os
import pkgutil
import sys
from discord.ext import commands
from dotenv import load_dotenv
from pathlib import Path

# Add the project root and src to Python path
project_root = Path(__file__).parent.parent.parent
src_root = project_root / "src"
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(src_root))

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DiscordBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True

        super().__init__(
            command_prefix='!',
            intents=intents,
            help_command=None
        )

        self.loaded_events = {}

    async def setup_hook(self):
        """This is called when the bot is starting up"""
        logger.info("Setting up bot...")

        await self.load_commands()
        await self.load_events()

        await self.initialize_antiphish()

        logger.info("Syncing slash commands globally...")
        try:
            synced_global = await self.tree.sync()
            logger.info(f"Synced {len(synced_global)} command(s) globally")

        except Exception as e:
            logger.error(f"Failed to sync commands globally: {e}")

    async def load_commands(self):
        """Load all command files from the commands directory"""
        commands_dir = src_root / "commands"
        if not commands_dir.exists():
            logger.warning("Commands directory not found")
            return

        logger.info("Loading commands...")
        loaded_count = 0

        for file_path in commands_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue

            module_name = f"commands.{file_path.stem}"
            try:
                module = importlib.import_module(module_name)

                # Check if module has __all__ defined, use that
                if hasattr(module, '__all__'):
                    for attr_name in module.__all__:
                        attr = getattr(module, attr_name)

                        if isinstance(attr, discord.app_commands.Command):
                            try:
                                self.tree.add_command(attr)
                                loaded_count += 1
                                logger.info(f"Loaded command: {attr.name}")
                            except Exception as e:
                                logger.warning(f"Command {attr.name} already registered: {e}")
                        elif isinstance(attr, discord.app_commands.Group):
                            try:
                                self.tree.add_command(attr)
                                loaded_count += 1
                                logger.info(f"Loaded command group: {attr.name}")
                            except Exception as e:
                                logger.warning(f"Command group {attr.name} already registered: {e}")
                else:
                    # Fallback to scanning all attributes
                    for attr_name in dir(module):
                        if attr_name.startswith('_'):
                            continue
                        attr = getattr(module, attr_name)

                        if isinstance(attr, discord.app_commands.Command):
                            try:
                                self.tree.add_command(attr)
                                loaded_count += 1
                                logger.info(f"Loaded command: {attr.name}")
                            except Exception as e:
                                logger.warning(f"Command {attr.name} already registered: {e}")
                        elif isinstance(attr, discord.app_commands.Group):
                            try:
                                self.tree.add_command(attr)
                                loaded_count += 1
                                logger.info(f"Loaded command group: {attr.name}")
                            except Exception as e:
                                logger.warning(f"Command group {attr.name} already registered: {e}")

            except Exception as e:
                logger.error(f"Failed to load command file {file_path.name}: {e}")

        logger.info(f"Loaded {loaded_count} commands")

    async def load_events(self):
        """Load all event files from the events directory"""
        events_dir = src_root / "events"
        if not events_dir.exists():
            logger.warning("Events directory not found")
            return

        logger.info("Loading events...")

        for file_path in events_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue

            module_name = f"events.{file_path.stem}"
            try:
                module = importlib.import_module(module_name)

                for attr_name in dir(module):
                    if attr_name.startswith("on_"):
                        attr = getattr(module, attr_name)
                        if callable(attr):
                            self.loaded_events[attr_name] = attr
                            logger.info(f"Loaded event: {attr_name}")

            except Exception as e:
                logger.error(f"Failed to load event file {file_path.name}: {e}")

        logger.info(f"Loaded {len(self.loaded_events)} events")

    async def initialize_antiphish(self):
        """Initialize the optimized anti-phishing system"""
        try:
            from optimizations import optimized_engine
            await optimized_engine.initialize()
            logger.info("Optimized anti-phishing system initialized")
        except ImportError:
            logger.warning("Optimized engine not found, falling back to basic initialization")
            try:
                from events.message import initialize_anti_phish
                await initialize_anti_phish()
                logger.info("Basic anti-phishing system initialized")
            except ImportError:
                logger.warning("initialize_anti_phish not found; skipping explicit initialization.")
        except Exception as e:
            logger.error(f"Failed to initialize anti-phishing system: {e}")

    # Override event methods to call our loaded events
    async def on_ready(self):
        """Called when the bot is ready"""
        logger.info(f"Bot is ready! Logged in as {self.user}")
        if self.user:
            logger.info(f"Bot ID: {self.user.id}")
        logger.info(f"Connected to {len(self.guilds)} guilds")

        activity = discord.Game(name="eyp")
        await self.change_presence(status=discord.Status.idle, activity=activity)

        if "on_ready" in self.loaded_events:
            try:
                await self.loaded_events["on_ready"](self)
            except Exception as e:
                logger.error(f"Error in on_ready event: {e}")

    async def on_message(self, message):
        """Called when a message is sent"""
        if "on_message" in self.loaded_events:
            try:
                await self.loaded_events["on_message"](self, message)
            except Exception as e:
                logger.error(f"Error in on_message event: {e}")

        await self.process_commands(message)

    async def on_message_delete(self, message):
        """Called when a message is deleted"""
        if "on_message_delete" in self.loaded_events:
            try:
                await self.loaded_events["on_message_delete"](self, message)
            except Exception as e:
                logger.error(f"Error in on_message_delete event: {e}")

    async def on_message_edit(self, before, after):
        """Called when a message is edited"""
        if "on_message_edit" in self.loaded_events:
            try:
                await self.loaded_events["on_message_edit"](self, before, after)
            except Exception as e:
                logger.error(f"Error in on_message_edit event: {e}")

    async def on_member_join(self, member):
        """Called when a member joins"""
        if "on_member_join" in self.loaded_events:
            try:
                await self.loaded_events["on_member_join"](self, member)
            except Exception as e:
                logger.error(f"Error in on_member_join event: {e}")

    async def on_member_remove(self, member):
        """Called when a member leaves"""
        if "on_member_remove" in self.loaded_events:
            try:
                await self.loaded_events["on_member_remove"](self, member)
            except Exception as e:
                logger.error(f"Error in on_member_remove event: {e}")

    async def on_guild_join(self, guild):
        """Called when the bot joins a guild"""
        logger.info(f"Joined guild: {guild.name} (ID: {guild.id})")

        if "on_guild_join" in self.loaded_events:
            try:
                await self.loaded_events["on_guild_join"](self, guild)
            except Exception as e:
                logger.error(f"Error in on_guild_join event: {e}")

    async def on_guild_remove(self, guild):
        """Called when the bot is removed from a guild"""
        logger.info(f"Removed from guild: {guild.name} (ID: {guild.id})")

        if "on_guild_remove" in self.loaded_events:
            try:
                await self.loaded_events["on_guild_remove"](self, guild)
            except Exception as e:
                logger.error(f"Error in on_guild_remove event: {e}")

    async def close(self):
        """Called when the bot is shutting down"""
        logger.info("Shutting down bot...")
        # Cleanup optimized anti-phishing system
        try:
            from optimizations import optimized_engine
            await optimized_engine.cleanup()
            logger.info("Optimized anti-phishing system cleaned up")
        except ImportError:
            # Fallback to basic cleanup
            try:
                from events.message import cleanup_anti_phish
                await cleanup_anti_phish()
                logger.info("Basic anti-phishing system cleaned up")
            except ImportError:
                logger.warning("cleanup_anti_phish not found; skipping explicit cleanup.")
        except Exception as e:
            logger.error(f"Error cleaning up anti-phishing system: {e}")
        await super().close()


async def main():
    bot = DiscordBot()

    # Get bot token from environment
    token = os.getenv('BOT_TOKEN')
    if not token:
        logger.error("BOT_TOKEN not found in environment variables!")
        logger.error("Please add your bot token to the .env file")
        return

    try:
        await bot.start(token)
    except discord.LoginFailure:
        logger.error("Invalid bot token!")
    except KeyboardInterrupt:
        logger.info("Bot shutdown requested")
    except Exception as e:
        logger.error(f"Error running bot: {e}")
    finally:
        if not bot.is_closed():
            await bot.close()


if __name__ == "__main__":
    asyncio.run(main())
