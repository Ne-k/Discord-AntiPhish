import discord
import importlib
import logging
import os
from discord.ext import commands
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModularBot(commands.Bot):
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

        self.commands_loaded = 0
        self.events_loaded = 0

    async def setup_hook(self):
        """This is called when the bot is starting up"""
        logger.info("Starting bot setup...")

        # Load all commands and events
        await self.load_all_commands()
        await self.load_all_events()

        # Sync slash commands
        await self.sync_commands()

        logger.info(f"Setup complete! Loaded {self.commands_loaded} commands and {self.events_loaded} events")

    async def load_all_commands(self):
        """Load all command files from the commands directory"""
        commands_dir = Path("commands")
        if not commands_dir.exists():
            logger.warning("Commands directory not found!")
            return

        # Get all Python files in the commands directory
        command_files = [f for f in commands_dir.glob("*.py") if f.name != "__init__.py"]

        for command_file in command_files:
            try:
                # Import the command module
                module_name = f"commands.{command_file.stem}"
                module = importlib.import_module(module_name)

                # Look for app command objects
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    # Check if it's an app command instance
                    if isinstance(attr, discord.app_commands.Command):
                        self.tree.add_command(attr)
                        self.commands_loaded += 1
                        logger.info(f"Loaded command: {attr.name}")

            except Exception as e:
                logger.error(f"Failed to load command from {command_file}: {e}")

    async def load_all_events(self):
        """Load all event files from the events directory"""
        events_dir = Path("events")
        if not events_dir.exists():
            logger.warning("Events directory not found!")
            return

        # Get all Python files in the events directory
        event_files = [f for f in events_dir.glob("*.py") if f.name != "__init__.py"]

        for event_file in event_files:
            try:
                # Import the event module
                module_name = f"events.{event_file.stem}"
                module = importlib.import_module(module_name)

                # Register events based on the module
                if event_file.name == "ready.py" and hasattr(module, 'on_ready'):
                    @self.event
                    async def on_ready():
                        await module.on_ready(self)

                    self.events_loaded += 1

                elif event_file.name == "guild.py":
                    if hasattr(module, 'on_guild_join'):
                        @self.event
                        async def on_guild_join(guild):
                            await module.on_guild_join(self, guild)

                        self.events_loaded += 1

                    if hasattr(module, 'on_guild_remove'):
                        @self.event
                        async def on_guild_remove(guild):
                            await module.on_guild_remove(self, guild)

                        self.events_loaded += 1

                elif event_file.name == "member.py":
                    if hasattr(module, 'on_member_join'):
                        @self.event
                        async def on_member_join(member):
                            await module.on_member_join(self, member)

                        self.events_loaded += 1

                    if hasattr(module, 'on_member_remove'):
                        @self.event
                        async def on_member_remove(member):
                            await module.on_member_remove(self, member)

                        self.events_loaded += 1

                elif event_file.name == "message.py":
                    if hasattr(module, 'on_message'):
                        @self.event
                        async def on_message(message):
                            await module.on_message(self, message)

                        self.events_loaded += 1

                    if hasattr(module, 'on_message_delete'):
                        @self.event
                        async def on_message_delete(message):
                            await module.on_message_delete(self, message)

                        self.events_loaded += 1

                    if hasattr(module, 'on_message_edit'):
                        @self.event
                        async def on_message_edit(before, after):
                            await module.on_message_edit(self, before, after)

                        self.events_loaded += 1

                elif event_file.name == "error.py":
                    if hasattr(module, 'on_command_error'):
                        @self.event
                        async def on_command_error(ctx, error):
                            await module.on_command_error(self, ctx, error)

                        self.events_loaded += 1

                    if hasattr(module, 'on_app_command_error'):
                        @self.tree.error
                        async def on_app_command_error(interaction, error):
                            await module.on_app_command_error(self, interaction, error)

                        self.events_loaded += 1

                logger.info(f"Loaded events from: {event_file.name}")

            except Exception as e:
                logger.error(f"Failed to load events from {event_file}: {e}")

    async def sync_commands(self):
        """Sync slash commands to Discord"""
        try:
            guild_id = os.getenv('GUILD_ID')

            if guild_id and guild_id != 'your_guild_id_here':
                # Sync to specific guild for testing (faster)
                guild = discord.Object(id=int(guild_id))
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                logger.info(f"Synced {len(synced)} commands to guild {guild_id}")
            else:
                # Sync globally (takes up to 1 hour to appear)
                synced = await self.tree.sync()
                logger.info(f"Synced {len(synced)} commands globally")

        except Exception as e:
            logger.error(f"Failed to sync commands: {e}")


def main():
    """Main function to run the bot"""
    bot = ModularBot()

    # Get bot token from environment
    token = os.getenv('BOT_TOKEN')
    if not token:
        logger.error("BOT_TOKEN not found in environment variables!")
        print("ERROR: BOT_TOKEN not found in environment variables!")
        print("Please add your bot token to the .env file")
        return

    try:
        bot.run(token)
    except discord.LoginFailure:
        logger.error("Invalid bot token!")
        print("ERROR: Invalid bot token!")
    except Exception as e:
        logger.error(f"Bot error: {e}")
        print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
