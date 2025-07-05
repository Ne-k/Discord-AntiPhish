"""
Autoresponder management commands for Discord Anti-Phishing Bot
"""
import discord
import logging
from discord import app_commands
from typing import Optional

from guild_config import (
    add_autoresponder_rule,
    remove_autoresponder_rule,
    get_autoresponder_rules,
    toggle_autoresponder_rule,
    get_autoresponder_rule_count
)
from src.core.config import config
from src.features.autoresponder import autoresponder_engine

logger = logging.getLogger(__name__)

# Autoresponder command group
autoresponder_group = app_commands.Group(name="autoresponder", description="Manage autoresponder rules for this server")


def _check_permissions(interaction: discord.Interaction) -> bool:
    """Check if user has manage_messages permission"""
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return False
    return interaction.user.guild_permissions.manage_messages


def _check_guild(interaction: discord.Interaction) -> bool:
    """Check if interaction is in a guild"""
    return interaction.guild is not None


@autoresponder_group.command(name="add", description="Add a new autoresponder rule")
@app_commands.describe(
    rule_name="Name for this autoresponder rule",
    trigger_pattern="Pattern that will trigger the autoresponse",
    response_message="Message to send when triggered",
    is_regex="Whether the trigger pattern is a regex (default: False)",
    case_sensitive="Whether matching should be case sensitive (default: False)"
)
async def add_rule(interaction: discord.Interaction, rule_name: str, trigger_pattern: str, response_message: str,
                   is_regex: bool = False, case_sensitive: bool = False):
    """Add a new autoresponder rule"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        if not config.AUTORESPONDER_ENABLED:
            await interaction.response.send_message("❌ Autoresponder is disabled on this bot.", ephemeral=True)
            return

        # Check rule limit
        assert interaction.guild is not None  # Type assertion for type checker
        current_count = get_autoresponder_rule_count(interaction.guild.id)
        if current_count >= config.AUTORESPONDER_MAX_RULES_PER_GUILD:
            await interaction.response.send_message(
                f"❌ Maximum number of autoresponder rules reached ({config.AUTORESPONDER_MAX_RULES_PER_GUILD})",
                ephemeral=True)
            return

        # Validate rule
        is_valid, error_msg = autoresponder_engine.validate_rule(trigger_pattern, is_regex, case_sensitive)
        if not is_valid:
            await interaction.response.send_message(f"❌ Invalid trigger pattern: {error_msg}", ephemeral=True)
            return

        # Validate response
        is_valid, error_msg = autoresponder_engine.validate_response(response_message)
        if not is_valid:
            await interaction.response.send_message(f"❌ Invalid response message: {error_msg}", ephemeral=True)
            return

        # Add the rule
        success = add_autoresponder_rule(
            interaction.guild.id,
            rule_name,
            trigger_pattern,
            response_message,
            is_regex,
            case_sensitive
        )

        if success:
            embed = discord.Embed(
                title="✅ Autoresponder Rule Added",
                color=discord.Color.green(),
                description=f"Rule **{rule_name}** has been created successfully."
            )
            embed.add_field(name="Trigger", value=f"`{trigger_pattern}`", inline=False)
            embed.add_field(name="Response",
                            value=response_message[:1000] + ("..." if len(response_message) > 1000 else ""),
                            inline=False)
            embed.add_field(name="Type", value="Regex" if is_regex else "Text", inline=True)
            embed.add_field(name="Case Sensitive", value="Yes" if case_sensitive else "No", inline=True)
            await interaction.response.send_message(embed=embed)
        else:
            await interaction.response.send_message(
                f"❌ Failed to add rule. A rule with the name **{rule_name}** already exists.", ephemeral=True)

    except Exception as e:
        logger.error(f"Error in add_rule command: {e}")
        await interaction.response.send_message("❌ An error occurred while adding the rule.", ephemeral=True)


@autoresponder_group.command(name="remove", description="Remove an autoresponder rule")
@app_commands.describe(rule_name="Name of the rule to remove")
async def remove_rule(interaction: discord.Interaction, rule_name: str):
    """Remove an autoresponder rule"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        assert interaction.guild is not None  # Type assertion for type checker
        success = remove_autoresponder_rule(interaction.guild.id, rule_name)

        if success:
            await interaction.response.send_message(f"✅ Autoresponder rule **{rule_name}** has been removed.")
        else:
            await interaction.response.send_message(f"❌ No autoresponder rule found with the name **{rule_name}**.",
                                                    ephemeral=True)

    except Exception as e:
        logger.error(f"Error in remove_rule command: {e}")
        await interaction.response.send_message("❌ An error occurred while removing the rule.", ephemeral=True)


@autoresponder_group.command(name="list", description="List all autoresponder rules for this server")
async def list_rules(interaction: discord.Interaction):
    """List all autoresponder rules for this server"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        assert interaction.guild is not None  # Type assertion for type checker
        rules = get_autoresponder_rules(interaction.guild.id)

        if not rules:
            embed = discord.Embed(
                title="📋 Autoresponder Rules",
                description="No autoresponder rules configured for this server.",
                color=discord.Color.blue()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        embed = discord.Embed(
            title="📋 Autoresponder Rules",
            description=f"Found {len(rules)} autoresponder rule(s)",
            color=discord.Color.blue()
        )

        for rule in rules[:10]:  # Limit to first 10 rules to avoid embed limits
            status = "🟢 Enabled" if rule['is_enabled'] else "🔴 Disabled"
            rule_type = "🔤 Regex" if rule['is_regex'] else "📝 Text"
            case_info = " (Case Sensitive)" if rule['case_sensitive'] else ""

            trigger_display = rule['trigger_pattern'][:50] + ("..." if len(rule['trigger_pattern']) > 50 else "")
            response_display = rule['response_message'][:100] + ("..." if len(rule['response_message']) > 100 else "")

            embed.add_field(
                name=f"{rule['rule_name']} - {status}",
                value=f"**Type:** {rule_type}{case_info}\n**Trigger:** `{trigger_display}`\n**Response:** {response_display}",
                inline=False
            )

        if len(rules) > 10:
            embed.set_footer(text=f"Showing first 10 of {len(rules)} rules")

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in list_rules command: {e}")
        await interaction.response.send_message("❌ An error occurred while listing rules.", ephemeral=True)


@autoresponder_group.command(name="toggle", description="Enable or disable an autoresponder rule")
@app_commands.describe(
    rule_name="Name of the rule to toggle",
    enabled="True to enable, False to disable"
)
async def toggle_rule(interaction: discord.Interaction, rule_name: str, enabled: bool):
    """Enable or disable an autoresponder rule"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        assert interaction.guild is not None  # Type assertion for type checker
        rules = get_autoresponder_rules(interaction.guild.id)
        current_rule = next((r for r in rules if r['rule_name'] == rule_name), None)

        if not current_rule:
            await interaction.response.send_message(f"❌ No autoresponder rule found with the name **{rule_name}**.",
                                                    ephemeral=True)
            return

        success = toggle_autoresponder_rule(interaction.guild.id, rule_name, enabled)

        if success:
            status = "enabled" if enabled else "disabled"
            await interaction.response.send_message(f"✅ Autoresponder rule **{rule_name}** has been {status}.")
        else:
            await interaction.response.send_message(f"❌ Failed to update rule **{rule_name}**.", ephemeral=True)

    except Exception as e:
        logger.error(f"Error in toggle_rule command: {e}")
        await interaction.response.send_message("❌ An error occurred while toggling the rule.", ephemeral=True)


@autoresponder_group.command(name="test", description="Test an autoresponder rule against a message")
@app_commands.describe(
    rule_name="Name of the rule to test",
    test_message="Message to test against the rule"
)
async def test_rule(interaction: discord.Interaction, rule_name: str, test_message: str):
    """Test an autoresponder rule against a message"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        assert interaction.guild is not None  # Type assertion for type checker
        rules = get_autoresponder_rules(interaction.guild.id)
        rule = next((r for r in rules if r['rule_name'] == rule_name), None)

        if not rule:
            await interaction.response.send_message(f"❌ No autoresponder rule found with the name **{rule_name}**.",
                                                    ephemeral=True)
            return

        # Test the pattern matching
        matches = autoresponder_engine._matches_pattern(test_message, rule)

        embed = discord.Embed(
            title=f"🧪 Test Result for Rule: {rule_name}",
            color=discord.Color.green() if matches else discord.Color.red()
        )

        embed.add_field(name="Test Message", value=f"```{test_message}```", inline=False)
        embed.add_field(name="Trigger Pattern", value=f"`{rule['trigger_pattern']}`", inline=False)
        embed.add_field(name="Match Result", value="✅ Matches" if matches else "❌ No Match", inline=True)
        embed.add_field(name="Rule Type", value="Regex" if rule['is_regex'] else "Text", inline=True)
        embed.add_field(name="Case Sensitive", value="Yes" if rule['case_sensitive'] else "No", inline=True)

        if matches:
            embed.add_field(name="Would Respond With", value=rule['response_message'][:500] + (
                "..." if len(rule['response_message']) > 500 else ""), inline=False)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in test_rule command: {e}")
        await interaction.response.send_message("❌ An error occurred while testing the rule.", ephemeral=True)


@autoresponder_group.command(name="info", description="Get detailed information about an autoresponder rule")
@app_commands.describe(rule_name="Name of the rule to get information about")
async def rule_info(interaction: discord.Interaction, rule_name: str):
    """Get detailed information about an autoresponder rule"""
    try:
        if not _check_guild(interaction):
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        assert interaction.guild is not None  # Type assertion for type checker
        rules = get_autoresponder_rules(interaction.guild.id)
        rule = next((r for r in rules if r['rule_name'] == rule_name), None)

        if not rule:
            await interaction.response.send_message(f"❌ No autoresponder rule found with the name **{rule_name}**.",
                                                    ephemeral=True)
            return

        embed = discord.Embed(
            title=f"📋 Rule Information: {rule['rule_name']}",
            color=discord.Color.blue()
        )

        embed.add_field(name="Status", value="🟢 Enabled" if rule['is_enabled'] else "🔴 Disabled", inline=True)
        embed.add_field(name="Type", value="🔤 Regex" if rule['is_regex'] else "📝 Text", inline=True)
        embed.add_field(name="Case Sensitive", value="Yes" if rule['case_sensitive'] else "No", inline=True)
        embed.add_field(name="Trigger Pattern", value=f"```{rule['trigger_pattern']}```", inline=False)
        embed.add_field(name="Response Message",
                        value=rule['response_message'][:1000] + ("..." if len(rule['response_message']) > 1000 else ""),
                        inline=False)
        embed.add_field(name="Created", value=rule['created_at'], inline=True)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in rule_info command: {e}")
        await interaction.response.send_message("❌ An error occurred while getting rule information.", ephemeral=True)


# Help command for autoresponder
@app_commands.command(name="autoresponder-help", description="Show detailed help for autoresponder commands")
async def autoresponder_help(interaction: discord.Interaction):
    """Show detailed help for autoresponder commands"""
    try:
        if not _check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this command.",
                                                    ephemeral=True)
            return

        embed = discord.Embed(
            title="🤖 Autoresponder Help",
            description="The autoresponder allows you to automatically respond to messages that match certain patterns.",
            color=discord.Color.blue()
        )

        embed.add_field(
            name="📝 Commands",
            value="""
            `/autoresponder add` - Add a new rule
            `/autoresponder remove` - Remove a rule
            `/autoresponder list` - Show all rules
            `/autoresponder toggle` - Enable/disable a rule
            `/autoresponder test` - Test a rule
            `/autoresponder info` - Get rule details
            """,
            inline=False
        )

        embed.add_field(
            name="🚀 Pattern Types",
            value="""
            **Text**: Simple substring matching
            **Regex**: Advanced pattern matching with regular expressions
            """,
            inline=False
        )

        embed.add_field(
            name="📚 Examples",
            value="""
            Simple text: `hello` matches "hello world"
            Regex: `(?i)help.*` matches "HELP ME" (case insensitive)
            Case sensitive: `Hello` only matches "Hello" (not "hello")
            """,
            inline=False
        )

        embed.set_footer(text=f"Cooldown: {config.AUTORESPONDER_COOLDOWN}s between responses per user")

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in autoresponder_help command: {e}")
        await interaction.response.send_message("❌ An error occurred while showing help.", ephemeral=True)


# Export the command group and help command
__all__ = ['autoresponder_group', 'autoresponder_help']
