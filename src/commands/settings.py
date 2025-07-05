"""
Settings command for bot configuration
"""
import discord
import logging
import json
import re
from discord import app_commands
from typing import Optional

from guild_config import (
    get_guild_full_config, set_guild_action, set_guild_log_channel,
    set_guild_timeout_duration, set_guild_anti_phish_enabled,
    set_guild_anti_malware_enabled, set_guild_anti_piracy_enabled,
    set_guild_bypass_roles, set_guild_max_attempts, get_guild_bypass_roles,
    get_autoresponder_rule_count, get_guild_autoresponder_use_embeds,
    set_guild_autoresponder_use_embeds, get_guild_autoresponder_use_reply,
    set_guild_autoresponder_use_reply, set_guild_autoresponder_embed_config,
    add_autoresponder_rule, remove_autoresponder_rule, get_autoresponder_rules,
    toggle_autoresponder_rule, get_guild_autoresponder_embed_config
)

logger = logging.getLogger(__name__)

# Settings command group
settings_group = app_commands.Group(name="settings", description="Configure bot settings for this server")


class SettingsView(discord.ui.View):
    """Interactive settings panel with buttons"""

    def __init__(self, guild_id: int):
        super().__init__(timeout=300)  # 5 minute timeout
        self.guild_id = guild_id

    def _check_permissions(self, interaction: discord.Interaction) -> bool:
        """Check if user has permissions to modify settings"""
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return False
        return interaction.user.guild_permissions.manage_guild

    @discord.ui.button(label="🔨 Configure Action", style=discord.ButtonStyle.primary, row=0)
    async def configure_action_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Configure action settings for detection"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(ActionModal(self.guild_id))

    @discord.ui.button(label="📋 Set Log Channel", style=discord.ButtonStyle.secondary, row=0)
    async def set_log_channel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Set log channel for detection alerts"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(LogChannelModal(self.guild_id))

    @discord.ui.button(label="⏰ Timeout Duration", style=discord.ButtonStyle.secondary, row=0)
    async def set_timeout_duration_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Set timeout duration for users"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(TimeoutDurationModal(self.guild_id))

    @discord.ui.button(label="🛡️ Toggle Anti-Phishing", style=discord.ButtonStyle.success, row=1)
    async def toggle_antiphish_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Toggle anti-phishing protection"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        config = get_guild_full_config(self.guild_id)
        new_state = not config['anti_phish_enabled']
        set_guild_anti_phish_enabled(self.guild_id, new_state)

        embed = discord.Embed(
            title="✅ Anti-Phishing Updated",
            description=f"Anti-Phishing is now {'✅ Enabled' if new_state else '❌ Disabled'}",
            color=discord.Color.green() if new_state else discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="🦠 Toggle Anti-Malware", style=discord.ButtonStyle.success, row=1)
    async def toggle_antimalware_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Toggle anti-malware protection"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        config = get_guild_full_config(self.guild_id)
        new_state = not config['anti_malware_enabled']
        set_guild_anti_malware_enabled(self.guild_id, new_state)

        embed = discord.Embed(
            title="✅ Anti-Malware Updated",
            description=f"Anti-Malware is now {'✅ Enabled' if new_state else '❌ Disabled'}",
            color=discord.Color.green() if new_state else discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="🏴‍☠️ Toggle Anti-Piracy", style=discord.ButtonStyle.success, row=1)
    async def toggle_antipiracy_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Toggle anti-piracy protection"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        config = get_guild_full_config(self.guild_id)
        new_state = not config['anti_piracy_enabled']
        set_guild_anti_piracy_enabled(self.guild_id, new_state)

        embed = discord.Embed(
            title="✅ Anti-Piracy Updated",
            description=f"Anti-Piracy is now {'✅ Enabled' if new_state else '❌ Disabled'}",
            color=discord.Color.green() if new_state else discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="🔄 Set Max Attempts", style=discord.ButtonStyle.secondary, row=2)
    async def set_max_attempts_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Set maximum attempts before action"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(MaxAttemptsModal(self.guild_id))

    @discord.ui.button(label="🔑 Set Bypass Roles", style=discord.ButtonStyle.secondary, row=2)
    async def set_bypass_roles_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Set roles that bypass protection"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(BypassRolesModal(self.guild_id))

    @discord.ui.button(label="🔄 Refresh", style=discord.ButtonStyle.primary, row=2)
    async def refresh_settings_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Refresh the settings display"""
        if not interaction.guild:
            await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
            return

        try:
            embed = await self._create_settings_embed(interaction.guild)
            await interaction.response.edit_message(embed=embed, view=self)

        except Exception as e:
            logger.error(f"Error refreshing settings: {e}")
            await interaction.response.send_message("❌ Error refreshing settings.", ephemeral=True)

    @discord.ui.button(label="🤖 Autoresponder Settings", style=discord.ButtonStyle.secondary, row=3)
    async def autoresponder_settings_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Configure autoresponder settings"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Server' permission to use this.",
                                                    ephemeral=True)
            return

        if not interaction.guild:
            await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
            return

        # Create autoresponder settings view
        autoresponder_view = AutoresponderSettingsView(self.guild_id)
        embed = await autoresponder_view._create_autoresponder_embed(interaction.guild)
        await interaction.response.send_message(embed=embed, view=autoresponder_view, ephemeral=True)

    async def _create_settings_embed(self, guild: discord.Guild) -> discord.Embed:
        """Create the detailed settings embed"""
        config = get_guild_full_config(guild.id)

        embed = discord.Embed(
            title="🛠️ Bot Configuration",
            description="Current settings for this server:",
            color=discord.Color.blue()
        )

        # Action on Detection
        action_text = config['action'].replace('_', ' ').title()
        if config['action'] == 'delete':
            action_emoji = "🗑️"
        elif config['action'] == 'timeout':
            action_emoji = "⏰"
        elif config['action'] == 'kick':
            action_emoji = "👢"
        elif config['action'] == 'ban':
            action_emoji = "🔨"
        elif config['action'] == 'all':
            action_emoji = "⏰"
            action_text = "Delete message and timeout user"
        else:
            action_emoji = "⚙️"

        embed.add_field(
            name="🔨 Action on Detection",
            value=f"{action_emoji} {action_text}",
            inline=True
        )

        # Timeout Duration
        if config['timeout_duration'] and config['timeout_duration'] > 0:
            timeout_text = f"{config['timeout_duration']} minutes"
        else:
            timeout_text = "Not set"

        embed.add_field(
            name="⏰ Timeout Duration",
            value=timeout_text,
            inline=True
        )

        # Log Channel
        if config['log_channel_id']:
            channel = guild.get_channel(config['log_channel_id'])
            log_text = channel.mention if channel else f"ID: {config['log_channel_id']}"
        else:
            log_text = "Not set"

        embed.add_field(
            name="📋 Log Channel",
            value=log_text,
            inline=True
        )

        # Protection Features
        embed.add_field(
            name="🛡️ Anti-Phishing",
            value="✅ Enabled" if config['anti_phish_enabled'] else "❌ Disabled",
            inline=True
        )

        embed.add_field(
            name="🦠 Anti-Malware",
            value="✅ Enabled" if config['anti_malware_enabled'] else "❌ Disabled",
            inline=True
        )

        embed.add_field(
            name="🏴‍☠️ Anti-Piracy",
            value="✅ Enabled" if config['anti_piracy_enabled'] else "❌ Disabled",
            inline=True
        )

        # Bypass Roles
        bypass_roles = get_guild_bypass_roles(guild.id)
        if bypass_roles:
            role_mentions = []
            for role_id in bypass_roles:
                role = guild.get_role(role_id)
                if role:
                    role_mentions.append(role.mention)
            bypass_text = ", ".join(role_mentions) if role_mentions else f"{len(bypass_roles)} roles"
        else:
            bypass_text = "None (No special roles)"

        embed.add_field(
            name="🔑 Bypass Roles",
            value=bypass_text,
            inline=True
        )

        # Max Attempts
        embed.add_field(
            name="🔄 Max Attempts",
            value=str(config['max_attempts']),
            inline=True
        )

        # Autoresponder Rules
        autoresponder_count = get_autoresponder_rule_count(guild.id)
        from src.core.config import config as bot_config
        autoresponder_status = "✅ Enabled" if bot_config.AUTORESPONDER_ENABLED else "❌ Disabled"
        embed.add_field(
            name="🤖 Autoresponder",
            value=f"{autoresponder_status}\n{autoresponder_count} rule(s) configured",
            inline=True
        )

        # Empty field for spacing
        embed.add_field(name="\u200b", value="\u200b", inline=True)

        embed.set_footer(text="Use the buttons below to modify settings")

        return embed


class TimeoutDurationModal(discord.ui.Modal, title="Set Timeout Duration"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        config = get_guild_full_config(guild_id)

        self.duration_input = discord.ui.TextInput(
            label="Timeout Duration (minutes)",
            placeholder="Enter timeout duration in minutes (1-10080)",
            default=str(config['timeout_duration']) if config['timeout_duration'] else "5",
            max_length=5
        )
        self.add_item(self.duration_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            duration = int(self.duration_input.value)

            if duration < 1 or duration > 10080:  # Max 1 week (7 days * 24 hours * 60 minutes)
                await interaction.response.send_message(
                    "❌ Timeout duration must be between 1 and 10080 minutes (1 week).", ephemeral=True)
                return

            set_guild_timeout_duration(self.guild_id, duration)

            # Convert to human readable format
            if duration < 60:
                duration_text = f"{duration} minute{'s' if duration != 1 else ''}"
            elif duration < 1440:
                hours = duration // 60
                minutes = duration % 60
                duration_text = f"{hours} hour{'s' if hours != 1 else ''}"
                if minutes > 0:
                    duration_text += f" {minutes} minute{'s' if minutes != 1 else ''}"
            else:
                days = duration // 1440
                hours = (duration % 1440) // 60
                duration_text = f"{days} day{'s' if days != 1 else ''}"
                if hours > 0:
                    duration_text += f" {hours} hour{'s' if hours != 1 else ''}"

            embed = discord.Embed(
                title="✅ Timeout Duration Updated",
                description=f"Timeout duration set to: **{duration_text}**",
                color=discord.Color.green()
            )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except ValueError:
            await interaction.response.send_message("❌ Please enter a valid number.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error updating timeout duration: {e}")
            await interaction.response.send_message("❌ Error updating timeout duration.", ephemeral=True)


class BypassRolesModal(discord.ui.Modal, title="Set Bypass Roles"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        bypass_roles = get_guild_bypass_roles(guild_id)

        self.roles_input = discord.ui.TextInput(
            label="Role IDs or mentions",
            placeholder="@role1, @role2, 123456789012345678, or leave empty to clear",
            default=", ".join(str(role_id) for role_id in bypass_roles) if bypass_roles else "",
            style=discord.TextStyle.paragraph,
            max_length=1000,
            required=False
        )
        self.add_item(self.roles_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            roles_input = self.roles_input.value.strip()

            if not roles_input:
                # Clear bypass roles
                set_guild_bypass_roles(self.guild_id, [])
                await interaction.response.send_message("✅ Bypass roles cleared. No special roles bypass protection.",
                                                        ephemeral=True)
                return

            # Parse role IDs from input
            role_ids = []
            role_parts = [part.strip() for part in roles_input.split(',')]

            for part in role_parts:
                if not part:
                    continue

                # Try to parse role mention or direct ID
                role_id = None
                if part.startswith('<@&') and part.endswith('>'):
                    role_id = int(part[3:-1])
                else:
                    try:
                        role_id = int(part)
                    except ValueError:
                        await interaction.response.send_message(f"❌ Invalid role ID or mention: `{part}`",
                                                                ephemeral=True)
                        return

                # Verify role exists
                role = interaction.guild.get_role(role_id)
                if not role:
                    await interaction.response.send_message(f"❌ Role with ID {role_id} not found in this server.",
                                                            ephemeral=True)
                    return

                role_ids.append(role_id)

            # Remove duplicates while preserving order
            unique_role_ids = []
            for role_id in role_ids:
                if role_id not in unique_role_ids:
                    unique_role_ids.append(role_id)

            set_guild_bypass_roles(self.guild_id, unique_role_ids)

            # Create response
            if unique_role_ids:
                role_mentions = []
                for role_id in unique_role_ids:
                    role = interaction.guild.get_role(role_id)
                    if role:
                        role_mentions.append(role.mention)

                embed = discord.Embed(
                    title="✅ Bypass Roles Updated",
                    description=f"Users with these roles can bypass protection:\n{', '.join(role_mentions)}",
                    color=discord.Color.green()
                )
            else:
                embed = discord.Embed(
                    title="✅ Bypass Roles Cleared",
                    description="No special roles bypass protection.",
                    color=discord.Color.green()
                )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error updating bypass roles: {e}")
            await interaction.response.send_message("❌ Error updating bypass roles.", ephemeral=True)


class ActionModal(discord.ui.Modal, title="Configure Action Settings"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        config = get_guild_full_config(guild_id)

        self.action_input = discord.ui.TextInput(
            label="Action Type",
            placeholder="Enter: delete, timeout, kick, ban, or all",
            default=config['action'],
            max_length=10
        )
        self.add_item(self.action_input)

        self.timeout_input = discord.ui.TextInput(
            label="Timeout Duration (minutes)",
            placeholder="Enter timeout duration in minutes (1-10080)",
            default=str(config['timeout_duration']) if config['timeout_duration'] else "5",
            max_length=5,
            required=False
        )
        self.add_item(self.timeout_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            action = self.action_input.value.lower().strip()

            if action not in ['delete', 'timeout', 'kick', 'ban', 'all']:
                await interaction.response.send_message("❌ Invalid action. Use: delete, timeout, kick, ban, or all",
                                                        ephemeral=True)
                return

            set_guild_action(self.guild_id, action)

            # Set timeout duration if provided and action uses timeouts
            timeout_duration = None
            if self.timeout_input.value and action in ['timeout', 'all']:
                try:
                    timeout_duration = int(self.timeout_input.value)
                    if timeout_duration < 1 or timeout_duration > 10080:
                        await interaction.response.send_message(
                            "❌ Timeout duration must be between 1 and 10080 minutes (1 week).", ephemeral=True)
                        return
                    set_guild_timeout_duration(self.guild_id, timeout_duration)
                except ValueError:
                    await interaction.response.send_message("❌ Please enter a valid timeout duration.", ephemeral=True)
                    return

            # Create response embed
            embed = discord.Embed(
                title="✅ Action Settings Updated",
                color=discord.Color.green()
            )

            action_descriptions = {
                'delete': '🗑️ Delete malicious messages',
                'timeout': '⏰ Timeout users who post malicious content',
                'kick': '👢 Kick users who post malicious content',
                'ban': '🔨 Ban users who post malicious content',
                'all': '⏰ Delete message and timeout user'
            }

            embed.add_field(
                name="Action",
                value=action_descriptions.get(action, action.title()),
                inline=False
            )

            if timeout_duration and action in ['timeout', 'all']:
                # Convert to human readable format
                if timeout_duration < 60:
                    duration_text = f"{timeout_duration} minute{'s' if timeout_duration != 1 else ''}"
                elif timeout_duration < 1440:
                    hours = timeout_duration // 60
                    minutes = timeout_duration % 60
                    duration_text = f"{hours} hour{'s' if hours != 1 else ''}"
                    if minutes > 0:
                        duration_text += f" {minutes} minute{'s' if minutes != 1 else ''}"
                else:
                    days = timeout_duration // 1440
                    hours = (timeout_duration % 1440) // 60
                    duration_text = f"{days} day{'s' if days != 1 else ''}"
                    if hours > 0:
                        duration_text += f" {hours} hour{'s' if hours != 1 else ''}"

                embed.add_field(
                    name="Timeout Duration",
                    value=duration_text,
                    inline=False
                )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error updating action settings: {e}")
            await interaction.response.send_message("❌ Error updating action settings.", ephemeral=True)


class LogChannelModal(discord.ui.Modal, title="Set Log Channel"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.channel_input = discord.ui.TextInput(
            label="Channel ID or mention",
            placeholder="#channel-name or 123456789012345678",
            required=False
        )
        self.add_item(self.channel_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            channel_input = self.channel_input.value.strip()

            if not channel_input:
                # Disable logging by setting to 0 (which will be treated as None/disabled)
                set_guild_log_channel(self.guild_id, 0)
                await interaction.response.send_message("✅ Log channel disabled.", ephemeral=True)
                return

            # Try to parse channel ID from mention or direct ID
            channel_id = None
            if channel_input.startswith('<#') and channel_input.endswith('>'):
                channel_id = int(channel_input[2:-1])
            else:
                try:
                    channel_id = int(channel_input)
                except ValueError:
                    await interaction.response.send_message("❌ Invalid channel ID or mention.", ephemeral=True)
                    return

            # Verify channel exists
            channel = interaction.guild.get_channel(channel_id)
            if not channel:
                await interaction.response.send_message("❌ Channel not found in this server.", ephemeral=True)
                return

            set_guild_log_channel(self.guild_id, channel_id)

            embed = discord.Embed(
                title="✅ Log Channel Updated",
                description=f"Log channel set to: {channel.mention}",
                color=discord.Color.green()
            )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error updating log channel: {e}")
            await interaction.response.send_message("❌ Error updating log channel.", ephemeral=True)


class MaxAttemptsModal(discord.ui.Modal, title="Set Maximum Attempts"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        config = get_guild_full_config(guild_id)

        self.attempts_input = discord.ui.TextInput(
            label="Maximum Attempts (1-10)",
            default=str(config['max_attempts']),
            max_length=2
        )
        self.add_item(self.attempts_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            max_attempts = int(self.attempts_input.value)

            if max_attempts < 1 or max_attempts > 10:
                await interaction.response.send_message("❌ Maximum attempts must be between 1 and 10.", ephemeral=True)
                return

            set_guild_max_attempts(self.guild_id, max_attempts)

            embed = discord.Embed(
                title="✅ Maximum Attempts Updated",
                description=f"Maximum attempts set to: **{max_attempts}**",
                color=discord.Color.green()
            )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except ValueError:
            await interaction.response.send_message("❌ Please enter a valid number.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error updating max attempts: {e}")
            await interaction.response.send_message("❌ Error updating maximum attempts.", ephemeral=True)


class AutoresponderSettingsView(discord.ui.View):
    """Autoresponder settings management view"""

    def __init__(self, guild_id: int):
        super().__init__(timeout=300)  # 5 minute timeout
        self.guild_id = guild_id

    def _check_permissions(self, interaction: discord.Interaction) -> bool:
        """Check if user has permissions to modify settings"""
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return False
        return interaction.user.guild_permissions.manage_messages

    @discord.ui.button(label="➕ Add Rule", style=discord.ButtonStyle.success, row=0)
    async def add_rule_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Add a new autoresponder rule"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(AddAutoresponderRuleModal(self.guild_id))

    @discord.ui.button(label="📋 List Rules", style=discord.ButtonStyle.secondary, row=0)
    async def list_rules_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """List all autoresponder rules"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this.",
                                                    ephemeral=True)
            return

        try:
            from guild_config import get_autoresponder_rules
            rules = get_autoresponder_rules(self.guild_id)

            if not rules:
                embed = discord.Embed(
                    title="📋 Autoresponder Rules",
                    description="No autoresponder rules configured for this server.",
                    color=discord.Color.blue()
                )
            else:
                embed = discord.Embed(
                    title="📋 Autoresponder Rules",
                    description=f"Found {len(rules)} rule(s):",
                    color=discord.Color.blue()
                )

                for rule in rules[:10]:  # Limit to first 10 rules to avoid embed limits
                    status = "✅ Active" if rule.get('enabled', True) else "❌ Inactive"
                    trigger = rule['trigger_pattern']
                    if len(trigger) > 50:
                        trigger = trigger[:47] + "..."

                    embed.add_field(
                        name=f"🔹 {rule['rule_name']} ({status})",
                        value=f"**Trigger:** `{trigger}`\n**Response:** {rule['response_message'][:100]}{'...' if len(rule['response_message']) > 100 else ''}",
                        inline=False
                    )

                if len(rules) > 10:
                    embed.set_footer(text=f"Showing first 10 of {len(rules)} rules")

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error listing autoresponder rules: {e}")
            await interaction.response.send_message("❌ Error retrieving autoresponder rules.", ephemeral=True)

    @discord.ui.button(label="🗑️ Remove Rule", style=discord.ButtonStyle.danger, row=0)
    async def remove_rule_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Remove an autoresponder rule"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(RemoveAutoresponderRuleModal(self.guild_id))

    @discord.ui.button(label="🔄 Toggle Rule", style=discord.ButtonStyle.secondary, row=1)
    async def toggle_rule_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Toggle an autoresponder rule on/off"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this.",
                                                    ephemeral=True)
            return

        await interaction.response.send_modal(ToggleAutoresponderRuleModal(self.guild_id))
    
    @discord.ui.button(label="🔄 Refresh", style=discord.ButtonStyle.primary, row=1)
    async def refresh_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Refresh the autoresponder settings display"""
        if not interaction.guild:
            await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
            return
            
        try:
            embed = await self._create_autoresponder_embed(interaction.guild)
            await interaction.response.edit_message(embed=embed, view=self)
            
        except Exception as e:
            logger.error(f"Error refreshing autoresponder settings: {e}")
            await interaction.response.send_message("❌ Error refreshing settings.", ephemeral=True)
    
    @discord.ui.button(label="📖 Pattern Help", style=discord.ButtonStyle.secondary, row=1)
    async def pattern_help_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show pattern help and examples"""
        embed = discord.Embed(
            title="📖 Autoresponder Pattern Guide",
            description="Learn how to create effective trigger patterns:",
            color=discord.Color.blue()
        )
        
        # Plain text examples
        embed.add_field(
            name="📝 Plain Text Patterns",
            value="• `hello` - matches anywhere 'hello' appears\n"
                  "• `bad word` - matches the exact phrase\n"
                  "• Use for simple word/phrase matching",
            inline=False
        )
        
        # Regex examples
        embed.add_field(
            name="🔣 Regex Patterns",
            value="• `(?i)\\bhello\\b` - case insensitive word 'hello'\n"
                  "• `(?i)\\b(hi|hello|hey)\\b` - matches hi, hello, or hey\n"
                  "• `(?i)\\bballs?\\b` - matches 'ball' or 'balls'\n"
                  "• `^spam` - matches messages starting with 'spam'\n"
                  "• `\\d{3,}` - matches 3 or more digits",
            inline=False
        )
        
        # Pattern options
        embed.add_field(
            name="⚙️ Pattern Options",
            value="In the 'Options' field, you can specify:\n"
                  "• `case_sensitive=true` - make matching case sensitive\n"
                  "• `case_sensitive=false` - case insensitive (default)\n"
                  "• `embed=true` - force embed format for this rule\n"
                  "• Example: `case_sensitive=false, embed=true`\n"
                  "• Leave empty for auto-detection",
            inline=False
        )
        
        # JSON Embed format
        embed.add_field(
            name="🎨 JSON Embed Format",
            value="Create rich embeds using JSON in the response:\n"
                  "```json\n"
                  '{"title": "My Title", "description": "Content", "color": "blue"}\n'
                  "```\n"
                  "• Available colors: red, blue, green, yellow, purple, orange, #hex\n"
                  "• Add fields: `\"fields\": [{\"name\": \"Field\", \"value\": \"Text\"}]`\n"
                  "• Auto-detected when response starts with `{` and contains embed fields",
            inline=False
        )
        
        # Common regex symbols
        embed.add_field(
            name="🔤 Common Regex Symbols",
            value="• `\\b` - word boundary\n"
                  "• `(?i)` - case insensitive flag\n"
                  "• `|` - OR operator\n"
                  "• `+` - one or more\n"
                  "• `*` - zero or more\n"
                  "• `?` - optional\n"
                  "• `^` - start of message\n"
                  "• `$` - end of message",
            inline=False
        )
        
        embed.set_footer(text="💡 Copy the pattern exactly, including special characters like \\b and (?i)")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="🎨 Configure Embed", style=discord.ButtonStyle.secondary, row=3)
    async def configure_embed_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Configure embed appearance settings"""
        if not self._check_permissions(interaction):
            await interaction.response.send_message("❌ You need 'Manage Messages' permission to use this.",
                                                    ephemeral=True)
            return

        if not interaction.guild:
            await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
            return

        await interaction.response.send_modal(ConfigureEmbedModal(self.guild_id))

    async def _create_autoresponder_embed(self, guild: discord.Guild) -> discord.Embed:
        """Create the autoresponder settings embed"""
        embed = discord.Embed(
            title="🤖 Autoresponder Settings",
            description="Configure autoresponder rules and settings:",
            color=discord.Color.blue()
        )

        # Get current settings
        use_embeds = get_guild_autoresponder_use_embeds(guild.id)
        use_reply = get_guild_autoresponder_use_reply(guild.id)
        rule_count = get_autoresponder_rule_count(guild.id)
        embed_config = get_guild_autoresponder_embed_config(guild.id)

        # Settings status
        embed.add_field(
            name="⚙️ Current Settings",
            value=f"**Output Format:** {'🎨 Embeds' if use_embeds else '📝 Plain Text'}\n"
                  f"**Reply Mode:** {'✅ Enabled' if use_reply else '❌ Disabled'}\n"
                  f"**Active Rules:** {rule_count}",
            inline=False
        )

        # Embed configuration (if embeds are enabled)
        if use_embeds:
            embed_title = embed_config.get('title', '') or "No title"
            embed_color = embed_config.get('color', 'blue')
            custom_footer = embed_config.get('custom_footer', '') or "No footer"
            
            embed.add_field(
                name="🎨 Embed Configuration",
                value=f"**Title:** {embed_title}\n"
                      f"**Color:** {embed_color}\n"
                      f"**Footer:** {custom_footer}",
                inline=False
            )

        # Usage instructions
        embed.add_field(
            name="📖 Quick Help",
            value="• **Add Rule:** Create new autoresponder patterns\n"
                  "• **List Rules:** View all configured rules\n"
                  "• **Remove Rule:** Delete existing rules\n"
                  "• **Toggle Rule:** Enable/disable specific rules\n"
                  "• **Configure Embed:** Customize embed appearance\n"
                  "• **Pattern Help:** Learn about regex and patterns\n"
                  "• Use `/settings embed-examples` for JSON embed help",
            inline=False
        )

        # Pattern types info
        embed.add_field(
            name="🎯 Pattern Types Supported",
            value="**📝 Plain Text:** Simple word/phrase matching\n"
                  "**🔣 Regex:** Advanced pattern matching (auto-detected)\n"
                  "**🎨 JSON Embeds:** Rich embed responses (auto-detected)",
            inline=False
        )

        embed.set_footer(text=f"Server: {guild.name} | Use buttons below to manage autoresponder")
        return embed


@settings_group.command(name="embed-examples", description="Show JSON embed examples for autoresponder")
async def embed_examples(interaction: discord.Interaction):
    """Show examples of JSON embed formats for autoresponder"""
    embed = discord.Embed(
        title="🎨 JSON Embed Examples for Autoresponder",
        description="Copy these JSON examples to create rich embed responses:",
        color=discord.Color.blue()
    )
    
    # Basic embed
    embed.add_field(
        name="🔸 Basic Embed",
        value="```json\n" + """{
  "title": "Welcome!",
  "description": "Thanks for joining our server!",
  "color": "green"
}""" + "\n```",
        inline=False
    )
    
    # Embed with fields
    embed.add_field(
        name="🔸 Embed with Fields",
        value="```json\n" + """{
  "title": "Server Rules",
  "description": "Please follow these important rules:",
  "color": "#ff6b6b",
  "fields": [
    {"name": "Rule 1", "value": "Be respectful", "inline": true},
    {"name": "Rule 2", "value": "No spam", "inline": true},
    {"name": "Rule 3", "value": "Have fun!", "inline": false}
  ]
}""" + "\n```",
        inline=False
    )
    
    # Embed with footer and author
    embed.add_field(
        name="🔸 Complete Embed",
        value="```json\n" + """{
  "title": "🎉 Event Announcement",
  "description": "Join us for our special event!",
  "color": "purple",
  "author": {"name": "Event Team", "icon_url": "https://example.com/icon.png"},
  "footer": {"text": "Event starts soon!", "icon_url": "https://example.com/footer.png"},
  "thumbnail": "https://example.com/thumb.png",
  "fields": [
    {"name": "📅 Date", "value": "Tomorrow", "inline": true},
    {"name": "⏰ Time", "value": "8 PM EST", "inline": true}
  ]
}""" + "\n```",
        inline=False
    )
    
    # Available colors
    embed.add_field(
        name="🎨 Available Colors",
        value="**Named colors:** red, blue, green, yellow, purple, orange\n"
              "**Hex colors:** #ff0000, #00ff00, #0000ff, etc.\n"
              "**Examples:** `\"color\": \"red\"` or `\"color\": \"#ff6b6b\"`",
        inline=False
    )
    
    # Usage tips
    embed.add_field(
        name="💡 Usage Tips",
        value="• JSON must be valid (use quotes around strings)\n"
              "• Embed format is auto-detected when response starts with `{`\n"
              "• You can force embed mode with `embed=true` in options\n"
              "• Mix with server embed settings for consistent styling",
        inline=False
    )
    
    embed.set_footer(text="💡 Test your JSON at jsonlint.com before using!")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)


class AddAutoresponderRuleModal(discord.ui.Modal, title="Add Autoresponder Rule"):
    """Modal for adding new autoresponder rules"""
    
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter a unique name for this rule",
            max_length=100,
            required=True
        )
        self.add_item(self.rule_name)

        self.trigger_pattern = discord.ui.TextInput(
            label="Trigger Pattern",
            placeholder="Enter pattern (plain text or regex)",
            max_length=500,
            required=True
        )
        self.add_item(self.trigger_pattern)

        self.response_message = discord.ui.TextInput(
            label="Response Message",
            placeholder="Enter response message or JSON embed",
            style=discord.TextStyle.paragraph,
            max_length=2000,
            required=True
        )
        self.add_item(self.response_message)

        self.options = discord.ui.TextInput(
            label="Options (optional)",
            placeholder="case_sensitive=false, embed=true",
            max_length=200,
            required=False
        )
        self.add_item(self.options)

    def _is_regex_pattern(self, pattern: str) -> bool:
        """Auto-detect if a pattern is regex based on common regex features"""
        regex_indicators = [
            r'\(',          # Groups
            r'\[',          # Character classes  
            r'\{',          # Quantifiers
            r'\+',          # One or more
            r'\*',          # Zero or more
            r'\?',          # Optional
            r'\|',          # OR operator
            r'\^',          # Start anchor
            r'\$',          # End anchor
            r'\\b',         # Word boundary
            r'\\d',         # Digit class
            r'\\w',         # Word class
            r'\\s',         # Whitespace class
            r'\(\?',        # Non-capturing groups or flags
        ]
        
        return any(re.search(indicator, pattern) for indicator in regex_indicators)

    def _is_json_embed(self, response: str) -> bool:
        """Check if response is a JSON embed"""
        response = response.strip()
        if not (response.startswith('{') and response.endswith('}')):
            return False
        
        try:
            data = json.loads(response)
            embed_fields = ['title', 'description', 'color', 'fields', 'author', 'footer', 'thumbnail', 'image']
            return isinstance(data, dict) and any(field in data for field in embed_fields)
        except (json.JSONDecodeError, TypeError):
            return False

    def _create_embed_preview(self, embed_data: dict) -> discord.Embed:
        """Create a Discord embed from JSON data"""
        embed = discord.Embed()
        
        if 'title' in embed_data:
            embed.title = str(embed_data['title'])[:256]
        
        if 'description' in embed_data:
            embed.description = str(embed_data['description'])[:4096]
        
        if 'color' in embed_data:
            color = embed_data['color']
            if isinstance(color, str):
                if color.startswith('#'):
                    embed.color = discord.Color(int(color[1:], 16))
                else:
                    color_map = {
                        'red': discord.Color.red(),
                        'blue': discord.Color.blue(),
                        'green': discord.Color.green(),
                        'yellow': discord.Color.yellow(),
                        'purple': discord.Color.purple(),
                        'orange': discord.Color.orange(),
                    }
                    embed.color = color_map.get(color.lower(), discord.Color.blue())
            elif isinstance(color, int):
                embed.color = discord.Color(color)
        
        if 'fields' in embed_data and isinstance(embed_data['fields'], list):
            for field in embed_data['fields'][:25]:  # Discord limit
                if isinstance(field, dict) and 'name' in field and 'value' in field:
                    embed.add_field(
                        name=str(field['name'])[:256],
                        value=str(field['value'])[:1024],
                        inline=field.get('inline', True)
                    )
        
        if 'author' in embed_data and isinstance(embed_data['author'], dict):
            author = embed_data['author']
            embed.set_author(
                name=str(author.get('name', ''))[:256],
                icon_url=author.get('icon_url'),
                url=author.get('url')
            )
        
        if 'footer' in embed_data and isinstance(embed_data['footer'], dict):
            footer = embed_data['footer']
            embed.set_footer(
                text=str(footer.get('text', ''))[:2048],
                icon_url=footer.get('icon_url')
            )
        
        if 'thumbnail' in embed_data:
            embed.set_thumbnail(url=embed_data['thumbnail'])
        
        if 'image' in embed_data:
            embed.set_image(url=embed_data['image'])
        
        return embed

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            rule_name = self.rule_name.value.strip()
            trigger_pattern = self.trigger_pattern.value.strip()
            response_message = self.response_message.value.strip()
            options_str = self.options.value.strip() if self.options.value else ""

            # Parse options
            options = {}
            if options_str:
                for option in options_str.split(','):
                    if '=' in option:
                        key, value = option.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip().lower()
                        if value in ['true', 'false']:
                            options[key] = value == 'true'
                        else:
                            options[key] = value

            # Auto-detect pattern type
            is_regex = self._is_regex_pattern(trigger_pattern)
            case_sensitive = options.get('case_sensitive', False)

            # Check if response is JSON embed
            is_json_embed = self._is_json_embed(response_message)

            # Validate JSON if it's detected as embed
            if is_json_embed:
                try:
                    embed_data = json.loads(response_message)
                    # Create preview embed
                    preview_embed = self._create_embed_preview(embed_data)
                except json.JSONDecodeError as e:
                    await interaction.response.send_message(
                        f"❌ Invalid JSON format: {str(e)}\n\nPlease check your JSON syntax and try again.",
                        ephemeral=True
                    )
                    return

            # Add the rule
            result = add_autoresponder_rule(
                self.guild_id,
                rule_name,
                trigger_pattern,
                response_message,
                is_regex=is_regex,
                case_sensitive=case_sensitive
            )

            if result:
                embed = discord.Embed(
                    title="✅ Autoresponder Rule Added",
                    description=f"Successfully added rule: **{rule_name}**",
                    color=discord.Color.green()
                )
                
                embed.add_field(
                    name="🎯 Trigger Pattern",
                    value=f"`{trigger_pattern}`\n{'🔣 Regex pattern' if is_regex else '📝 Plain text pattern'}",
                    inline=False
                )
                
                if is_json_embed:
                    embed.add_field(
                        name="📋 Response Type", 
                        value="🎨 JSON Embed (see preview below)",
                        inline=False
                    )
                    await interaction.response.send_message(embed=embed, ephemeral=True)
                    
                    # Send embed preview
                    try:
                        embed_data = json.loads(response_message)
                        preview_embed = self._create_embed_preview(embed_data)
                        preview_embed.set_footer(text="📋 Embed Preview - This is how your autoresponder embed will look")
                        await interaction.followup.send(embed=preview_embed, ephemeral=True)
                    except:
                        pass
                else:
                    embed.add_field(
                        name="📋 Response Message",
                        value=response_message[:500] + ("..." if len(response_message) > 500 else ""),
                        inline=False
                    )
                    await interaction.response.send_message(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(
                    f"❌ Failed to add autoresponder rule. Rule name '{rule_name}' may already exist.",
                    ephemeral=True
                )

        except Exception as e:
            logger.error(f"Error adding autoresponder rule: {e}")
            await interaction.response.send_message(
                "❌ Error adding autoresponder rule. Please try again.",
                ephemeral=True
            )


class RemoveAutoresponderRuleModal(discord.ui.Modal, title="Remove Autoresponder Rule"):
    """Modal for removing autoresponder rules"""
    
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter the exact name of the rule to remove",
            max_length=100,
            required=True
        )
        self.add_item(self.rule_name)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            rule_name = self.rule_name.value.strip()

            # Check if rule exists first
            rules = get_autoresponder_rules(self.guild_id)
            rule_exists = any(rule['rule_name'] == rule_name for rule in rules)

            if not rule_exists:
                await interaction.response.send_message(
                    f"❌ No autoresponder rule named '{rule_name}' found.",
                    ephemeral=True
                )
                return

            # Remove the rule
            success = remove_autoresponder_rule(self.guild_id, rule_name)

            if success:
                embed = discord.Embed(
                    title="✅ Autoresponder Rule Removed",
                    description=f"Successfully removed rule: **{rule_name}**",
                    color=discord.Color.green()
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(
                    f"❌ Failed to remove autoresponder rule '{rule_name}'.",
                    ephemeral=True
                )

        except Exception as e:
            logger.error(f"Error removing autoresponder rule: {e}")
            await interaction.response.send_message(
                "❌ Error removing autoresponder rule. Please try again.",
                ephemeral=True
            )


class ToggleAutoresponderRuleModal(discord.ui.Modal, title="Toggle Autoresponder Rule"):
    """Modal for toggling autoresponder rules on/off"""
    
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter the exact name of the rule to toggle",
            max_length=100,
            required=True
        )
        self.add_item(self.rule_name)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            rule_name = self.rule_name.value.strip()

            # Check if rule exists first
            rules = get_autoresponder_rules(self.guild_id)
            rule = next((r for r in rules if r['rule_name'] == rule_name), None)

            if not rule:
                await interaction.response.send_message(
                    f"❌ No autoresponder rule named '{rule_name}' found.",
                    ephemeral=True
                )
                return

            # Toggle the rule (flip current state)
            current_state = rule.get('enabled', True)
            new_state = not current_state
            success = toggle_autoresponder_rule(self.guild_id, rule_name, new_state)

            if success:
                is_enabled = new_state

                embed = discord.Embed(
                    title="✅ Autoresponder Rule Toggled",
                    description=f"Rule **{rule_name}** is now {'✅ **Enabled**' if is_enabled else '❌ **Disabled**'}",
                    color=discord.Color.green() if is_enabled else discord.Color.red()
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(
                    f"❌ Failed to toggle autoresponder rule '{rule_name}'.",
                    ephemeral=True
                )

        except Exception as e:
            logger.error(f"Error toggling autoresponder rule: {e}")
            await interaction.response.send_message(
                "❌ Error toggling autoresponder rule. Please try again.",
                ephemeral=True
            )


class ConfigureEmbedModal(discord.ui.Modal, title="Configure Autoresponder Embed"):
    """Modal for configuring autoresponder embed appearance"""
    
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        # Get current embed configuration
        from guild_config import get_guild_autoresponder_embed_config
        embed_config = get_guild_autoresponder_embed_config(guild_id)

        self.embed_title = discord.ui.TextInput(
            label="Embed Title (optional)",
            placeholder="Leave empty for no title",
            default=embed_config.get('title', ''),
            max_length=256,
            required=False
        )
        self.add_item(self.embed_title)

        self.embed_color = discord.ui.TextInput(
            label="Embed Color",
            placeholder="red, blue, green, yellow, purple, orange, or #hex",
            default=embed_config.get('color', 'blue'),
            max_length=20,
            required=False
        )
        self.add_item(self.embed_color)

        self.custom_footer = discord.ui.TextInput(
            label="Custom Footer (optional)",
            placeholder="Leave empty for no footer",
            default=embed_config.get('custom_footer', ''),
            max_length=100,
            required=False
        )
        self.add_item(self.custom_footer)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            if not interaction.guild:
                await interaction.response.send_message("❌ This can only be used in a server.", ephemeral=True)
                return

            embed_title = self.embed_title.value.strip()
            embed_color = self.embed_color.value.strip() or 'blue'
            custom_footer = self.custom_footer.value.strip()

            # Validate color
            valid_colors = ['red', 'blue', 'green', 'yellow', 'purple', 'orange']
            if embed_color.lower() not in valid_colors and not embed_color.startswith('#'):
                await interaction.response.send_message(
                    f"❌ Invalid color. Use one of: {', '.join(valid_colors)} or a hex color like #ff0000",
                    ephemeral=True
                )
                return

            # Validate hex color if provided
            if embed_color.startswith('#'):
                try:
                    int(embed_color[1:], 16)
                    if len(embed_color) not in [4, 7]:  # #rgb or #rrggbb
                        raise ValueError()
                except ValueError:
                    await interaction.response.send_message(
                        "❌ Invalid hex color format. Use #rgb or #rrggbb (e.g., #f00 or #ff0000)",
                        ephemeral=True
                    )
                    return

            # Save configuration
            from guild_config import set_guild_autoresponder_embed_config
            set_guild_autoresponder_embed_config(
                self.guild_id,
                title=embed_title,
                color=embed_color,
                custom_footer=custom_footer
            )

            # Create response embed with preview
            embed = discord.Embed(
                title="✅ Embed Configuration Updated",
                description="Autoresponder embed settings have been updated:",
                color=discord.Color.green()
            )

            embed.add_field(
                name="🎨 Title",
                value=f"`{embed_title}`" if embed_title else "No title",
                inline=True
            )

            embed.add_field(
                name="🌈 Color",
                value=f"`{embed_color}`",
                inline=True
            )

            embed.add_field(
                name="📝 Footer",
                value=f"`{custom_footer}`" if custom_footer else "No footer",
                inline=True
            )

            await interaction.response.send_message(embed=embed, ephemeral=True)

            # Send a preview of how autoresponder embeds will look
            try:
                # Parse color for preview
                color = discord.Color.blue()  # Default
                if embed_color.lower() == 'red':
                    color = discord.Color.red()
                elif embed_color.lower() == 'green':
                    color = discord.Color.green()
                elif embed_color.lower() == 'yellow':
                    color = discord.Color.yellow()
                elif embed_color.lower() == 'purple':
                    color = discord.Color.purple()
                elif embed_color.lower() == 'orange':
                    color = discord.Color.orange()
                elif embed_color.startswith('#'):
                    color = discord.Color(int(embed_color[1:], 16))

                preview_embed = discord.Embed(
                    title=embed_title if embed_title else None,
                    description="This is how your autoresponder embeds will look!",
                    color=color
                )

                if custom_footer:
                    preview_embed.set_footer(text=custom_footer)

                preview_embed.set_author(name="🔍 Embed Preview")

                await interaction.followup.send(embed=preview_embed, ephemeral=True)

            except Exception as e:
                logger.error(f"Error creating embed preview: {e}")

        except Exception as e:
            logger.error(f"Error configuring embed settings: {e}")
            await interaction.response.send_message(
                "❌ Error saving embed configuration. Please try again.",
                ephemeral=True
            )


@settings_group.command(name="view", description="View and configure bot settings for this server")
async def settings_view(interaction: discord.Interaction):
    """Main settings command that shows the interactive settings panel"""
    if not interaction.guild:
        await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
        return

    # Check permissions
    if not isinstance(interaction.user, discord.Member):
        await interaction.response.send_message("❌ This command can only be used by server members.", ephemeral=True)
        return

    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ You need 'Manage Server' permission to use this command.", ephemeral=True)
        return

    # Create settings view
    view = SettingsView(interaction.guild.id)
    embed = await view._create_settings_embed(interaction.guild)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


# Export the command group
__all__ = ['settings_group']
