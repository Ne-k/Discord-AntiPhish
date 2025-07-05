"""
Settings command for bot configuration
"""
import discord
import logging
from discord import app_commands
from typing import Optional

from guild_config import (
    get_guild_full_config, set_guild_action, set_guild_log_channel,
    set_guild_timeout_duration, set_guild_anti_phish_enabled,
    set_guild_anti_malware_enabled, set_guild_anti_piracy_enabled,
    set_guild_bypass_roles, set_guild_max_attempts, get_guild_bypass_roles,
    get_autoresponder_rule_count
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

    async def _create_autoresponder_embed(self, guild: discord.Guild) -> discord.Embed:
        """Create the autoresponder settings embed"""
        from guild_config import get_autoresponder_rules, get_autoresponder_rule_count
        from src.core.config import config as bot_config

        embed = discord.Embed(
            title="🤖 Autoresponder Settings",
            description="Manage autoresponder rules for this server:",
            color=discord.Color.green()
        )

        # Autoresponder status
        autoresponder_status = "✅ Enabled" if bot_config.AUTORESPONDER_ENABLED else "❌ Disabled"
        embed.add_field(
            name="🔄 Status",
            value=autoresponder_status,
            inline=True
        )

        # Rule count
        rule_count = get_autoresponder_rule_count(guild.id)
        embed.add_field(
            name="📊 Rules Count",
            value=f"{rule_count} rule(s) configured",
            inline=True
        )

        # Recent rules (up to 3)
        try:
            rules = get_autoresponder_rules(guild.id)
            if rules:
                recent_rules = rules[:3]  # Show first 3 rules
                rules_text = []
                for rule in recent_rules:
                    status = "✅" if rule.get('enabled', True) else "❌"
                    rules_text.append(f"{status} **{rule['rule_name']}**")

                embed.add_field(
                    name="📋 Recent Rules",
                    value="\n".join(rules_text) if rules_text else "No rules configured",
                    inline=False
                )
        except Exception as e:
            logger.error(f"Error getting autoresponder rules: {e}")
            embed.add_field(
                name="📋 Rules",
                value="Error loading rules",
                inline=False
            )

        embed.set_footer(text="Use the buttons below to manage autoresponder rules")

        return embed


class AddAutoresponderRuleModal(discord.ui.Modal, title="Add Autoresponder Rule"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter a name for this rule",
            max_length=50
        )
        self.add_item(self.rule_name)

        self.trigger_pattern = discord.ui.TextInput(
            label="Trigger Pattern",
            placeholder="Enter the text/pattern that will trigger the response",
            max_length=200
        )
        self.add_item(self.trigger_pattern)

        self.response_message = discord.ui.TextInput(
            label="Response Message",
            placeholder="Enter the response message",
            style=discord.TextStyle.paragraph,
            max_length=1000
        )
        self.add_item(self.response_message)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            from guild_config import add_autoresponder_rule

            success = add_autoresponder_rule(
                self.guild_id,
                self.rule_name.value.strip(),
                self.trigger_pattern.value.strip(),
                self.response_message.value.strip(),
                is_regex=False,
                case_sensitive=False
            )

            if success:
                embed = discord.Embed(
                    title="✅ Autoresponder Rule Added",
                    description=f"Rule **{self.rule_name.value}** has been created successfully.",
                    color=discord.Color.green()
                )
                embed.add_field(name="Trigger", value=f"`{self.trigger_pattern.value}`", inline=False)
                embed.add_field(name="Response", value=self.response_message.value[:100] + (
                    "..." if len(self.response_message.value) > 100 else ""), inline=False)
            else:
                embed = discord.Embed(
                    title="❌ Error Adding Rule",
                    description="Failed to add the autoresponder rule. A rule with this name may already exist.",
                    color=discord.Color.red()
                )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error adding autoresponder rule: {e}")
            await interaction.response.send_message("❌ Error adding autoresponder rule.", ephemeral=True)


class RemoveAutoresponderRuleModal(discord.ui.Modal, title="Remove Autoresponder Rule"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter the exact name of the rule to remove",
            max_length=50
        )
        self.add_item(self.rule_name)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            from guild_config import remove_autoresponder_rule

            success = remove_autoresponder_rule(self.guild_id, self.rule_name.value.strip())

            if success:
                embed = discord.Embed(
                    title="✅ Autoresponder Rule Removed",
                    description=f"Rule **{self.rule_name.value}** has been removed successfully.",
                    color=discord.Color.green()
                )
            else:
                embed = discord.Embed(
                    title="❌ Rule Not Found",
                    description=f"No autoresponder rule found with the name **{self.rule_name.value}**.",
                    color=discord.Color.red()
                )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error removing autoresponder rule: {e}")
            await interaction.response.send_message("❌ Error removing autoresponder rule.", ephemeral=True)


class ToggleAutoresponderRuleModal(discord.ui.Modal, title="Toggle Autoresponder Rule"):
    def __init__(self, guild_id: int):
        super().__init__()
        self.guild_id = guild_id

        self.rule_name = discord.ui.TextInput(
            label="Rule Name",
            placeholder="Enter the exact name of the rule to toggle",
            max_length=50
        )
        self.add_item(self.rule_name)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            from guild_config import get_autoresponder_rules, toggle_autoresponder_rule

            # First, find the rule to get its current state
            rules = get_autoresponder_rules(self.guild_id)
            rule_name = self.rule_name.value.strip()

            target_rule = None
            for rule in rules:
                if rule['rule_name'] == rule_name:
                    target_rule = rule
                    break

            if target_rule is None:
                embed = discord.Embed(
                    title="❌ Rule Not Found",
                    description=f"No autoresponder rule found with the name **{rule_name}**.",
                    color=discord.Color.red()
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return

            # Toggle the rule state
            current_state = target_rule.get('enabled', True)
            new_state = not current_state

            success = toggle_autoresponder_rule(self.guild_id, rule_name, new_state)

            if success:
                status = "enabled" if new_state else "disabled"
                embed = discord.Embed(
                    title="✅ Autoresponder Rule Toggled",
                    description=f"Rule **{rule_name}** has been **{status}**.",
                    color=discord.Color.green()
                )
            else:
                embed = discord.Embed(
                    title="❌ Error Toggling Rule",
                    description=f"Failed to toggle rule **{rule_name}**.",
                    color=discord.Color.red()
                )

            await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error toggling autoresponder rule: {e}")
            await interaction.response.send_message("❌ Error toggling autoresponder rule.", ephemeral=True)


@settings_group.command(name="view", description="View current server settings")
@app_commands.default_permissions(manage_guild=True)
async def view_settings(interaction: discord.Interaction):
    """Display current guild settings with interactive buttons"""
    try:
        if not interaction.guild:
            await interaction.response.send_message("❌ This command can only be used in a server.", ephemeral=True)
            return

        view = SettingsView(interaction.guild.id)
        embed = await view._create_settings_embed(interaction.guild)

        await interaction.response.send_message(embed=embed, view=view)

    except Exception as e:
        logger.error(f"Error in view settings command: {e}")
        await interaction.response.send_message("❌ Error retrieving settings.", ephemeral=True)


# Export the command group
__all__ = ['settings_group']
