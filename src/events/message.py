import asyncio
import discord
import logging
import socket

try:
    import dns.resolver
except ImportError:
    dns = None
import aiohttp
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from guild_config import (
    get_guild_action, get_guild_log_channel, get_guild_timeout_duration,
    get_guild_anti_phish_enabled, get_guild_anti_malware_enabled, get_guild_anti_piracy_enabled
)
from optimizations import optimized_engine, performance_monitor, async_timed
from src.features.autoresponder import autoresponder_engine

logger = logging.getLogger(__name__)


async def send_detection_log(message: discord.Message, analysis_result: Dict[str, Any], actions_taken: List[str]):
    """Send detection log to configured log channel immediately after content removal"""
    try:
        # Ensure we have a guild
        if not message.guild:
            return

        log_channel_id = get_guild_log_channel(message.guild.id)
        if not log_channel_id:
            return

        log_channel = message.guild.get_channel(log_channel_id)
        if not log_channel or not isinstance(log_channel, discord.TextChannel):
            return

        # Determine threat type and emoji
        threat_type = "Malicious Content"
        threat_emoji = "🚨"
        if any("piracy" in source.lower() for source in analysis_result['sources']):
            threat_type = "Piracy Content"
            threat_emoji = "🏴‍☠️"
        elif any("phish" in source.lower() for source in analysis_result['sources']):
            threat_type = "Phishing"
            threat_emoji = "🎣"
        elif any("malware" in source.lower() for source in analysis_result['sources']):
            threat_type = "Malware"
            threat_emoji = "🦠"

        # Create detection embed
        embed = discord.Embed(
            title=f"🔍 Detection Log - {threat_type}",
            description=f"Malicious content has been detected and removed.",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="User", value=message.author.mention, inline=True)

        # Safe channel mention
        if isinstance(message.channel,
                      (discord.TextChannel, discord.VoiceChannel, discord.StageChannel, discord.ForumChannel,
                       discord.Thread)):
            channel_mention = message.channel.mention
        else:
            channel_mention = "DM or Unknown Channel"
        embed.add_field(name="Channel", value=channel_mention, inline=True)
        embed.add_field(name="Actions Taken", value="\n".join(actions_taken) if actions_taken else "None", inline=True)

        if analysis_result['sources']:
            sources_text = []
            for source in analysis_result['sources'][:5]:
                sources_text.append(f"• {source}")

            # Add Bitflow trust rating summary to sources if available
            if 'api_results' in analysis_result and 'bitflow' in analysis_result['api_results']:
                bitflow_result = analysis_result['api_results']['bitflow']
                if bitflow_result.get('match') and 'matches' in bitflow_result:
                    trust_ratings = [str(match.get('trust_rating', 'N/A')) for match in bitflow_result['matches']]
                    if trust_ratings:
                        # Find and update the Bitflow API source line
                        for i, source_line in enumerate(sources_text):
                            if "Bitflow API" in source_line:
                                sources_text[i] = f"• Bitflow API (Trust: {', '.join(trust_ratings[:3])})"
                                break

            embed.add_field(
                name="Detection Sources",
                value="\n".join(sources_text),
                inline=False
            )
        if analysis_result['domains']:
            domains_text = ", ".join(analysis_result['domains'][:3])
            if len(analysis_result['domains']) > 3:
                domains_text += f" (+{len(analysis_result['domains']) - 3} more)"
            embed.add_field(name="Domains", value=domains_text, inline=False)

        embed.add_field(
            name="Message Content",
            value=f"```{message.content[:500]}{'...' if len(message.content) > 500 else ''}```",
            inline=False
        )

        await log_channel.send(embed=embed)
        logger.info(f"Sent detection log for {threat_type} from {message.author} to {log_channel.name}")

    except Exception as e:
        logger.error(f"Failed to send detection log: {e}")


class FalsePositiveView(discord.ui.View):
    """View for false positive reporting"""

    def __init__(self, user_id: int, message_content: str, domains: List[str],
                 sources: List[str], log_channel: Optional[discord.TextChannel] = None):
        super().__init__(timeout=300)  # 5 minute timeout
        self.user_id = user_id
        self.message_content = message_content
        self.domains = domains
        self.sources = sources
        self.log_channel = log_channel

    @discord.ui.button(label="Report False Positive", style=discord.ButtonStyle.secondary, emoji="⚠️")
    async def report_false_positive(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handle false positive reports with enhanced domain analysis and detailed information."""
        try:
            # Check if user has permission to report
            # Permissions: Original user OR users with manage_messages (mods/admins) OR users with administrator permission
            has_permission = False
            permission_type = "none"

            if interaction.user.id == self.user_id:
                has_permission = True
                permission_type = "original_user"
            elif interaction.guild and isinstance(interaction.user, discord.Member):
                if interaction.user.guild_permissions.administrator:
                    has_permission = True
                    permission_type = "administrator"
                elif interaction.user.guild_permissions.manage_messages:
                    has_permission = True
                    permission_type = "moderator"

            if not has_permission:
                await interaction.response.send_message(
                    "❌ **Permission Denied**\n"
                    "You need one of the following permissions to report false positives:\n"
                    "• Be the original user who posted the message\n"
                    "• Have `Manage Messages` permission (Moderator)\n"
                    "• Have `Administrator` permission",
                    ephemeral=True
                )
                return

            await interaction.response.defer(ephemeral=True)

            # Create enhanced false positive report
            report_embed = discord.Embed(
                title="🚨 FALSE POSITIVE REPORT",
                description="A threat detection has been reported as a false positive and requires manual review.",
                color=discord.Color.yellow(),
                timestamp=datetime.now(timezone.utc)
            )

            # Reporter information
            channel_info = "Unknown"
            if interaction.channel:
                try:
                    if isinstance(interaction.channel, discord.TextChannel):
                        channel_info = interaction.channel.mention
                    else:
                        # Fallback for other channel types
                        channel_name = getattr(interaction.channel, 'name', None)
                        if channel_name:
                            channel_info = f"#{channel_name}"
                        else:
                            channel_info = f"Channel ID: {interaction.channel.id}"
                except Exception:
                    channel_info = f"Channel ID: {interaction.channel.id}"

            permission_labels = {
                "original_user": "🙋‍♂️ Original User",
                "moderator": "🛡️ Moderator",
                "administrator": "👑 Administrator"
            }
            report_embed.add_field(
                name="Report Details",
                value=f"**Reported by:** {interaction.user.mention} ({permission_labels.get(permission_type, 'User')})\n"
                      f"**Original User:** <@{self.user_id}>\n"
                      f"**Guild:** {interaction.guild.name if interaction.guild else 'Unknown'}\n"
                      f"**Channel:** {channel_info}",
                inline=False
            )

            # Enhanced domain analysis
            if self.domains:
                domain_analysis = []
                for i, domain in enumerate(self.domains[:3], 1):
                    analysis = await self._get_enhanced_domain_info(domain)
                    domain_analysis.append(f"**Domain {i}:** {analysis}")

                report_embed.add_field(
                    name="🔍 Domain Analysis",
                    value="\n\n".join(domain_analysis),
                    inline=False
                )

            # Detection details with enhanced information
            if self.sources:
                source_details = []
                for source in self.sources[:5]:
                    if "bitflow" in source.lower():
                        source_details.append("🎯 **Bitflow API** - Community-driven threat database")
                    elif "sinking" in source.lower():
                        source_details.append("🚢 **Sinking Yachts API** - Real-time phishing detection")
                    elif "adguard" in source.lower():
                        source_details.append("🛡️ **AdGuard Blocklist** - Curated malicious domain list")
                    elif "cache" in source.lower():
                        source_details.append("💾 **Local Cache** - Previously detected threat")
                    elif "phishing" in source.lower():
                        source_details.append("🎣 **Phishing Database** - Known phishing domains")
                    elif "malware" in source.lower():
                        source_details.append("🦠 **Malware Database** - Known malicious domains")
                    elif "piracy" in source.lower():
                        source_details.append("🏴‍☠️ **Anti-Piracy List** - Copyright violation domains")
                    else:
                        source_details.append(f"❓ **{source}** - Detection source")

                report_embed.add_field(
                    name="🎯 Detection Sources",
                    value="\n".join(source_details),
                    inline=False
                )

            # Original message with better formatting
            message_preview = self.message_content[:500]
            if len(self.message_content) > 500:
                message_preview += "..."

            report_embed.add_field(
                name="📝 Original Message Content",
                value=f"```\n{message_preview}\n```",
                inline=False
            )

            # Add timestamp and report ID for tracking
            report_id = f"FP-{int(datetime.now().timestamp())}-{interaction.user.id % 10000}"
            report_embed.add_field(
                name="📋 Report Information",
                value=f"**Report ID:** `{report_id}`\n"
                      f"**Timestamp:** <t:{int(datetime.now().timestamp())}:F>\n"
                      f"**Action Required:** Manual review by administrators",
                inline=False
            )

            # Try to get a screenshot for visual verification
            screenshot_url = None
            if self.domains:
                screenshot_url = await self._get_screenshot_url(self.domains[0])
                if screenshot_url:
                    report_embed.set_image(url=screenshot_url)

            # Send to log channel if available, otherwise to current channel
            if self.log_channel:
                await self.log_channel.send(embed=report_embed)
                response_msg = "✅ False positive report sent to log channel."
            else:
                await interaction.followup.send(embed=report_embed)
                response_msg = "✅ False positive report submitted."

            # Disable the button
            button.disabled = True
            button.label = "Reported"
            await interaction.response.edit_message(view=self)

            # Send confirmation if we sent to log channel
            if self.log_channel:
                await interaction.followup.send(response_msg, ephemeral=True)

            # Log the report
            logger.info(f"False positive reported by {interaction.user} for domains: {', '.join(self.domains)}")

        except Exception as e:
            logger.error(f"Error handling false positive report: {e}")
            await interaction.response.send_message(
                "❌ An error occurred while reporting the false positive.", ephemeral=True
            )

    async def _get_domain_info(self, domain: str) -> str:
        """Fetch IPs and name servers for a domain."""
        info = f"`{domain}`\n"
        try:
            # IP addresses
            ips = []
            try:
                ips = list({ai[4][0] for ai in await asyncio.get_event_loop().getaddrinfo(domain, None)})
            except Exception:
                pass
            if ips:
                info += f"IPs: {', '.join(ips)}\n"
            # Name servers
            ns_records = []
            if dns is not None:
                try:
                    ns_records = [r.to_text() for r in dns.resolver.resolve(domain, 'NS', lifetime=2)]
                except Exception:
                    pass
                if ns_records:
                    info += f"NS: {', '.join(ns_records)}\n"
            else:
                info += "(Install dnspython for NS info)\n"
        except Exception:
            info += "(Could not fetch domain info)"
        return info.strip()

    async def _get_screenshot_url(self, domain: str) -> Optional[str]:
        """Get a screenshot URL for the domain using an external service."""
        try:
            # Ensure the domain has a protocol for the screenshot service
            if not domain.startswith(('http://', 'https://')):
                # Default to HTTPS for modern domains
                domain_with_protocol = f"https://{domain}"
            else:
                domain_with_protocol = domain

            url = f"https://thum.io/get/width/800/crop/700/noanimate/{domain_with_protocol}"
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return url
        except Exception:
            pass
        return None

    async def _get_enhanced_domain_info(self, domain: str) -> str:
        """Fetch comprehensive domain information for false positive analysis."""
        info = f"**`{domain}`**\n"

        try:
            # Basic domain info
            basic_info = await self._get_domain_info(domain)

            # Extract just the useful parts from basic info
            lines = basic_info.split('\n')[1:]  # Skip domain name line
            for line in lines:
                if line.strip() and not line.startswith('`'):
                    info += f"• {line.strip()}\n"

            # Subdomain analysis
            parts = domain.split('.')
            if len(parts) > 2:
                info += f"\n**Subdomain Analysis:**\n"
                info += f"• Full domain: {domain}\n"
                info += f"• Root domain: {'.'.join(parts[-2:])}\n"
                info += f"• Subdomain levels: {len(parts) - 2}\n"

                # Show parent domains that might be checked
                parent_domains = []
                for i in range(1, len(parts)):
                    parent_domain = '.'.join(parts[i:])
                    parent_domains.append(parent_domain)
                if parent_domains:
                    info += f"• Parent domains checked: {', '.join(parent_domains[:3])}\n"

            # Additional security analysis
            security_notes = []

            # Check if domain looks suspicious
            if any(char in domain.lower() for char in ['0', '1', '-']):
                if domain.count('-') > 2:
                    security_notes.append("⚠️ Multiple hyphens (potential typosquatting)")
                if any(f"{char}{char}" in domain for char in "0o1l"):
                    security_notes.append("⚠️ Potentially confusing characters")

            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                security_notes.append("⚠️ High-risk TLD")

            # Check domain length
            if len(domain) > 30:
                security_notes.append("⚠️ Unusually long domain name")
            elif len(domain) < 4:
                security_notes.append("⚠️ Very short domain name")

            # Subdomain-specific checks
            if len(parts) > 3:
                security_notes.append("⚠️ Deep subdomain structure (potential evasion)")
            if len(parts) > 2 and any(
                    suspicious in parts[0].lower() for suspicious in ['admin', 'login', 'secure', 'bank', 'auth']):
                security_notes.append("⚠️ Suspicious subdomain prefix")

            # Add security analysis if any
            if security_notes:
                info += f"\n**Security Notes:**\n"
                for note in security_notes[:4]:  # Limit to 4 notes
                    info += f"• {note}\n"

            # Age estimation (basic)
            try:
                import socket
                # If we can resolve it, it's likely established
                socket.gethostbyname(domain)
                info += f"\n**Status:** ✅ Resolves successfully"
            except socket.gaierror:
                info += f"\n**Status:** ❌ Cannot resolve (domain may be down)"
            except Exception:
                pass

        except Exception as e:
            info += f"\n*(Error gathering enhanced info: {str(e)[:50]})*"

        return info.strip()


@async_timed("message_processing")
async def on_message(bot, message):
    """Optimized message event handler"""
    # Ignore bot messages
    if message.author.bot:
        return

    # Skip DMs for now
    if not message.guild:
        return

    # Skip admin users by default (they bypass all protection)
    if isinstance(message.author, discord.Member):
        if message.author.guild_permissions.administrator:
            logger.debug(f"Skipping message from admin user {message.author} in guild {message.guild.name}")
            return

    # Get guild protection settings
    guild_settings = {
        'anti_phish': get_guild_anti_phish_enabled(message.guild.id),
        'anti_malware': get_guild_anti_malware_enabled(message.guild.id),
        'anti_piracy': get_guild_anti_piracy_enabled(message.guild.id)
    }

    logger.debug(f"Guild {message.guild.name} protection settings: {guild_settings}")

    # Skip if no protection is enabled
    if not any(guild_settings.values()):
        logger.debug(f"No protection enabled for guild {message.guild.name}, skipping")
        return

    # Initialize engine if needed
    if not optimized_engine._initialized:
        await optimized_engine.initialize()

    # Check autoresponder first (before threat analysis)
    try:
        autoresponse = await autoresponder_engine.process_message(message)
        if autoresponse:
            logger.info(f"Sending autoresponse to {message.author} in guild {message.guild.name}")
            try:
                # Send response in the same channel
                await message.channel.send(autoresponse)
            except discord.Forbidden:
                logger.warning(f"No permission to send autoresponse in channel {message.channel.name}")
            except Exception as e:
                logger.error(f"Error sending autoresponse: {e}")
    except Exception as e:
        logger.error(f"Error in autoresponder processing: {e}")
        performance_monitor.track_error("autoresponder")

    # Analyze message content for threats
    try:
        analysis_result = await optimized_engine.analyze_content(message.content, guild_settings)

        logger.info(f"Analysis result for message from {message.author}: threat={analysis_result['is_threat']}")
        if analysis_result['is_threat']:
            logger.info(
                f"Threat detected! Sources: {analysis_result['sources']}, Domains: {analysis_result['domains']}")
            await handle_threat_detection(message, analysis_result)

    except Exception as e:
        logger.error(f"Error during message analysis: {e}")
        performance_monitor.track_error("message_analysis")


@async_timed("threat_handling")
async def handle_threat_detection(message, analysis_result):
    """Handle detected threats with optimized actions"""
    try:
        if not message.guild:
            return

        # Check if bot has necessary permissions
        bot_member = message.guild.me
        if not bot_member.guild_permissions.manage_messages:
            logger.error(f"Bot lacks 'Manage Messages' permission in {message.guild.name}")
            return

        from src.features.user_attempts import add_user_attempt, get_user_attempts, reset_user_attempts
        from guild_config import get_guild_bypass_roles, get_guild_max_attempts

        logger.info(f"Handling threat detection for user {message.author} in guild {message.guild.name}")

        # Check bypass permissions for roles (admins are already filtered out at start)
        should_bypass_action = False
        member = message.author if isinstance(message.author, discord.Member) else None
        if member:
            bypass_roles = set(get_guild_bypass_roles(message.guild.id))
            if any(role.id in bypass_roles for role in member.roles):
                should_bypass_action = True  # Bypass role users bypass punishment but message still gets deleted

        # Track attempts (only if not bypassing)
        max_attempts = get_guild_max_attempts(message.guild.id)
        attempts = 1  # Default to 1 if bypassing

        if not should_bypass_action:
            attempts = add_user_attempt(message.guild.id, message.author.id)

        # Always delete the message first (regardless of bypass status)
        delete_success = False
        try:
            await message.delete()
            delete_success = True
            logger.info(f"Successfully deleted malicious message from {message.author}")

        except discord.NotFound:
            logger.warning(f"Message from {message.author} was already deleted")
            pass
        except discord.Forbidden:
            logger.error(f"No permission to delete message from {message.author} in {message.guild.name}")
            pass
        except Exception as e:
            logger.error(f"Unexpected error deleting message from {message.author}: {e}")
            pass

        if should_bypass_action:
            # Send log for bypass case
            await send_detection_log(message, analysis_result,
                                     ["Message deleted", "No action taken (bypass permission)"])

            # For bypass users, just send a warning and don't take further action
            threat_type = "Malicious Content"
            threat_emoji = "🚨"
            if any("piracy" in source.lower() for source in analysis_result['sources']):
                threat_type = "Piracy Content"
                threat_emoji = "🏴‍☠️"
            elif any("phish" in source.lower() for source in analysis_result['sources']):
                threat_type = "Phishing"
                threat_emoji = "🎣"
            elif any("malware" in source.lower() for source in analysis_result['sources']):
                threat_type = "Malware"
                threat_emoji = "🦠"

            channel_embed = discord.Embed(
                title=f"{threat_emoji} {threat_type} Removed",
                description=f"A dangerous link from {message.author.mention} has been removed.\n*No action taken (bypass permission)*",
                color=discord.Color.yellow()
            )

            log_channel_id = get_guild_log_channel(message.guild.id)
            log_channel = message.guild.get_channel(log_channel_id) if log_channel_id else None
            channel_view = FalsePositiveView(
                user_id=message.author.id,
                message_content=message.content,
                domains=analysis_result['domains'],
                sources=analysis_result['sources'],
                log_channel=log_channel
            )
            warning_msg = await message.channel.send(embed=channel_embed, view=channel_view)
            logger.warning(
                f"{threat_type} detected (bypassed) - User: {message.author} ({message.author.id}), Guild: {message.guild.name}")
            return

        # For non-bypass users, check attempt count
        if attempts < max_attempts:
            # Send log for warning case
            await send_detection_log(message, analysis_result,
                                     ["Message deleted", f"Warning issued (attempt {attempts}/{max_attempts})"])

            # Only warn, do not take further action
            threat_type = "Malicious Content"
            threat_emoji = "🚨"
            if any("piracy" in source.lower() for source in analysis_result['sources']):
                threat_type = "Piracy Content"
                threat_emoji = "🏴‍☠️"
            elif any("phish" in source.lower() for source in analysis_result['sources']):
                threat_type = "Phishing"
                threat_emoji = "🎣"
            elif any("malware" in source.lower() for source in analysis_result['sources']):
                threat_type = "Malware"
                threat_emoji = "🦠"

            channel_embed = discord.Embed(
                title=f"{threat_emoji} {threat_type} Removed",
                description=f"A dangerous link from {message.author.mention} has been removed."
                            f"\nAttempts: {attempts}/{max_attempts}",
                color=discord.Color.orange()
            )
            if attempts == max_attempts - 1:
                channel_embed.add_field(
                    name="Final Warning",
                    value=f"Next infraction will result in action.",
                    inline=False
                )

            log_channel_id = get_guild_log_channel(message.guild.id)
            log_channel = message.guild.get_channel(log_channel_id) if log_channel_id else None
            channel_view = FalsePositiveView(
                user_id=message.author.id,
                message_content=message.content,
                domains=analysis_result['domains'],
                sources=analysis_result['sources'],
                log_channel=log_channel
            )
            warning_msg = await message.channel.send(embed=channel_embed, view=channel_view)
            logger.warning(
                f"{threat_type} detected (strike {attempts}/{max_attempts}) - User: {message.author} ({message.author.id}), Guild: {message.guild.name}")
            return

        # If here, user has reached/exceeded max attempts: reset attempts and take action
        reset_user_attempts(message.guild.id, message.author.id)

        actions_taken = []

        # Get guild configuration
        guild_action = get_guild_action(message.guild.id)
        log_channel_id = get_guild_log_channel(message.guild.id)
        timeout_duration = get_guild_timeout_duration(message.guild.id)

        # Message was already deleted above
        actions_taken.append("Message deleted")

        # Take additional actions based on settings
        if guild_action in ("timeout", "all") and timeout_duration > 0:
            try:
                timeout_until = datetime.now(timezone.utc) + timedelta(minutes=timeout_duration)
                await message.author.timeout(timeout_until, reason="Posted malicious content")
                actions_taken.append(f"User timed out for {timeout_duration} minutes")
            except discord.Forbidden:
                actions_taken.append("⚠️ Cannot timeout user (missing permissions)")
            except discord.HTTPException:
                actions_taken.append("⚠️ Failed to timeout user")

        if guild_action in ("kick", "all"):
            try:
                await message.author.kick(reason="Posted malicious content")
                actions_taken.append("User kicked")
            except discord.Forbidden:
                actions_taken.append("⚠️ Cannot kick user (missing permissions)")
            except discord.HTTPException:
                actions_taken.append("⚠️ Failed to kick user")

        if guild_action in ("ban", "all"):
            try:
                await message.author.ban(reason="Posted malicious content", delete_message_days=1)
                actions_taken.append("User banned")
            except discord.Forbidden:
                actions_taken.append("⚠️ Cannot ban user (missing permissions)")
            except discord.HTTPException:
                actions_taken.append("⚠️ Failed to ban user")

        # Send log immediately after actions are taken
        await send_detection_log(message, analysis_result, actions_taken)

        # Determine threat type for channel messaging
        threat_type = "Malicious Content"
        threat_emoji = "🚨"
        if any("piracy" in source.lower() for source in analysis_result['sources']):
            threat_type = "Piracy Content"
            threat_emoji = "🏴‍☠️"
        elif any("phish" in source.lower() for source in analysis_result['sources']):
            threat_type = "Phishing"
            threat_emoji = "🎣"
        elif any("malware" in source.lower() for source in analysis_result['sources']):
            threat_type = "Malware"
            threat_emoji = "🦠"

        # Send warning in channel (brief version) with false positive button
        channel_embed = discord.Embed(
            title=f"{threat_emoji} {threat_type} Removed",
            description=f"A dangerous link from {message.author.mention} has been removed.",
            color=discord.Color.orange()
        )
        if guild_action != "delete":
            action_text = ""
            if guild_action == "timeout":
                action_text = "timed out"
            elif guild_action == "kick":
                action_text = "kicked"
            elif guild_action == "ban":
                action_text = "banned"
            elif guild_action == "all":
                action_text = "banned"
            else:
                action_text = guild_action
            channel_embed.add_field(
                name="Action Taken",
                value=f"User has been **{action_text}**",
                inline=False
            )
        log_channel = None
        if log_channel_id:
            log_channel = message.guild.get_channel(log_channel_id)
        channel_view = FalsePositiveView(
            user_id=message.author.id,
            message_content=message.content,
            domains=analysis_result['domains'],
            sources=analysis_result['sources'],
            log_channel=log_channel
        )
        warning_msg = await message.channel.send(embed=channel_embed, view=channel_view)
        logger.warning(
            f"{threat_type} detected - User: {message.author} ({message.author.id}), "
            f"Guild: {message.guild.name}, Action: {guild_action}, "
            f"Sources: {', '.join(analysis_result['sources'][:3])}"
        )
    except Exception as e:
        logger.error(f"Error handling threat detection: {e}")
        performance_monitor.track_error("threat_handling")


@async_timed("message_edit")
async def on_message_edit(bot, before, after):
    """Handle message edits"""
    if before.author.bot or not before.guild or before.content == after.content:
        return

    # Check if any protection is enabled
    guild_settings = {
        'anti_phish': get_guild_anti_phish_enabled(before.guild.id),
        'anti_malware': get_guild_anti_malware_enabled(before.guild.id),
        'anti_piracy': get_guild_anti_piracy_enabled(before.guild.id)
    }

    if not any(guild_settings.values()):
        return

    # Initialize engine if needed
    if not optimized_engine._initialized:
        await optimized_engine.initialize()

    # Check edited message
    try:
        analysis_result = await optimized_engine.analyze_content(after.content, guild_settings)

        if analysis_result['is_threat']:
            await handle_threat_detection(after, analysis_result)

    except Exception as e:
        logger.error(f"Error during edited message analysis: {e}")
        performance_monitor.track_error("edit_analysis")


async def on_message_delete(bot, message):
    """Handle message deletions (for logging)"""
    if message.author.bot:
        return

    guild_name = message.guild.name if message.guild else 'DM'
    logger.debug(f"Message deleted in {guild_name}: {message.content[:50]}...")


async def initialize_anti_phish():
    """Initialize the optimized anti-phishing system"""
    try:
        await optimized_engine.initialize()

        # Start user attempt tracking
        from src.features.user_attempts import start_attempt_tracking
        start_attempt_tracking()

        logger.info("Optimized anti-phishing system initialized")
    except Exception as e:
        logger.error(f"Failed to initialize anti-phishing system: {e}")


async def cleanup_anti_phish():
    """Cleanup anti-phishing resources"""
    try:
        await optimized_engine.cleanup()

        # Stop user attempt tracking
        from src.features.user_attempts import stop_attempt_tracking
        stop_attempt_tracking()

        logger.info("Anti-phishing system cleaned up")
    except Exception as e:
        logger.error(f"Error cleaning up anti-phishing system: {e}")
