"""
Optimized Anti-Phishing Engine with memory and performance optimizations
"""
import aiohttp
import asyncio
import hashlib
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

from src.core.config import config
from src.core.config import get_api_headers, get_user_agent
from .cache import (
    result_cache, domain_cache_phishing, domain_cache_malware,
    domain_cache_adguard, domain_cache_piracy
)
from .memory_manager import memory_manager
from .performance import (
    async_timed, performance_monitor, task_pool, connection_pool
)

logger = logging.getLogger(__name__)


class RateLimiter:
    """Enhanced rate limiter with burst support"""

    def __init__(self, max_calls: int = 10, time_window: int = 60, burst_limit: Optional[int] = None):
        self.max_calls = max_calls
        self.time_window = time_window
        self.burst_limit = burst_limit or max_calls * 2
        self.calls = []
        self.burst_calls = []
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire rate limit permission"""
        async with self._lock:
            now = time.time()

            # Clean old calls
            self.calls = [call_time for call_time in self.calls
                          if now - call_time < self.time_window]
            self.burst_calls = [call_time for call_time in self.burst_calls
                                if now - call_time < 10]  # 10 second burst window

            # Check burst limit
            if len(self.burst_calls) >= self.burst_limit:
                sleep_time = 10 - (now - self.burst_calls[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

            # Check regular limit
            if len(self.calls) >= self.max_calls:
                sleep_time = self.time_window - (now - self.calls[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

            # Record the call
            now = time.time()  # Update after potential sleep
            self.calls.append(now)
            self.burst_calls.append(now)


class OptimizedAntiPhishEngine:
    """Optimized anti-phishing engine with advanced caching and performance features"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        # Rate limiters for different APIs using configuration
        self.bitflow_limiter = RateLimiter(
            max_calls=config.BITFLOW_MAX_CALLS,
            time_window=config.BITFLOW_TIME_WINDOW,
            burst_limit=config.BITFLOW_BURST_LIMIT
        )
        self.sinking_limiter = RateLimiter(
            max_calls=config.SINKING_MAX_CALLS,
            time_window=config.SINKING_TIME_WINDOW,
            burst_limit=config.SINKING_BURST_LIMIT
        )
        # Compiled regex patterns for better performance
        self.url_patterns = [
            re.compile(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
                       re.IGNORECASE),
            re.compile(r'(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
                       re.IGNORECASE)
        ]
        # Enhanced patterns for subdomain detection
        self.subdomain_patterns = [
            # Pattern for detecting domains with at least one subdomain (e.g., api.example.com, secure.login.bank.com)
            re.compile(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b', re.IGNORECASE),
            # Pattern for detecting suspicious subdomain structures (multiple levels)
            re.compile(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){3,}[a-zA-Z]{2,}\b', re.IGNORECASE),
            # Pattern for common phishing subdomain prefixes
            re.compile(
                r'\b(?:login|secure|auth|verify|account|portal|admin|mail|www\d+|app|api)\.([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b',
                re.IGNORECASE)
        ]
        # Domain validation pattern
        self.domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        # AdGuard blocklist URLs optimized for loading
        self.adguard_lists = [
            ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt", "phishing"),
            ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", "malware"),
            ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt", "phishing"),
            ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt", "phishing"),
            ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt", "piracy")
        ]
        # Whitelist URLs for trusted domains
        self.whitelist_urls = [
            "https://raw.githubusercontent.com/pressrestart/topdomainswhitelist/refs/heads/main/allowlist",
            "https://raw.githubusercontent.com/pressrestart/topdomainswhitelist/refs/heads/main/nsfw/allowlist_nsfw"
        ]
        # Whitelist cache
        self.whitelist_domains = set()
        self._last_whitelist_update = 0.0
        # Blocklist update scheduling using configuration
        self._blocklist_update_interval = config.BLOCKLIST_UPDATE_INTERVAL
        self._whitelist_update_interval = config.WHITELIST_UPDATE_INTERVAL
        self._last_blocklist_update = 0.0
        self._blocklist_update_task = None
        # Background tasks
        self._cleanup_tasks = []
        self._initialized = False
        # Performance counters
        self.stats = defaultdict(int)

    async def initialize(self):
        """Initialize the engine with all optimizations"""
        if self._initialized:
            return
        try:
            # Initialize HTTP session
            self.session = await connection_pool.get_session()
            # Start memory management
            await memory_manager.start_monitoring()
            memory_manager.register_cleanup_target(self)
            # Start cache cleanup tasks
            await result_cache.start_cleanup()
            # Load blocklists in background
            asyncio.create_task(self._load_all_blocklists())
            # Load whitelist in background
            asyncio.create_task(self._load_whitelist())
            # Start blocklist auto-update task
            self._blocklist_update_task = asyncio.create_task(self._blocklist_update_loop())
            # Start performance monitoring
            self._cleanup_tasks.append(
                asyncio.create_task(self._performance_monitor_loop())
            )
            self._initialized = True
            logger.info("Optimized anti-phishing engine initialized")
        except Exception as e:
            logger.error(f"Failed to initialize anti-phishing engine: {e}")
            raise

    async def _blocklist_update_loop(self):
        """Background task to periodically update AdGuard blocklists and whitelist efficiently."""
        while True:
            try:
                now = time.time()
                # Only update if enough time has passed
                if now - self._last_blocklist_update >= self._blocklist_update_interval:
                    logger.info("Checking for AdGuard blocklist updates...")
                    await self._load_all_blocklists()
                    self._last_blocklist_update = now

                # Update whitelist using configured interval
                if now - self._last_whitelist_update >= self._whitelist_update_interval:
                    logger.info("Updating domain whitelist...")
                    await self._load_whitelist()

                await asyncio.sleep(60 * 30)  # Check every 30 minutes
            except Exception as e:
                logger.error(f"Blocklist update loop error: {e}")
                await asyncio.sleep(300)

    @async_timed("extract_domains")
    async def extract_domains(self, content: str) -> List[str]:
        """Extract domains from content with optimized regex and enhanced subdomain detection"""
        urls = set()
        domains = set()

        # Extract markdown links [text](url)
        markdown_pattern = re.compile(r'\[([^\]]*)\]\(([^)]+)\)', re.IGNORECASE)
        markdown_matches = markdown_pattern.findall(content)
        for text, url in markdown_matches:
            urls.add(url)

        # Use regular patterns for direct URLs
        for pattern in self.url_patterns:
            urls.update(pattern.findall(content))

        # Enhanced subdomain detection - extract domains directly from content
        for pattern in self.subdomain_patterns:
            subdomain_matches = pattern.findall(content)
            for match in subdomain_matches:
                if isinstance(match, tuple):
                    # Extract the full match from tuple results
                    full_match = match[0] if match else ""
                    # Find the complete domain in the original content
                    for found_domain in pattern.finditer(content):
                        domain_text = found_domain.group().lower().strip()
                        if self.domain_pattern.match(domain_text):
                            domains.add(domain_text)
                else:
                    domain_text = match.lower().strip()
                    if self.domain_pattern.match(domain_text):
                        domains.add(domain_text)

        # Process URLs to extract domains
        for url in urls:
            try:
                # Ensure URL has protocol
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url

                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc.lower().strip()
                    # Remove port if present
                    domain = domain.split(':')[0]
                    if self.domain_pattern.match(domain):
                        domains.add(domain)
            except Exception as e:
                logger.debug(f"Error parsing URL {url}: {e}")

        return list(domains)

    @async_timed("check_local_caches")
    async def check_local_caches(self, domains: List[str]) -> Dict[str, List[str]]:
        """Check domains against local caches"""
        results = {
            'phishing': [],
            'malware': [],
            'adguard': [],
            'piracy': []
        }

        for domain in domains:
            # Check in parallel for better performance
            tasks = [
                domain_cache_phishing.contains(domain),
                domain_cache_malware.contains(domain),
                domain_cache_adguard.contains(domain),
                domain_cache_piracy.contains(domain)
            ]

            cache_results = await asyncio.gather(*tasks, return_exceptions=True)

            if cache_results[0] is True:
                results['phishing'].append(domain)
            if cache_results[1] is True:
                results['malware'].append(domain)
            if cache_results[2] is True:
                results['adguard'].append(domain)
            if cache_results[3] is True:
                results['piracy'].append(domain)

        return results

    @async_timed("check_bitflow_api")
    async def check_bitflow_api(self, content: str) -> Optional[Dict]:
        """Check content against Bitflow API with rate limiting"""
        if not self.session:
            return None

        # Check cache first
        cache_key = f"bitflow:{hash(content) % 1000000}"
        cached_result = await result_cache.get(cache_key)
        if cached_result is not None:
            self.stats['bitflow_cache_hits'] += 1
            return cached_result

        try:
            await self.bitflow_limiter.acquire()

            payload = {"message": content}
            headers = get_api_headers('bitflow')

            async with self.session.post(
                    "https://anti-fish.bitflow.dev/check",
                    json=payload,
                    headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    await result_cache.set(cache_key, result)
                    self.stats['bitflow_api_calls'] += 1
                    return result
                elif response.status == 404:
                    # No match found
                    result = {"match": False}
                    await result_cache.set(cache_key, result)
                    self.stats['bitflow_api_calls'] += 1
                    return result
                else:
                    logger.warning(f"Bitflow API returned status {response.status}")
                    self.stats['bitflow_api_errors'] += 1
                    return None

        except Exception as e:
            logger.error(f"Error checking Bitflow API: {e}")
            self.stats['bitflow_api_errors'] += 1
            return None

    @async_timed("check_sinking_yachts_api")
    async def check_sinking_yachts_api(self, domains: List[str]) -> Dict[str, bool]:
        """Check domains against Sinking Yachts API with batch processing"""
        if not self.session or not domains:
            return {}

        results = {}

        # Check cache first
        uncached_domains = []
        for domain in domains:
            cache_key = f"sinking:{domain}"
            cached_result = await result_cache.get(cache_key)
            if cached_result is not None:
                results[domain] = cached_result
                self.stats['sinking_cache_hits'] += 1
            else:
                uncached_domains.append(domain)

        # Process uncached domains
        for domain in uncached_domains:
            try:
                await self.sinking_limiter.acquire()

                headers = get_api_headers('sinking_yachts', content_type='text/html')

                async with self.session.get(
                        f"https://phish.sinking.yachts/v2/check/{domain}",
                        headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        is_phishing = result is True
                        results[domain] = is_phishing

                        cache_key = f"sinking:{domain}"
                        await result_cache.set(cache_key, is_phishing)
                        self.stats['sinking_api_calls'] += 1
                    else:
                        logger.warning(f"Sinking Yachts API returned status {response.status} for {domain}")
                        results[domain] = False
                        self.stats['sinking_api_errors'] += 1

            except Exception as e:
                logger.error(f"Error checking domain {domain} with Sinking Yachts: {e}")
                results[domain] = False
                self.stats['sinking_api_errors'] += 1

        return results

    @async_timed("analyze_content")
    async def analyze_content(self, content: str, guild_settings: Dict[str, bool]) -> Dict[str, Any]:
        """Analyze content for threats with full optimization"""
        self.stats['total_analyses'] += 1

        # Extract domains
        domains = await self.extract_domains(content)
        if not domains:
            return {'is_threat': False, 'domains': [], 'sources': []}

        # Check whitelist first - if any domain is whitelisted, skip all checks
        whitelisted_domains = []
        for domain in domains:
            if self._is_domain_whitelisted(domain):
                whitelisted_domains.append(domain)

        if whitelisted_domains:
            logger.debug(f"Domains whitelisted, skipping analysis: {whitelisted_domains}")
            self.stats['whitelist_hits'] += 1
            return {
                'is_threat': False,
                'domains': domains,
                'sources': [f"Whitelisted: {', '.join(whitelisted_domains)}"],
                'cache_hits': {},
                'api_results': {},
                'whitelisted': True
            }

        # Check local caches first
        cache_results = await self.check_local_caches(domains)

        results = {
            'is_threat': False,
            'domains': domains,
            'sources': [],
            'cache_hits': cache_results,
            'api_results': {}
        }

        # Check if we found threats in cache
        threat_found = (
                (guild_settings.get('anti_phish', True) and (cache_results['phishing'] or cache_results['adguard'])) or
                (guild_settings.get('anti_malware', True) and cache_results['malware']) or
                (guild_settings.get('anti_piracy', False) and cache_results['piracy'])
        )

        if threat_found:
            results['is_threat'] = True
            if cache_results['phishing']:
                results['sources'].append(f"Phishing cache: {', '.join(cache_results['phishing'])}")
            if cache_results['malware']:
                results['sources'].append(f"Malware cache: {', '.join(cache_results['malware'])}")
            if cache_results['adguard']:
                results['sources'].append(f"AdGuard blocklist: {', '.join(cache_results['adguard'])}")
            if cache_results['piracy']:
                results['sources'].append(f"Anti-piracy blocklist: {', '.join(cache_results['piracy'])}")

        # If no cache hits and anti-phishing is enabled, check APIs
        if not threat_found and guild_settings.get('anti_phish', True):
            # Run API checks in parallel
            api_tasks = []

            # Bitflow API check
            api_tasks.append(self.check_bitflow_api(content))

            # Sinking Yachts API check
            api_tasks.append(self.check_sinking_yachts_api(domains))

            api_results = await asyncio.gather(*api_tasks, return_exceptions=True)

            # Process Bitflow result
            if isinstance(api_results[0], dict) and api_results[0].get('match'):
                results['is_threat'] = True
                results['api_results']['bitflow'] = api_results[0]
                results['sources'].append("Bitflow API")

            # Process Sinking Yachts results
            if isinstance(api_results[1], dict):
                phishing_domains = [domain for domain, is_phishing in api_results[1].items() if is_phishing]
                if phishing_domains:
                    results['is_threat'] = True
                    results['api_results']['sinking_yachts'] = phishing_domains
                    results['sources'].append(f"Sinking Yachts API: {', '.join(phishing_domains)}")

        return results

    @async_timed("load_blocklist")
    async def _load_single_blocklist(self, url: str, list_type: str) -> int:
        """Load a single blocklist"""
        if not self.session:
            return 0

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    domains = self._parse_adguard_list(content)

                    # Add to appropriate cache
                    if list_type == "piracy":
                        await domain_cache_piracy.add_domains(list(domains))
                    elif list_type == "malware":
                        await domain_cache_malware.add_domains(list(domains))
                    else:  # phishing
                        await domain_cache_adguard.add_domains(list(domains))

                    logger.info(f"Loaded {len(domains)} {list_type} domains from {url}")
                    return len(domains)
                else:
                    logger.warning(f"Failed to load blocklist {url}: HTTP {response.status}")
                    return 0

        except Exception as e:
            logger.error(f"Error loading blocklist {url}: {e}")
            return 0

    async def _load_all_blocklists(self):
        """Load all blocklists in parallel"""
        logger.info("Loading AdGuard blocklists...")

        tasks = []
        for url, list_type in self.adguard_lists:
            task = task_pool.run_task(self._load_single_blocklist(url, list_type))
            tasks.append(task)
            # Small delay between starting tasks
            await asyncio.sleep(0.1)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_domains = sum(r for r in results if isinstance(r, int))
        logger.info(f"Loaded total of {total_domains} domains from AdGuard blocklists")
        logger.info(f"Cache sizes - AdGuard: {len(domain_cache_adguard)}, Piracy: {len(domain_cache_piracy)}")

    def _parse_adguard_list(self, content: str) -> Set[str]:
        """Parse AdGuard format blocklist"""
        domains = set()

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith(('!', '#')):
                continue

            # Handle AdGuard format ||domain.com^
            if line.startswith('||') and line.endswith('^'):
                domain = line[2:-1]
                if self._is_valid_domain(domain):
                    domains.add(domain.lower())
            # Handle hosts file format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
            elif line.startswith(('0.0.0.0 ', '127.0.0.1 ')):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
                    if self._is_valid_domain(domain):
                        domains.add(domain.lower())
            # Handle plain domain format
            elif '.' in line and not line.startswith(('@@', '||', '0.', '127.', '192.')):
                domain = line.strip()
                if self._is_valid_domain(domain):
                    domains.add(domain.lower())

        return domains

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid"""
        if not domain or len(domain) > 253 or '/' in domain:
            return False
        return bool(self.domain_pattern.match(domain))

    async def _load_whitelist(self):
        """Load whitelist domains from GitHub repository"""
        logger.info("Loading domain whitelist...")

        total_domains = 0
        for url in self.whitelist_urls:
            try:
                count = await self._load_single_whitelist(url)
                total_domains += count
                # Small delay between requests
                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Error loading whitelist from {url}: {e}")

        logger.info(f"Loaded {total_domains} trusted domains to whitelist")
        logger.info(f"Total whitelist size: {len(self.whitelist_domains)}")
        self._last_whitelist_update = time.time()

    async def _load_single_whitelist(self, url: str) -> int:
        """Load a single whitelist file"""
        if not self.session:
            return 0

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    domains = self._parse_whitelist(content)

                    # Add to whitelist cache
                    self.whitelist_domains.update(domains)

                    logger.info(f"Loaded {len(domains)} trusted domains from {url}")
                    return len(domains)
                else:
                    logger.warning(f"Failed to load whitelist {url}: HTTP {response.status}")
                    return 0

        except Exception as e:
            logger.error(f"Error loading whitelist {url}: {e}")
            return 0

    def _parse_whitelist(self, content: str) -> Set[str]:
        """Parse whitelist format (simple list of domains)"""
        domains = set()

        for line in content.split('\n'):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith(('#', '//', ';')):
                continue

            # Clean the domain
            domain = line.lower().strip()

            # Remove protocol if present
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('://', 1)[1]

            # Remove path if present
            if '/' in domain:
                domain = domain.split('/', 1)[0]

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':', 1)[0]

            # Remove www prefix for consistent matching
            if domain.startswith('www.'):
                domain = domain[4:]

            # Validate domain
            if self._is_valid_domain(domain) and '.' in domain:
                domains.add(domain)

        return domains

    def _is_domain_whitelisted(self, domain: str) -> bool:
        """Check if a domain is in the whitelist"""
        if not domain:
            return False

        domain = domain.lower().strip()

        # Remove www prefix for consistent matching
        if domain.startswith('www.'):
            domain = domain[4:]

        # Direct match
        if domain in self.whitelist_domains:
            return True

        # Check parent domains (e.g., subdomain.example.com matches example.com)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.whitelist_domains:
                return True

        return False

    async def _performance_monitor_loop(self):
        """Monitor performance and log statistics"""
        while True:
            try:
                await asyncio.sleep(config.PERFORMANCE_MONITOR_INTERVAL)

                # Log performance stats
                perf_stats = performance_monitor.get_stats()
                cache_stats = {
                    'result_cache': result_cache.get_stats(),
                    'phishing_cache': domain_cache_phishing.get_stats(),
                    'malware_cache': domain_cache_malware.get_stats(),
                    'adguard_cache': domain_cache_adguard.get_stats(),
                    'piracy_cache': domain_cache_piracy.get_stats()
                }

                logger.info(f"Performance stats: {dict(self.stats)}")
                logger.info(f"Active tasks: {task_pool.get_active_count()}")

                # Force GC if memory is high
                if memory_manager.should_force_gc():
                    memory_manager.force_gc()

            except Exception as e:
                logger.error(f"Error in performance monitor: {e}")
                await asyncio.sleep(60)

    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up anti-phishing engine...")
        # Cancel background tasks
        for task in self._cleanup_tasks:
            if not task.done():
                task.cancel()
        # Cancel blocklist update task
        if self._blocklist_update_task and not self._blocklist_update_task.done():
            self._blocklist_update_task.cancel()
        # Stop cache cleanup
        await result_cache.stop_cleanup()
        # Stop memory monitoring
        await memory_manager.stop_monitoring()
        # Close connection pool
        await connection_pool.close()
        logger.info("Anti-phishing engine cleanup complete")

    def analyze_subdomain_patterns(self, content: str) -> Dict[str, Any]:
        """Analyze content for subdomain patterns and provide detailed breakdown"""
        results = {
            'basic_subdomains': [],
            'deep_subdomains': [],
            'suspicious_subdomains': [],
            'pattern_matches': {}
        }

        # Test each subdomain pattern
        pattern_names = [
            'basic_subdomain_pattern',
            'deep_subdomain_pattern',
            'suspicious_subdomain_pattern'
        ]

        for i, pattern in enumerate(self.subdomain_patterns):
            pattern_name = pattern_names[i] if i < len(pattern_names) else f'pattern_{i}'
            matches = []

            for match in pattern.finditer(content):
                domain = match.group().lower().strip()
                if self.domain_pattern.match(domain):
                    matches.append({
                        'domain': domain,
                        'start': match.start(),
                        'end': match.end(),
                        'context': content[max(0, match.start() - 10):match.end() + 10]
                    })

            results['pattern_matches'][pattern_name] = matches

            # Categorize by pattern type
            if i == 0:  # Basic subdomain pattern
                results['basic_subdomains'] = [m['domain'] for m in matches]
            elif i == 1:  # Deep subdomain pattern
                results['deep_subdomains'] = [m['domain'] for m in matches]
            elif i == 2:  # Suspicious subdomain pattern
                results['suspicious_subdomains'] = [m['domain'] for m in matches]

        # Add summary statistics
        all_domains = set()
        for matches in results['pattern_matches'].values():
            all_domains.update(m['domain'] for m in matches)

        results['summary'] = {
            'total_unique_subdomains': len(all_domains),
            'has_suspicious_patterns': len(results['suspicious_subdomains']) > 0,
            'max_subdomain_depth': max([d.count('.') for d in all_domains]) if all_domains else 0
        }

        return results


# Global optimized engine instance
optimized_engine = OptimizedAntiPhishEngine()
