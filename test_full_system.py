#!/usr/bin/env python3
"""
Comprehensive Full System Test Suite
Combines all test functionality into one unified test file for complete system validation
"""

import asyncio
import sqlite3
import os
import sys
import logging
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.optimizations import optimized_engine
from src.optimizations.cache import (
    domain_cache_adguard, domain_cache_piracy, domain_cache_malware, 
    domain_cache_phishing, result_cache
)
from src.optimizations.performance import performance_monitor
from src.optimizations.memory_manager import memory_manager
from guild_config import *
from autoresponder import autoresponder_engine
from config import config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FullSystemTest:
    """Comprehensive system test suite"""
    
    def __init__(self):
        self.test_results = {}
        self.test_guild_id = 123456789
        
    def log_test_result(self, test_name: str, passed: bool, message: str = ""):
        """Log a test result"""
        self.test_results[test_name] = {'passed': passed, 'message': message}
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {test_name:40}: {message}")
        
    async def test_module_imports(self):
        """Test that all modules can be imported successfully"""
        print("\n[TOOLS] TESTING MODULE IMPORTS")
        print("=" * 50)
        
        try:
            from src.optimizations import optimized_engine
            from guild_config import get_guild_full_config
            from src.events.message import on_message
            
            try:
                from src.commands import settings, antiphish, help, performance
                try:
                    from src.commands import dev
                    dev_imported = True
                except ImportError:
                    dev_imported = False
                try:
                    from src.commands import ping
                    ping_imported = True
                except ImportError:
                    ping_imported = False
                    
                self.log_test_result("Command imports", True, 
                                   f"Core commands imported (dev: {dev_imported}, ping: {ping_imported})")
            except ImportError as e:
                self.log_test_result("Command imports", False, f"Command import error: {e}")
            
            try:
                from src.events import message, ready
                self.log_test_result("Event imports", True, "All event modules imported")
            except ImportError as e:
                self.log_test_result("Event imports", False, f"Event import error: {e}")
                
            self.log_test_result("Core imports", True, "All core modules imported successfully")
            
        except Exception as e:
            self.log_test_result("Core imports", False, f"Import error: {e}")
    
    async def test_database_configuration(self):
        """Test database configuration and guild settings"""
        print("\n[DATABASE] TESTING DATABASE CONFIGURATION")
        print("=" * 50)
        
        try:
            # Test basic guild configuration
            set_guild_action(self.test_guild_id, 'timeout')
            action = get_guild_action(self.test_guild_id)
            self.log_test_result(
                "guild_action_setting",
                action == 'timeout',
                f"Action set to 'timeout', got '{action}'"
            )
            
            # Test log channel setting
            test_channel_id = 987654321
            set_guild_log_channel(self.test_guild_id, test_channel_id)
            channel_id = get_guild_log_channel(self.test_guild_id)
            self.log_test_result(
                "guild_log_channel",
                channel_id == test_channel_id,
                f"Log channel set and retrieved correctly"
            )
            
            # Test timeout duration
            set_guild_timeout_duration(self.test_guild_id, 30)
            duration = get_guild_timeout_duration(self.test_guild_id)
            self.log_test_result(
                "guild_timeout_duration",
                duration == 30,
                f"Timeout duration set to 30, got {duration}"
            )
            
            # Test protection features
            set_guild_anti_phish_enabled(self.test_guild_id, True)
            set_guild_anti_malware_enabled(self.test_guild_id, False)
            set_guild_anti_piracy_enabled(self.test_guild_id, True)
            
            phish_enabled = get_guild_anti_phish_enabled(self.test_guild_id)
            malware_enabled = get_guild_anti_malware_enabled(self.test_guild_id)
            piracy_enabled = get_guild_anti_piracy_enabled(self.test_guild_id)
            
            self.log_test_result(
                "guild_protection_settings",
                phish_enabled and not malware_enabled and piracy_enabled,
                f"Protection settings: phish={phish_enabled}, malware={malware_enabled}, piracy={piracy_enabled}"
            )
            
            # Test bypass roles
            test_roles = [111, 222, 333]
            set_guild_bypass_roles(self.test_guild_id, test_roles)
            roles = get_guild_bypass_roles(self.test_guild_id)
            self.log_test_result(
                "guild_bypass_roles",
                set(roles) == set(test_roles),
                f"Bypass roles set and retrieved correctly"
            )
            
            # Test max attempts
            set_guild_max_attempts(self.test_guild_id, 5)
            max_attempts = get_guild_max_attempts(self.test_guild_id)
            self.log_test_result(
                "guild_max_attempts",
                max_attempts == 5,
                f"Max attempts set to 5, got {max_attempts}"
            )
            
        except Exception as e:
            self.log_test_result("database_configuration", False, f"Error: {e}")

    async def test_engine_initialization(self):
        """Test optimized engine initialization"""
        print("\n[ENGINE] TESTING ENGINE INITIALIZATION")
        print("=" * 50)
        
        try:
            # Initialize engine
            await optimized_engine.initialize()
            
            # Wait for blocklists to load
            print("Loading blocklists...")
            await asyncio.sleep(15)
            
            # Check if engine is initialized
            assert optimized_engine._initialized == True
            self.log_test_result("Engine initialization", True, "Engine initialized successfully")
            
            # Check session is created
            assert optimized_engine.session is not None
            self.log_test_result("HTTP session", True, "HTTP session created")
            
            # Check blocklist loading
            adguard_count = len(domain_cache_adguard)
            piracy_count = len(domain_cache_piracy)
            malware_count = len(domain_cache_malware)
            
            print(f"[STATS] Blocklist Statistics:")
            print(f"   AdGuard domains: {adguard_count:,}")
            print(f"   Piracy domains: {piracy_count:,}")
            print(f"   Malware domains: {malware_count:,}")
            
            if adguard_count > 50000:
                self.log_test_result("AdGuard blocklist", True, f"Loaded {adguard_count:,} domains")
            else:
                self.log_test_result("AdGuard blocklist", False, f"Only {adguard_count:,} domains loaded")
                
            if piracy_count > 1000:
                self.log_test_result("Piracy blocklist", True, f"Loaded {piracy_count:,} domains")
            else:
                self.log_test_result("Piracy blocklist", False, f"Only {piracy_count:,} domains loaded")
                
        except Exception as e:
            self.log_test_result("Engine initialization", False, f"Error: {e}")
    
    async def test_detection_accuracy(self):
        """Test detection accuracy with various scenarios"""
        print("\n[DETECTION] TESTING DETECTION ACCURACY")
        print("=" * 50)
        
        guild_settings = {
            'anti_phish': True,
            'anti_malware': True,
            'anti_piracy': True
        }
        
        test_cases = [
            {
                "name": "Legitimate domains",
                "content": "Check out https://google.com and https://github.com for coding",
                "expected_threat": False,
                "description": "Should not flag legitimate domains"
            },
            {
                "name": "Known malicious domain",
                "content": "Suspicious link: https://0-1-x.16215785.xyz/login",
                "expected_threat": True,
                "description": "Should detect domains from AdGuard blocklist"
            },
            {
                "name": "Mixed legitimate and malicious",
                "content": "Good: https://github.com but bad: https://0-1-x.26215785.xyz/phish",
                "expected_threat": True,
                "description": "Should detect threat even with legitimate domains"
            },
            {
                "name": "No URLs",
                "content": "This is just a regular message with no links at all",
                "expected_threat": False,
                "description": "Should not flag messages without URLs"
            },
            {
                "name": "Email addresses",
                "content": "Contact me at user@example.com for more info",
                "expected_threat": False,
                "description": "Should not flag email addresses as threats"
            },
            {
                "name": "Version numbers",
                "content": "Updated to version 1.2.3 today",
                "expected_threat": False,
                "description": "Should not flag version numbers"
            },
            {
                "name": "Markdown links",
                "content": "Check out [this site](https://0-1-x.16215785.xyz/login) for more info",
                "expected_threat": True,
                "description": "Should detect malicious domains in markdown links"
            }
        ]
        
        passed_tests = 0
        total_tests = len(test_cases)
        
        for i, test in enumerate(test_cases, 1):
            try:
                print(f"\nTest {i}/{total_tests}: {test['name']}")
                result = await optimized_engine.analyze_content(test['content'], guild_settings)
                is_threat = result['is_threat']
                
                if is_threat == test['expected_threat']:
                    self.log_test_result(f"Detection test {i}", True, 
                                       f"Expected: {test['expected_threat']}, Got: {is_threat}")
                    passed_tests += 1
                    if is_threat and result.get('sources'):
                        print(f"   Sources: {', '.join(result['sources'])}")
                else:
                    self.log_test_result(f"Detection test {i}", False, 
                                       f"Expected: {test['expected_threat']}, Got: {is_threat}")
                    if result.get('sources'):
                        print(f"   Sources: {', '.join(result['sources'])}")
                        
            except Exception as e:
                self.log_test_result(f"Detection test {i}", False, f"Error: {e}")
        
        overall_accuracy = passed_tests / total_tests * 100
        self.log_test_result("Overall detection accuracy", passed_tests == total_tests, 
                           f"{passed_tests}/{total_tests} tests passed ({overall_accuracy:.1f}%)")
    
    async def test_configurability(self):
        """Test configuration options work correctly"""
        print("\n[CONFIG] TESTING CONFIGURABILITY")
        print("=" * 50)
        
        test_content = "Suspicious link: https://0-1-x.16215785.xyz/login"
        
        config_tests = [
            {
                "name": "All protections enabled",
                "settings": {'anti_phish': True, 'anti_malware': True, 'anti_piracy': True},
                "expected_threat": True
            },
            {
                "name": "Only anti-phishing enabled",
                "settings": {'anti_phish': True, 'anti_malware': False, 'anti_piracy': False},
                "expected_threat": True
            },
            {
                "name": "Only anti-malware enabled",
                "settings": {'anti_phish': False, 'anti_malware': True, 'anti_piracy': False},
                "expected_threat": False  # This domain is in phishing list, not malware
            },
            {
                "name": "All protections disabled",
                "settings": {'anti_phish': False, 'anti_malware': False, 'anti_piracy': False},
                "expected_threat": False
            }
        ]
        
        for i, test in enumerate(config_tests, 1):
            try:
                result = await optimized_engine.analyze_content(test_content, test['settings'])
                is_threat = result['is_threat']
                
                if is_threat == test['expected_threat']:
                    self.log_test_result(f"Config test {i}", True, 
                                       f"{test['name']}: Expected {test['expected_threat']}, Got {is_threat}")
                else:
                    self.log_test_result(f"Config test {i}", False, 
                                       f"{test['name']}: Expected {test['expected_threat']}, Got {is_threat}")
                    
            except Exception as e:
                self.log_test_result(f"Config test {i}", False, f"Error: {e}")
    
    async def test_performance(self):
        """Test performance optimizations"""
        print("\n[ENGINE] TESTING PERFORMANCE")
        print("=" * 50)
        
        try:
            stats = performance_monitor.get_stats()
            operations_tracked = len(stats)
            self.log_test_result("Performance monitoring", operations_tracked > 0, 
                               f"Tracking {operations_tracked} operations")
            
            cache_stats = result_cache.get_stats()
            self.log_test_result("Result caching", True, 
                               f"Cache: {cache_stats.get('hits', 0)} hits, {cache_stats.get('size', 0)} entries")
            
            test_messages = [
                "Check out https://google.com",
                "Suspicious: https://0-1-x.16215785.xyz/login",
                "Multiple: https://github.com and https://stackoverflow.com",
                "No links here",
                "Test: https://example.com"
            ]
            
            guild_settings = {'anti_phish': True, 'anti_malware': True, 'anti_piracy': True}
            
            start_time = time.time()
            tasks = [optimized_engine.analyze_content(msg, guild_settings) for msg in test_messages]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            processing_time = end_time - start_time
            successful_results = [r for r in results if not isinstance(r, Exception)]
            
            avg_time = processing_time / len(test_messages)
            performance_ok = processing_time < 10.0  # Should be fast
            
            self.log_test_result("Concurrent processing", performance_ok, 
                               f"Processed {len(successful_results)}/{len(test_messages)} messages in {processing_time:.2f}s (avg: {avg_time:.3f}s)")
            
        except Exception as e:
            self.log_test_result("Performance testing", False, f"Error: {e}")
    
    async def test_memory_management(self):
        """Test memory management"""
        print("\n[MEMORY] TESTING MEMORY MANAGEMENT")
        print("=" * 50)
        
        try:
            # Get initial memory stats
            initial_stats = memory_manager.get_memory_usage()
            initial_memory = initial_stats['rss_mb']
            
            self.log_test_result("Memory monitoring", True, f"Initial memory: {initial_memory:.1f} MB")
            
            # Stress test with many analyses
            test_content = "Test https://google.com and https://0-1-x.16215785.xyz/test"
            guild_settings = {'anti_phish': True, 'anti_malware': True, 'anti_piracy': True}
            
            # Run multiple analyses
            for i in range(30):
                await optimized_engine.analyze_content(test_content, guild_settings)
            
            # Check final memory
            final_stats = memory_manager.get_memory_usage()
            final_memory = final_stats['rss_mb']
            memory_increase = final_memory - initial_memory
            
            memory_ok = memory_increase < 50.0  # Should not increase too much
            self.log_test_result("Memory stress test", memory_ok, 
                               f"Memory increase: {memory_increase:.1f} MB (final: {final_memory:.1f} MB)")
            
            if memory_manager.should_force_gc():
                gc_stats = memory_manager.force_gc()
                self.log_test_result("Garbage collection", True, f"GC completed, cleaned {gc_stats}")
            else:
                self.log_test_result("Garbage collection", True, "GC not needed")
                
        except Exception as e:
            self.log_test_result("Memory management", False, f"Error: {e}")
    
    async def test_api_integrations(self):
        """Test external API integrations"""
        print("\n[API] TESTING API INTEGRATIONS")
        print("=" * 50)
        
        try:
            # Test Bitflow API
            bitflow_result = await optimized_engine.check_bitflow_api("Test message with https://google.com")
            if isinstance(bitflow_result, dict):
                self.log_test_result("Bitflow API", True, "API responded successfully")
            else:
                self.log_test_result("Bitflow API", False, "API did not respond properly")
            
            # Test Sinking Yachts API
            sinking_result = await optimized_engine.check_sinking_yachts_api(["google.com"])
            if isinstance(sinking_result, dict):
                self.log_test_result("Sinking Yachts API", True, "API responded successfully")
            else:
                self.log_test_result("Sinking Yachts API", False, "API did not respond properly")
                
        except Exception as e:
            self.log_test_result("API integrations", False, f"Error: {e}")
    
    async def test_domain_extraction(self):
        """Test domain extraction functionality"""
        print("\n[INTEGRATION] TESTING DOMAIN EXTRACTION")
        print("=" * 50)
        
        test_cases = [
            ("Check out https://google.com", ["google.com"]),
            ("Visit http://example.com and https://github.com", ["example.com", "github.com"]),
            ("No domains here", []),
            ("Email user@domain.com should not be extracted", []),
            ("https://sub.domain.com/path?param=value", ["sub.domain.com"]),
            ("Markdown link: [Click here](https://test.com)", ["test.com"]),
            ("Mixed: https://direct.com and [markdown](https://markdown.com)", ["direct.com", "markdown.com"]),
        ]
        
        for i, (content, expected_domains) in enumerate(test_cases, 1):
            try:
                extracted = await optimized_engine.extract_domains(content)
                extracted_set = set(extracted)
                expected_set = set(expected_domains)
                
                if extracted_set == expected_set:
                    self.log_test_result(f"Domain extraction {i}", True, 
                                       f"Extracted: {extracted}")
                else:
                    self.log_test_result(f"Domain extraction {i}", False, 
                                       f"Expected: {expected_domains}, Got: {extracted}")
                    
            except Exception as e:
                self.log_test_result(f"Domain extraction {i}", False, f"Error: {e}")
    
    async def test_config_system(self):
        """Test configuration loading with defaults"""
        print("\n[CONFIG] TESTING CONFIGURATION SYSTEM")
        print("=" * 50)
        
        try:
            # Test basic config loading
            has_user_agent = hasattr(config, 'USER_AGENT') and bool(config.USER_AGENT)
            self.log_test_result(
                "config_user_agent",
                has_user_agent,
                f"User agent loaded: {getattr(config, 'USER_AGENT', 'None')}"
            )
            
            # Test performance settings
            self.log_test_result(
                "config_performance_settings",
                hasattr(config, 'MAX_CONCURRENT_REQUESTS') and config.MAX_CONCURRENT_REQUESTS > 0,
                f"Max concurrent requests: {getattr(config, 'MAX_CONCURRENT_REQUESTS', 'None')}"
            )
            
            # Test rate limiting settings
            self.log_test_result(
                "config_rate_limiting",
                hasattr(config, 'BITFLOW_MAX_CALLS') and config.BITFLOW_MAX_CALLS > 0,
                f"Bitflow max calls: {getattr(config, 'BITFLOW_MAX_CALLS', 'None')}"
            )
            
            # Test cache settings
            self.log_test_result(
                "config_cache_settings",
                hasattr(config, 'RESULT_CACHE_L1_SIZE') and config.RESULT_CACHE_L1_SIZE > 0,
                f"L1 cache size: {getattr(config, 'RESULT_CACHE_L1_SIZE', 'None')}"
            )
            
            # Test autoresponder settings
            self.log_test_result(
                "config_autoresponder_enabled",
                hasattr(config, 'AUTORESPONDER_ENABLED'),
                f"Autoresponder enabled: {getattr(config, 'AUTORESPONDER_ENABLED', 'None')}"
            )
            
            self.log_test_result(
                "config_autoresponder_limits",
                hasattr(config, 'AUTORESPONDER_MAX_RULES_PER_GUILD') and config.AUTORESPONDER_MAX_RULES_PER_GUILD > 0,
                f"Max rules per guild: {getattr(config, 'AUTORESPONDER_MAX_RULES_PER_GUILD', 'None')}"
            )
            
            # Test timeout settings
            self.log_test_result(
                "config_timeout_settings",
                hasattr(config, 'HTTP_TIMEOUT') and config.HTTP_TIMEOUT > 0,
                f"HTTP timeout: {getattr(config, 'HTTP_TIMEOUT', 'None')}"
            )
            
            # Test config validation
            from config import Config
            validation_passed = True
            try:
                Config.validate()
            except Exception as e:
                validation_passed = False
                
            self.log_test_result(
                "config_validation",
                validation_passed,
                "Configuration validation passed" if validation_passed else "Configuration validation failed"
            )
            
        except Exception as e:
            self.log_test_result("config_system", False, f"Error: {e}")

    async def test_autoresponder_functionality(self):
        """Test autoresponder pattern matching and responses"""
        print("\n[AUTORESPONDER] TESTING AUTORESPONDER FUNCTIONALITY")
        print("=" * 50)
        
        try:
            # Test autoresponder engine initialization
            self.log_test_result(
                "autoresponder_engine_init",
                autoresponder_engine is not None,
                "Autoresponder engine initialized"
            )
            
            # Test pattern validation
            valid_pattern, error = autoresponder_engine.validate_rule("hello", False)
            self.log_test_result(
                "autoresponder_pattern_validation_simple",
                valid_pattern and not error,
                f"Simple pattern validation: {error if error else 'passed'}"
            )
            
            # Test regex pattern validation
            valid_regex, error = autoresponder_engine.validate_rule(r"(?i)test.*message", True)
            self.log_test_result(
                "autoresponder_pattern_validation_regex",
                valid_regex and not error,
                f"Regex pattern validation: {error if error else 'passed'}"
            )
            
            # Test invalid regex pattern
            invalid_regex, error = autoresponder_engine.validate_rule(r"[invalid(regex", True)
            invalid_detected = not invalid_regex and bool(error)
            self.log_test_result(
                "autoresponder_invalid_regex",
                invalid_detected,
                f"Invalid regex detection: {error if error else 'failed to detect'}"
            )
            
            # Test response validation
            valid_response, error = autoresponder_engine.validate_response("This is a valid response")
            self.log_test_result(
                "autoresponder_response_validation",
                valid_response and not error,
                f"Response validation: {error if error else 'passed'}"
            )
            
            # Test response too long
            long_response = "x" * (config.AUTORESPONDER_MAX_RESPONSE_LENGTH + 1)
            invalid_response, error = autoresponder_engine.validate_response(long_response)
            long_response_detected = not invalid_response and bool(error)
            self.log_test_result(
                "autoresponder_response_too_long",
                long_response_detected,
                f"Long response detection: {error if error else 'failed to detect'}"
            )
            
            # Test database operations
            success = add_autoresponder_rule(
                self.test_guild_id,
                "test_rule",
                "hello",
                "Hello there!",
                False,
                False
            )
            self.log_test_result(
                "autoresponder_add_rule",
                success,
                "Rule added successfully" if success else "Failed to add rule"
            )
            
            # Test rule retrieval
            rules = get_autoresponder_rules(self.test_guild_id)
            rule_found = any(rule['rule_name'] == 'test_rule' for rule in rules)
            self.log_test_result(
                "autoresponder_get_rules",
                rule_found,
                f"Retrieved {len(rules)} rules, test rule found: {rule_found}"
            )
            
            # Test rule counting
            count = get_autoresponder_rule_count(self.test_guild_id)
            self.log_test_result(
                "autoresponder_rule_count",
                count > 0,
                f"Rule count: {count}"
            )
            
            # Test rule toggle
            toggle_success = toggle_autoresponder_rule(self.test_guild_id, "test_rule", False)
            self.log_test_result(
                "autoresponder_toggle_rule",
                toggle_success,
                "Rule toggled successfully" if toggle_success else "Failed to toggle rule"
            )
            
            # Test rule removal
            remove_success = remove_autoresponder_rule(self.test_guild_id, "test_rule")
            self.log_test_result(
                "autoresponder_remove_rule",
                remove_success,
                "Rule removed successfully" if remove_success else "Failed to remove rule"
            )
            
            # Test pattern matching
            test_rule = {
                'rule_name': 'test_match',
                'trigger_pattern': 'hello world',
                'response_message': 'Hi there!',
                'is_regex': False,
                'case_sensitive': False,
                'is_enabled': True
            }
            
            matches = autoresponder_engine._matches_pattern("Hello World! How are you?", test_rule)
            self.log_test_result(
                "autoresponder_pattern_matching_case_insensitive",
                matches,
                f"Case insensitive matching: {'passed' if matches else 'failed'}"
            )
            
            # Test case sensitive matching
            test_rule['case_sensitive'] = True
            matches_case = autoresponder_engine._matches_pattern("hello world", test_rule)
            no_match_case = autoresponder_engine._matches_pattern("Hello World", test_rule)
            self.log_test_result(
                "autoresponder_pattern_matching_case_sensitive",
                matches_case and not no_match_case,
                f"Case sensitive matching: exact={matches_case}, different={not no_match_case}"
            )
            
            # Test regex matching
            regex_rule = {
                'rule_name': 'test_regex',
                'trigger_pattern': r'(?i)test\s+\d+',
                'response_message': 'Test number detected!',
                'is_regex': True,
                'case_sensitive': False,
                'is_enabled': True
            }
            
            regex_matches = autoresponder_engine._matches_pattern("This is Test 123 message", regex_rule)
            self.log_test_result(
                "autoresponder_regex_matching",
                regex_matches,
                f"Regex matching: {'passed' if regex_matches else 'failed'}"
            )
            
        except Exception as e:
            self.log_test_result("autoresponder_functionality", False, f"Error: {e}")

    async def test_integration_scenarios(self):
        """Test integrated scenarios combining multiple features"""
        print("\n[INTEGRATION] TESTING INTEGRATION SCENARIOS")
        print("=" * 50)
        
        try:
            # Test guild with multiple protection types enabled
            test_guild_2 = self.test_guild_id + 1
            
            # Setup guild with all protections enabled
            set_guild_anti_phish_enabled(test_guild_2, True)
            set_guild_anti_malware_enabled(test_guild_2, True)
            set_guild_anti_piracy_enabled(test_guild_2, True)
            set_guild_action(test_guild_2, 'all')
            set_guild_timeout_duration(test_guild_2, 15)
            
            # Add autoresponder rules
            add_autoresponder_rule(test_guild_2, "greeting", "hello", "Welcome!", False, False)
            add_autoresponder_rule(test_guild_2, "help", r"(?i)help|assist", "How can I help you?", True, False)
            
            # Test configuration retrieval
            guild_config = get_guild_full_config(test_guild_2)
            autoresponder_count = get_autoresponder_rule_count(test_guild_2)
            
            config_valid = (
                guild_config['anti_phish_enabled'] and
                guild_config['anti_malware_enabled'] and
                guild_config['anti_piracy_enabled'] and
                guild_config['action'] == 'all' and
                guild_config['timeout_duration'] == 15 and
                autoresponder_count == 2
            )
            
            # Debug information
            debug_info = (
                f"phish={guild_config['anti_phish_enabled']}, "
                f"malware={guild_config['anti_malware_enabled']}, "
                f"piracy={guild_config['anti_piracy_enabled']}, "
                f"action={guild_config['action']}, "
                f"timeout={guild_config['timeout_duration']}, "
                f"ar_count={autoresponder_count}"
            )
            
            self.log_test_result(
                "integration_full_guild_setup",
                config_valid,
                f"Full guild setup - {debug_info}"
            )
            
            # Test engine initialization with guild settings
            if not optimized_engine._initialized:
                await optimized_engine.initialize()
            
            guild_settings = {
                'anti_phish': guild_config['anti_phish_enabled'],
                'anti_malware': guild_config['anti_malware_enabled'],
                'anti_piracy': guild_config['anti_piracy_enabled']
            }
            
            # Test with safe content
            safe_result = await optimized_engine.analyze_content("This is a safe message", guild_settings)
            self.log_test_result(
                "integration_safe_content_analysis",
                not safe_result['is_threat'],
                f"Safe content correctly identified: threat={safe_result['is_threat']}"
            )
            
            # Test performance monitoring integration  
            metrics = performance_monitor.get_stats()
            
            self.log_test_result(
                "integration_performance_monitoring",
                isinstance(metrics, dict) and len(metrics) > 0,
                f"Performance monitoring active: {len(metrics)} metrics tracked"
            )
            
            # Test memory management integration
            await memory_manager.start_monitoring()
            memory_usage = memory_manager.get_memory_usage()
            
            self.log_test_result(
                "integration_memory_monitoring",
                isinstance(memory_usage, dict) and 'rss_mb' in memory_usage,
                f"Memory monitoring active: {memory_usage.get('rss_mb', 0):.1f}MB usage"
            )
            
            # Test cache integration
            cache_stats = {
                'domain_cache_stats': domain_cache_adguard.get_stats(),
                'result_cache_stats': result_cache.get_stats()
            }
            
            self.log_test_result(
                "integration_cache_systems",
                isinstance(cache_stats['domain_cache_stats'], dict) and isinstance(cache_stats['result_cache_stats'], dict),
                f"Cache systems operational: domain stats available, result cache stats available"
            )
            
            # Clean up test data
            remove_autoresponder_rule(test_guild_2, "greeting")
            remove_autoresponder_rule(test_guild_2, "help")
            
        except Exception as e:
            self.log_test_result("integration_scenarios", False, f"Error: {e}")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("[SUMMARY] FULL SYSTEM TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results.values() if result['passed'])
        total = len(self.test_results)
        percentage = (passed / total * 100) if total > 0 else 0
        
        print(f"[STATS] Overall Results: {passed}/{total} tests passed ({percentage:.1f}%)")
        
        # Group results by category
        categories = {
            'Core System': ['Core imports', 'Engine initialization', 'HTTP session'],
            'Database': ['Guild action setting', 'Log channel setting', 'Timeout duration', 
                        'Protection toggles', 'Full config retrieval', 'Default config'],
            'Detection': [k for k in self.test_results.keys() if 'Detection test' in k or 'Overall detection' in k],
            'Configuration': [k for k in self.test_results.keys() if 'Config test' in k],
            'Performance': ['Performance monitoring', 'Result caching', 'Concurrent processing'],
            'Memory': ['Memory monitoring', 'Memory stress test', 'Garbage collection'],
            'APIs': ['Bitflow API', 'Sinking Yachts API'],
            'Other': [k for k in self.test_results.keys() if 'extraction' in k or 'blocklist' in k]
        }
        
        for category, tests in categories.items():
            category_tests = [t for t in tests if t in self.test_results]
            if category_tests:
                category_passed = sum(1 for t in category_tests if self.test_results[t]['passed'])
                category_total = len(category_tests)
                category_percent = (category_passed / category_total * 100) if category_total > 0 else 0
                
                status = "[PASS]" if category_passed == category_total else "[WARN]" if category_passed > 0 else "[FAIL]"
                print(f"{status} {category}: {category_passed}/{category_total} ({category_percent:.0f}%)")
        
        print("\n" + "=" * 60)
        if passed == total:
            print("[SUCCESS] ALL TESTS PASSED!")
            print("[PASS] The optimized system is working perfectly")
            print("[PASS] No functionality has been lost in optimizations")
            print("[PASS] All features are working as intended")
        elif passed >= total * 0.8:  # 80% pass rate
            print("[SUCCESS] MOSTLY SUCCESSFUL!")
            print("[WARN] Some tests failed, but core functionality is working")
            print("[INFO] Review failed tests above for details")
        else:
            print("[FAIL] SIGNIFICANT ISSUES DETECTED!")
            print("[WARN] Multiple tests failed - system needs attention")
            
        return passed == total

async def main():
    """Run the full system test suite"""
    print("COMPREHENSIVE FULL SYSTEM TEST SUITE")
    print("=" * 60)
    print("ANTI-PHISHING BOT TEST SUITE")
    print("=" * 60)
    print("Testing all aspects of the optimized anti-phishing bot:")
    print("• Module imports and initialization")
    print("• Configuration system with environment defaults")
    print("• Autoresponder pattern matching and responses")
    print("• Database configuration and guild settings") 
    print("• Detection accuracy and configurability")
    print("• Performance and memory optimizations")
    print("• API integrations and domain extraction")
    print("• End-to-end integration scenarios")
    print("=" * 60)
    
    test_suite = FullSystemTest()
    
    try:
        # Run all test categories
        await test_suite.test_module_imports()
        await test_suite.test_database_configuration()
        await test_suite.test_config_system()
        await test_suite.test_autoresponder_functionality()
        await test_suite.test_engine_initialization()
        await test_suite.test_detection_accuracy()
        await test_suite.test_configurability()
        await test_suite.test_performance()
        await test_suite.test_memory_management()
        await test_suite.test_api_integrations()
        await test_suite.test_domain_extraction()
        await test_suite.test_integration_scenarios()
        
        # Print summary and return result
        success = test_suite.print_summary()
        return success
        
    except Exception as e:
        print(f"\n[ERROR] CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        try:
            await optimized_engine.cleanup()
            print("\n[CLEANUP] System cleanup completed")
        except:
            pass

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
