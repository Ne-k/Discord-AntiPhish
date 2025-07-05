"""
Configuration management for the Discord Anti-Phishing Bot
Loads settings from environment variables with sensible defaults
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration class that loads settings from environment variables"""

    # Bot Configuration
    BOT_TOKEN: str = os.getenv("BOT_TOKEN", "")
    DEV_USER_ID: int = int(os.getenv("DEV", "178277628522921984"))

    # User Agent (single consolidated user agent)
    USER_AGENT: str = os.getenv("USER_AGENT", "Discord Nek_ng Anti-Phish Bot")

    # Performance Settings
    MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    CACHE_SIZE: int = int(os.getenv("CACHE_SIZE", "1000"))
    BLOCKLIST_UPDATE_INTERVAL: int = int(os.getenv("BLOCKLIST_UPDATE_INTERVAL", "21600"))  # 6 hours
    WHITELIST_UPDATE_INTERVAL: int = int(os.getenv("WHITELIST_UPDATE_INTERVAL", "86400"))  # 24 hours

    # Rate Limiting Configuration
    BITFLOW_MAX_CALLS: int = int(os.getenv("BITFLOW_MAX_CALLS", "100"))
    BITFLOW_TIME_WINDOW: int = int(os.getenv("BITFLOW_TIME_WINDOW", "60"))
    BITFLOW_BURST_LIMIT: int = int(os.getenv("BITFLOW_BURST_LIMIT", "150"))
    SINKING_MAX_CALLS: int = int(os.getenv("SINKING_MAX_CALLS", "50"))
    SINKING_TIME_WINDOW: int = int(os.getenv("SINKING_TIME_WINDOW", "60"))
    SINKING_BURST_LIMIT: int = int(os.getenv("SINKING_BURST_LIMIT", "75"))

    # Cache Configuration
    RESULT_CACHE_L1_SIZE: int = int(os.getenv("RESULT_CACHE_L1_SIZE", "1000"))
    RESULT_CACHE_L2_SIZE: int = int(os.getenv("RESULT_CACHE_L2_SIZE", "5000"))
    RESULT_CACHE_L1_TTL: int = int(os.getenv("RESULT_CACHE_L1_TTL", "300"))  # 5 minutes
    RESULT_CACHE_L2_TTL: int = int(os.getenv("RESULT_CACHE_L2_TTL", "3600"))  # 1 hour
    DOMAIN_CACHE_SIZE: int = int(os.getenv("DOMAIN_CACHE_SIZE", "50000"))
    DOMAIN_CACHE_TTL: int = int(os.getenv("DOMAIN_CACHE_TTL", "3600"))  # 1 hour

    # Memory Management
    MEMORY_CLEANUP_INTERVAL: int = int(os.getenv("MEMORY_CLEANUP_INTERVAL", "300"))  # 5 minutes
    PERFORMANCE_MONITOR_INTERVAL: int = int(os.getenv("PERFORMANCE_MONITOR_INTERVAL", "300"))  # 5 minutes

    # API Timeouts
    HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "30"))
    BITFLOW_TIMEOUT: int = int(os.getenv("BITFLOW_TIMEOUT", "10"))
    SINKING_TIMEOUT: int = int(os.getenv("SINKING_TIMEOUT", "10"))

    # Database Configuration
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite:///guild_config.db')

    # Autoresponder Configuration
    AUTORESPONDER_ENABLED: bool = os.getenv("AUTORESPONDER_ENABLED", "true").lower() == "true"
    AUTORESPONDER_MAX_RULES_PER_GUILD: int = int(os.getenv("AUTORESPONDER_MAX_RULES_PER_GUILD", "20"))
    AUTORESPONDER_MAX_RESPONSE_LENGTH: int = int(os.getenv("AUTORESPONDER_MAX_RESPONSE_LENGTH", "2000"))
    AUTORESPONDER_COOLDOWN: int = int(os.getenv("AUTORESPONDER_COOLDOWN", "5"))  # seconds

    @classmethod
    def validate(cls) -> bool:
        """Validate that required configuration is present"""
        if not cls.BOT_TOKEN:
            raise ValueError("BOT_TOKEN is required in .env file")
        return True

    @classmethod
    def get_summary(cls) -> dict:
        """Get a summary of current configuration (excluding sensitive data)"""
        return {
            "user_agent": cls.USER_AGENT,
            "max_concurrent_requests": cls.MAX_CONCURRENT_REQUESTS,
            "cache_size": cls.CACHE_SIZE,
            "blocklist_update_interval": cls.BLOCKLIST_UPDATE_INTERVAL,
            "whitelist_update_interval": cls.WHITELIST_UPDATE_INTERVAL,
            "bitflow_rate_limit": f"{cls.BITFLOW_MAX_CALLS}/{cls.BITFLOW_TIME_WINDOW}s",
            "sinking_rate_limit": f"{cls.SINKING_MAX_CALLS}/{cls.SINKING_TIME_WINDOW}s",
            "result_cache_l1_size": cls.RESULT_CACHE_L1_SIZE,
            "result_cache_l2_size": cls.RESULT_CACHE_L2_SIZE,
            "domain_cache_size": cls.DOMAIN_CACHE_SIZE,
            "http_timeout": cls.HTTP_TIMEOUT
        }


# Create a global config instance
config = Config()


# Legacy compatibility functions
def get_user_agent(service: str = 'default') -> str:
    """Get user agent string (consolidated to single user agent)"""
    return config.USER_AGENT


def get_api_headers(service: str = 'default', content_type: str = 'application/json') -> dict:
    """Get headers for API requests including user agent"""
    return {
        'User-Agent': config.USER_AGENT,
        'Content-Type': content_type,
    }


# Validate configuration on import
try:
    config.validate()
except ValueError as e:
    print(f"Configuration error: {e}")
    print("Please check your .env file")
