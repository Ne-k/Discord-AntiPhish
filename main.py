#!/usr/bin/env python3
"""
Main entry point for the Discord Anti-Phishing Bot
Launches the bot from the reorganized src structure
"""
import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import and run the main bot
from src.core.main import main

if __name__ == "__main__":
    asyncio.run(main())
