# Docker Setup for Phishing Detection Bot

This guide explains how to run the Discord Anti-Phishing Bot using Docker.

## Prerequisites

- Docker and Docker Compose installed
- A Discord bot token
- Git (for updates)

## Quick Start

### 1. Environment Setup

Create a `.env` file in the project root:

```bash
# Discord Bot Token (required)
BOT_TOKEN=your_discord_bot_token_here

# Developer User ID (optional - for dev commands)
DEV=your_discord_user_id_here
```

### 2. Build and Run

#### Option A: Using Helper Scripts

**Linux/macOS:**
```bash
# Make script executable
chmod +x docker-helper.sh

# Build and run
./docker-helper.sh build
./docker-helper.sh run
```

**Windows:**
```powershell
# Build and run
.\docker-helper.ps1 build
.\docker-helper.ps1 run
```

#### Option B: Using Docker Compose Directly

```bash
# Build the image
docker-compose build

# Run in production mode
docker-compose up -d

# View logs
docker-compose logs -f
```

## Available Commands

### Helper Script Commands

| Command | Description |
|---------|-------------|
| `build` | Build the Docker image |
| `run` | Run bot in production mode |
| `dev` | Run bot in development mode with live reloading |
| `stop` | Stop the bot container |
| `restart` | Restart the bot container |
| `logs` | Show live logs |
| `logs-tail` | Show last 100 log lines |
| `clean` | Remove containers and images |
| `shell` | Open shell in container |
| `health` | Check bot health |
| `update` | Pull code and rebuild |

### Docker Compose Files

- `docker-compose.yml` - Production configuration
- `docker-compose.dev.yml` - Development configuration with live reloading

## Production Deployment

### 1. Environment Variables

Set these in your `.env` file:

```bash
BOT_TOKEN=your_actual_bot_token
DEV=your_discord_user_id_for_dev_commands
```

### 2. Run in Production

```bash
docker-compose up -d
```

### 3. Monitor Logs

```bash
docker-compose logs -f
```

### 4. Health Monitoring

The container includes health checks that run every 60 seconds. Check status:

```bash
docker-compose ps
```

## Development Setup

For development with live code reloading:

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up
```

This mounts your source code into the container for real-time changes.

## Persistent Data

The following data is persisted using Docker volumes:

- **Database**: `guild_config.db` - Guild configurations and autoresponder rules
- **Cache**: Blocklist cache for improved performance
- **Logs**: Application logs

## Resource Limits

Production container limits:
- **Memory**: 512MB limit, 256MB reserved
- **CPU**: No specific limits (adjust as needed)

## Troubleshooting

### Common Issues

1. **Bot won't start**:
   ```bash
   # Check logs
   docker-compose logs discord-bot
   
   # Verify environment
   docker-compose config
   ```

2. **Permission issues**:
   ```bash
   # Rebuild with no cache
   docker-compose build --no-cache
   ```

3. **Database issues**:
   ```bash
   # Check if database file exists and has correct permissions
   ls -la guild_config.db
   ```

### Health Checks

The container includes built-in health checks:

```bash
# Check container health
docker-compose ps

# Manual health check
docker-compose exec discord-bot python -c "
import sys
sys.path.insert(0, '/app')
sys.path.insert(0, '/app/src')
from src.core.config import config
print('Health check passed!')
"
```

## Updates

To update the bot:

```bash
# Using helper script
./docker-helper.sh update

# Or manually
git pull
docker-compose build --no-cache
docker-compose up -d
```

## Logs and Monitoring

### View Logs

```bash
# Follow logs in real-time
docker-compose logs -f

# View last 100 lines
docker-compose logs --tail=100

# View logs for specific time
docker-compose logs --since="1h"
```

### Log Rotation

Logs are automatically rotated:
- Maximum size: 10MB per file
- Maximum files: 5 files kept
- Format: JSON for structured logging

## Security Considerations

1. **Environment Variables**: Keep `.env` file secure and never commit it
2. **Network**: Bot runs on isolated Docker network
3. **Volumes**: Database and logs are properly isolated
4. **Updates**: Regularly update the bot and dependencies

## Performance Optimization

- **Multi-stage builds**: Optimized Docker image size
- **Volume caching**: Persistent cache for blocklists
- **Memory limits**: Prevents resource exhaustion
- **Health checks**: Automatic restart on failures

## Backup and Recovery

### Backup Important Data

```bash
# Backup database
cp guild_config.db guild_config.db.backup

# Backup using Docker
docker-compose exec discord-bot cp /app/guild_config.db /app/data/backup-$(date +%Y%m%d).db
```

### Restore from Backup

```bash
# Stop bot
docker-compose down

# Restore database
cp guild_config.db.backup guild_config.db

# Start bot
docker-compose up -d
```

---

For more information, see the main project README or open an issue on GitHub.
