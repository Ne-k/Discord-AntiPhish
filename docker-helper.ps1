# Docker helper script for Phishing Detection Bot (PowerShell version)

param(
    [Parameter(Position=0)]
    [string]$Command
)

# Function to print colored output
function Write-Status { 
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue 
}

function Write-Success { 
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green 
}

function Write-Warning { 
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow 
}

function Write-Error { 
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red 
}

# Check if .env file exists
function Test-EnvFile {
    if (-not (Test-Path ".env")) {
        Write-Error ".env file not found!"
        Write-Status "Creating .env template..."
        @"
# Discord Bot Token (required)
BOT_TOKEN=your_bot_token_here

# Developer User ID (optional)
DEV=your_discord_user_id_here
"@ | Out-File -FilePath ".env" -Encoding UTF8
        Write-Warning "Please edit .env file and add your BOT_TOKEN before running the bot!"
        exit 1
    }
}

# Help function
function Show-Help {
    @"
Docker Helper Script for Phishing Detection Bot

Usage: .\docker-helper.ps1 [COMMAND]

Commands:
    build       Build the Docker image
    run         Run the bot in production mode
    dev         Run the bot in development mode with live reloading
    stop        Stop the running bot container
    restart     Restart the bot container
    logs        Show bot logs (follow mode)
    logs-tail   Show last 100 lines of logs
    clean       Remove bot containers and images
    shell       Open a shell in the bot container
    health      Check bot health status
    update      Pull latest code and rebuild

Examples:
    .\docker-helper.ps1 build          # Build the Docker image
    .\docker-helper.ps1 run            # Start the bot in production
    .\docker-helper.ps1 dev            # Start bot in development mode
    .\docker-helper.ps1 logs           # Follow logs in real-time
    .\docker-helper.ps1 clean          # Clean up Docker resources

"@
}

# Build the Docker image
function Build-Image {
    Write-Status "Building Docker image..."
    docker-compose build
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker image built successfully!"
    } else {
        Write-Error "Failed to build Docker image!"
        exit 1
    }
}

# Run in production mode
function Start-Production {
    Test-EnvFile
    Write-Status "Starting bot in production mode..."
    docker-compose up -d
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Bot started in production mode!"
        Write-Status "Use '.\docker-helper.ps1 logs' to view logs"
    } else {
        Write-Error "Failed to start bot!"
        exit 1
    }
}

# Run in development mode
function Start-Development {
    Test-EnvFile
    Write-Status "Starting bot in development mode..."
    docker-compose -f docker-compose.dev.yml up
}

# Stop containers
function Stop-Containers {
    Write-Status "Stopping bot containers..."
    docker-compose down
    docker-compose -f docker-compose.dev.yml down 2>$null
    Write-Success "Bot containers stopped!"
}

# Restart containers
function Restart-Containers {
    Write-Status "Restarting bot..."
    docker-compose restart
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Bot restarted!"
    } else {
        Write-Error "Failed to restart bot!"
        exit 1
    }
}

# Show logs
function Show-Logs {
    docker-compose logs -f
}

# Show tail logs
function Show-LogsTail {
    docker-compose logs --tail=100
}

# Clean up
function Remove-Resources {
    Write-Warning "This will remove all bot containers and images!"
    $confirmation = Read-Host "Are you sure? (y/N)"
    if ($confirmation -eq "y" -or $confirmation -eq "Y") {
        Write-Status "Cleaning up..."
        docker-compose down --rmi all --volumes
        docker-compose -f docker-compose.dev.yml down --rmi all --volumes 2>$null
        Write-Success "Cleanup completed!"
    } else {
        Write-Status "Cleanup cancelled."
    }
}

# Open shell
function Open-Shell {
    Write-Status "Opening shell in bot container..."
    $result = docker-compose exec discord-bot /bin/bash
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Container not running, starting temporary container..."
        docker-compose run --rm discord-bot /bin/bash
    }
}

# Check health
function Test-Health {
    Write-Status "Checking bot health..."
    $containerStatus = docker-compose ps | Select-String "Up"
    if ($containerStatus) {
        $healthCheck = @"
import sys
sys.path.insert(0, '/app')
sys.path.insert(0, '/app/src')
try:
    import discord
    from src.core.config import config
    print('✅ Bot health check passed!')
except Exception as e:
    print(f'❌ Health check failed: {e}')
    sys.exit(1)
"@
        docker-compose exec discord-bot python -c $healthCheck
    } else {
        Write-Error "Bot container is not running!"
        exit 1
    }
}

# Update and rebuild
function Update-Rebuild {
    Write-Status "Pulling latest changes..."
    git pull
    Write-Status "Rebuilding Docker image..."
    docker-compose build --no-cache
    Write-Status "Restarting bot..."
    docker-compose up -d
    Write-Success "Update completed!"
}

# Main script logic
switch ($Command) {
    "build" { Build-Image }
    "run" { Start-Production }
    "dev" { Start-Development }
    "stop" { Stop-Containers }
    "restart" { Restart-Containers }
    "logs" { Show-Logs }
    "logs-tail" { Show-LogsTail }
    "clean" { Remove-Resources }
    "shell" { Open-Shell }
    "health" { Test-Health }
    "update" { Update-Rebuild }
    { $_ -in "help", "--help", "-h" } { Show-Help }
    default {
        if ([string]::IsNullOrEmpty($Command)) {
            Show-Help
        } else {
            Write-Error "Unknown command: $Command"
            ""
            Show-Help
            exit 1
        }
    }
}
