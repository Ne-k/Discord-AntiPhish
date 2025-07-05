#!/bin/bash

# Docker helper script for Phishing Detection Bot

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if .env file exists
check_env_file() {
    if [ ! -f .env ]; then
        print_error ".env file not found!"
        print_status "Creating .env template..."
        cat > .env << EOF
# Discord Bot Token (required)
BOT_TOKEN=your_bot_token_here

# Developer User ID (optional)
DEV=your_discord_user_id_here
EOF
        print_warning "Please edit .env file and add your BOT_TOKEN before running the bot!"
        exit 1
    fi
}

# Help function
show_help() {
    cat << EOF
Docker Helper Script for Phishing Detection Bot

Usage: $0 [COMMAND]

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
    $0 build          # Build the Docker image
    $0 run            # Start the bot in production
    $0 dev            # Start bot in development mode
    $0 logs           # Follow logs in real-time
    $0 clean          # Clean up Docker resources

EOF
}

# Build the Docker image
build_image() {
    print_status "Building Docker image..."
    docker-compose build
    print_success "Docker image built successfully!"
}

# Run in production mode
run_production() {
    check_env_file
    print_status "Starting bot in production mode..."
    docker-compose up -d
    print_success "Bot started in production mode!"
    print_status "Use '$0 logs' to view logs"
}

# Run in development mode
run_development() {
    check_env_file
    print_status "Starting bot in development mode..."
    docker-compose -f docker-compose.dev.yml up
}

# Stop containers
stop_containers() {
    print_status "Stopping bot containers..."
    docker-compose down
    docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
    print_success "Bot containers stopped!"
}

# Restart containers
restart_containers() {
    print_status "Restarting bot..."
    docker-compose restart
    print_success "Bot restarted!"
}

# Show logs
show_logs() {
    docker-compose logs -f
}

# Show tail logs
show_logs_tail() {
    docker-compose logs --tail=100
}

# Clean up
clean_up() {
    print_warning "This will remove all bot containers and images!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Cleaning up..."
        docker-compose down --rmi all --volumes
        docker-compose -f docker-compose.dev.yml down --rmi all --volumes 2>/dev/null || true
        print_success "Cleanup completed!"
    else
        print_status "Cleanup cancelled."
    fi
}

# Open shell
open_shell() {
    print_status "Opening shell in bot container..."
    docker-compose exec discord-bot /bin/bash || {
        print_warning "Container not running, starting temporary container..."
        docker-compose run --rm discord-bot /bin/bash
    }
}

# Check health
check_health() {
    print_status "Checking bot health..."
    if docker-compose ps | grep -q "Up"; then
        docker-compose exec discord-bot python -c "
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
"
    else
        print_error "Bot container is not running!"
        exit 1
    fi
}

# Update and rebuild
update_rebuild() {
    print_status "Pulling latest changes..."
    git pull
    print_status "Rebuilding Docker image..."
    docker-compose build --no-cache
    print_status "Restarting bot..."
    docker-compose up -d
    print_success "Update completed!"
}

# Main script logic
case "$1" in
    build)
        build_image
        ;;
    run)
        run_production
        ;;
    dev)
        run_development
        ;;
    stop)
        stop_containers
        ;;
    restart)
        restart_containers
        ;;
    logs)
        show_logs
        ;;
    logs-tail)
        show_logs_tail
        ;;
    clean)
        clean_up
        ;;
    shell)
        open_shell
        ;;
    health)
        check_health
        ;;
    update)
        update_rebuild
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        if [ -z "$1" ]; then
            show_help
        else
            print_error "Unknown command: $1"
            echo
            show_help
            exit 1
        fi
        ;;
esac
