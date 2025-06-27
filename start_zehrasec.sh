#!/bin/bash
# ZehraShield Startup Script (Linux/macOS)
# Copyright (c) 2025 ZehraSec - Yashab Alam

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEHRASHIELD_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ZEHRASHIELD_DIR/zehrashield.pid"
LOG_FILE="$ZEHRASHIELD_DIR/logs/startup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    echo_info "Checking system requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo_warning "Not running as root. Some features may not work properly."
        echo_warning "Consider running with: sudo $0"
    fi
    
    # Check if config exists
    if [[ ! -f "$ZEHRASHIELD_DIR/config/firewall.json" ]]; then
        echo_warning "Configuration file not found. Using defaults."
    fi
    
    echo_success "Requirements check completed"
}

start_zehrashield() {
    echo_info "Starting ZehraShield Advanced Firewall..."
    
    # Create logs directory
    mkdir -p "$ZEHRASHIELD_DIR/logs"
    
    # Check if already running
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo_warning "ZehraShield is already running (PID: $PID)"
            exit 0
        else
            echo_warning "Stale PID file found, removing..."
            rm -f "$PID_FILE"
        fi
    fi
    
    # Navigate to ZehraShield directory
    cd "$ZEHRASHIELD_DIR"
    
    # Activate virtual environment if it exists
    if [[ -f "venv/bin/activate" ]]; then
        echo_info "Activating virtual environment..."
        source venv/bin/activate
    fi
    
    # Start ZehraShield
    echo_info "Launching ZehraShield firewall engine..."
    nohup python3 main.py --daemon > "$LOG_FILE" 2>&1 &
    
    # Save PID
    echo $! > "$PID_FILE"
    
    # Wait a moment and check if it started successfully
    sleep 3
    if ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
        echo_success "ZehraShield started successfully!"
        echo_info "PID: $(cat "$PID_FILE")"
        echo_info "Log file: $LOG_FILE"
        echo_info "Web console: https://localhost:8443"
        echo_info "Default credentials: admin / zehrasec123"
    else
        echo_error "Failed to start ZehraShield"
        echo_error "Check log file: $LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
}

stop_zehrashield() {
    echo_info "Stopping ZehraShield..."
    
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            kill "$PID"
            echo_success "ZehraShield stopped (PID: $PID)"
            rm -f "$PID_FILE"
        else
            echo_warning "ZehraShield process not found"
            rm -f "$PID_FILE"
        fi
    else
        echo_warning "ZehraShield is not running"
    fi
}

status_zehrashield() {
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo_success "ZehraShield is running (PID: $PID)"
            echo_info "Web console: https://localhost:8443"
        else
            echo_warning "ZehraShield is not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        echo_info "ZehraShield is not running"
    fi
}

restart_zehrashield() {
    echo_info "Restarting ZehraShield..."
    stop_zehrashield
    sleep 2
    start_zehrashield
}

show_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        echo_info "Showing ZehraShield logs (last 50 lines):"
        tail -n 50 "$LOG_FILE"
    else
        echo_warning "Log file not found: $LOG_FILE"
    fi
}

show_help() {
    echo "ZehraShield Advanced Firewall Control Script"
    echo "Copyright (c) 2025 ZehraSec - Yashab Alam"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start ZehraShield firewall"
    echo "  stop      Stop ZehraShield firewall"
    echo "  restart   Restart ZehraShield firewall"
    echo "  status    Show ZehraShield status"
    echo "  logs      Show recent log entries"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start          # Start the firewall"
    echo "  $0 status         # Check if running"
    echo "  $0 logs           # View logs"
    echo ""
    echo "Web Console: https://localhost:8443"
    echo "Default Credentials: admin / zehrasec123"
}

# Main script logic
case "${1:-start}" in
    start)
        check_requirements
        start_zehrashield
        ;;
    stop)
        stop_zehrashield
        ;;
    restart)
        restart_zehrashield
        ;;
    status)
        status_zehrashield
        ;;
    logs)
        show_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
