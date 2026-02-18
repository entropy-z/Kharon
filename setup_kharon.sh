#!/bin/bash

# Color codes for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function error_exit {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

function info_msg {
    echo -e "${GREEN}[+]${NC} $1"
}

function warning_msg {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Default values
PULL_CHANGES=false
ADAPTIX_DIR=""
AGENT="agent_kharon"
LISTENER="listener_kharon_http"
ACTION="all"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pull)
            PULL_CHANGES=true
            shift
            ;;
        --ax)
            ADAPTIX_DIR="$(realpath "$2" 2>/dev/null || echo "$2")"
            shift 2
            ;;
        --action)
            ACTION="$2"
            shift 2
            ;;
        *)
            error_exit "Unknown parameter: $1"
            ;;
    esac
done

# Validate required parameters
if [ -z "$ADAPTIX_DIR" ]; then
    echo "Usage: $0 --ax <AdaptixC2_directory> [--action <action>] [--pull]"
    echo ""
    echo "Required:"
    echo "  --ax <dir>          Path to AdaptixC2 directory"
    echo ""
    echo "Optional:"
    echo "  --action <action>   Action to perform (default: all)"
    echo "  --pull              Execute git pull before installation"
    echo ""
    echo "Actions:"
    echo "  all                 Complete installation (default)"
    echo "  agent-full          Build agent server, modules and beacon"
    echo "  agent-modules       Build and copy agent modules only"
    echo "  agent-code          Build and copy agent code only"
    echo "  listener            Build and copy listener only"
    echo ""
    echo "Examples:"
    echo "  $0 --ax AdaptixC2"
    echo "  $0 --ax AdaptixC2 --action agent-modules"
    echo "  $0 --ax /full/path/to/AdaptixC2 --action listener --pull"
    error_exit "Required parameters missing"
fi

# Validate Adaptix directory
if [ ! -d "$ADAPTIX_DIR" ]; then
    error_exit "Directory does not exist: $ADAPTIX_DIR"
fi

if [ ! -d "$ADAPTIX_DIR/AdaptixServer" ]; then
    error_exit "Directory structure incomplete. AdaptixServer not found in: $ADAPTIX_DIR"
fi

# Git pull if requested
if [ "$PULL_CHANGES" = true ]; then
    git pull || error_exit "Git pull failed"
    info_msg "Pulled latest changes"
fi

# Validate local directories
if [ ! -d "$AGENT" ]; then
    error_exit "Agent folder ($AGENT) not found in current directory"
fi

if [ ! -d "$LISTENER" ]; then
    error_exit "Listener folder ($LISTENER) not found in current directory"
fi

# Create necessary directories
mkdir -p "$ADAPTIX_DIR/AdaptixServer/extenders" || error_exit "Failed to create extenders directory"
mkdir -p "$ADAPTIX_DIR/dist/extenders" || error_exit "Failed to create dist/extenders directory"

# Action functions
function clean_agent {
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT"
    rm -rf "$ADAPTIX_DIR/dist/extenders/$AGENT"
    info_msg "Cleaned previous agent installation"
}

function clean_listener {
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER"
    rm -rf "$ADAPTIX_DIR/dist/extenders/$LISTENER"
    info_msg "Cleaned previous listener installation"
}

function copy_agent {
    cp -r "$AGENT" "$ADAPTIX_DIR/AdaptixServer/extenders/" || error_exit "Failed to copy agent"
    info_msg "Copied agent files to AdaptixServer"
}

function copy_listener {
    cp -r "$LISTENER" "$ADAPTIX_DIR/AdaptixServer/extenders/" || error_exit "Failed to copy listener"
    info_msg "Copied listener files to AdaptixServer"
}

function setup_go_workspace {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter $ADAPTIX_DIR/AdaptixServer"
    
    if [ -d "extenders/$AGENT" ]; then
        go work use "extenders/$AGENT" || error_exit "Failed to add agent to Go workspace"
    fi
    
    if [ -d "extenders/$LISTENER" ]; then
        go work use "extenders/$LISTENER" || error_exit "Failed to add listener to Go workspace"
    fi
    
    go work sync || error_exit "Failed to synchronize Go workspace"
    info_msg "Go workspace configured"
}

function setup_go_workspace_agent {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter $ADAPTIX_DIR/AdaptixServer"
    
    if [ -d "extenders/$AGENT" ]; then
        go work use "extenders/$AGENT" || error_exit "Failed to add agent to Go workspace"
    fi
    
    go work sync || error_exit "Failed to synchronize Go workspace"
    info_msg "Go workspace configured for agent"
}

function setup_go_workspace_listener {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter $ADAPTIX_DIR/AdaptixServer"
    
    if [ -d "extenders/$LISTENER" ]; then
        go work use "extenders/$LISTENER" || error_exit "Failed to add listener to Go workspace"
    fi
    
    go work sync || error_exit "Failed to synchronize Go workspace"
    info_msg "Go workspace configured for listener"
}

function build_agent_code {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter AdaptixServer directory"
    
    if [ ! -f "extenders/$AGENT/Makefile" ]; then
        error_exit "Makefile not found for $AGENT"
    fi
    
    make -C "extenders/$AGENT" agent || error_exit "Failed to build agent code"
    info_msg "Built agent code"
}

function build_agent_core {
    cd "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT/src_core" || error_exit "Could not enter src_core directory"
    
    if [ ! -f "Makefile" ]; then
        error_exit "Makefile not found in src_core"
    fi
    
    make || error_exit "Failed to build agent core modules"
    info_msg "Built agent core modules"
}

function build_agent_beacon {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter AdaptixServer directory"
    
    if [ ! -f "extenders/$AGENT/Makefile" ]; then
        error_exit "Makefile not found for $AGENT"
    fi
    
    make -C "extenders/$AGENT" beacon || error_exit "Failed to build agent beacon"
    info_msg "Built agent beacon"
}

function build_listener {
    cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter AdaptixServer directory"
    
    if [ ! -f "extenders/$LISTENER/Makefile" ]; then
        error_exit "Makefile not found for $LISTENER"
    fi
    
    make -C "extenders/$LISTENER" all || error_exit "Failed to build listener"
    info_msg "Built listener"
}

function copy_agent_dist {
    mkdir -p "$ADAPTIX_DIR/dist/extenders/$AGENT" || error_exit "Failed to create agent dist directory"
    
    if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT/dist" ]; then
        cp -r "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT/dist"/* "$ADAPTIX_DIR/dist/extenders/$AGENT/" || error_exit "Failed to copy agent dist files"
    fi
    
    # Copy source directories
    SOURCE_DIRS=("src_beacon" "src_loader" "src_core" "src_modules")
    for src_dir in "${SOURCE_DIRS[@]}"; do
        if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT/$src_dir" ]; then
            cp -r "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT/$src_dir" "$ADAPTIX_DIR/dist/extenders/$AGENT/" || warning_msg "Failed to copy $src_dir"
        fi
    done
    
    info_msg "Copied agent distribution files to dist"
}

function copy_listener_dist {
    mkdir -p "$ADAPTIX_DIR/dist/extenders/$LISTENER" || error_exit "Failed to create listener dist directory"
    
    if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER/dist" ]; then
        cp -r "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER/dist"/* "$ADAPTIX_DIR/dist/extenders/$LISTENER/" || error_exit "Failed to copy listener dist files"
    fi
    
    info_msg "Copied listener distribution files to dist"
}

# Execute actions based on ACTION parameter
case $ACTION in
    all)
        info_msg "Action: Full installation (all)"
        clean_agent
        clean_listener
        copy_agent
        copy_listener
        setup_go_workspace
        build_agent_code
        build_agent_core
        build_agent_beacon
        build_listener
        copy_agent_dist
        copy_listener_dist
        ;;
    
    agent-full)
        info_msg "Action: Full agent build"
        clean_agent
        copy_agent
        setup_go_workspace_agent
        build_agent_code
        build_agent_core
        build_agent_beacon
        copy_agent_dist
        ;;
    
    agent-modules)
        info_msg "Action: Agent modules only"
        clean_agent
        copy_agent
        setup_go_workspace_agent
        build_agent_core
        copy_agent_dist
        ;;
    
    agent-code)
        info_msg "Action: Agent code only"
        clean_agent
        copy_agent
        setup_go_workspace_agent
        build_agent_code
        copy_agent_dist
        ;;
    
    listener)
        info_msg "Action: Listener only"
        clean_listener
        copy_listener
        setup_go_workspace_listener
        build_listener
        copy_listener_dist
        ;;
    
    *)
        error_exit "Unknown action: $ACTION"
        ;;
esac

# Success summary
info_msg "Installation completed successfully"
echo "================================================================"
echo "Action: $ACTION"
echo "Agent: $AGENT"
echo "Listener: $LISTENER"
echo "Location: $ADAPTIX_DIR"
echo "================================================================"