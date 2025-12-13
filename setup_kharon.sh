#!/bin/bash

function error_exit {
    echo "[ERROR] $1"
    exit 1
}

function info_msg {
    echo "[+] $1"
}

function warning_msg {
    echo "[!] $1"
}

PULL_CHANGES=false
ADAPTIX_DIR=""
AGENT="agent_kharon"
LISTENER="listener_kharon_http"

info_msg "Processing arguments..."

for arg in "$@"; do
    if [ "$arg" = "--pull" ]; then
        PULL_CHANGES=true
        info_msg "Git pull enabled"
    elif [ -z "$ADAPTIX_DIR" ] && [ "$arg" != "--pull" ]; then
        ADAPTIX_DIR="$(realpath "$arg" 2>/dev/null || echo "$arg")"
    fi
done

if [ -z "$ADAPTIX_DIR" ]; then
    echo "Usage: $0 <AdaptixC2-path> [--pull]"
    echo "Examples:"
    echo "  $0 ../../AdaptixC2"
    echo "  $0 ../../AdaptixC2 --pull"
    echo "  $0 /full/path/to/AdaptixC2"
    error_exit "AdaptixC2 directory not specified"
fi

if [ ! -d "$ADAPTIX_DIR" ]; then
    error_exit "Directory does not exist: $ADAPTIX_DIR"
fi

if [ ! -d "$ADAPTIX_DIR/AdaptixServer" ]; then
    error_exit "Directory structure incomplete. AdaptixServer not found in: $ADAPTIX_DIR"
fi

if [ "$PULL_CHANGES" = true ]; then
    info_msg "Executing git pull to get latest version..."
    if git pull 2>/dev/null; then
        info_msg "Git pull successful"
    else
        warning_msg "Git pull failed or not a git repository"
    fi
fi

if [ ! -d "$AGENT" ]; then
    error_exit "Agent folder ($AGENT) not found in current directory"
fi

if [ ! -d "$LISTENER" ]; then
    error_exit "Listener folder ($LISTENER) not found in current directory"
fi

mkdir -p "$ADAPTIX_DIR/AdaptixServer/extenders" 2>/dev/null
mkdir -p "$ADAPTIX_DIR/dist/extenders" 2>/dev/null

info_msg "Cleaning previous installations..."

if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT" ]; then
    info_msg "Removing existing agent: $AGENT"
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT"
fi

if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER" ]; then
    info_msg "Removing existing listener: $LISTENER"
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER"
fi

info_msg "Copying new files..."

if cp -r "$AGENT" "$ADAPTIX_DIR/AdaptixServer/extenders/"; then
    info_msg "Agent copied successfully"
else
    error_exit "Failed to copy agent"
fi

if cp -r "$LISTENER" "$ADAPTIX_DIR/AdaptixServer/extenders/"; then
    info_msg "Listener copied successfully"
else
    error_exit "Failed to copy listener"
fi

info_msg "Setting up Go workspace..."

cd "$ADAPTIX_DIR/AdaptixServer" || error_exit "Could not enter $ADAPTIX_DIR/AdaptixServer"

if ! command -v go >/dev/null 2>&1; then
    warning_msg "Go not installed. Workspace setup will be skipped."
else
    if go work use "extenders/$AGENT" 2>/dev/null; then
        info_msg "Agent added to Go workspace"
    else
        warning_msg "Could not add agent to Go workspace"
    fi
    
    if go work use "extenders/$LISTENER" 2>/dev/null; then
        info_msg "Listener added to Go workspace"
    else
        warning_msg "Could not add listener to Go workspace"
    fi
    
    if go work sync 2>/dev/null; then
        info_msg "Go workspace synchronized"
    else
        warning_msg "Failed to synchronize Go workspace"
    fi
fi

info_msg "Building projects..."

if [ -f "extenders/$AGENT/Makefile" ]; then
    info_msg "Building agent: $AGENT"
    if make -C "extenders/$AGENT" all; then
        info_msg "Agent built successfully"
    else
        warning_msg "Failed to build agent"
    fi
else
    warning_msg "Makefile not found for $AGENT"
fi

if [ -f "extenders/$LISTENER/Makefile" ]; then
    info_msg "Building listener: $LISTENER"
    if make -C "extenders/$LISTENER" all; then
        info_msg "Listener built successfully"
    else
        warning_msg "Failed to build listener"
    fi
else
    warning_msg "Makefile not found for $LISTENER"
fi

info_msg "Preparing distribution..."

mkdir -p "$ADAPTIX_DIR/dist/extenders/$AGENT"
mkdir -p "$ADAPTIX_DIR/dist/extenders/$LISTENER"

if [ -d "extenders/$AGENT/dist" ]; then
    info_msg "Copying agent binaries"
    cp -r "extenders/$AGENT/dist" "$ADAPTIX_DIR/dist/extenders/$AGENT/"
else
    warning_msg "dist folder not found for $AGENT"
fi

if [ -d "extenders/$LISTENER/dist" ]; then
    info_msg "Copying listener binaries"
    cp -r "extenders/$LISTENER/dist" "$ADAPTIX_DIR/dist/extenders/$LISTENER/"
else
    warning_msg "dist folder not found for $LISTENER"
fi

info_msg "Copying source files..."

SOURCE_DIRS=("src_beacon" "src_loader" "src_modules")

for src_dir in "${SOURCE_DIRS[@]}"; do
    if [ -d "extenders/$AGENT/$src_dir" ]; then
        info_msg "Copying $src_dir"
        cp -r "extenders/$AGENT/$src_dir" "$ADAPTIX_DIR/dist/extenders/$AGENT/"
    else
        warning_msg "Directory $src_dir not found"
    fi
done

info_msg "Process completed successfully!"
echo "================================================================"
echo "INSTALLATION SUMMARY:"
echo "  Agent:      $AGENT"
echo "  Listener:    $LISTENER"
echo "  Location:    $ADAPTIX_DIR"
echo "================================================================"
echo "Files installed at:"
echo "  - $ADAPTIX_DIR/AdaptixServer/extenders/$AGENT"
echo "  - $ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER"
echo "  - $ADAPTIX_DIR/dist/extenders/$AGENT"
echo "  - $ADAPTIX_DIR/dist/extenders/$LISTENER"
echo "================================================================"