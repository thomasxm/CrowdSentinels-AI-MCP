#!/bin/bash

################################################################################
# CrowdSentinel MCP Server Setup Script
#
# AI-Powered Threat Hunting & Incident Response Framework
#
# This script:
# - Checks and installs all prerequisites
# - Downloads detection rules (Elastic ES|QL + Sigma)
# - Sets up Chainsaw for EVTX analysis
# - Configures data source connection (Elasticsearch/OpenSearch)
# - Sets up Claude authentication
# - Configures the MCP server with Claude Code
#
# Usage:
#   ./setup.sh              # Interactive setup
#   ./setup.sh --dry-run    # Show what would happen without changes
#   ./setup.sh --help       # Display usage information
#   ./setup.sh --uninstall  # Remove CrowdSentinel configuration
#
# Version: 0.3.0
################################################################################

set -e  # Exit on error

# Script version
VERSION="0.3.0"

# Fixed/tested versions
REQUIRED_PYTHON_VERSION="3.13.9"
REQUIRED_UV_VERSION="0.9.18"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Flags
DRY_RUN=false
UNINSTALL=false

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

# OS Detection
OS_TYPE=""
PKG_MANAGER=""

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_dry_run() {
    echo -e "${MAGENTA}[DRY RUN]${NC} $1"
}

prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local default="$3"
    local is_password="$4"

    if [ -n "$default" ]; then
        prompt="$prompt (default: $default)"
    fi

    if [ "$is_password" = "true" ]; then
        read -sp "$prompt: " input
        echo ""  # New line after password input
    else
        read -p "$prompt: " input
    fi

    if [ -z "$input" ] && [ -n "$default" ]; then
        input="$default"
    fi

    eval "$var_name='$input'"
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local response

    if [ "$default" = "y" ]; then
        read -p "$prompt (Y/n): " response
        [[ -z "$response" || "$response" =~ ^[Yy]$ ]]
    else
        read -p "$prompt (y/N): " response
        [[ "$response" =~ ^[Yy]$ ]]
    fi
}

run_cmd() {
    local description="$1"
    shift

    if [ "$DRY_RUN" = true ]; then
        print_dry_run "$description"
        print_dry_run "Command: $*"
        return 0
    else
        "$@"
    fi
}

################################################################################
# Usage / Help
################################################################################

show_help() {
    cat << EOF
${BOLD}CrowdSentinel MCP Server Setup${NC}
AI-Powered Threat Hunting & Incident Response Framework

${BOLD}USAGE:${NC}
    ./setup.sh [OPTIONS]

${BOLD}OPTIONS:${NC}
    --dry-run       Show what would happen without making changes
    --uninstall     Remove CrowdSentinel MCP configuration
    --help, -h      Display this help message
    --version, -v   Display version information

${BOLD}EXAMPLES:${NC}
    ./setup.sh                  # Run interactive setup
    ./setup.sh --dry-run        # Preview setup without changes
    ./setup.sh --uninstall      # Remove configuration

${BOLD}REQUIREMENTS (tested versions):${NC}
    • Python ${REQUIRED_PYTHON_VERSION}
    • uv ${REQUIRED_UV_VERSION}

${BOLD}WHAT THIS SCRIPT DOES:${NC}
    1. Checks and installs system dependencies
    2. Downloads detection rules (5,000+ rules)
    3. Sets up Chainsaw for EVTX log analysis
    4. Configures Elasticsearch/OpenSearch connection
    5. Sets up Claude authentication
    6. Configures MCP server with Claude Code

${BOLD}FEATURES:${NC}
    • 90+ threat hunting tools
    • ES|QL, EQL, and Lucene query support
    • MITRE ATT&CK mapping
    • Cyber Kill Chain analysis
    • Chainsaw EVTX hunting with Sigma rules
    • TShark network analysis (18 tools)
    • Investigation state management

${BOLD}DOCUMENTATION:${NC}
    • Quick Start: QUICK_START.md
    • Full Guide: CLAUDE_CODE_SETUP.md
    • Threat Hunting: THREAT_HUNTING_GUIDE.md

EOF
    exit 0
}

show_version() {
    echo "CrowdSentinel MCP Server Setup v${VERSION}"
    exit 0
}

################################################################################
# Command Line Argument Parsing
################################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            --version|-v)
                show_version
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

################################################################################
# OS Detection
################################################################################

detect_os() {
    print_info "Detecting operating system..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|kali|linuxmint|pop)
                OS_TYPE="debian"
                PKG_MANAGER="apt"
                ;;
            fedora|rhel|centos|rocky|alma)
                OS_TYPE="rhel"
                PKG_MANAGER="dnf"
                ;;
            arch|manjaro)
                OS_TYPE="arch"
                PKG_MANAGER="pacman"
                ;;
            *)
                OS_TYPE="unknown"
                PKG_MANAGER=""
                ;;
        esac
    elif [ "$(uname)" = "Darwin" ]; then
        OS_TYPE="macos"
        PKG_MANAGER="brew"
    else
        OS_TYPE="unknown"
        PKG_MANAGER=""
    fi

    print_success "Detected: $OS_TYPE (package manager: ${PKG_MANAGER:-none})"
}

################################################################################
# Install Package Helper
################################################################################

install_package() {
    local package="$1"
    local package_debian="${2:-$1}"
    local package_rhel="${3:-$1}"
    local package_macos="${4:-$1}"
    local package_arch="${5:-$1}"

    if [ "$DRY_RUN" = true ]; then
        print_dry_run "Would install package: $package"
        return 0
    fi

    case "$OS_TYPE" in
        debian)
            # Try to update and install, handling common APT issues
            print_info "Installing $package_debian..."

            # First attempt: try without update (package might be cached)
            if sudo apt-get install -y "$package_debian" 2>/dev/null; then
                return 0
            fi

            # Second attempt: update first, suppress warnings
            print_info "Updating package lists..."
            if ! sudo apt-get update -qq 2>&1 | grep -v "^W:"; then
                # APT update failed - try to fix common issues
                print_warning "APT update encountered issues"

                # Try to fix missing GPG keys (common on Kali/Debian)
                if sudo apt-get update 2>&1 | grep -q "NO_PUBKEY"; then
                    local missing_key=$(sudo apt-get update 2>&1 | grep "NO_PUBKEY" | tail -1 | awk '{print $NF}')
                    if [ -n "$missing_key" ]; then
                        print_info "Attempting to fix missing GPG key: $missing_key"
                        sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys "$missing_key" 2>/dev/null || true
                    fi
                fi
            fi

            # Final attempt to install
            if sudo apt-get install -y "$package_debian" 2>/dev/null; then
                return 0
            else
                print_error "Failed to install $package_debian"
                print_info "Your system may have APT configuration issues"
                print_info "Try running: sudo apt update && sudo apt install $package_debian"
                return 1
            fi
            ;;
        rhel)
            sudo dnf install -y "$package_rhel" || {
                print_error "Failed to install $package_rhel"
                return 1
            }
            ;;
        macos)
            brew install "$package_macos" || {
                print_error "Failed to install $package_macos"
                return 1
            }
            ;;
        arch)
            sudo pacman -S --noconfirm "$package_arch" || {
                print_error "Failed to install $package_arch"
                return 1
            }
            ;;
        *)
            print_error "Cannot auto-install on this OS"
            print_info "Please install $package manually"
            return 1
            ;;
    esac
}

################################################################################
# Prerequisite Checks and Installation
################################################################################

check_and_install_prerequisites() {
    print_header "Checking Prerequisites"

    local missing_critical=()
    local missing_optional=()

    # Critical dependencies
    # Python version check - note: uv can manage Python versions if system version differs
    local system_python_version=""

    if command -v python3 &> /dev/null; then
        system_python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')

        if [ "$system_python_version" = "$REQUIRED_PYTHON_VERSION" ]; then
            print_success "Python $system_python_version found ✓"
        else
            print_warning "System Python $system_python_version found (required: $REQUIRED_PYTHON_VERSION)"
            print_info "uv will manage the correct Python version for this project"
        fi
    else
        print_warning "System Python 3 not found"
        print_info "uv will install and manage Python $REQUIRED_PYTHON_VERSION"
    fi

    # Git
    if command -v git &> /dev/null; then
        print_success "git found: $(git --version | head -c 20)..."
    else
        print_warning "git not found"
        missing_critical+=("git")
    fi

    # curl
    if command -v curl &> /dev/null; then
        print_success "curl found"
    else
        print_warning "curl not found"
        missing_critical+=("curl")
    fi

    # uv (Python package manager) - exact version required
    if command -v uv &> /dev/null; then
        local uv_version=$(uv --version | awk '{print $2}')
        if [ "$uv_version" = "$REQUIRED_UV_VERSION" ]; then
            print_success "uv $uv_version found ✓"
        else
            print_warning "uv $uv_version found (tested: $REQUIRED_UV_VERSION)"
            print_info "Different version may work but is not tested"
        fi
    else
        print_warning "uv not found (required: $REQUIRED_UV_VERSION)"
        missing_critical+=("uv")
    fi

    # Claude CLI
    if command -v claude &> /dev/null; then
        print_success "Claude CLI found"
    else
        print_warning "Claude CLI not found"
        missing_critical+=("claude")
    fi

    # Optional dependencies
    # TShark (for network analysis)
    if command -v tshark &> /dev/null; then
        print_success "tshark found: $(tshark --version 2>&1 | head -1)"
    else
        print_warning "tshark not found (network analysis will be unavailable)"
        missing_optional+=("tshark")
    fi

    # jq (for JSON processing)
    if command -v jq &> /dev/null; then
        print_success "jq found"
    else
        print_warning "jq not found (JSON output won't be pretty-printed)"
        missing_optional+=("jq")
    fi

    # unzip (for Chainsaw extraction)
    if command -v unzip &> /dev/null; then
        print_success "unzip found"
    else
        print_warning "unzip not found (needed for Chainsaw setup)"
        missing_optional+=("unzip")
    fi

    # Docker (optional, for local Elasticsearch)
    if command -v docker &> /dev/null; then
        print_success "docker found"
    else
        print_info "docker not found (optional, for local Elasticsearch)"
    fi

    echo ""

    # Install missing critical dependencies
    if [ ${#missing_critical[@]} -gt 0 ]; then
        print_warning "Missing critical dependencies: ${missing_critical[*]}"
        echo ""

        for dep in "${missing_critical[@]}"; do
            case "$dep" in
                python3)
                    if confirm "Install Python 3? "; then
                        install_package "python3" "python3" "python3" "python3" "python"
                    else
                        print_error "Python 3 is required. Cannot continue."
                        exit 2
                    fi
                    ;;
                git)
                    if confirm "Install git?"; then
                        install_package "git"
                    else
                        print_error "git is required. Cannot continue."
                        exit 2
                    fi
                    ;;
                curl)
                    if confirm "Install curl?"; then
                        install_package "curl"
                    else
                        print_error "curl is required. Cannot continue."
                        exit 2
                    fi
                    ;;
                uv)
                    if confirm "Install uv (Python package manager) v${REQUIRED_UV_VERSION}?"; then
                        if [ "$DRY_RUN" = true ]; then
                            print_dry_run "Would install uv v${REQUIRED_UV_VERSION} via curl"
                        else
                            print_info "Installing uv v${REQUIRED_UV_VERSION}..."
                            curl -LsSf "https://astral.sh/uv/${REQUIRED_UV_VERSION}/install.sh" | sh
                            export PATH="$HOME/.local/bin:$PATH"

                            # Verify installation
                            if command -v uv &> /dev/null; then
                                print_success "uv installed: $(uv --version)"
                            else
                                print_error "uv installation failed"
                                exit 2
                            fi
                        fi
                    else
                        print_error "uv is required. Cannot continue."
                        exit 2
                    fi
                    ;;
                claude)
                    if confirm "Install Claude CLI?"; then
                        if [ "$DRY_RUN" = true ]; then
                            print_dry_run "Would install Claude CLI via official installer"
                        else
                            print_info "Installing Claude CLI..."
                            if curl -fsSL https://claude.ai/install.sh | bash; then
                                export PATH="$HOME/.claude/bin:$PATH"
                                print_success "Claude CLI installed successfully"
                            else
                                print_error "Claude CLI installation failed"
                                print_info "Install manually: curl -fsSL https://claude.ai/install.sh | bash"
                                if ! confirm "Continue anyway?"; then
                                    exit 2
                                fi
                            fi
                        fi
                    else
                        print_warning "Claude CLI is required for MCP integration"
                        print_info "Install later: curl -fsSL https://claude.ai/install.sh | bash"
                        if ! confirm "Continue anyway?"; then
                            exit 2
                        fi
                    fi
                    ;;
            esac
        done
    fi

    # Offer to install optional dependencies
    if [ ${#missing_optional[@]} -gt 0 ]; then
        echo ""
        print_info "Optional dependencies not found: ${missing_optional[*]}"

        if confirm "Install optional dependencies for full functionality?"; then
            local failed_optional=()

            for dep in "${missing_optional[@]}"; do
                case "$dep" in
                    tshark)
                        if ! install_package "tshark" "tshark" "wireshark-cli" "wireshark" "wireshark-cli"; then
                            failed_optional+=("tshark")
                        fi
                        ;;
                    jq)
                        if ! install_package "jq"; then
                            failed_optional+=("jq")
                        fi
                        ;;
                    unzip)
                        if ! install_package "unzip"; then
                            failed_optional+=("unzip")
                        fi
                        ;;
                esac
            done

            # Report failures but don't block setup
            if [ ${#failed_optional[@]} -gt 0 ]; then
                echo ""
                print_warning "Could not install some optional packages: ${failed_optional[*]}"
                print_info "This won't block setup, but some features may be unavailable"
                print_info "You can install them manually later if needed"
            fi
        fi
    fi

    print_success "Prerequisite check complete"
}

################################################################################
# Ensure Python Version via uv
################################################################################

ensure_python_version() {
    print_header "Ensuring Python $REQUIRED_PYTHON_VERSION"

    # Check if uv is available
    if ! command -v uv &> /dev/null; then
        print_error "uv is required but not found"
        print_info "Run setup again to install uv"
        exit 2
    fi

    # Check if system Python already matches
    if command -v python3 &> /dev/null; then
        local system_py=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
        if [ "$system_py" = "$REQUIRED_PYTHON_VERSION" ]; then
            print_success "System Python $system_py matches required version ✓"
            return 0
        fi
    fi

    # Check if uv already has the required version
    print_info "Checking if Python $REQUIRED_PYTHON_VERSION is available via uv..."

    if [ "$DRY_RUN" = true ]; then
        print_dry_run "Would check: uv python list | grep $REQUIRED_PYTHON_VERSION"
        print_dry_run "Would install if needed: uv python install $REQUIRED_PYTHON_VERSION"
        return 0
    fi

    if uv python list 2>/dev/null | grep -q "$REQUIRED_PYTHON_VERSION"; then
        print_success "Python $REQUIRED_PYTHON_VERSION already available via uv ✓"
        return 0
    fi

    # Install the required Python version
    print_info "Installing Python $REQUIRED_PYTHON_VERSION via uv..."
    print_info "This may take a minute..."

    if uv python install "$REQUIRED_PYTHON_VERSION"; then
        print_success "Python $REQUIRED_PYTHON_VERSION installed successfully ✓"

        # Verify installation
        if uv python list 2>/dev/null | grep -q "$REQUIRED_PYTHON_VERSION"; then
            print_success "Python $REQUIRED_PYTHON_VERSION verified ✓"
        fi
    else
        print_error "Failed to install Python $REQUIRED_PYTHON_VERSION"
        print_info "This may be due to:"
        print_info "  • Unsupported OS/architecture"
        print_info "  • Network issues"
        print_info "  • Insufficient disk space"
        echo ""
        print_info "You can try manually: uv python install $REQUIRED_PYTHON_VERSION"
        print_info "Or install Python $REQUIRED_PYTHON_VERSION from python.org"

        if ! confirm "Continue anyway with system Python? (may not work)"; then
            exit 2
        fi
    fi
}

################################################################################
# Install Python Dependencies
################################################################################

install_dependencies() {
    print_header "Installing Python Dependencies"

    cd "$SCRIPT_DIR"

    if [ "$DRY_RUN" = true ]; then
        print_dry_run "Would run: uv sync --python $REQUIRED_PYTHON_VERSION"
        print_dry_run "Would install packages from pyproject.toml"
        return 0
    fi

    print_info "Installing Python packages with uv (Python $REQUIRED_PYTHON_VERSION)..."

    # Use --python flag to ensure we use the correct Python version
    # This will use uv-managed Python if system Python doesn't match
    if uv sync --python "$REQUIRED_PYTHON_VERSION" 2>/dev/null; then
        print_success "All Python dependencies installed"
    elif uv sync 2>/dev/null; then
        # Fallback: try without explicit Python version
        print_warning "Installed with default Python (may not be $REQUIRED_PYTHON_VERSION)"
        print_success "Dependencies installed"
    else
        print_error "Failed to install dependencies"
        exit 3
    fi

    # Verify the Python version in the venv
    if [ -f ".venv/bin/python" ]; then
        local venv_py_version=$(.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
        if [ "$venv_py_version" = "$REQUIRED_PYTHON_VERSION" ]; then
            print_success "Virtual environment uses Python $venv_py_version ✓"
        else
            print_warning "Virtual environment uses Python $venv_py_version (expected $REQUIRED_PYTHON_VERSION)"
            print_info "This may work but is not tested"
        fi
    fi
}

################################################################################
# Detection Rules Setup
################################################################################

setup_detection_rules() {
    print_header "Setting Up Detection Rules"

    cd "$SCRIPT_DIR"

    echo "CrowdSentinel includes 5,000+ detection rules:"
    echo "  • Elastic ES|QL hunting rules (cloud, endpoint, network)"
    echo "  • Sigma rules for Chainsaw EVTX analysis"
    echo "  • Pre-converted EQL/Lucene rules (already included)"
    echo ""

    if ! confirm "Download/update detection rules?"; then
        print_info "Skipping detection rules setup"
        return 0
    fi

    # 1. Elastic Detection Rules (for ES|QL hunting)
    print_info "Setting up Elastic detection-rules..."

    if [ -d "detection-rules/.git" ]; then
        print_info "Updating existing detection-rules repository..."
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would run: git -C detection-rules pull --ff-only"
        else
            git -C detection-rules pull --ff-only 2>/dev/null || {
                print_warning "Could not update detection-rules (may have local changes)"
            }
        fi
    elif [ -d "detection-rules" ]; then
        print_warning "detection-rules exists but is not a git repo"
        if confirm "Remove and re-clone?"; then
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would remove detection-rules and clone fresh"
            else
                rm -rf detection-rules
                git clone --depth 1 https://github.com/elastic/detection-rules.git
            fi
        fi
    else
        print_info "Cloning Elastic detection-rules repository..."
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would clone: https://github.com/elastic/detection-rules.git"
        else
            git clone --depth 1 https://github.com/elastic/detection-rules.git || {
                print_warning "Failed to clone detection-rules (ES|QL hunting may be limited)"
            }
        fi
    fi

    # Count ES|QL hunting rules
    if [ -d "detection-rules/hunting" ]; then
        local esql_count=$(find detection-rules/hunting -name "*.toml" 2>/dev/null | wc -l)
        print_success "ES|QL hunting rules: $esql_count rule files"
    fi

    # 2. Verify pre-converted rules
    print_info "Verifying pre-converted detection rules..."

    local eql_count=$(find rules/ -name "*.eql" 2>/dev/null | wc -l)
    local lucene_count=$(find rules/ -name "*.lucene" 2>/dev/null | wc -l)

    if [ "$eql_count" -gt 1000 ]; then
        print_success "EQL rules: $eql_count rules"
    else
        print_warning "EQL rules may be incomplete: only $eql_count found"
    fi

    if [ "$lucene_count" -gt 500 ]; then
        print_success "Lucene rules: $lucene_count rules"
    else
        print_warning "Lucene rules may be incomplete: only $lucene_count found"
    fi

    print_success "Detection rules setup complete"
}

################################################################################
# Chainsaw Log Analyser Setup
################################################################################

setup_chainsaw() {
    print_header "Setting Up Chainsaw Log Analyser"

    cd "$SCRIPT_DIR"

    # Create chainsaw directory if it doesn't exist
    if [ ! -d "chainsaw" ]; then
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would create chainsaw directory"
        else
            mkdir -p chainsaw
        fi
        print_info "Created chainsaw directory"
    fi

    cd chainsaw

    # Check if chainsaw binary exists
    if [ -f "chainsaw" ] && [ -x "chainsaw" ]; then
        print_success "Chainsaw binary found"
        ./chainsaw --version 2>/dev/null || print_warning "Chainsaw binary exists but may not be functional"
    else
        print_warning "Chainsaw binary not found"
        print_info "Chainsaw is required for EVTX log analysis (6 tools)"

        if ! confirm "Install Chainsaw?"; then
            print_error "Chainsaw is required for EVTX analysis features"
            print_info "You can install it later by re-running this script"
            cd "$SCRIPT_DIR"
            return 1
        fi

        print_info "Installing Chainsaw..."

        # Detect OS and architecture
        local OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        local ARCH=$(uname -m)

        case "$ARCH" in
            x86_64) ARCH="x86_64" ;;
            aarch64|arm64) ARCH="aarch64" ;;
            *)
                print_error "Unsupported architecture: $ARCH"
                print_warning "Skipping Chainsaw installation"
                cd "$SCRIPT_DIR"
                return 1
                ;;
        esac

        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would download Chainsaw for $OS/$ARCH"
            print_dry_run "Would extract and set up binary"
        else
            local CHAINSAW_URL="https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules+examples.zip"
            local CHAINSAW_FILE="chainsaw_all_platforms+rules+examples.zip"

            print_info "Downloading Chainsaw from GitHub releases..."
            if ! curl -L -o "$CHAINSAW_FILE" "$CHAINSAW_URL"; then
                print_error "Failed to download Chainsaw"
                cd "$SCRIPT_DIR"
                return 1
            fi

            if command -v unzip &> /dev/null; then
                print_info "Extracting Chainsaw..."
                unzip -q -o "$CHAINSAW_FILE" || {
                    print_error "Failed to extract Chainsaw"
                    cd "$SCRIPT_DIR"
                    return 1
                }

                # Find and set up the appropriate binary
                # The zip extracts to a nested chainsaw/ subdirectory
                local binary_name=""
                if [ "$OS" = "linux" ]; then
                    if [ "$ARCH" = "x86_64" ]; then
                        binary_name="chainsaw_x86_64-unknown-linux-gnu"
                    else
                        binary_name="chainsaw_aarch64-unknown-linux-gnu"
                    fi
                elif [ "$OS" = "darwin" ]; then
                    binary_name="chainsaw_x86_64-apple-darwin"
                fi

                if [ -n "$binary_name" ] && [ -f "chainsaw/$binary_name" ]; then
                    # Move binary to current directory (parent of nested chainsaw/)
                    mv "chainsaw/$binary_name" "./chainsaw_binary_temp"
                    chmod +x "./chainsaw_binary_temp"

                    # Move mappings if they exist in nested dir
                    if [ -d "chainsaw/mappings" ] && [ ! -d "mappings" ]; then
                        mv "chainsaw/mappings" "./mappings"
                    fi

                    # Move rules if they exist in nested dir
                    if [ -d "chainsaw/rules" ] && [ ! -d "rules" ]; then
                        mv "chainsaw/rules" "./rules"
                    fi

                    # Remove the nested chainsaw directory (now empty or has other binaries)
                    rm -rf "chainsaw"

                    # Rename binary to final name
                    mv "./chainsaw_binary_temp" "./chainsaw"

                    print_success "Chainsaw installed successfully"
                else
                    print_error "Could not find Chainsaw binary for $OS/$ARCH"
                    print_info "Expected: chainsaw/$binary_name"
                    print_info "Available files:"
                    ls -la chainsaw/ 2>/dev/null || echo "  (no chainsaw directory)"
                fi

                rm -f "$CHAINSAW_FILE"
            else
                print_error "unzip not found - cannot extract Chainsaw"
                rm -f "$CHAINSAW_FILE"
                cd "$SCRIPT_DIR"
                return 1
            fi
        fi
    fi

    # Setup Sigma rules
    if [ -d "sigma" ] && [ "$(ls -A sigma 2>/dev/null)" ]; then
        local sigma_count=$(find sigma -name "*.yml" 2>/dev/null | wc -l)
        print_success "Sigma rules directory found: $sigma_count rules"
    else
        print_info "Cloning Sigma rules repository..."
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would clone Sigma rules from SigmaHQ/sigma"
        else
            if command -v git &> /dev/null; then
                git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git sigma_temp 2>/dev/null
                cd sigma_temp
                git sparse-checkout set rules 2>/dev/null
                cd ..

                if [ -d "sigma_temp/rules" ]; then
                    rm -rf sigma
                    mv sigma_temp/rules sigma
                    rm -rf sigma_temp
                    print_success "Sigma rules cloned successfully"
                else
                    print_warning "Failed to clone Sigma rules"
                    rm -rf sigma_temp
                fi
            fi
        fi
    fi

    # Setup EVTX attack samples (for testing)
    if [ -d "EVTX-ATTACK-SAMPLES" ] && [ "$(ls -A EVTX-ATTACK-SAMPLES 2>/dev/null)" ]; then
        local evtx_count=$(find EVTX-ATTACK-SAMPLES -name "*.evtx" 2>/dev/null | wc -l)
        print_success "EVTX-ATTACK-SAMPLES found: $evtx_count files"
    else
        if confirm "Clone EVTX-ATTACK-SAMPLES for testing? (optional)"; then
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would clone EVTX-ATTACK-SAMPLES"
            else
                git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git 2>/dev/null || {
                    print_warning "Failed to clone EVTX-ATTACK-SAMPLES"
                }
            fi
        fi
    fi

    cd "$SCRIPT_DIR"

    # Print summary
    echo ""
    echo "Chainsaw Setup Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ -f "chainsaw/chainsaw" ] && echo "  ✓ Chainsaw binary: Installed" || echo "  ✗ Chainsaw binary: Not installed"
    [ -d "chainsaw/sigma" ] && echo "  ✓ Sigma rules: $(find chainsaw/sigma -name '*.yml' 2>/dev/null | wc -l) rules" || echo "  ✗ Sigma rules: Not installed"
    [ -d "chainsaw/EVTX-ATTACK-SAMPLES" ] && echo "  ✓ EVTX samples: $(find chainsaw/EVTX-ATTACK-SAMPLES -name '*.evtx' 2>/dev/null | wc -l) files" || echo "  ○ EVTX samples: Not installed (optional)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

################################################################################
# TShark Verification
################################################################################

verify_tshark() {
    print_header "Verifying TShark (Network Analysis)"

    if ! command -v tshark &> /dev/null; then
        print_warning "TShark not installed"
        print_info "Network analysis tools (18 tools) will be unavailable"
        print_info "To install: sudo apt install tshark (Debian/Ubuntu)"
        print_info "           brew install wireshark (macOS)"
        return 1
    fi

    local tshark_version=$(tshark --version 2>&1 | head -1)
    print_success "TShark found: $tshark_version"

    # Check if user can capture without root
    if [ "$DRY_RUN" = false ]; then
        if groups | grep -q wireshark; then
            print_success "User is in wireshark group (can capture packets)"
        else
            print_warning "User not in wireshark group"
            print_info "To capture packets, run: sudo usermod -aG wireshark \$USER"
            print_info "Then log out and back in"
        fi
    fi

    print_success "TShark verification complete"
    print_info "Available: 18 network analysis tools (PCAP analysis, beaconing detection, etc.)"
}

################################################################################
# Data Source Configuration (Elasticsearch/OpenSearch)
################################################################################

configure_data_source() {
    print_header "Data Source Configuration"

    echo "CrowdSentinel connects to Elasticsearch or OpenSearch for log analysis."
    echo ""

    # Try to auto-detect running instance
    local detected_host=""
    local detected_type=""

    for host in "http://localhost:9200" "https://localhost:9200" "http://localhost:9201"; do
        if curl -s -k --connect-timeout 2 "$host" &>/dev/null; then
            local response=$(curl -s -k --connect-timeout 2 "$host" 2>/dev/null)
            if echo "$response" | grep -q "cluster_name"; then
                detected_host="$host"
                if echo "$response" | grep -q "opensearch"; then
                    detected_type="OpenSearch"
                else
                    detected_type="Elasticsearch"
                fi
                break
            fi
        fi
    done

    if [ -n "$detected_host" ]; then
        print_success "Auto-detected $detected_type at $detected_host"
        if confirm "Use detected instance?"; then
            ES_HOST="$detected_host"
        else
            prompt_input "Enter host URL" ES_HOST "http://localhost:9200"
        fi
    else
        print_info "No running instance detected"
        prompt_input "Enter Elasticsearch/OpenSearch host" ES_HOST "http://localhost:9200"
    fi

    # Authentication method
    echo ""
    echo "Authentication Method:"
    echo "  1) Username & Password"
    echo "  2) API Key"
    read -p "Select authentication method (1 or 2) [1]: " AUTH_METHOD
    AUTH_METHOD="${AUTH_METHOD:-1}"

    if [ "$AUTH_METHOD" = "2" ]; then
        prompt_input "API Key" ES_API_KEY "" "true"
        ES_USERNAME=""
        ES_PASSWORD=""
    else
        prompt_input "Username" ES_USERNAME "elastic"
        prompt_input "Password" ES_PASSWORD "" "true"
        ES_API_KEY=""
    fi

    # SSL verification
    echo ""
    if [[ "$ES_HOST" == https://* ]]; then
        read -p "Verify SSL certificates? (y/N, use N for self-signed): " VERIFY_SSL_RESPONSE
        if [[ "$VERIFY_SSL_RESPONSE" =~ ^[Yy]$ ]]; then
            VERIFY_CERTS="true"
        else
            VERIFY_CERTS="false"
        fi
    else
        VERIFY_CERTS="false"
    fi

    # Read-only mode (recommended for IR)
    echo ""
    print_info "Read-only mode disables write operations for security"
    read -p "Enable read-only mode? (Y/n, recommended): " READONLY_RESPONSE
    if [[ -z "$READONLY_RESPONSE" || "$READONLY_RESPONSE" =~ ^[Yy]$ ]]; then
        DISABLE_HIGH_RISK="true"
    else
        DISABLE_HIGH_RISK="false"
    fi
}

################################################################################
# Validate Data Source Connection
################################################################################

validate_connection() {
    print_header "Validating Connection"

    if [ "$DRY_RUN" = true ]; then
        print_dry_run "Would test connection to $ES_HOST"
        return 0
    fi

    print_info "Testing connection to $ES_HOST..."

    # Build curl command
    local curl_cmd="curl -s --connect-timeout 10"

    if [ "$VERIFY_CERTS" = "false" ]; then
        curl_cmd="$curl_cmd -k"
    fi

    if [ -n "$ES_API_KEY" ]; then
        curl_cmd="$curl_cmd -H 'Authorization: ApiKey $ES_API_KEY'"
    elif [ -n "$ES_USERNAME" ] && [ -n "$ES_PASSWORD" ]; then
        curl_cmd="$curl_cmd -u '$ES_USERNAME:$ES_PASSWORD'"
    fi

    curl_cmd="$curl_cmd '$ES_HOST'"

    local response=$(eval "$curl_cmd" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ] && echo "$response" | grep -q "cluster_name"; then
        print_success "Connection successful!"

        if command -v jq &> /dev/null; then
            local cluster_name=$(echo "$response" | jq -r '.cluster_name' 2>/dev/null || echo "unknown")
            local version=$(echo "$response" | jq -r '.version.number' 2>/dev/null || echo "unknown")
            print_info "Cluster: $cluster_name"
            print_info "Version: $version"
        fi
        return 0
    else
        print_error "Connection failed"
        print_info "Response: $response"
        return 1
    fi
}

################################################################################
# Claude Authentication
################################################################################

setup_claude_auth() {
    print_header "Claude CLI Setup"

    # Check if Claude CLI is installed
    if ! command -v claude &> /dev/null; then
        print_warning "Claude CLI not found"

        if confirm "Install Claude CLI now?"; then
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would install Claude CLI via npm"
            else
                print_info "Installing Claude CLI..."
                if command -v npm &> /dev/null; then
                    if npm install -g @anthropic-ai/claude-code 2>/dev/null; then
                        print_success "Claude CLI installed successfully"
                    else
                        print_warning "npm install failed, trying curl method..."
                        if curl -fsSL https://claude.ai/install.sh | bash; then
                            print_success "Claude CLI installed successfully"
                        else
                            print_error "Failed to install Claude CLI"
                            print_info "Manual install: npm install -g @anthropic-ai/claude-code"
                            print_info "Or visit: https://claude.ai/download"
                            return 1
                        fi
                    fi
                else
                    print_info "npm not found, using curl method..."
                    if curl -fsSL https://claude.ai/install.sh | bash; then
                        print_success "Claude CLI installed successfully"
                    else
                        print_error "Failed to install Claude CLI"
                        print_info "Manual install: npm install -g @anthropic-ai/claude-code"
                        return 1
                    fi
                fi
            fi
        else
            print_info "Skipping Claude CLI installation"
            return 0
        fi
    else
        print_success "Claude CLI already installed"
    fi

    # Check if already authenticated
    if [ "$DRY_RUN" = false ]; then
        if claude auth status &>/dev/null 2>&1; then
            print_success "Claude CLI already authenticated"
            return 0
        fi
    fi

    echo ""
    echo "Authentication Required:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  To authenticate Claude CLI, run this command in a new terminal:"
    echo ""
    echo "    claude login"
    echo ""
    echo "  This will open your browser for secure OAuth login."
    echo ""
    echo "  Alternatively, use an API key:"
    echo ""
    echo "    claude auth --api-key YOUR_API_KEY"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if confirm "Configure API key now? (No = authenticate later via 'claude login')"; then
        echo ""
        read -sp "Paste your Anthropic API key: " api_key
        echo ""

        if [ -z "$api_key" ]; then
            print_error "No API key provided"
            print_info "Authenticate later with: claude login"
            return 0
        fi

        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would configure Claude CLI with provided API key"
        else
            # Try to configure with API key
            if echo "$api_key" | claude auth --api-key - 2>/dev/null; then
                print_success "API key configured successfully"
            else
                # Alternative method
                export ANTHROPIC_API_KEY="$api_key"
                print_success "API key set in environment"
                print_info "Add to ~/.bashrc: export ANTHROPIC_API_KEY='your-key'"
            fi
        fi
    else
        print_info "Authenticate later with: claude login"
    fi

    return 0
}


################################################################################
# MCP Server Configuration
################################################################################

find_mcp_config() {
    # Check possible config locations
    local locations=(
        "$HOME/.claude/mcp.json"
        "$HOME/.config/claude-code/mcp_config.json"
    )

    for loc in "${locations[@]}"; do
        if [ -f "$loc" ]; then
            echo "$loc"
            return 0
        fi
    done

    # Default to newer location
    echo "$HOME/.claude/mcp.json"
}

configure_mcp_server() {
    print_header "Configuring MCP Server"

    local MCP_CONFIG=$(find_mcp_config)
    local MCP_CONFIG_DIR=$(dirname "$MCP_CONFIG")

    print_info "MCP config location: $MCP_CONFIG"

    # Backup existing config
    if [ -f "$MCP_CONFIG" ] && [ "$DRY_RUN" = false ]; then
        local backup="$MCP_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$MCP_CONFIG" "$backup"
        print_info "Backed up existing config to: $backup"
    fi

    # Try using claude mcp add command first
    if command -v claude &> /dev/null && claude mcp list &>/dev/null 2>&1; then
        print_info "Using Claude CLI to configure MCP server..."

        # Check if already configured
        if claude mcp list 2>&1 | grep -q "crowdsentinel"; then
            print_warning "MCP server 'crowdsentinel' already configured"
            if confirm "Remove and reconfigure?"; then
                if [ "$DRY_RUN" = true ]; then
                    print_dry_run "Would remove existing crowdsentinel config"
                else
                    claude mcp remove crowdsentinel 2>/dev/null || true
                fi
            else
                print_info "Keeping existing configuration"
                return 0
            fi
        fi

        # Ask about scope
        echo ""
        echo "Where should CrowdSentinel be available?"
        echo "  1) This project only (default)"
        echo "  2) All projects (user level)"
        read -p "Select option [1]: " scope_choice
        scope_choice="${scope_choice:-1}"

        local scope_flag=""
        local scope_desc="project"
        if [ "$scope_choice" = "2" ]; then
            scope_flag="-s user"
            scope_desc="user (all projects)"
        fi

        local mcp_cmd="claude mcp add crowdsentinel $scope_flag"
        mcp_cmd="$mcp_cmd -e ELASTICSEARCH_HOSTS=\"$ES_HOST\""

        if [ -n "$ES_API_KEY" ]; then
            mcp_cmd="$mcp_cmd -e ELASTICSEARCH_API_KEY=\"$ES_API_KEY\""
        else
            mcp_cmd="$mcp_cmd -e ELASTICSEARCH_USERNAME=\"$ES_USERNAME\""
            mcp_cmd="$mcp_cmd -e ELASTICSEARCH_PASSWORD=\"$ES_PASSWORD\""
        fi

        mcp_cmd="$mcp_cmd -e VERIFY_CERTS=\"$VERIFY_CERTS\""
        mcp_cmd="$mcp_cmd -e DISABLE_HIGH_RISK_OPERATIONS=\"$DISABLE_HIGH_RISK\""
        mcp_cmd="$mcp_cmd -- uv --directory \"$SCRIPT_DIR\" run crowdsentinel-mcp-server"

        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would run: $mcp_cmd"
        else
            print_info "Adding MCP server ($scope_desc)..."
            if eval "$mcp_cmd"; then
                print_success "MCP server added ($scope_desc)"
            else
                print_warning "claude mcp add failed, falling back to direct config"
                # Will fall through to direct config method below
            fi
        fi
    else
        # Fallback: Write config directly (Claude CLI not available or mcp command failed)
        print_info "Claude CLI not available - writing MCP config directly..."
        print_info "You can install Claude CLI later: curl -fsSL https://claude.ai/install.sh | bash"

        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would create directory: $MCP_CONFIG_DIR"
            print_dry_run "Would write config to: $MCP_CONFIG"
        else
            mkdir -p "$MCP_CONFIG_DIR"
        fi

        # Build env section
        local env_section=""
        env_section="\"ELASTICSEARCH_HOSTS\": \"$ES_HOST\","

        if [ -n "$ES_API_KEY" ]; then
            env_section="$env_section
        \"ELASTICSEARCH_API_KEY\": \"$ES_API_KEY\","
        else
            env_section="$env_section
        \"ELASTICSEARCH_USERNAME\": \"$ES_USERNAME\",
        \"ELASTICSEARCH_PASSWORD\": \"$ES_PASSWORD\","
        fi

        env_section="$env_section
        \"VERIFY_CERTS\": \"$VERIFY_CERTS\",
        \"DISABLE_HIGH_RISK_OPERATIONS\": \"$DISABLE_HIGH_RISK\""

        local config_content='{
  "mcpServers": {
    "crowdsentinel": {
      "command": "uv",
      "args": [
        "--directory",
        "'"$SCRIPT_DIR"'",
        "run",
        "crowdsentinel-mcp-server"
      ],
      "env": {
        '"$env_section"'
      }
    }
  }
}'

        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Config content:"
            echo "$config_content" | head -20
            echo "..."
        else
            # If config exists, merge with existing
            if [ -f "$MCP_CONFIG" ]; then
                if command -v jq &> /dev/null; then
                    # Use jq to merge
                    local merged=$(jq -s '.[0] * .[1]' "$MCP_CONFIG" <(echo "$config_content"))
                    echo "$merged" > "$MCP_CONFIG"
                else
                    # Simple overwrite (not ideal but works)
                    echo "$config_content" > "$MCP_CONFIG"
                fi
            else
                echo "$config_content" > "$MCP_CONFIG"
            fi

            chmod 600 "$MCP_CONFIG"
        fi
    fi

    # Verify MCP configuration
    echo ""
    print_info "Verifying MCP configuration..."

    local config_ok=false
    local server_ok=false

    # Step 1: Check if configured in Claude
    if command -v claude &> /dev/null; then
        if claude mcp list 2>&1 | grep -q "crowdsentinel"; then
            print_success "MCP server 'crowdsentinel' found in Claude config"
            config_ok=true
        else
            print_error "MCP server 'crowdsentinel' NOT found in Claude config"
            print_info "Run: claude mcp add crowdsentinel -s user -- uv --directory \"$SCRIPT_DIR\" run crowdsentinel-mcp-server"
        fi
    else
        print_warning "Claude CLI not installed - cannot verify config"
        print_info "Install: curl -fsSL https://claude.ai/install.sh | bash"
    fi

    # Step 2: Test if server actually starts
    echo ""
    print_info "Testing MCP server startup..."

    # Set environment variables for the test
    export ELASTICSEARCH_HOSTS="$ES_HOST"
    if [ -n "$ES_API_KEY" ]; then
        export ELASTICSEARCH_API_KEY="$ES_API_KEY"
    else
        export ELASTICSEARCH_USERNAME="$ES_USERNAME"
        export ELASTICSEARCH_PASSWORD="$ES_PASSWORD"
    fi
    export VERIFY_CERTS="$VERIFY_CERTS"
    export DISABLE_HIGH_RISK_OPERATIONS="$DISABLE_HIGH_RISK"

    # Try to start the server briefly and check for errors
    cd "$SCRIPT_DIR"
    local test_output
    test_output=$(timeout 5 uv run crowdsentinel-mcp-server 2>&1) || true

    # Check for successful initialization patterns first
    if echo "$test_output" | grep -qi "Loaded.*rules successfully\|client initialised\|Initialising.*mcp-server"; then
        print_success "MCP server starts successfully"
        server_ok=true
    # Check for actual ERROR level messages or Python exceptions (not just the word "error" in logs)
    elif echo "$test_output" | grep -qE "^.*- ERROR -|Traceback \(most recent|ModuleNotFoundError|ImportError|ConnectionError|AuthenticationException"; then
        print_error "MCP server failed to start"
        print_info "Error output:"
        echo "$test_output" | grep -E "ERROR|Traceback|Exception|Error:" | head -5
        echo ""
        print_info "Check your Elasticsearch connection settings"
    else
        # No clear error, assume server is working
        print_success "MCP server appears to start correctly"
        server_ok=true
    fi

    # Final verdict
    echo ""
    if [ "$config_ok" = true ] && [ "$server_ok" = true ]; then
        print_success "MCP server is properly configured and working!"
    elif [ "$config_ok" = true ]; then
        print_warning "MCP is configured but server has issues - check Elasticsearch connection"
    elif [ "$server_ok" = true ]; then
        print_warning "Server works but not configured in Claude - add it manually"
    else
        print_error "MCP setup incomplete - see errors above"
    fi
}

################################################################################
# CrowdSentinel Skills Installation
################################################################################

install_crowdsentinel_skills() {
    print_header "CrowdSentinel Agent Skills Installation"

    # Skills are bundled with this project
    local SKILL_SOURCE="$SCRIPT_DIR/skills/crowdsentinel-skills"
    local SKILL_DEST="$HOME/.claude/skills/crowdsentinel-skills"

    # Verify bundled skills exist
    if [ ! -d "$SKILL_SOURCE" ] || [ ! -f "$SKILL_SOURCE/SKILL.md" ]; then
        print_error "Bundled skills not found at $SKILL_SOURCE"
        print_info "The skills directory should be included with this project."
        print_info "Expected location: $SKILL_SOURCE"
        return 1
    fi

    # If skills already exist at destination
    if [ -d "$SKILL_DEST" ]; then
        print_success "CrowdSentinel skills already installed at $SKILL_DEST"
        if [ "$SKILL_SOURCE" != "$SKILL_DEST" ] && [ -d "$SKILL_SOURCE" ]; then
            if confirm "Update from source?"; then
                if [ "$DRY_RUN" = true ]; then
                    print_dry_run "Would update skills from $SKILL_SOURCE"
                else
                    rm -rf "$SKILL_DEST"
                    cp -r "$SKILL_SOURCE" "$SKILL_DEST"
                    print_success "Skills updated"
                fi
            fi
        fi
        return 0
    fi

    echo ""
    echo "CrowdSentinel Skills provide AI guidance for:"
    echo "  • Threat hunting workflow decisions"
    echo "  • Detection rule selection and execution"
    echo "  • Kill chain analysis and MITRE mapping"
    echo "  • Field mapping for non-ECS data"
    echo "  • Connection debugging"
    echo ""
    echo "Installation options:"
    echo "  a) Copy skills to ~/.claude/skills/ (default, recommended)"
    echo "  b) Create symlink to source location"
    echo "  c) Skip skill installation"
    echo ""
    read -p "Select option [a]: " skill_choice
    skill_choice="${skill_choice:-a}"

    case "$skill_choice" in
        a|A)
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would copy $SKILL_SOURCE to $SKILL_DEST"
            else
                mkdir -p "$(dirname "$SKILL_DEST")"
                cp -r "$SKILL_SOURCE" "$SKILL_DEST"
                print_success "Skills copied to $SKILL_DEST"
            fi
            ;;
        b|B)
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would create symlink: $SKILL_DEST -> $SKILL_SOURCE"
            else
                mkdir -p "$(dirname "$SKILL_DEST")"
                ln -sf "$SKILL_SOURCE" "$SKILL_DEST"
                print_success "Symlink created: $SKILL_DEST -> $SKILL_SOURCE"
            fi
            ;;
        c|C)
            print_info "Skipping skill installation"
            return 0
            ;;
        *)
            print_warning "Invalid choice, defaulting to copy"
            if [ "$DRY_RUN" = true ]; then
                print_dry_run "Would copy $SKILL_SOURCE to $SKILL_DEST"
            else
                mkdir -p "$(dirname "$SKILL_DEST")"
                cp -r "$SKILL_SOURCE" "$SKILL_DEST"
                print_success "Skills copied to $SKILL_DEST"
            fi
            ;;
    esac

    # Verify installation
    if [ -d "$SKILL_DEST" ] && [ -f "$SKILL_DEST/SKILL.md" ]; then
        print_success "Skills installed successfully"

        # Count scripts
        local script_count=$(find "$SKILL_DEST/scripts" -type f -name "*.sh" -o -name "*.py" 2>/dev/null | wc -l)
        local ref_count=$(find "$SKILL_DEST/references" -type f -name "*.md" 2>/dev/null | wc -l)

        echo ""
        echo "Installed components:"
        echo "  • SKILL.md: Decision trees and workflow guidance"
        echo "  • Scripts: $script_count executable scripts"
        echo "  • References: $ref_count framework documents"
    fi
}

################################################################################
# Uninstall
################################################################################

uninstall() {
    print_header "Uninstalling CrowdSentinel Configuration"

    echo "This will remove:"
    echo "  • MCP server configuration for 'crowdsentinel'"
    echo "  • Local transport config file (.mcp_transport_config)"
    echo ""
    echo "This will NOT remove:"
    echo "  • Downloaded detection rules"
    echo "  • Chainsaw and Sigma rules"
    echo "  • Python dependencies"
    echo ""

    if ! confirm "Continue with uninstall?"; then
        echo "Uninstall cancelled"
        exit 0
    fi

    # Remove MCP config
    if command -v claude &> /dev/null; then
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would run: claude mcp remove crowdsentinel"
        else
            claude mcp remove crowdsentinel 2>/dev/null && \
                print_success "Removed MCP server configuration" || \
                print_warning "Could not remove via CLI (may not exist)"
        fi
    fi

    # Remove local config
    if [ -f "$SCRIPT_DIR/.mcp_transport_config" ]; then
        if [ "$DRY_RUN" = true ]; then
            print_dry_run "Would remove: $SCRIPT_DIR/.mcp_transport_config"
        else
            rm -f "$SCRIPT_DIR/.mcp_transport_config"
            print_success "Removed local transport config"
        fi
    fi

    print_success "Uninstall complete"
    exit 0
}

################################################################################
# Print Summary
################################################################################

print_summary() {
    print_header "Setup Complete!"

    if [ "$DRY_RUN" = true ]; then
        echo -e "${MAGENTA}════════════════════════════════════════════════════════════${NC}"
        echo -e "${MAGENTA}  DRY RUN COMPLETE - No changes were made${NC}"
        echo -e "${MAGENTA}════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Run without --dry-run to apply changes:"
        echo "  ./setup.sh"
        echo ""
        return
    fi

    echo -e "${GREEN}✓ CrowdSentinel MCP Server is ready!${NC}"
    echo ""

    echo "Configuration Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Data Source: $ES_HOST"
    if [ -n "$ES_API_KEY" ]; then
        echo "  Authentication: API Key"
    else
        echo "  Authentication: Username ($ES_USERNAME)"
    fi
    echo "  SSL Verification: $VERIFY_CERTS"
    echo "  Read-Only Mode: $DISABLE_HIGH_RISK"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    echo "Detection Rules:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local eql_count=$(find rules/ -name "*.eql" 2>/dev/null | wc -l)
    local lucene_count=$(find rules/ -name "*.lucene" 2>/dev/null | wc -l)
    local sigma_count=$(find chainsaw/sigma -name "*.yml" 2>/dev/null | wc -l)
    echo "  EQL Rules: $eql_count"
    echo "  Lucene Rules: $lucene_count"
    echo "  Sigma Rules: $sigma_count"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    echo "Available Tools: 90+"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  • Threat Hunting (20 tools)"
    echo "  • Detection Rules (8 tools, 5,000+ rules)"
    echo "  • ES|QL Hunting (6 tools)"
    echo "  • IoC Analysis (11 tools)"
    echo "  • Investigation Prompts (5 tools)"
    echo "  • Cyber Kill Chain (5 tools)"
    echo "  • Chainsaw EVTX Analysis (6 tools) $([ -f "$SCRIPT_DIR/chainsaw/chainsaw" ] && echo '✓' || echo '✗ NOT INSTALLED')"
    echo "  • Network Analysis (18 tools) $(command -v tshark &>/dev/null && echo '✓' || echo '✗ tshark not installed')"
    echo "  • Investigation State (9 tools)"
    echo "  • Standard Elasticsearch (18 tools)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # MCP status - check both config and actual connectivity
    echo "MCP Server Status:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local mcp_configured=false
    local mcp_scope="not configured"

    if command -v claude &>/dev/null; then
        local mcp_list_output
        mcp_list_output=$(claude mcp list 2>&1)

        if echo "$mcp_list_output" | grep -q "crowdsentinel"; then
            mcp_configured=true
            # Try to detect scope from output
            if echo "$mcp_list_output" | grep -A1 "crowdsentinel" | grep -qi "user"; then
                mcp_scope="user (all projects)"
            elif echo "$mcp_list_output" | grep -A1 "crowdsentinel" | grep -qi "local\|project"; then
                mcp_scope="local (this project only)"
            else
                mcp_scope="configured"
            fi
        fi
    fi

    if [ "$mcp_configured" = true ]; then
        echo "  ✓ crowdsentinel: $mcp_scope"
        echo ""
        echo "  To verify in Claude Code, run: /mcp"
        echo "  You should see 'crowdsentinel' in the list"
    else
        echo "  ✗ NOT CONFIGURED"
        echo ""
        echo "  To fix, run one of:"
        echo "  Project only:  claude mcp add crowdsentinel -- uv --directory \"$SCRIPT_DIR\" run crowdsentinel-mcp-server"
        echo "  All projects:  claude mcp add crowdsentinel -s user -- uv --directory \"$SCRIPT_DIR\" run crowdsentinel-mcp-server"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Agent Skills status
    echo "Agent Skills:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local skill_path="$HOME/.claude/skills/crowdsentinel-skills"
    if [ -d "$skill_path" ] && [ -f "$skill_path/SKILL.md" ]; then
        echo "  ✓ CrowdSentinel Skills installed"
        echo "    Location: $skill_path"
        local script_count=$(find "$skill_path/scripts" -name "*.sh" -o -name "*.py" 2>/dev/null | wc -l)
        local ref_count=$(find "$skill_path/references" -name "*.md" 2>/dev/null | wc -l)
        echo "    Scripts: $script_count | References: $ref_count"
    else
        echo "  ✗ Skills not installed"
        echo "    Run setup.sh again to install, or manually copy:"
        echo "    cp -r skills/crowdsentinel-skills ~/.claude/skills/"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    echo "Next Steps:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  1. Open a new terminal and run: claude"
    echo "  2. Type: /mcp"
    echo "  3. Verify 'crowdsentinel' appears in the list"
    echo "  4. Test with: 'Discover all assets in my cluster'"
    echo ""
    echo "Troubleshooting:"
    echo "  • If /mcp shows nothing: Restart Claude Code (exit and run 'claude' again)"
    echo "  • If still not listed, add manually:"
    echo "    claude mcp add crowdsentinel -- uv --directory \"$SCRIPT_DIR\" run crowdsentinel-mcp-server"
    echo "  • If server errors: Check Elasticsearch is running and credentials are correct"
    echo "  • Run setup again: ./setup.sh"
    echo ""
    echo "Documentation:"
    echo "  • Quick Start: QUICK_START.md"
    echo "  • Threat Hunting: THREAT_HUNTING_GUIDE.md"
    echo "  • Detection Rules: DETECTION_RULES_GUIDE.md"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

################################################################################
# Main Setup Flow
################################################################################

main() {
    # Parse command line arguments
    parse_args "$@"

    # Handle uninstall
    if [ "$UNINSTALL" = true ]; then
        uninstall
    fi

    clear

    # Banner
    echo -e "${CYAN}"
    cat << "EOF"
   ______                       _______            __  _            __
  / ____/________ _      ______/ / ___/___  ____  / /_(_)___  ___  / /
 / /   / ___/ __ \ | /| / / __  /\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
/ /___/ /  / /_/ / |/ |/ / /_/ /___/ /  __/ / / / /_/ / / / /  __/ /  
\____/_/   \____/|__/|__/\__,_//____/\___/_/ /_/\__/_/_/ /_/\___/_/   
                                                                      
EOF
    echo -e "${NC}"
    echo -e "${BOLD}  AI-Powered Threat Hunting & Incident Response${NC}"
    echo -e "  Version: ${VERSION}"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        echo -e "${MAGENTA}════════════════════════════════════════════════════════════${NC}"
        echo -e "${MAGENTA}  DRY RUN MODE - No changes will be made${NC}"
        echo -e "${MAGENTA}════════════════════════════════════════════════════════════${NC}"
        echo ""
    fi

    echo "This script will:"
    echo "  • Check and install prerequisites"
    echo "  • Download detection rules (5,000+ rules)"
    echo "  • Set up Chainsaw for EVTX log analysis"
    echo "  • Configure your data source connection"
    echo "  • Set up Claude authentication"
    echo "  • Configure the MCP server"
    echo "  • Install CrowdSentinel agent skills (optional)"
    echo ""

    if ! confirm "Continue with setup?"; then
        echo "Setup cancelled."
        exit 1
    fi

    # Detect OS first
    detect_os

    # Run setup steps
    check_and_install_prerequisites
    ensure_python_version
    install_dependencies
    setup_detection_rules
    setup_chainsaw
    verify_tshark
    configure_data_source

    # Validate connection
    if ! validate_connection; then
        print_error "Connection validation failed"
        if ! confirm "Continue anyway?"; then
            exit 3
        fi
    fi

    setup_claude_auth
    configure_mcp_server
    install_crowdsentinel_skills
    print_summary

    print_success "Setup completed successfully!"
}

################################################################################
# Run Main
################################################################################

main "$@"
