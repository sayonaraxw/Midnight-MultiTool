#!/bin/bash

#################################################
# MIDNIGHT MULTI-TOOL Installation Script
# For Linux and macOS
#################################################

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           MIDNIGHT MULTI-TOOL Installer                  ║"
echo "║           For Linux and macOS                            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and install package
check_and_install_pkg() {
    local pkg_name="$1"
    local pkg_import_name="${2:-$pkg_name}"
    local feature_desc="$3"

    echo -e "${YELLOW}[*] Checking dependency: ${pkg_name} (${feature_desc})...${NC}"
    if python3 -c "import ${pkg_import_name}" 2>/dev/null; then
        echo -e "${GREEN}[+] Module '${pkg_name}': Ready.${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Module '${pkg_name}' is missing.${NC}"
        read -p "$(echo -e ${CYAN}'[?] Install automatically via pip? (y/n): '${NC})" INSTALL_CONFIRM
        if [[ "$INSTALL_CONFIRM" == "y" || "$INSTALL_CONFIRM" == "Y" ]]; then
            echo -e "${YELLOW}[*] Installing '${pkg_name}'...${NC}"
            if $PIP_COMMAND install "$pkg_name" >/dev/null 2>&1; then
                if python3 -c "import ${pkg_import_name}" 2>/dev/null; then
                    echo -e "${GREEN}[+] '${pkg_name}' installed successfully.${NC}"
                    return 0
                else
                    echo -e "${RED}[!] Installation failed or module still not found.${NC}"
                    return 1
                fi
            else
                echo -e "${RED}[!] Failed to install '${pkg_name}'. Please install manually:${NC}"
                echo -e "${CYAN}   $PIP_COMMAND install ${pkg_name}${NC}"
                return 1
            fi
        else
            echo -e "${RED}[!] '${pkg_name}' is required. Aborting.${NC}"
            return 1
        fi
    fi
}

# Check Python 3
echo -e "${BLUE}[*] Checking system requirements...${NC}"
if ! command_exists python3; then
    echo -e "${RED}[!] Error: Python 3 not found.${NC}"
    echo -e "${YELLOW}[!] Please install Python 3:${NC}"
    echo -e "${CYAN}   - Ubuntu/Debian: sudo apt install python3${NC}"
    echo -e "${CYAN}   - macOS: brew install python3${NC}"
    echo -e "${CYAN}   - Or download from: https://www.python.org/downloads/${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[+] Python 3 detected: ${PYTHON_VERSION}${NC}"

# Check pip
if python3 -m pip --version >/dev/null 2>&1; then
    PIP_COMMAND="python3 -m pip"
elif command_exists pip3; then
    PIP_COMMAND="pip3"
else
    echo -e "${RED}[!] Error: pip not found.${NC}"
    echo -e "${YELLOW}[!] Installing pip...${NC}"
    if python3 -m ensurepip --upgrade 2>/dev/null; then
        PIP_COMMAND="python3 -m pip"
        echo -e "${GREEN}[+] pip installed successfully.${NC}"
    else
        echo -e "${RED}[!] Failed to install pip automatically.${NC}"
        echo -e "${YELLOW}[!] Please install pip manually:${NC}"
        echo -e "${CYAN}   - Ubuntu/Debian: sudo apt install python3-pip${NC}"
        echo -e "${CYAN}   - macOS: python3 -m ensurepip --upgrade${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}[+] pip detected: $($PIP_COMMAND --version | awk '{print $1, $2}')${NC}"

# Upgrade pip
echo -e "${BLUE}[*] Upgrading pip to latest version...${NC}"
$PIP_COMMAND install --upgrade pip --quiet --disable-pip-version-check 2>/dev/null || true

# Check if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo -e "${BLUE}[*] Installing dependencies from requirements.txt...${NC}"
    if $PIP_COMMAND install -r requirements.txt --quiet --disable-pip-version-check; then
        echo -e "${GREEN}[+] All dependencies installed successfully.${NC}"
    else
        echo -e "${YELLOW}[!] Some dependencies may have failed. Checking individually...${NC}"
    fi
else
    echo -e "${YELLOW}[!] requirements.txt not found. Checking dependencies individually...${NC}"
fi

# Check individual dependencies
echo -e "${BLUE}[*] Verifying required Python modules...${NC}"
check_and_install_pkg "cryptography" "cryptography" "Core Encryption" || exit 1
check_and_install_pkg "requests" "requests" "Web Features" || exit 1
check_and_install_pkg "python-whois" "whois" "Whois Lookup" || exit 1
check_and_install_pkg "dnspython" "dns.resolver" "DNS Lookup" || exit 1
check_and_install_pkg "psutil" "psutil" "System Info" || exit 1
check_and_install_pkg "pystyle" "pystyle" "UI Styling" || exit 1
check_and_install_pkg "tqdm" "tqdm" "Progress Bars" || exit 1
check_and_install_pkg "colorama" "colorama" "Colors" || exit 1
check_and_install_pkg "pyyaml" "yaml" "YAML Config" || true  # Optional

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}[*] To run the tool, use one of the following:${NC}"
echo -e "${YELLOW}   1. python3 main.py${NC}"
echo -e "${YELLOW}   2. ./run.sh${NC}"
echo ""
echo -e "${CYAN}[*] Or make run.sh executable and run it:${NC}"
echo -e "${YELLOW}   chmod +x run.sh && ./run.sh${NC}"
echo ""
