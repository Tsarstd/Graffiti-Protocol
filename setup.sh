#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}==>${NC} ${GREEN}$1${NC}"
}

print_warn() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

run_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo &> /dev/null; then
        if sudo -n true 2>/dev/null; then
            sudo "$@"
        else
            echo -e "${YELLOW}INFO:${NC} The following command requires root access.: $*"
            sudo "$@"
        fi
    else
        print_warn "Sudo not found and user is not root. Command '$*' it might fail."
        "$@"
    fi
}

# 1. INSTALL RUST (via rustup)
print_step "1/9: Checking/Installing Rust..."
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

# 2. INSTALL CMAKE
print_step "2/9: Checking/Installing CMake..."
if ! command -v cmake &> /dev/null; then
    echo "CMake not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_sudo apt-get update && run_sudo apt-get install -y cmake
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install cmake
        else
            print_warn "Homebrew not found. Please install CMake manually."
        fi
    else
        print_warn "Unsupported OS for automatic CMake installation. Please install CMake manually."
    fi
else
    echo "CMake is already installed."
fi

# 3. INSTALL PYTHON
print_step "3/9: Checking/Installing Python..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_sudo apt-get update && run_sudo apt-get install -y python3 python3-venv python3-pip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install python
        else
            print_warn "Homebrew not found. Please install Python manually."
        fi
    fi
else
    echo "Python3 is already installed."
fi

# 4. INSTALL WEBSITE REQUIREMENTS ( Frontend Explorer )
print_step "4/9: Checking/Installing Node.js & Frontend Explorer Dependencies..."
if ! command -v npm &> /dev/null; then
    echo "npm not found. Installing Node.js..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_sudo apt-get update && run_sudo apt-get install -y nodejs npm
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install node
        else
            print_warn "Homebrew not found. Please install Node.js manually."
        fi
    fi
fi

if command -v npm &> /dev/null; then
    echo "Installing Frontend Explorer dependencies..."
    (cd src/web/Frontend && npm install)
else
    print_warn "npm is still not available. Skipping frontend dependencies."
fi

# 5. INSTALL FFMPEG (for video thumbnails in Web Backend)
print_step "5/9: Checking/Installing FFmpeg (for video thumbnails)..."
if ! command -v ffmpeg &> /dev/null; then
    echo "ffmpeg not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_sudo apt-get update && run_sudo apt-get install -y ffmpeg
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install ffmpeg
        else
            print_warn "Homebrew not found. Please install ffmpeg manually."
        fi
    else
        print_warn "Unsupported OS for automatic ffmpeg installation. Please install ffmpeg manually."
    fi
else
    echo "ffmpeg is already installed."
fi

# 6. SETUP VIRTUAL ENVIRONMENT
print_step "6/9: Setting up Python Virtual Environment (.venv)..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

# 7. INSTALL MATURIN
print_step "7/9: Installing Maturin..."
.venv/bin/pip install --upgrade pip maturin
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_step "7.1/9: Installing patchelf for Linux rpath support..."
    if ! command -v patchelf &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            run_sudo apt-get update && run_sudo apt-get install -y patchelf
        elif command -v dnf &> /dev/null; then
            run_sudo dnf install -y patchelf
        elif command -v brew &> /dev/null; then
            brew install patchelf
        else
            print_warn "Could not install patchelf. Build will still work but may have warnings."
            print_warn "You can install manually or via: pip install patchelf"
        fi
    else
        echo "patchelf already installed."
    fi
fi

# 8. INSTALL REQUIREMENTS
print_step "8/9: Installing Python Requirements..."
.venv/bin/pip install -r requirements.txt

# 9. BUILD NATIVE EXTENSION
print_step "9/9: Building Native Extension (tsarcore_native)..."
cd tsarcore_native
../.venv/bin/maturin develop --release --features parallel
cd ..

# --- ACTIVATE ENVIRONMENT ---
print_step "Creating helper script 'activate_env.sh' for easy environment activation..."
cat > activate_env.sh << 'EOF'
#!/usr/bin/env bash
# Helper script to activate venv and set PYTHONPATH
# USAGE: source activate_env.sh
echo -e "\033[0;34mActivating virtual environment...\033[0m"
source .venv/bin/activate
export PYTHONPATH="$PWD/src"
echo -e "\033[0;32mEnvironment ready! PYTHONPATH is set to $PYTHONPATH\033[0m"
echo -e "\033[0;32mYou are now in the virtual environment.\033[0m"
EOF
chmod +x activate_env.sh

# --- FINAL OUTPUT ---
print_step "DONE!! Setup is complete."
echo ""
echo -e "${YELLOW}================================================================${NC}"
echo -e "${GREEN}Graffiti Protocol environment is ready!${NC}"
echo ""
echo -e "To activate the environment (with PYTHONPATH already set),"
echo -e "run the following command in your terminal:"
echo ""
echo -e "    ${BLUE}source activate_env.sh${NC}"
echo ""
echo -e "After that, you can run your applications, benchmarks, or tests."
echo ""
echo -e "${YELLOW}================================================================${NC}"