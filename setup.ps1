$ErrorActionPreference = "Stop"

function Print-Step {
    param([string]$Text)
    Write-Host -ForegroundColor Cyan "==> " -NoNewline
    Write-Host -ForegroundColor Green $Text
}

function Print-Warn {
    param([string]$Text)
    Write-Host -ForegroundColor Yellow "WARNING: $Text"
}

# 1. INSTALL RUST (via rustup)
Print-Step "1/9: Checking/Installing Rust..."
if (!(Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "Rust not found. Downloading and installing via rustup..."
    Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile "rustup-init.exe"
    .\rustup-init.exe -y
    Remove-Item ".\rustup-init.exe" -Force
    $env:Path += ";$env:USERPROFILE\.cargo\bin"
} else {
    Write-Host "Rust is already installed."
}

# 2. INSTALL CMAKE
Print-Step "2/9: Checking/Installing CMake..."
if (!(Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "CMake not found. Installing via winget..."
    winget install -e --id Kitware.CMake --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "CMake is already installed."
}

# 3. INSTALL PYTHON
Print-Step "3/9: Checking/Installing Python..."
if (!(Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Installing Python 3.12 via winget..."
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "Python is already installed."
}

# 4. INSTALL WEBSITE REQUIREMENTS ( Frontend Explorer )
Print-Step "4/9: Checking/Installing Node.js & Frontend Explorer Dependencies..."
if (!(Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "npm not found. Installing Node.js via winget..."
    winget install -e --id OpenJS.NodeJS --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

if (Get-Command "npm" -ErrorAction SilentlyContinue) {
    Write-Host "Installing Frontend Explorer dependencies..."
    Push-Location "src\web\Frontend"
    npm install
    Pop-Location
} else {
    Print-Warn "npm is still not available. Please install Node.js manually. Skipping frontend dependencies."
}

# 5. INSTALL FFMPEG (for video thumbnails in Web Backend)
Print-Step "5/9: Checking/Installing FFmpeg (for video thumbnails)..."
if (!(Get-Command "ffmpeg" -ErrorAction SilentlyContinue)) {
    Write-Host "ffmpeg not found. Installing via winget..."
    winget install -e --id Gyan.FFmpeg --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "ffmpeg is already installed."
}

# 6. SETUP VIRTUAL ENVIRONMENT
Print-Step "6/9: Setting up Python Virtual Environment (.venv)..."
if (!(Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Virtual environment created."
} else {
    Write-Host "Virtual environment already exists."
}

# 7. INSTALL MATURIN
Print-Step "7/9: Installing Maturin..."
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip maturin

# 8. INSTALL REQUIREMENTS
Print-Step "8/9: Installing Python Requirements..."
& ".\.venv\Scripts\pip.exe" install -r requirements.txt

# 9. BUILD NATIVE EXTENSION
Print-Step "9/9: Building Native Extension (tsarcore_native)..."
Push-Location "tsarcore_native"
& "..\.venv\Scripts\maturin.exe" develop --release --features parallel
Pop-Location

# --- ACTIVATE ENVIRONMENT ---
Print-Step "Creating helper script 'activate_env.ps1' for easy environment activation..."
$helperScript = @"
# Helper script to activate venv and set PYTHONPATH
# USAGE: .\activate_env.ps1
Write-Host "Activating virtual environment..." -ForegroundColor Cyan
.\.venv\Scripts\Activate.ps1
`$env:PYTHONPATH = "`$PWD\src"
Write-Host "Environment ready! PYTHONPATH is set to `$env:PYTHONPATH" -ForegroundColor Green
Write-Host "You are now in the virtual environment." -ForegroundColor Green
"@
$helperScript | Out-File -FilePath "activate_env.ps1" -Encoding utf8

# --- CHECK EXECUTION POLICY ---
Print-Step "Checking PowerShell Execution Policy..."
$currentPolicy = Get-ExecutionPolicy
if ($currentPolicy -eq "Restricted") {
    Write-Host ""
    Print-Warn "Your PowerShell Execution Policy is set to 'Restricted'."
    Write-Host "This will prevent you from running '.\activate_env.ps1'."
    Write-Host "To fix this, please run PowerShell as Administrator and execute:" -ForegroundColor Yellow
    Write-Host "    Set-ExecutionPolicy RemoteSigned" -ForegroundColor Cyan
    Write-Host ""
}

# --- FINAL OUTPUT ---
Print-Step "DONE!! Setup is complete."
Write-Host ""
Write-Host -ForegroundColor Yellow "================================================================"
Write-Host -ForegroundColor Green "Graffiti Protocol environment is ready!"
Write-Host ""
Write-Host "To activate the environment (with PYTHONPATH already set),"
Write-Host "run the following command in your PowerShell terminal:"
Write-Host ""
Write-Host -ForegroundColor Cyan "    . .\activate_env.ps1"
Write-Host ""
Write-Host "After that, you can run your applications, benchmarks, or tests."
Write-Host ""
Write-Host -ForegroundColor Yellow "================================================================"