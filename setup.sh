#!/bin/bash

echo "[*] Upgrading pip..."
python3 -m ensurepip --quiet 2>/dev/null
python3 -m pip install --upgrade pip --quiet --disable-pip-version-check

echo "[*] Installing required Python packages from requirements.txt..."
python3 -m pip install -r requirements.txt --quiet --disable-pip-version-check

if [ $? -ne 0 ]; then
    echo "[!] Failed to install some requirements. Check your internet connection or requirements.txt."
    exit 1
fi

echo "[*] Setup Complete! You can now run MIDNIGHT MULTI-TOOL using 'python3 main.py' or './run.sh'"
