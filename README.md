# 🌙 MIDNIGHT MULTI-TOOL

A powerful command-line multi-tool suite with a midnight aesthetic, combining various utilities for cryptography, network analysis, data manipulation, and system information. Built with Python featuring modular architecture and a beautiful gradient-based command-line interface.

---

## ✨ Features

### 🔐 Cryptography Tools

- **Encrypt/Decrypt Text** - Symmetric encryption of text messages using a password (AES-256 via Fernet, PBKDF2 with 480,000 iterations)
- **Encrypt/Decrypt Files** - Full file encryption of any size with streaming processing for large files
- **Hash Calculator** - Calculate hashes (MD5, SHA-1, SHA-256, SHA-512) for text and files
- **Password Generator** - Create strong random passwords with customizable length and character sets

### 🌐 Network Tools

- **Port Scanner** - Scan target IP or hostname for open TCP ports (common ports or custom range)
- **Whois Domain Lookup** - Retrieve public registration information for a domain name
- **DNS Lookup** - Query various DNS record types (A, AAAA, MX, TXT, NS, CNAME)
- **HTTP Headers Viewer** - Fetch and display HTTP response headers from a given URL
- **Website Cookie Viewer** - View cookies set by the server in the response

### 💻 Data Utilities

- **Encode/Decode** - Encode and decode data in Base64 and Hexadecimal formats

### ⚙️ System Utilities

- **System Information** - Display basic information about the operating system, architecture, and Python version
- **Process List** - Show a list of running processes on the local machine (PID, Username, Name)

### 🚀 Additional Features

- **Modular Architecture** - Clear separation of functionality into modules
- **Colorized Interface** - ASCII art and colorized output for enhanced user experience
- **Automatic Dependency Check** - Installation script automatically checks for required libraries
- **Configurability** - Support for YAML/JSON configuration files
- **Logging** - Built-in logging system for operations
- **Error Handling** - Extended error handling with custom exceptions
- **Operation Auditing** - Logging of critical operations for security

---

## ⚠️ Disclaimer and Ethical Use

**This tool includes features (such as port scanner) that can be misused for malicious purposes.**

- ✅ **This tool is intended ONLY for educational and ethical purposes**
- ❌ **DO NOT use** this tool for illegal or malicious activities
- ❌ **DO NOT scan** networks or systems you do not have explicit permission to test
- ⚠️ The author (sayonara) is **NOT responsible** for any damage or legal consequences resulting from misuse of this tool
- ⚠️ Use at your own risk

---

## 📋 Requirements

### System Requirements

- **OS**: Linux, macOS, or Windows (via WSL) - Linux/Unix-like system recommended due to Bash installation script
- **Python**: version 3.6 or higher (3.8+ recommended)
- **pip**: Python 3 package manager
- **Git**: for cloning the repository (optional)
- **Internet Connection**: for cloning the repository and installing dependencies

### Required Python Dependencies

- `cryptography` - Core encryption (AES-256, Fernet)
- `requests` - Web features (HTTP requests, cookies, headers)
- `python-whois` - Whois Lookup
- `dnspython` - DNS Lookup
- `psutil` - Process and system information
- `tqdm` - Progress bars for long-running operations
- `pystyle` - UI styling and gradient colors
- `colorama` - Cross-platform colored terminal text

### Optional Dependencies

- `pyyaml` - YAML configuration file support

---

## 🛠️ Installation

### Method 1: Quick Setup Script (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sayonaraxw/midnight-multitool.git
   cd midnight-multitool/"MIDNIGHT MULTI-TOOL"
   ```

2. **Run the setup script:**
   
   **For Linux/macOS:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   
   **For Windows:**
   ```cmd
   setup.bat
   ```
   
   Or using Python:
   ```bash
   python3 setup.py
   # or
   python setup.py
   ```

   The setup script will:
   - Upgrade pip to the latest version
   - Install all required dependencies from `requirements.txt`
   - Verify installation success

### Method 2: Using Virtual Environment (Recommended for Development)

This method isolates project dependencies from your system Python:

```bash
# Navigate to project directory
cd midnight-multitool/"MIDNIGHT MULTI-TOOL"

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Run setup script (will install dependencies into venv)
# Linux/macOS:
./setup.sh
# Windows:
setup.bat

# Or install manually:
pip install -r requirements.txt
```

**To deactivate the virtual environment when done:**
```bash
deactivate
```

### Method 3: Manual Dependency Installation

If you prefer to install dependencies manually:

```bash
pip3 install cryptography requests python-whois dnspython psutil tqdm pystyle colorama

# Optional, for YAML configuration support:
pip3 install pyyaml
```

---

## ▶️ Usage

After successful installation, you can run MIDNIGHT MULTI-TOOL using any of the following methods:

### Running the Application

**Option 1: Direct Python execution (Recommended)**
```bash
cd "MIDNIGHT MULTI-TOOL"
python3 main.py
# or on Windows:
python main.py
```

**Option 2: Using the interactive installer script (Linux/macOS)**
```bash
cd "MIDNIGHT MULTI-TOOL"
chmod +x encrypt-tool.sh
./encrypt-tool.sh
```
This script checks dependencies and launches the tool interactively.

**Option 3: Using batch file (Windows)**
```cmd
cd "MIDNIGHT MULTI-TOOL"
midnight.bat
```

**Note:** If you're using a virtual environment, make sure it's activated before running the application.

### Menu Structure

After launch, you will see the main menu with four main categories:

<div align="center">
  <img src="https://media.discordapp.net/attachments/1396120664682922097/1461470388318900296/image.png?ex=696aabdd&is=69695a5d&hm=b78615def68ef65c4886226e7c5203a5034118b7b1035b3dc5897bb044a99f27&=&format=webp&quality=lossless&width=1754&height=606" alt="MIDNIGHT MULTI-TOOL">
</div>

#### Cryptography Tools Menu:
- `[1]` Encrypt Text Message
- `[2]` Decrypt Text Message
- `[3]` Encrypt File
- `[4]` Decrypt File
- `[5]` Hash Calculator (MD5, SHA...)
- `[6]` Generate Strong Password
- `[0]` Back to Main Menu

#### Network Tools Menu:
- `[1]` Basic Port Scanner
- `[2]` Whois Domain Lookup
- `[3]` DNS Record Lookup
- `[4]` Get HTTP Headers
- `[5]` Get Website Cookies
- `[0]` Back to Main Menu

#### Data Utilities Menu:
- `[1]` Encode/Decode (Base64, Hex)
- `[0]` Back to Main Menu

#### System Utilities Menu:
- `[1]` Display System Information
- `[2]` List Running Processes
- `[0]` Back to Main Menu

### Usage Examples

#### Text Encryption
1. Select `[1] Cryptography Tools`
2. Select `[1] Encrypt Text Message`
3. Enter password (hidden input)
4. Enter text to encrypt
5. Copy the encrypted text (Base64)

#### Port Scanning
1. Select `[2] Network Tools`
2. Select `[1] Basic Port Scanner`
3. Enter target IP or hostname
4. Choose port range (e.g., `1-1024` or `c` for common ports)

#### Password Generation
1. Select `[1] Cryptography Tools`
2. Select `[6] Generate Strong Password`
3. Specify password length
4. Choose character sets (uppercase, lowercase, digits, symbols)

---

## 📁 Project Structure

```
MIDNIGHT MULTI-TOOL/
├── __init__.py
├── main.py                 # Application entry point
├── config.py               # Configuration and settings
├── requirements.txt        # Python dependencies
├── LICENSE                 # MIT License
├── README.md               # This file
│
├── setup.sh               # Setup script (Linux/macOS)
├── setup.py               # Setup script (Python)
├── setup.bat              # Setup script (Windows)
├── encrypt-tool.sh        # Interactive installer/launcher (Linux/macOS)
├── install.sh             # Advanced installer (Linux/macOS)
├── midnight.bat           # Launcher script (Windows)
│
├── crypto/                # Cryptographic modules
│   ├── __init__.py
│   ├── encryption.py      # Encryption/decryption (AES-256, Fernet)
│   ├── hashing.py         # Hash calculation (MD5, SHA-*)
│   └── password_gen.py    # Password generation and validation
│
├── network/               # Network modules
│   ├── __init__.py
│   ├── scanner.py         # Port scanner (multithreaded)
│   ├── dns_lookup.py      # DNS Lookup with caching
│   └── web_tools.py       # HTTP tools, Whois, cookies
│
├── utils/                 # Utility modules
│   ├── __init__.py
│   ├── encoding.py        # Base64, Hex encoding/decoding
│   ├── system_info.py     # System information display
│   ├── validators.py      # Input validation
│   ├── logger.py          # Logging system
│   ├── error_handler.py   # Error handling
│   ├── exceptions.py      # Custom exceptions
│   ├── audit.py           # Operation auditing
│   ├── dependencies.py    # Dependency checking
│   ├── export.py          # Data export utilities
│   └── updater.py         # Update checking
│
└── ui/                    # User interface modules
    ├── __init__.py
    ├── menus.py           # Application menus and navigation
    ├── colors.py          # Colorized output with gradient support
    ├── display.py         # Information display with ASCII art
    └── command_history.py # Command history tracking
```

---

## ⚙️ Configuration

The project supports configuration files in YAML or JSON formats. Create a `config.yaml` or `config.json` file in the `MIDNIGHT MULTI-TOOL/` root directory for configuration:

### Example `config.yaml`:

```yaml
encryption:
  iterations: 480000
  salt_size: 16
  key_length: 32

network:
  timeout: 0.5
  max_workers: 100
  dns_cache_ttl: 300

file_processing:
  chunk_size: 65536
  streaming_threshold: 10485760

ui:
  colors_enabled: true
  show_progress: true
  progress_bar_style: "default"

logging:
  level: "INFO"
  file: "midnight_multitool.log"
  max_size_mb: 10
```

---

## 🔧 Implementation Features

### Security

- Use of `getpass.getpass()` for hidden password input
- PBKDF2 with 480,000 iterations for key derivation
- AES-256 encryption via Fernet
- Validation of all input data
- Memory cleanup of sensitive data after use

### Performance

- Streaming processing of large files (chunked)
- Multithreaded port scanning (ThreadPoolExecutor)
- DNS query caching
- Progress bars for long-running operations

### Architecture

- Modular structure with clear separation of responsibilities
- Custom exceptions for better error handling
- Logging of all critical operations
- Input data validation system

---

## 📝 Logging

All operations are logged to the `midnight_multitool.log` file (if enabled in configuration). Logging levels:

- `DEBUG` - Detailed debug information
- `INFO` - General operational information
- `WARNING` - Warnings
- `ERROR` - Errors
- `CRITICAL` - Critical errors

**Important:** Passwords, encryption keys, and other sensitive data are **NOT logged**.

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError"

**Solution:** Make sure all dependencies are installed. Run the setup script:
```bash
# Linux/macOS:
./setup.sh

# Windows:
setup.bat

# Or manually:
pip3 install -r requirements.txt
```

### Issue: "Permission denied" when running script

**Solution:** Make the script executable:
```bash
chmod +x setup.sh
chmod +x encrypt-tool.sh
# or
chmod +x install.sh
```

### Issue: Colors not displaying in terminal

**Solution:** Make sure your terminal supports ANSI colors. On Windows, use Windows Terminal or PowerShell 7+.

### Issue: Slow port scanning

**Solution:** Adjust `max_workers` in configuration (default 100). You can also change `timeout` for faster but less accurate scanning.

---

## 📄 License

This project is distributed under the MIT license. See the `LICENSE` file for details.

---

## 📞 Support

If you have questions or issues:

1. Check the "Troubleshooting" section above
2. Open an Issue in the GitHub repository
3. Contact the author via GitHub

---

**Version:** 6.6.6  
**Last Updated:** 2025-01-27

---

*Use responsibly. Stay safe! 🌙*
