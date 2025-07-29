# SubSpyder - Advanced Subdomain Enumeration Tool

A comprehensive, modular subdomain enumeration tool that combines multiple advanced techniques for discovering subdomains of any target domain. Built with modern Python packaging practices for maintainability and extensibility.

## 🚀 Features

### Module 1: Passive Enumeration
- **crt.sh**: Certificate transparency logs
- **VirusTotal**: Public threat intelligence
- **Wayback Machine**: Historical web archives
- **Shodan**: Internet-wide scan data

### Module 2: Active Brute Force
- **Wordlist-based discovery**: Systematic subdomain testing
- **Multi-threaded scanning**: Fast and efficient enumeration
- **Status code validation**: HTTP/HTTPS response verification

### Module 3: AI-Powered Prediction
- **Gemini AI Integration**: Intelligent subdomain prediction
- **Website type detection**: Context-aware suggestions
- **Pattern recognition**: Learning from discovered subdomains

### Module 4: Comprehensive Validation & Notifications
- **Async validation**: High-performance subdomain checking
- **Discord notifications**: Real-time results via webhooks
- **Live/dead classification**: Detailed status reporting
- **IP resolution**: DNS validation for all subdomains

## 📋 Requirements

### 💻 Python Requirements
- Python 3.8 or higher
- pip package manager

### 🐳 Docker (Optional)
- Docker Engine 20.10+
- Docker Compose 2.0+ (optional)

## 🛠️ Installation

### Method 1: Install as Package (Recommended)
```bash
# Install from current directory
pip install -e .

# Or install directly
pip install -r requirements.txt
```

### Method 2: Local Development
```bash
# Clone and install in development mode
git clone <repository-url>
cd subspyder
pip install -e .
```

### Method 3: Docker Installation
```bash
# Build and run with Docker
docker build -t subspyder .
docker run --rm subspyder --help
```

## 📦 Package Structure

```
subspyder/
├── __init__.py              # Package initialization and exports
├── core/                    # Core components
│   ├── __init__.py
│   ├── config.py           # Configuration management
│   └── subspyder.py        # Main orchestrator class
├── modules/                 # Enumeration modules
│   ├── __init__.py
│   ├── passive.py          # Passive enumeration
│   ├── active.py           # Active brute force
│   ├── ai_predictor.py     # AI-powered prediction
│   └── validator.py        # Validation and Discord
└── utils/                   # Utility functions
    ├── __init__.py
    ├── helpers.py          # Helper functions
    └── discord.py          # Discord notification utilities
```

## ⚙️ Configuration

Edit `subspyder_config.ini` to configure API keys and settings:

```ini
[API_KEYS]
virustotal_api_key = your_virustotal_key
securitytrails_api_key = your_securitytrails_key
shodan_api_key = your_shodan_key
dnsdumpster_api_key = your_dnsdumpster_key
criminalip_api_key = your_criminalip_key
gemini_api_key = your_gemini_key

[SETTINGS]
timeout = 10
delay = 1
output_file = subspyder_results.json
discord_webhook_url = your_discord_webhook_url
enable_discord_notifications = false
```

## 🎯 Usage

### 🚀 Quick Start

#### Command Line Interface
```bash
# Basic usage
python subspyder_cli.py example.com

# With custom options
python subspyder_cli.py example.com -o results.json --status-codes 200,403,500

# Test Discord webhook
python subspyder_cli.py --test-discord

# Show configuration
python subspyder_cli.py --config
```

#### Python Package Usage
```python
from subspyder import CompleteSubSpyder, run_enumeration

# Simple one-liner
results = run_enumeration("example.com")

# Advanced usage
subspyder = CompleteSubSpyder(accepted_status_codes=[200, 403, 500])
results = subspyder.run_complete_enumeration("example.com", "custom_wordlist.txt")
subspyder.save_results(results, "results.json")
```

#### Individual Module Usage
```python
from subspyder import PassiveEnumerator, AIPredictor
from subspyder.core.config import Config

config = Config()

# Use only passive enumeration
passive = PassiveEnumerator(config)
results = passive.enumerate_passive("example.com")

# Use only AI prediction
ai = AIPredictor(config)
predictions = ai.predict_subdomains("example.com", ["www.example.com"])
```

### 🐳 Docker Usage

#### Quick Start with Docker
```bash
# Build and run
docker build -t subspyder .
docker run --rm subspyder example.com

# With custom options
docker run --rm subspyder example.com -o results.json --status-codes 200,403,500
```

#### Docker Compose
```bash
# Run with docker-compose
docker-compose run --rm subspyder example.com

# With environment variables
export VIRUSTOTAL_API_KEY="your_key"
docker-compose run --rm subspyder example.com
```

## 📊 Output

The tool generates a comprehensive JSON report with:

```json
{
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "mail.example.com"
  ]
}
```

## 🔔 Discord Notifications

Enable Discord notifications by:

1. Setting `discord_webhook_url` in `subspyder_config.ini`
2. Setting `enable_discord_notifications = true`

Notifications include:
- Live/dead subdomain counts
- HTTP/HTTPS status codes
- IP addresses
- Timestamp and summary

#### Testing Discord Notifications

Test your Discord webhook configuration:

```bash
# Using the main script
python subspyder.py --test-discord

# Using the dedicated test script
python test_discord.py

# Using Docker
docker run --rm -v $(pwd)/subspyder_config.ini:/app/subspyder_config.ini:ro subspyder --test-discord
```

#### Discord Webhook Setup

1. **Create a Discord webhook:**
   - Go to your Discord server settings
   - Navigate to Integrations → Webhooks
   - Create a new webhook
   - Copy the webhook URL

2. **Configure the webhook:**
   ```ini
   [SETTINGS]
   discord_webhook_url = https://discord.com/api/webhooks/YOUR_WEBHOOK_URL
   enable_discord_notifications = true
   ```

3. **Test the configuration:**
   ```bash
   python subspyder.py --test-discord
   ```

## 🏗️ Architecture

### Application Architecture
```
CompleteSubSpyder
├── Config (Configuration management)
├── PassiveEnumerator (Module 1)
├── ActiveEnumerator (Module 2)
├── AIPredictor (Module 3)
└── SubdomainValidator (Module 4)
```

### Docker Architecture
```
SubSpyder Container
├── Python 3.11 Runtime
├── Dependencies (requests, aiohttp, shodan, etc.)
├── Application Code (subspyder.py)
├── Configuration (subspyder_config.ini)
├── Wordlist (wordlist.txt)
└── Volume Mounts
    ├── Results Directory
    ├── Custom Config
    └── Custom Wordlist
```

### Docker Benefits
- **Consistent Environment**: Same behavior across different systems
- **Easy Deployment**: No need to install Python dependencies locally
- **Isolation**: Runs in isolated container environment
- **Portability**: Works on any system with Docker
- **Resource Management**: Built-in resource limits and monitoring

## 📈 Performance

- **Passive enumeration**: ~30-60 seconds
- **Brute force**: Depends on wordlist size
- **AI prediction**: ~10-20 seconds
- **Validation**: Async processing, ~100 subdomains/second

## 🔧 Troubleshooting

### Docker Issues

1. **Docker not running**: Ensure Docker Desktop is started
2. **Permission errors**: Run Docker commands with appropriate permissions
3. **Volume mounting**: Check file paths and permissions for mounted volumes
4. **Image build failures**: Check Dockerfile and dependencies

### Common Issues

1. **API Key Errors**: Check your API keys in `subspyder_config.ini`
2. **Timeout Errors**: Increase timeout value in settings
3. **Discord Notifications**: Verify webhook URL and permissions
4. **Wordlist Issues**: Ensure wordlist file exists and is readable

### Debug Mode

Enable logging by modifying the logging level in the SubdomainValidator class.

### Docker Debug Commands

```bash
# Check Docker status
docker info

# View container logs
docker logs <container_id>

# Run with debug output
docker run --rm -it subspyder --help

# Check image contents
docker run --rm -it subspyder ls -la
```

## 📝 License

This tool is for educational and authorized security testing purposes only.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ⚠️ Disclaimer

This tool is designed for authorized security testing and research purposes only. Always ensure you have proper authorization before scanning any domain. 