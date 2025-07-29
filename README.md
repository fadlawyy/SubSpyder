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

### 🔑 API Keys Setup

**Important**: Before using SubSpyder, you need to configure your API keys. Follow these steps:

1. **Copy the template configuration file:**
   ```bash
   cp subspyder_config_template.ini subspyder_config.ini
   ```

2. **Edit `subspyder_config.ini` and add your API keys:**

   ```ini
   [API_KEYS]
   # Get your API keys from the respective services
   virustotal_api_key = YOUR_VIRUSTOTAL_API_KEY_HERE
   securitytrails_api_key = YOUR_SECURITYTRAILS_API_KEY_HERE
   shodan_api_key = YOUR_SHODAN_API_KEY_HERE
   dnsdumpster_api_key = YOUR_DNSDUMPSTER_API_KEY_HERE
   criminalip_api_key = YOUR_CRIMINALIP_API_KEY_HERE
   gemini_api_key = YOUR_GEMINI_API_KEY_HERE

   [SETTINGS]
   timeout = 10
   delay = 1
   output_file = subspyder_results.json
   discord_webhook_url = YOUR_DISCORD_WEBHOOK_URL_HERE
   enable_discord_notifications = false
   ```

### 🔗 API Key Sources

| Service | URL | Description |
|---------|-----|-------------|
| **VirusTotal** | https://www.virustotal.com/gui/join-us | Free account with API access |
| **SecurityTrails** | https://securitytrails.com/app/api | Free tier available |
| **Shodan** | https://account.shodan.io/register | Free account with limited queries |
| **DNSDumpster** | https://dnsdumpster.com/ | Free service |
| **Criminal IP** | https://www.criminalip.io/ | Free tier available |
| **Google Gemini** | https://makersuite.google.com/app/apikey | Free API key |

### 🔒 Security Note

- **Never commit your `subspyder_config.ini` file** with real API keys to version control
- The `.gitignore` file is configured to exclude this file
- Use the template file (`subspyder_config_template.ini`) as a reference
- Consider using environment variables for production deployments

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

## 🚀 Getting Started

### Quick Start
```bash
# 1. Clone the repository
git clone <repository-url>
cd SubSpyder

# 2. Install dependencies
pip install -e .

# 3. Set up configuration
cp subspyder_config_template.ini subspyder_config.ini
# Edit subspyder_config.ini with your API keys

# 4. Run your first scan
python subspyder_cli.py example.com
```

### 📖 Detailed Setup
For detailed setup instructions, see [SETUP_GUIDE.md](SETUP_GUIDE.md).

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone and setup development environment
git clone <repository-url>
cd SubSpyder
pip install -e .
pip install -r requirements-dev.txt  # If available
```

## 🐛 Bug Reports

If you find a bug, please open an issue with:
- Detailed description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your configuration (without API keys)

## ⚠️ Disclaimer

This tool is designed for **authorized security testing and research purposes only**. 

**⚠️ Important Legal Notice:**
- Always ensure you have **proper authorization** before scanning any domain
- This tool should only be used on domains you own or have explicit permission to test
- The authors are not responsible for any misuse of this tool
- Users are responsible for complying with all applicable laws and regulations

## 📞 Support

- **Documentation**: [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/subspyder/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/subspyder/discussions)

## ⭐ Star History

If you find this tool useful, please consider giving it a star on GitHub! 