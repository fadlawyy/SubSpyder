# SubSpyder Setup Guide

## 🚀 Quick Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd SubSpyder
```

### 2. Install Dependencies
```bash
# Install as a package (recommended)
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

### 3. Configure API Keys
```bash
# Copy the template configuration file
cp subspyder_config_template.ini subspyder_config.ini

# Edit the configuration file with your API keys
# (See API Key Setup section below)
```

### 4. Test Installation
```bash
# Test the tool
python subspyder_cli.py --help

# Test with a sample domain
python subspyder_cli.py example.com
```

## 🔑 API Key Setup

### Required API Keys

SubSpyder uses several external services for comprehensive subdomain enumeration. Here's how to get each API key:

#### 1. VirusTotal API Key
- **URL**: https://www.virustotal.com/gui/join-us
- **Cost**: Free
- **Steps**:
  1. Create a free account
  2. Go to your profile settings
  3. Copy your API key
  4. Add to `subspyder_config.ini`

#### 2. SecurityTrails API Key
- **URL**: https://securitytrails.com/app/api
- **Cost**: Free tier available
- **Steps**:
  1. Sign up for a free account
  2. Navigate to API section
  3. Generate your API key
  4. Add to `subspyder_config.ini`

#### 3. Shodan API Key
- **URL**: https://account.shodan.io/register
- **Cost**: Free (limited queries)
- **Steps**:
  1. Create a free account
  2. Go to your account settings
  3. Copy your API key
  4. Add to `subspyder_config.ini`

#### 4. DNSDumpster API Key
- **URL**: https://dnsdumpster.com/
- **Cost**: Free
- **Steps**:
  1. Visit the website
  2. Use the service (no API key required for basic usage)
  3. Leave empty in config or use service directly

#### 5. Criminal IP API Key
- **URL**: https://www.criminalip.io/
- **Cost**: Free tier available
- **Steps**:
  1. Sign up for a free account
  2. Access your API dashboard
  3. Copy your API key
  4. Add to `subspyder_config.ini`

#### 6. Google Gemini API Key
- **URL**: https://makersuite.google.com/app/apikey
- **Cost**: Free
- **Steps**:
  1. Go to Google AI Studio
  2. Create a new API key
  3. Copy the key
  4. Add to `subspyder_config.ini`

### Optional: Discord Webhook Setup

For Discord notifications:

1. **Create a Discord Server** (if you don't have one)
2. **Create a Webhook**:
   - Go to Server Settings → Integrations → Webhooks
   - Click "New Webhook"
   - Give it a name (e.g., "SubSpyder Notifications")
   - Copy the webhook URL
3. **Add to Configuration**:
   ```ini
   discord_webhook_url = YOUR_WEBHOOK_URL_HERE
   enable_discord_notifications = true
   ```

## ⚙️ Configuration File

### Template Structure
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
# Request timeout in seconds
timeout = 10

# Delay between requests in seconds (to avoid rate limiting)
delay = 1

# Output file for results
output_file = subspyder_results.json

# Discord webhook URL for notifications
discord_webhook_url = YOUR_DISCORD_WEBHOOK_URL_HERE

# Enable/disable Discord notifications
enable_discord_notifications = false
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `timeout` | 10 | HTTP request timeout in seconds |
| `delay` | 1 | Delay between requests to avoid rate limiting |
| `output_file` | subspyder_results.json | Default output file name |
| `enable_discord_notifications` | false | Enable/disable Discord notifications |

## 🔒 Security Best Practices

### 1. Never Commit API Keys
- The `.gitignore` file excludes `subspyder_config.ini`
- Always use the template file as a reference
- Never share your configuration file publicly

### 2. Use Environment Variables (Optional)
For production deployments, consider using environment variables:

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
# ... etc
```

### 3. Regular Key Rotation
- Rotate your API keys periodically
- Monitor API usage to avoid rate limits
- Use different keys for different environments

## 🧪 Testing Your Setup

### 1. Test API Keys
```bash
# Test all API keys
python subspyder_cli.py --config

# Test Discord webhook
python subspyder_cli.py --test-discord
```

### 2. Test Enumeration
```bash
# Test with a simple domain
python subspyder_cli.py example.com

# Test with custom options
python subspyder_cli.py example.com -o test_results.json --status-codes 200,403
```

### 3. Verify Output
Check that the tool generates results:
```bash
# Check if results file was created
ls -la *.json

# View results
cat subspyder_results.json
```

## 🐳 Docker Setup (Optional)

### 1. Build Docker Image
```bash
docker build -t subspyder .
```

### 2. Run with Docker
```bash
# Basic usage
docker run --rm subspyder example.com

# With custom configuration
docker run --rm -v $(pwd)/subspyder_config.ini:/app/subspyder_config.ini:ro subspyder example.com
```

### 3. Docker Compose
```bash
# Run with docker-compose
docker-compose run --rm subspyder example.com
```

## 🚨 Troubleshooting

### Common Issues

#### 1. "API key not found" errors
- **Solution**: Ensure all API keys are properly set in `subspyder_config.ini`
- **Check**: Run `python subspyder_cli.py --config` to verify

#### 2. Rate limiting errors
- **Solution**: Increase the `delay` setting in configuration
- **Check**: Monitor API usage limits for each service

#### 3. Discord webhook not working
- **Solution**: Test webhook with `python subspyder_cli.py --test-discord`
- **Check**: Verify webhook URL is correct and server has proper permissions

#### 4. Import errors
- **Solution**: Ensure all dependencies are installed: `pip install -r requirements.txt`
- **Check**: Verify Python version is 3.8 or higher

### Getting Help

1. **Check the logs**: Look for error messages in the output
2. **Verify configuration**: Use `--config` flag to check settings
3. **Test individual modules**: Use the example scripts in `example_usage.py`
4. **Check API status**: Verify your API keys are valid and not expired

## ✅ Setup Complete!

Once you've completed these steps, you're ready to use SubSpyder for comprehensive subdomain enumeration!

```bash
# Start enumerating
python subspyder_cli.py your-target-domain.com
``` 