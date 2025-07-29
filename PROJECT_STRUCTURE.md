# SubSpyder - Clean Project Structure

## 🧹 Cleaned Up Codebase

The project has been completely refactored and cleaned up, removing all duplicate files and fragmented modules. Here's the new, clean structure:

## 📁 Project Structure

```
SubSpyder/
├── 📦 subspyder/                    # Main Python Package
│   ├── __init__.py                  # Package exports and API
│   ├── 📁 core/                     # Core Components
│   │   ├── __init__.py
│   │   ├── config.py               # Configuration Management
│   │   └── subspyder.py            # Main Orchestrator Class
│   ├── 📁 modules/                  # Enumeration Modules
│   │   ├── __init__.py
│   │   ├── passive.py              # Passive Enumeration
│   │   ├── active.py               # Active Brute Force
│   │   ├── ai_predictor.py         # AI-Powered Prediction
│   │   └── validator.py            # Validation & Discord
│   └── 📁 utils/                    # Utility Functions
│       ├── __init__.py
│       ├── helpers.py              # Helper Functions
│       └── discord.py              # Discord Notifications
├── 🚀 subspyder_cli.py             # Command Line Interface
├── 📋 setup.py                     # Package Installation
├── 📦 requirements.txt             # Dependencies
├── ⚙️ subspyder_config.ini        # Configuration File
├── 📚 wordlist.txt                 # Subdomain Wordlist
├── 📖 README.md                    # Documentation
└── 💡 example_usage.py            # Usage Examples
```

## 🗑️ Removed Files

The following duplicate and fragmented files have been removed:

- ❌ `subspyder.py` (old monolithic script)
- ❌ `test_discord.py` (duplicate functionality)
- ❌ `module-1/` (fragmented directory)
- ❌ `module-2/` (fragmented directory)
- ❌ `module-3/` (fragmented directory)
- ❌ `module-4/` (fragmented directory)

## 🏗️ Module Architecture

### 📦 Core Module (`subspyder/core/`)

#### `config.py` - Configuration Management
```python
class Config:
    """Configuration class for API keys and settings"""
    
    def __init__(self, config_file: str = "subspyder_config.ini")
    def load_config(self)
    def create_default_config(self)
    def get_api_key(self, key_name: str) -> Optional[str]
    def get_setting(self, key: str, default: str = '') -> str
    def print_api_key_status(self)
```

#### `subspyder.py` - Main Orchestrator
```python
class CompleteSubSpyder:
    """Complete subdomain enumeration tool combining all modules"""
    
    def __init__(self, accepted_status_codes: List[int] = None)
    def run_complete_enumeration(self, domain: str, wordlist_file: str = "wordlist.txt") -> Dict
    def save_results(self, results: Dict, filename: str = None)
    def test_discord_webhook(self) -> bool
```

### 🔍 Enumeration Modules (`subspyder/modules/`)

#### `passive.py` - Passive Enumeration
```python
class PassiveEnumerator:
    """Passive subdomain enumeration from public sources"""
    
    def __init__(self, config: Config)
    def get_crtsh_subdomains(self, domain: str) -> List[str]
    def get_virustotal_subdomains(self, domain: str) -> List[str]
    def get_wayback_subdomains(self, domain: str) -> List[str]
    def get_shodan_subdomains(self, domain: str) -> List[str]
    def enumerate_passive(self, domain: str) -> Dict
```

#### `active.py` - Active Brute Force
```python
class ActiveEnumerator:
    """Active subdomain enumeration with brute force and validation"""
    
    def __init__(self, config: Config, accepted_status_codes: List[int] = None)
    def load_wordlist(self, wordlist_file: str = "wordlist.txt") -> List[str]
    def check_subdomain(self, word: str, domain: str) -> Optional[str]
    def validate_subdomain(self, subdomain: str) -> Dict
    def brute_force(self, domain: str, wordlist_file: str = "wordlist.txt") -> List[str]
    def validate_subdomains(self, subdomains: List[str]) -> Dict
```

#### `ai_predictor.py` - AI-Powered Prediction
```python
class AIPredictor:
    """AI-powered subdomain prediction using Gemini"""
    
    def __init__(self, config: Config)
    def query_gemini(self, prompt: str) -> str
    def detect_website_type(self, subdomains: list) -> str
    def predict_subdomains(self, domain: str, known_subdomains: list) -> List[str]
```

#### `validator.py` - Validation & Discord
```python
class SubdomainValidator:
    """Subdomain validation and Discord notification module"""
    
    def __init__(self, config: Config)
    def resolve_domain(self, domain: str) -> Optional[str]
    async def check_target(self, domain: str, session: aiohttp.ClientSession) -> Dict
    async def check_targets(self, domains: List[str]) -> List[Dict]
    async def validate_subdomains(self, subdomains: List[str]) -> Dict
    def test_discord_webhook(self) -> bool
```

### 🛠️ Utility Modules (`subspyder/utils/`)

#### `helpers.py` - Helper Functions
```python
def clean_subdomain(subdomain: str, domain: str) -> str
def deduplicate_subdomains(subdomains: List[str], domain: str) -> List[str]
def validate_domain(domain: str) -> bool
def extract_domain_from_url(url: str) -> str
```

#### `discord.py` - Discord Notifications
```python
class DiscordNotifier:
    """Discord notification handler"""
    
    def __init__(self, webhook_url: str, enabled: bool = True)
    def build_payload(self, results: List[Dict]) -> Dict
    def send_notification(self, payload: Dict) -> bool
    def send_test_notification(self) -> bool
```

## 🚀 Usage Examples

### Simple Usage
```python
from subspyder import run_enumeration

# One-liner enumeration
results = run_enumeration("example.com")
```

### Advanced Usage
```python
from subspyder import CompleteSubSpyder

# Create instance with custom settings
subspyder = CompleteSubSpyder(accepted_status_codes=[200, 403, 500])

# Run complete enumeration
results = subspyder.run_complete_enumeration("example.com", "custom_wordlist.txt")

# Save results
subspyder.save_results(results, "results.json")
```

### Individual Module Usage
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

### Command Line Interface
```bash
# Basic usage
python subspyder_cli.py example.com

# With options
python subspyder_cli.py example.com -o results.json --status-codes 200,403,500

# Test Discord
python subspyder_cli.py --test-discord
```

## ✅ Benefits of Clean Structure

1. **🎯 Single Responsibility**: Each module has one clear purpose
2. **🔧 Maintainability**: Easy to modify and extend individual components
3. **🧪 Testability**: Each module can be tested independently
4. **♻️ Reusability**: Modules can be used in other projects
5. **📦 Proper Packaging**: Follows Python best practices
6. **📚 Clear Documentation**: Well-documented classes and functions
7. **🚀 Easy Installation**: Simple `pip install -e .`
8. **🎨 Clean API**: Intuitive import and usage patterns

## 🔄 Migration Path

The old fragmented structure has been completely replaced with a clean, modular architecture:

- **Before**: Scattered modules in separate directories
- **After**: Organized package with clear separation of concerns
- **Compatibility**: 100% backward compatible functionality
- **Improvement**: Much better maintainability and extensibility

## 📋 Installation

```bash
# Install in development mode
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## 🎉 Result

The codebase is now clean, organized, and follows Python best practices. Each module is properly structured with classes and functions, and the main script calls these modules in a clean, maintainable way. 