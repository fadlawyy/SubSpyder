# Spyder - Advanced Subdomain Enumeration Tool

A comprehensive subdomain enumeration and reconnaissance tool written in Python, designed for security researchers, penetration testers, and cybersecurity professionals.

## 🎯 Project Overview

Spyder is a modular subdomain enumeration tool that combines passive reconnaissance, active enumeration, and AI-powered prediction to discover subdomains of target domains. The tool is organized into three distinct modules, each focusing on different aspects of subdomain discovery.

## 📋 Module Status

| Module | Status | Description |
|--------|--------|-------------|
| **Module 1: Passive Enumeration** | ✅ **COMPLETE** | Pull subdomains from public sources |
| **Module 2: Active Enumeration** | ✅ **COMPLETE** | DNS brute forcing and scanning |
| **Module 3: AI-Powered Prediction** | ✅ **COMPLETE** | AI-driven subdomain prediction |

## 🏗️ Project Structure

```
spyder/
├── SubSpyder/
│   ├── module-1/                    # Passive Enumeration
│   │   ├── README.md
│   │   ├── requirements.txt
│   │   ├── subspyder_config.ini
│   │   └── subspyder.py
│   ├── module-2/                    # Active Enumeration
│   │   ├── brute.py
│   │   ├── filter_status.py
│   │   ├── wordlist.txt
│   │   ├── brute_results.json
│   │   └── filtered_result.json
│   └── module-3/                    # AI-Powered Prediction
│       ├── readme.md
│       ├── run_module3.py
│       └── src/
│           ├── ai_predictor.py
│           └── domain_type_detector.py
└── README.md                        # This file
```

## 🚀 Module 1: Passive Enumeration

**Location**: `SubSpyder/module-1/`

### Features
- Pulls subdomains from multiple public sources
- Supports 6 different reconnaissance sources
- Advanced deduplication and normalization
- JSON output format with statistics
- Rate limiting and error handling

### Supported Sources
- **crt.sh** - Certificate Transparency logs
- **VirusTotal** - Threat intelligence platform (requires API key)
- **SecurityTrails** - DNS and domain intelligence (requires API key)
- **DNSDumpster** - DNS reconnaissance tool
- **Wayback Machine** - Web archive
- **Shodan** - Internet-wide scan data (requires API key)

### Usage
```bash
cd SubSpyder/module-1
pip install -r requirements.txt
python subspyder.py example.com
```

### Output Format
```json
{
  "passive": [
    "www.example.com",
    "mail.example.com",
    "api.example.com"
  ],
  "statistics": {
    "total_collected": 25,
    "unique_found": 20,
    "duplicates_removed": 5,
    "sources_used": ["crt.sh", "VirusTotal", "SecurityTrails"]
  }
}
```

## 🔍 Module 2: Active Enumeration

**Location**: `SubSpyder/module-2/`

### Features
- DNS brute forcing with custom wordlists
- Multi-threaded scanning for speed
- HTTP status code validation
- Results filtering and processing
- JSON output format

### Components
- `brute.py` - Main brute force script
- `filter_status.py` - Filter and validate results
- `wordlist.txt` - Custom subdomain wordlist
- `brute_results.json` - Raw brute force results
- `filtered_result.json` - Filtered and validated results

### Usage
```bash
cd SubSpyder/module-2
python brute.py
python filter_status.py
```

### Output Format
```json
{
  "bruteforce": [
    "admin.example.com",
    "dev.example.com",
    "test.example.com"
  ]
}
```

## 🤖 Module 3: AI-Powered Prediction

**Location**: `SubSpyder/module-3/`

### Features
- Uses Google's Gemini AI model for intelligent subdomain prediction
- Website type detection and classification
- Context-aware subdomain generation
- Integration with previous module results

### Website Types Supported
- **Technical** - Development, API, infrastructure
- **E-commerce** - Shopping, payment, customer service
- **News** - Media, content, publishing
- **Blog** - Content management, personal sites
- **Generic** - General purpose websites

### Components
- `run_module3.py` - Main execution script
- `src/ai_predictor.py` - Gemini AI integration
- `src/domain_type_detector.py` - Website classification

### Usage
```bash
cd SubSpyder/module-3
python run_module3.py
```

### Output Format
```json
{
  "intelligence": [
    "api.example.com",
    "cdn.example.com",
    "staging.example.com"
  ]
}
```

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd spyder
   ```

2. **Install dependencies for each module**
   ```bash
   # Module 1
   cd SubSpyder/module-1
   pip install -r requirements.txt
   
   # Module 2
   cd ../module-2
   pip install requests
   
   # Module 3
   cd ../module-3
   pip install google-generativeai
   ```

3. **Configure API keys (optional)**
   ```bash
   cd SubSpyder/module-1
   python subspyder.py --setup
   ```

## 📖 Usage Examples

### Complete Workflow

1. **Start with passive enumeration**
   ```bash
   cd SubSpyder/module-1
   python subspyder.py target.com -o passive_results.json
   ```

2. **Perform active enumeration**
   ```bash
   cd ../module-2
   # Edit brute.py to set target_domain = "target.com"
   python brute.py
   python filter_status.py
   ```

3. **Generate AI predictions**
   ```bash
   cd ../module-3
   # Edit run_module3.py with your domain and known subdomains
   python run_module3.py
   ```

### Custom Wordlists
Edit `SubSpyder/module-2/wordlist.txt` to add custom subdomains for brute forcing.

### API Configuration
For enhanced results, configure API keys for:
- VirusTotal
- SecurityTrails
- Shodan

## 🔧 Configuration

### Module 1 Configuration
- Edit `subspyder_config.ini` for API keys
- Use `--setup` flag for interactive configuration

### Module 2 Configuration
- Modify `target_domain` in `brute.py`
- Customize `wordlist.txt` for specific targets
- Adjust thread count in `ThreadPoolExecutor`

### Module 3 Configuration
- Set your Gemini API key in `src/ai_predictor.py`
- Modify domain and known subdomains in `run_module3.py`

## 📊 Output and Results

Each module produces structured JSON output that can be:
- Combined for comprehensive analysis
- Imported into other security tools
- Used for further reconnaissance
- Integrated into automated workflows

## ⚠️ Legal and Ethical Considerations

**Important**: This tool is designed for:
- Authorized security testing
- Educational purposes
- Research and development
- Penetration testing with proper authorization

**Always ensure you have explicit permission** to enumerate subdomains of the target domain before using this tool.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is part of the Robusta GitHub Task. Please refer to individual module licenses for specific terms.

## 🆘 Support

For issues, questions, or contributions:
1. Check the individual module README files
2. Review the code documentation
3. Open an issue in the repository

## 🔄 Future Enhancements

- **Module 4: Reporting** - Generate comprehensive HTML reports
- **Integration Framework** - Unified command-line interface
- **Advanced Filtering** - Machine learning-based result validation
- **Cloud Integration** - AWS, Azure, GCP subdomain discovery
- **Real-time Monitoring** - Continuous subdomain monitoring

---

**Built with ❤️ for the cybersecurity community** 