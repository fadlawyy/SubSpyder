# Robusta - GitHub Task SubSpyder

An advanced subdomain enumeration tool written in Python.

## 🎯 Current Status: Module 1 Complete

**This repository contains Module 1 (Passive Enumeration) of the SubSpyder tool.**

## Overview

SubSpyder is a comprehensive subdomain enumeration tool designed with 4 main modules, each responsible for a critical phase of the enumeration process.

### 📋 Module Status

| Module | Status | Description |
|--------|--------|-------------|
| **Module 1: Passive Enumeration** | ✅ **COMPLETE** | Pull subdomains from public sources |
| Module 2: Active Enumeration | 🔄 **TODO** | DNS brute forcing and scanning |
| Module 3: Validation | 🔄 **TODO** | Verify discovered subdomains |
| Module 4: Reporting | 🔄 **TODO** | Generate comprehensive reports |

## 🚀 Module 1: Passive Enumeration

This module pulls subdomains from public sources and outputs them in JSON format.

### Supported Sources

- **crt.sh** - Certificate Transparency logs
- **VirusTotal** - Threat intelligence platform (requires API key)
- **SecurityTrails** - DNS and domain intelligence (requires API key)
- **DNSDumpster** - DNS reconnaissance tool
- **Wayback Machine** - Web archive
- **Shodan** - Internet-wide scan data and SSL certificates (requires API key)

### Output Format

The tool outputs results in the following JSON format with deduplication statistics:

```json
{
  "passive": [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com",
    "vpn.example.com"
  ],
  "statistics": {
    "total_collected": 25,
    "unique_found": 20,
    "duplicates_removed": 5,
    "sources_used": ["crt.sh", "VirusTotal", "SecurityTrails", "DNSDumpster", "Wayback Machine", "Shodan"]
  }
}
```

## Installation

1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Quick Start (Free Sources Only)

```bash
python subspyder_complete.py example.com
```

### Setup API Keys

```bash
python subspyder_complete.py --setup
```

### Check API Key Status

```bash
python subspyder_complete.py --config
```

### Custom Output File

```bash
python subspyder_complete.py github.com -o results.json
```

### Get Help

```bash
python subspyder_complete.py --help
```

## API Keys

Some sources require API keys for access:

- **VirusTotal**: Get your API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
- **SecurityTrails**: Get your API key from [SecurityTrails](https://securitytrails.com/app/api)
- **Shodan**: Get your API key from [Shodan](https://account.shodan.io/register)

## Features

- ✅ Passive enumeration from multiple sources
- ✅ Advanced deduplication and normalization
- ✅ JSON output format with statistics
- ✅ Rate limiting and error handling
- ✅ Configurable API keys
- ✅ Results saving to file
- ✅ Duplicate removal and sorting
- ✅ Source breakdown and analytics
- ✅ Command line interface
- ✅ Interactive setup

## Project Structure

```
subspyder/
├── subspyder_complete.py    # Complete tool (everything included)
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── .gitignore              # Git ignore rules
```

## 🔄 Next Steps for Development Team

### Module 2: Active Enumeration
- Implement DNS brute forcing with wordlists
- Add DNS zone transfer attempts
- Include reverse DNS lookups
- Add subdomain permutation techniques

### Module 3: Validation
- Verify discovered subdomains are active
- Check DNS resolution
- Validate HTTP responses
- Filter out false positives

### Module 4: Reporting
- Generate comprehensive HTML reports
- Create CSV/JSON exports
- Add statistics and analytics
- Include visualization of results

### Integration Points
The `SubSpyder` class is designed to be extended. Each module should:
1. Add new methods to the existing class
2. Maintain the same JSON output structure
3. Include proper error handling and logging
4. Follow the established code style

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to enumerate subdomains of the target domain.

## License

This project is part of the Robusta GitHub Task.

---

**📝 Note for Development Team:** This repository contains a complete, working implementation of Module 1 in a single file. The code is well-documented and follows Python best practices. Use this as a foundation for implementing the remaining modules. 