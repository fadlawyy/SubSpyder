#!/usr/bin/env python3
"""

Complete Subdomain Enumeration Tool

Module 1: Passive Enumeration with API Key Management
- Pull subdomains from public sources
- Collect all subdomains and output them into JSON format
- Built-in API key management and configuration
"""

import requests
import shodan
import json
import time
import os
import configparser
from urllib.parse import urlparse
import re
from typing import List, Dict, Set, Optional


class Config:
    """Configuration class for API keys and settings"""
    
    def __init__(self):
        self.config_file = "subspyder_config.ini"
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        self.config = configparser.ConfigParser()
        
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['API_KEYS'] = {
            'virustotal_api_key': '',
            'securitytrails_api_key': '',
            'shodan_api_key': '',
            'dnsdumpster_api_key': '',
            'criminalip_api_key': ''
        }
        
        self.config['SETTINGS'] = {
            'timeout': '10',
            'delay': '1',
            'output_file': 'subspyder_results.json'
        }
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        
        print(f"Created default config file: {self.config_file}")
        print("Please edit the file to add your API keys.")
    
    def get_virustotal_api_key(self) -> Optional[str]:
        """Get VirusTotal API key from config or environment"""
        return (self.config.get('API_KEYS', 'virustotal_api_key', fallback='') or 
                os.getenv('VIRUSTOTAL_API_KEY'))
    
    def get_securitytrails_api_key(self) -> Optional[str]:
        """Get SecurityTrails API key from config or environment"""
        return (self.config.get('API_KEYS', 'securitytrails_api_key', fallback='') or 
                os.getenv('SECURITYTRAILS_API_KEY'))
    
    def get_shodan_api_key(self) -> Optional[str]:
        """Get Shodan API key from config or environment"""
        return (self.config.get('API_KEYS', 'shodan_api_key', fallback='') or 
                os.getenv('SHODAN_API_KEY'))
    
    def get_dnsdumpster_api_key(self) -> Optional[str]:
        """Get DNSDumpster API key from config or environment"""
        return (self.config.get('API_KEYS', 'dnsdumpster_api_key', fallback='') or 
                os.getenv('DNSDUMPSTER_API_KEY'))
    
    def get_criminalip_api_key(self) -> Optional[str]:
        """Get CriminalIP API key from config or environment"""
        return (self.config.get('API_KEYS', 'criminalip_api_key', fallback='') or 
                os.getenv('CRIMINALIP_API_KEY'))
    
    def get_setting(self, key: str, default: str = '') -> str:
        """Get a setting value"""
        return self.config.get('SETTINGS', key, fallback=default)
    
    def print_api_key_status(self):
        """Print the status of API keys"""
        print("\n=== API Key Status ===")
        virustotal_key = self.get_virustotal_api_key()
        securitytrails_key = self.get_securitytrails_api_key()
        shodan_key = self.get_shodan_api_key()
        dnsdumpster_key = self.get_dnsdumpster_api_key()
        criminalip_key = self.get_criminalip_api_key()
        
        print(f"VirusTotal: {'✅ Set' if virustotal_key else '❌ Not set'}")
        print(f"SecurityTrails: {'✅ Set' if securitytrails_key else '❌ Not set'}")
        print(f"Shodan: {'✅ Set' if shodan_key else '❌ Not set'}")
        print(f"DNSDumpster: {'✅ Set' if dnsdumpster_key else '❌ Not set'}")
        print(f"CriminalIP: {'✅ Set' if criminalip_key else '❌ Not set'}")
        print(f"Config file: {self.config_file}")


class SubSpyder:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.subdomains = set()
    
    def get_crtsh_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Split by newlines and clean up
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name.endswith(f'.{domain}'):
                                subdomains.add(name)
                return list(subdomains)
        except Exception as e:
            print(f"Error fetching from crt.sh: {e}")
        return []
    
    def get_virustotal_subdomains(self, domain: str, api_key: str = None) -> List[str]:
        """Get subdomains from VirusTotal (requires API key)"""
        if not api_key:
            print("VirusTotal requires API key - skipping")
            return []
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': domain}
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                return [f"{sub}.{domain}" for sub in subdomains]
        except Exception as e:
            print(f"Error fetching from VirusTotal: {e}")
        return []
    
    def get_securitytrails_subdomains(self, domain: str, api_key: str = None) -> List[str]:
        """Get subdomains from SecurityTrails (requires API key)"""
        if not api_key:
            print("SecurityTrails requires API key - skipping")
            return []
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {'apikey': api_key}
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                return [f"{sub}.{domain}" for sub in subdomains]
        except Exception as e:
            print(f"Error fetching from SecurityTrails: {e}")
        return []
    
    def get_dnsdumpster_subdomains(self, domain: str, api_key: str = None) -> List[str]:
        """Get subdomains from DNSDumpster"""
        try:
            if api_key:
                # Use DNSDumpster API if key is provided
                url = f"https://api.dnsdumpster.com/domain/{domain}"
                headers = {
                    'X-API-Key': api_key
                }
                
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    subdomains = set()
                    
                    # Extract subdomains from A records
                    if 'a' in data:
                        for record in data['a']:
                            if 'host' in record and record['host'].endswith(f'.{domain}'):
                                subdomains.add(record['host'])
                    
                    # Extract subdomains from CNAME records
                    if 'cname' in data:
                        for record in data['cname']:
                            if 'host' in record and record['host'].endswith(f'.{domain}'):
                                subdomains.add(record['host'])
                    
                    # Extract subdomains from MX records
                    if 'mx' in data:
                        for record in data['mx']:
                            if 'host' in record and record['host'].endswith(f'.{domain}'):
                                subdomains.add(record['host'])
                    
                    # Extract subdomains from NS records
                    if 'ns' in data:
                        for record in data['ns']:
                            if 'host' in record and record['host'].endswith(f'.{domain}'):
                                subdomains.add(record['host'])
                    
                    return list(subdomains)
                else:
                    print(f"DNSDumpster API returned status code: {response.status_code}")
            else:
                # Fallback to web scraping method
                url = "https://dnsdumpster.com/"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Extract CSRF token
                    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
                    if csrf_match:
                        csrf_token = csrf_match.group(1)
                        
                        # Submit domain search
                        data = {
                            'csrfmiddlewaretoken': csrf_token,
                            'targetip': domain
                        }
                        headers = {
                            'Referer': url,
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }
                        
                        response = self.session.post(url, data=data, headers=headers, timeout=10)
                        if response.status_code == 200:
                            # Extract subdomains from response
                            subdomain_pattern = rf'([a-zA-Z0-9.-]+\.{re.escape(domain)})'
                            subdomains = re.findall(subdomain_pattern, response.text)
                            return list(set(subdomains))
        except Exception as e:
            print(f"Error fetching from DNSDumpster: {e}")
        return []
    
    def get_wayback_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from Wayback Machine"""
        try:
            url = f"https://web.archive.org/cdx/search/cdx"
            params = {
                'url': f'*.{domain}',
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey'
            }
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data[1:]:  # Skip header row
                    if entry:
                        parsed_url = urlparse(entry[0])
                        hostname = parsed_url.hostname
                        if hostname and hostname.endswith(f'.{domain}'):
                            subdomains.add(hostname)
                return list(subdomains)
        except Exception as e:
            print(f"Error fetching from Wayback Machine: {e}")
        return []
    
    def get_shodan_subdomains(self, domain: str, api_key: str = None) -> List[str]:
        """Get subdomains from Shodan using official library"""
        try:
            if not api_key:
                return []
            
            # Initialize Shodan API
            api = shodan.Shodan(api_key)
            subdomains = set()
            
            # Search for SSL certificates containing the domain
            search_query = f'ssl:"{domain}"'
            try:
                results = api.search(search_query, limit=100)
                
                for result in results['matches']:
                    # Extract hostnames from SSL certificate data
                    if 'ssl' in result and 'cert' in result['ssl']:
                        cert = result['ssl']['cert']
                        
                        # Check subject alternative names
                        if 'subjectaltname' in cert:
                            for san in cert['subjectaltname']:
                                if san.endswith(f'.{domain}'):
                                    subdomains.add(san)
                        
                        # Check common name
                        if 'subject' in cert and 'CN' in cert['subject']:
                            cn = cert['subject']['CN']
                            if cn.endswith(f'.{domain}'):
                                subdomains.add(cn)
                
                # Also search for hostnames in the result data
                for result in results['matches']:
                    if 'hostnames' in result:
                        for hostname in result['hostnames']:
                            if hostname.endswith(f'.{domain}'):
                                subdomains.add(hostname)
                
            except shodan.APIError as e:
                print(f"Shodan API error: {e}")
            except Exception as e:
                print(f"Error searching Shodan: {e}")
                
        except Exception as e:
            print(f"Error initializing Shodan API: {e}")
        
        return list(subdomains)
    
    def get_criminalip_subdomains(self, domain: str, api_key: str = None) -> List[str]:
        """Get subdomains from CriminalIP"""
        try:
            if not api_key:
                return []
            
            # CriminalIP subdomain search endpoint
            url = "https://api.criminalip.io/v1/domain/subdomain"
            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json"
            }
            params = {
                "query": domain,
                "full": "true"
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                # Extract subdomains from response
                if 'data' in data and 'result' in data['data']:
                    for item in data['data']['result']:
                        if 'hostname' in item:
                            hostname = item['hostname']
                            if hostname.endswith(f'.{domain}'):
                                subdomains.add(hostname)
                
                return list(subdomains)
            else:
                print(f"CriminalIP API returned status code: {response.status_code}")
                
        except Exception as e:
            print(f"Error fetching from CriminalIP: {e}")
        return []

    def get_criminalip_domain_report(self, domain: str, api_key: str = None) -> Dict:
        """Get domain report from CriminalIP (new functionality)"""
        try:
            if not api_key:
                api_key = self.config.get_criminalip_api_key()
            
            if not api_key:
                print("  CriminalIP API key not configured")
                return {}
            
            # CriminalIP domain reports endpoint
            url = "https://api.criminalip.io/v1/domain/reports"
            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json"
            }
            params = {
                "query": domain,
                "offset": 0
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                report_data = {}
                
                if 'data' in data and 'reports' in data['data']:
                    reports = data['data']['reports']
                    if reports:
                        # Get the first report (most relevant)
                        report = reports[0]
                        report_data = {
                            'score': report.get('score', 'Unknown'),
                            'title': report.get('title', ''),
                            'country_code': report.get('country_code', []),
                            'reg_dtime': report.get('reg_dtime', ''),
                            'scan_id': report.get('scan_id', ''),
                            'connected_ip_cnt': report.get('connected_ip_cnt', 0),
                            'view_cnt': report.get('view_cnt', 0),
                            'jarm': report.get('jarm', ''),
                            'url': report.get('url', []),
                            'issue': report.get('issue', []),
                            'technologies': report.get('technologies', {})
                        }
                
                print(f"  Found domain report from CriminalIP")
                return report_data
            else:
                print(f"  CriminalIP Domain Report API error: {response.status_code} - {response.text}")
                return {}
                
        except Exception as e:
            print(f"  Error fetching domain report from CriminalIP: {e}")
            return {}
    
    def clean_subdomain(self, subdomain: str, domain: str) -> str:
        """Clean and normalize subdomain"""
        # Remove wildcards and clean up
        subdomain = subdomain.replace('*.', '').strip().lower()
        
        # Remove any trailing dots
        subdomain = subdomain.rstrip('.')
        
        # Handle redundant domain patterns (e.g., admin.example.com.example.com)
        # Check if the subdomain contains the domain twice
        domain_pattern = f'.{domain}.{domain}'
        if domain_pattern in subdomain:
            # Remove the redundant domain part
            subdomain = subdomain.replace(domain_pattern, f'.{domain}')
        
        # Also handle cases where domain appears multiple times
        while f'.{domain}.{domain}' in subdomain:
            subdomain = subdomain.replace(f'.{domain}.{domain}', f'.{domain}')
        
        # Handle cases where domain appears at the beginning
        if subdomain.startswith(f'{domain}.'):
            subdomain = subdomain[len(f'{domain}.'):]
        
        # Remove any leading/trailing whitespace again
        subdomain = subdomain.strip()
        
        # Ensure it ends with the target domain
        if not subdomain.endswith(f'.{domain}'):
            if subdomain == domain:
                return f"*.{domain}"
            else:
                return f"{subdomain}.{domain}"
        
        return subdomain
    
    def deduplicate_subdomains(self, subdomains: List[str], domain: str) -> List[str]:
        """Deduplicate and normalize subdomains"""
        cleaned_subdomains = set()
        
        for subdomain in subdomains:
            cleaned = self.clean_subdomain(subdomain, domain)
            if cleaned:
                cleaned_subdomains.add(cleaned)
        
        return sorted(list(cleaned_subdomains))
    
    def enumerate_passive(self, domain: str, shodan_api_key: str = None, dnsdumpster_key: str = None, criminalip_key: str = None) -> Dict:
        """Enumerate subdomains using passive sources"""
        print(f"Starting enumeration for: {domain}")
        
        # Define sources
        sources = ["crt.sh", "VirusTotal", "SecurityTrails", "DNSDumpster", "Wayback Machine", "Shodan", "CriminalIP"]
        
        # Initialize results
        results = {
            "domain": domain,
            "passive": [],
            "sources": {},
            "statistics": {
                "total_collected": 0,
                "unique_subdomains": 0,
                "duplicates_removed": 0,
                "deduplication_enabled": True
            }
        }
        
        # Get subdomains from crt.sh
        print("Fetching from crt.sh...")
        crtsh_subdomains = self.get_crtsh_subdomains(domain)
        print(f"  Found {len(crtsh_subdomains)} subdomains from crt.sh")
        results["sources"]["crt.sh"] = len(crtsh_subdomains)
        
        # Get subdomains from VirusTotal
        print("Fetching from VirusTotal...")
        virustotal_key = self.config.get_virustotal_api_key()
        virustotal_subdomains = self.get_virustotal_subdomains(domain, virustotal_key)
        print(f"  Found {len(virustotal_subdomains)} subdomains from VirusTotal")
        results["sources"]["VirusTotal"] = len(virustotal_subdomains)
        
        # Get subdomains from SecurityTrails
        print("Fetching from SecurityTrails...")
        securitytrails_key = self.config.get_securitytrails_api_key()
        securitytrails_subdomains = self.get_securitytrails_subdomains(domain, securitytrails_key)
        print(f"  Found {len(securitytrails_subdomains)} subdomains from SecurityTrails")
        results["sources"]["SecurityTrails"] = len(securitytrails_subdomains)
        
        # Get subdomains from DNSDumpster
        print("Fetching from DNSDumpster...")
        dnsdumpster_subdomains = self.get_dnsdumpster_subdomains(domain, dnsdumpster_key)
        print(f"  Found {len(dnsdumpster_subdomains)} subdomains from DNSDumpster")
        results["sources"]["DNSDumpster"] = len(dnsdumpster_subdomains)
        
        # Get subdomains from Wayback Machine
        print("Fetching from Wayback Machine...")
        wayback_subdomains = self.get_wayback_subdomains(domain)
        print(f"  Found {len(wayback_subdomains)} subdomains from Wayback Machine")
        results["sources"]["Wayback Machine"] = len(wayback_subdomains)
        
        # Get subdomains from Shodan
        print("Fetching from Shodan...")
        shodan_subdomains = self.get_shodan_subdomains(domain, shodan_api_key)
        print(f"  Found {len(shodan_subdomains)} subdomains from Shodan")
        results["sources"]["Shodan"] = len(shodan_subdomains)
        
        # Get subdomains from CriminalIP
        print("Fetching from CriminalIP...")
        criminalip_subdomains = self.get_criminalip_subdomains(domain, criminalip_key)
        print(f"  Found {len(criminalip_subdomains)} subdomains from CriminalIP")
        results["sources"]["CriminalIP"] = len(criminalip_subdomains)
        
        # Get domain report from CriminalIP (new functionality)
        print("Fetching domain report from CriminalIP...")
        criminalip_report = self.get_criminalip_domain_report(domain, criminalip_key)
        if criminalip_report:
            results["domain_report"] = criminalip_report
            print(f"  Domain score: {criminalip_report.get('score', 'Unknown')}")
            print(f"  Domain title: {criminalip_report.get('title', 'N/A')}")
        
        # Combine all subdomains
        all_subdomains = []
        all_subdomains.extend(crtsh_subdomains)
        all_subdomains.extend(virustotal_subdomains)
        all_subdomains.extend(securitytrails_subdomains)
        all_subdomains.extend(dnsdumpster_subdomains)
        all_subdomains.extend(wayback_subdomains)
        all_subdomains.extend(shodan_subdomains)
        all_subdomains.extend(criminalip_subdomains)
        
        # Deduplicate subdomains
        print(f"\nDeduplicating {len(all_subdomains)} total subdomains...")
        unique_subdomains = self.deduplicate_subdomains(all_subdomains, domain)
        duplicates_removed = len(all_subdomains) - len(unique_subdomains)
        print(f"  Removed {duplicates_removed} duplicate subdomains")
        
        # Update results
        results["passive"] = unique_subdomains
        results["statistics"]["total_collected"] = len(all_subdomains)
        results["statistics"]["unique_subdomains"] = len(unique_subdomains)
        results["statistics"]["duplicates_removed"] = duplicates_removed
        
        return results
    
    def save_results(self, results: Dict, filename: str = None):
        """Save results to JSON file (without sources/statistics)"""
        if not filename:
            filename = self.config.get_setting('output_file', 'subspyder_results.json')
        
        # Remove 'sources' and 'statistics' from results before saving
        results_to_save = {k: v for k, v in results.items() if k not in ('sources', 'statistics')}
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_to_save, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Results saved to: {filename}")
        print(f"🔍 Deduplication: Enabled")


def print_banner():
    """Print tool banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    SubSpyder v1.0                            ║
║              Subdomain Enumeration Tool                      ║
║                    Module 1: Passive Enumeration             ║
╚══════════════════════════════════════════════════════════════╝
""")


def print_help():
    """Print help information"""
    print("""
Usage: python subspyder_complete.py [OPTIONS] <domain>

Options:
  --help, -h          Show this help message
  --config <file>     Specify config file (default: subspyder_config.ini)
  --setup             Interactive API key setup
  -o <file>          Output file (default: subspyder_results.json)

Examples:
  python subspyder_complete.py example.com
  python subspyder_complete.py --setup
  python subspyder_complete.py -o results.json example.com

Supported Sources:
  - crt.sh (Certificate Transparency)
  - VirusTotal (API key required)
  - SecurityTrails (API key required)
  - DNSDumpster (API key optional)
  - Wayback Machine
  - Shodan (API key required)
  - CriminalIP (API key required) - Subdomain enumeration + Domain reports
""")


def setup_api_keys_interactive():
    """Interactive setup for API keys"""
    print("🔧 Interactive API Key Setup")
    print("Enter your API keys (press Enter to skip):")
    
    config = configparser.ConfigParser()
    config['API_KEYS'] = {}
    config['SETTINGS'] = {
        'timeout': '10',
        'delay': '1',
        'output_file': 'subspyder_results.json'
    }
    
    virustotal_key = input("Enter VirusTotal API key (optional): ").strip()
    securitytrails_key = input("Enter SecurityTrails API key (optional): ").strip()
    shodan_key = input("Enter Shodan API key (optional): ").strip()
    dnsdumpster_key = input("Enter DNSDumpster API key (optional): ").strip()
    criminalip_key = input("Enter CriminalIP API key (optional): ").strip()
    
    if virustotal_key:
        config["API_KEYS"]["virustotal_api_key"] = virustotal_key
    if securitytrails_key:
        config["API_KEYS"]["securitytrails_api_key"] = securitytrails_key
    if shodan_key:
        config["API_KEYS"]["shodan_api_key"] = shodan_key
    if dnsdumpster_key:
        config["API_KEYS"]["dnsdumpster_api_key"] = dnsdumpster_key
    if criminalip_key:
        config["API_KEYS"]["criminalip_api_key"] = criminalip_key
    
    with open('subspyder_config.ini', 'w') as f:
        config.write(f)
    
    print("✅ Configuration saved to subspyder_config.ini")


def main():
    """Main function"""
    import sys
    
    # Parse command line arguments
    args = sys.argv[1:]
    domain = None
    output_file = None
    config_file = None
    setup_mode = False
    
    i = 0
    while i < len(args):
        if args[i] in ['--help', '-h']:
            print_help()
            return
        elif args[i] == '--config':
            if i + 1 < len(args):
                config_file = args[i + 1]
                i += 2
            else:
                print("Error: --config requires a filename")
                return
        elif args[i] == '--setup':
            setup_mode = True
            i += 1
        elif args[i] == '-o':
            if i + 1 < len(args):
                output_file = args[i + 1]
                i += 2
            else:
                print("Error: -o requires a filename")
                return
        else:
            if not domain:
                domain = args[i]
            i += 1
    
    if setup_mode:
        setup_api_keys_interactive()
        return
    
    if not domain:
        print("Error: Domain is required")
        print_help()
        return
    
    # Initialize configuration
    config = Config()
    if config_file:
        config.config_file = config_file
        config.load_config()
    
    # Print banner and API key status
    print_banner()
    config.print_api_key_status()
    
    # Initialize SubSpyder
    spyder = SubSpyder(config)
    
    # Get API keys
    shodan_key = config.get_shodan_api_key()
    dnsdumpster_key = config.get_dnsdumpster_api_key()
    criminalip_key = config.get_criminalip_api_key()
    
    # Perform enumeration
    results = spyder.enumerate_passive(domain, shodan_key, dnsdumpster_key, criminalip_key)
    
    # Print statistics
    print("\n=== Enumeration Statistics ===")
    print(f"Total subdomains collected: {results['statistics']['total_collected']}")
    print(f"Unique subdomains after deduplication: {results['statistics']['unique_subdomains']}")
    print(f"Duplicates removed: {results['statistics']['duplicates_removed']}")
    
    print("\n=== Source Breakdown ===")
    for source, count in results['sources'].items():
        print(f"{source}: {count} subdomains")
    
    # Save results
    spyder.save_results(results, output_file)
    
    # Print summary
    print("\n=== Summary ===")
    print(f"Domain: {results['domain']}")
    print(f"Unique subdomains found: {results['statistics']['unique_subdomains']}")
    print(f"Total collected: {results['statistics']['total_collected']}")
    print(f"Duplicates removed: {results['statistics']['duplicates_removed']}")
    print("\nEnumeration completed successfully! 🎉")


if __name__ == "__main__":
    main()