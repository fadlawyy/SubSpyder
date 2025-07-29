#!/usr/bin/env python3
"""
Complete SubSpyder - All Modules Merged

A comprehensive subdomain enumeration tool that combines:
- Module 1: Passive enumeration from public sources
- Module 2: Active brute force discovery and validation
- Module 3: AI-powered subdomain prediction
- Module 4: Subdomain validation and Discord notifications

Usage: python complete_subspyder.py <domain>
"""

import requests
import json
import time
import os
import configparser
from urllib.parse import urlparse
import re
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor
import shodan
import socket
import asyncio
import aiohttp
import logging

# ============================================================================
# CONFIGURATION CLASS
# ============================================================================

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
            'criminalip_api_key': '',
            'gemini_api_key': 'AIzaSyC-r2l0Z6zEU6_VgKBOnBtf7yF_SvUPOOw'
        }
        
        self.config['SETTINGS'] = {
            'timeout': '10',
            'delay': '1',
            'output_file': 'complete_subspyder_results.json',
            'discord_webhook_url': '',
            'enable_discord_notifications': 'false'
        }
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        
        print(f"Created default config file: {self.config_file}")
        print("Please edit the file to add your API keys.")
    
    def get_api_key(self, key_name: str) -> Optional[str]:
        """Get API key from config or environment"""
        env_key = key_name.upper()
        return (self.config.get('API_KEYS', key_name, fallback='') or 
                os.getenv(env_key))
    
    def get_setting(self, key: str, default: str = '') -> str:
        """Get a setting value"""
        return self.config.get('SETTINGS', key, fallback=default)
    
    def print_api_key_status(self):
        """Print the status of API keys"""
        print("\n=== API Key Status ===")
        keys = ['virustotal_api_key', 'securitytrails_api_key', 'shodan_api_key', 
                'dnsdumpster_api_key', 'criminalip_api_key', 'gemini_api_key']
        
        for key in keys:
            api_key = self.get_api_key(key)
            status = '✅ Set' if api_key else '❌ Not set'
            print(f"{key.replace('_api_key', '').title()}: {status}")
        
        # Check Discord webhook
        webhook_url = self.get_setting('discord_webhook_url')
        discord_enabled = self.get_setting('enable_discord_notifications', 'false').lower() == 'true'
        webhook_status = '✅ Set' if webhook_url and discord_enabled else '❌ Not set/disabled'
        print(f"Discord Webhook: {webhook_status}")

# ============================================================================
# SUBDOMAIN VALIDATION MODULE (Module 4)
# ============================================================================

class SubdomainValidator:
    """Subdomain validation and Discord notification module"""
    
    def __init__(self, config: Config):
        self.config = config
        self.timeout = int(self.config.get_setting('timeout', '10'))
        self.webhook_url = self.config.get_setting('discord_webhook_url')
        self.discord_enabled = self.config.get_setting('enable_discord_notifications', 'false').lower() == 'true'
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.log = logging.getLogger(__name__)
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
        except Exception as e:
            self.log.error(f"Resolve error for {domain}: {e}")
            return None
    
    async def check_target(self, domain: str, session: aiohttp.ClientSession) -> Dict:
        """Check a single target domain"""
        result = {
            'domain': domain,
            'ip': None,
            'http_code': None,
            'https_code': None,
            'http_url': None,
            'https_url': None,
            'http_err': None,
            'https_err': None
        }

        result['ip'] = self.resolve_domain(domain)
        if result['ip']:
            http = f"http://{domain}"
            https = f"https://{domain}"
            try:
                async with session.get(http, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as res:
                    result['http_code'] = res.status
                    result['http_url'] = str(res.url)
            except Exception as e:
                result['http_err'] = str(e)
            try:
                async with session.get(https, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as res:
                    result['https_code'] = res.status
                    result['https_url'] = str(res.url)
            except Exception as e:
                result['https_err'] = str(e)
        return result
    
    async def check_targets(self, domains: List[str]) -> List[Dict]:
        """Check multiple targets asynchronously"""
        results = []
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.check_target(d, session) for d in domains]
            for i in range(0, len(tasks), 10):
                chunk = tasks[i:i+10]
                try:
                    chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                    for r in chunk_results:
                        if isinstance(r, Exception):
                            self.log.error(f"Batch error: {r}")
                        else:
                            results.append(r)
                except Exception as e:
                    self.log.error(f"Error during batch: {e}")
                await asyncio.sleep(0.5)
        return results
    
    def build_discord_payload(self, results: List[Dict]) -> Dict:
        """Build Discord notification payload"""
        live = []
        dead = []
        for r in results:
            if r['ip']:
                info = f"**{r['domain']}** ({r['ip']})"
                codes = []
                if r['http_code']: codes.append(f"HTTP: {r['http_code']}")
                if r['https_code']: codes.append(f"HTTPS: {r['https_code']}")
                if codes:
                    info += " - " + " | ".join(codes)
                    live.append(info)
                else:
                    dead.append(info)
            else:
                dead.append(f"**{r['domain']}** - No IP")
        
        embed = {
            "title": "🌐 Subdomain Status Report",
            "color": 0x00ff00 if live else 0xff0000,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fields": []
        }
        
        if live:
            live_txt = "\n".join(live[:25])
            if len(live) > 25:
                live_txt += f"\n... and {len(live) - 25} more"
            embed["fields"].append({"name": f"✅ Live ({len(live)})", "value": live_txt, "inline": False})
        
        if dead:
            dead_txt = "\n".join(dead[:25])
            if len(dead) > 25:
                dead_txt += f"\n... and {len(dead) - 25} more"
            embed["fields"].append({"name": f"❌ Dead ({len(dead)})", "value": dead_txt, "inline": False})
        
        return {"embeds": [embed]}
    
    def notify_discord(self, payload: Dict) -> bool:
        """Send Discord notification"""
        print(f"🔔 Discord notification status:")
        print(f"   - Enabled: {self.discord_enabled}")
        print(f"   - Webhook URL: {'Set' if self.webhook_url else 'Not set'}")
        
        if not self.discord_enabled:
            print("   - ❌ Discord notifications are disabled in config")
            return False
        
        if not self.webhook_url:
            print("   - ❌ Discord webhook URL not set")
            return False
        
        try:
            print("   - 📤 Sending notification to Discord...")
            res = requests.post(self.webhook_url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            if res.status_code == 204:
                print("   - ✅ Discord notification sent successfully")
                self.log.info("Discord notification sent successfully")
                return True
            else:
                print(f"   - ❌ Discord error: {res.status_code} - {res.text}")
                self.log.error(f"Discord error: {res.status_code} - {res.text}")
                return False
        except Exception as e:
            print(f"   - ❌ Discord send error: {e}")
            self.log.error(f"Discord send error: {e}")
            return False
    
    async def validate_subdomains(self, subdomains: List[str]) -> Dict:
        """Validate subdomains and optionally send Discord notification"""
        print(f"\n🔍 Subdomain Validation Phase...")
        print(f"Checking {len(subdomains)} subdomains...")
        
        start_time = time.time()
        results = await self.check_targets(subdomains)
        elapsed_time = time.time() - start_time
        
        # Count live and dead subdomains
        live_count = sum(1 for d in results if d['ip'] and (d['http_code'] or d['https_code']))
        dead_count = len(results) - live_count
        
        print(f"Validation completed in {elapsed_time:.2f}s")
        print(f"✅ Live: {live_count}, ❌ Dead: {dead_count}")
        
        # Send Discord notification if enabled
        print(f"\n🔔 Discord Notification Phase...")
        payload = self.build_discord_payload(results)
        notification_sent = self.notify_discord(payload)
        
        if notification_sent:
            print("✅ Discord notification completed successfully")
        else:
            print("⚠️  Discord notification failed or was disabled")
        
        return {
            "validation_results": results,
            "live_count": live_count,
            "dead_count": dead_count,
            "elapsed_time": elapsed_time
        }

# ============================================================================
# AI PREDICTION MODULE (Module 3)
# ============================================================================

class AIPredictor:
    """AI-powered subdomain prediction using Gemini"""
    
    def __init__(self, config: Config):
        self.config = config
        self.gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    
    def query_gemini(self, prompt: str) -> str:
        """Query Gemini AI with a prompt"""
        api_key = self.config.get_api_key('gemini_api_key')
        if not api_key:
            print("❌ Gemini API key not set")
            return json.dumps({"intelligence": []})
        
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": api_key,
        }

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ]
        }

        try:
            response = requests.post(self.gemini_url, headers=headers, json=payload)
            data = response.json()
            return data['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            print(f"Gemini API Error: {e}")
            return json.dumps({"intelligence": []})
    
    def detect_website_type(self, subdomains: list) -> str:
        """Detect website type based on subdomains"""
        prompt = (
            f"Given these subdomains: {subdomains}, what type of website is this most likely to be?\n"
            "Choose ONE category only from this list:\n"
            "ecommerce, technical, blog, news, education, media, finance, gaming, travel, security, general.\n"
            "Respond ONLY with the category name."
        )

        try:
            response = self.query_gemini(prompt)
            text = response.strip().lower()
            
            allowed_categories = [
                "ecommerce", "technical", "blog", "news", "education",
                "media", "finance", "gaming", "travel", "security", "general"
            ]
            return text if text in allowed_categories else "general"
        except Exception as e:
            print(f"Error detecting website type: {e}")
            return "general"
    
    def predict_subdomains(self, domain: str, known_subdomains: list) -> List[str]:
        """Predict additional subdomains using AI"""
        print(f"\n🤖 AI Prediction Phase for {domain}...")
        
        # Detect website type
        website_type = self.detect_website_type(known_subdomains)
        print(f"Detected website type: {website_type}")
        
        # Create prediction prompt
        prompt = f"""
        Given the domain '{domain}' and its known subdomains {known_subdomains},
        predict possible additional subdomains that might exist for a {website_type} website.
        Respond ONLY in this JSON format:
        {{
        "intelligence": [
        "sub1.{domain}",
        "sub2.{domain}"
        ]
        }}
        """
        
        # Query Gemini
        response_text = self.query_gemini(prompt)
        
        # Clean response
        if response_text.strip().startswith("```"):
            response_text = response_text.strip().removeprefix("```json").removesuffix("```").strip()
        
        try:
            data = json.loads(response_text)
            predicted = data.get("intelligence", [])
            print(f"AI predicted {len(predicted)} additional subdomains")
            return predicted
        except json.JSONDecodeError:
            print("Invalid AI response format")
            return []

# ============================================================================
# PASSIVE ENUMERATION MODULE (Module 1)
# ============================================================================

class PassiveEnumerator:
    """Passive subdomain enumeration from public sources"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def get_crtsh_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from crt.sh certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Split by newlines and commas
                        names = re.split(r'[\n,]', name_value)
                        for name in names:
                            name = name.strip().lower()
                            if name and domain in name:
                                subdomains.add(name)
                return list(subdomains)
        except Exception as e:
            print(f"Error getting crt.sh data: {e}")
        return []
    
    def get_virustotal_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from VirusTotal"""
        api_key = self.config.get_api_key('virustotal_api_key')
        if not api_key:
            return []
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': domain}
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('subdomains', [])
        except Exception as e:
            print(f"Error getting VirusTotal data: {e}")
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
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data[1:]:  # Skip header
                    if entry:
                        parsed = urlparse(entry[0])
                        if parsed.netloc and domain in parsed.netloc:
                            subdomains.add(parsed.netloc)
                return list(subdomains)
        except Exception as e:
            print(f"Error getting Wayback data: {e}")
        return []
    
    def get_shodan_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from Shodan SSL certificates"""
        api_key = self.config.get_api_key('shodan_api_key')
        if not api_key:
            return []
        
        try:
            api = shodan.Shodan(api_key)
            query = f"ssl:{domain}"
            results = api.search(query, limit=100)
            subdomains = set()
            
            for result in results['matches']:
                if 'ssl' in result and 'cert' in result['ssl']:
                    cert = result['ssl']['cert']
                    if 'subject' in cert and 'CN' in cert['subject']:
                        cn = cert['subject']['CN']
                        if domain in cn:
                            subdomains.add(cn)
            
            return list(subdomains)
        except Exception as e:
            print(f"Error getting Shodan data: {e}")
        return []
    
    def clean_subdomain(self, subdomain: str, domain: str) -> str:
        """Clean and normalize subdomain"""
        # Remove wildcards and invalid characters
        subdomain = re.sub(r'\*\.', '', subdomain)
        subdomain = re.sub(r'[^\w.-]', '', subdomain)
        
        # Ensure it's a valid subdomain of the target domain
        if subdomain.endswith(domain) and subdomain != domain:
            return subdomain.lower()
        return ""
    
    def deduplicate_subdomains(self, subdomains: List[str], domain: str) -> List[str]:
        """Remove duplicates and normalize subdomains"""
        cleaned = set()
        for subdomain in subdomains:
            cleaned_sub = self.clean_subdomain(subdomain, domain)
            if cleaned_sub:
                cleaned.add(cleaned_sub)
        return sorted(list(cleaned))
    
    def enumerate_passive(self, domain: str) -> Dict:
        """Perform passive enumeration from all sources"""
        print(f"\n🔍 Passive Enumeration Phase for {domain}...")
        
        all_subdomains = []
        sources_used = []
        
        # crt.sh
        print("Checking crt.sh...")
        crtsh_subs = self.get_crtsh_subdomains(domain)
        all_subdomains.extend(crtsh_subs)
        if crtsh_subs:
            sources_used.append("crt.sh")
            print(f"Found {len(crtsh_subs)} subdomains from crt.sh")
        
        # VirusTotal
        print("Checking VirusTotal...")
        vt_subs = self.get_virustotal_subdomains(domain)
        all_subdomains.extend(vt_subs)
        if vt_subs:
            sources_used.append("VirusTotal")
            print(f"Found {len(vt_subs)} subdomains from VirusTotal")
        
        # Wayback Machine
        print("Checking Wayback Machine...")
        wb_subs = self.get_wayback_subdomains(domain)
        all_subdomains.extend(wb_subs)
        if wb_subs:
            sources_used.append("Wayback Machine")
            print(f"Found {len(wb_subs)} subdomains from Wayback Machine")
        
        # Shodan
        print("Checking Shodan...")
        shodan_subs = self.get_shodan_subdomains(domain)
        all_subdomains.extend(shodan_subs)
        if shodan_subs:
            sources_used.append("Shodan")
            print(f"Found {len(shodan_subs)} subdomains from Shodan")
        
        # Deduplicate
        unique_subs = self.deduplicate_subdomains(all_subdomains, domain)
        duplicates_removed = len(all_subdomains) - len(unique_subs)
        
        print(f"\nPassive enumeration completed:")
        print(f"- Total collected: {len(all_subdomains)}")
        print(f"- Unique found: {len(unique_subs)}")
        print(f"- Duplicates removed: {duplicates_removed}")
        print(f"- Sources used: {', '.join(sources_used)}")
        
        return {
            "passive": unique_subs
        }

# ============================================================================
# ACTIVE ENUMERATION MODULE (Module 2)
# ============================================================================

class ActiveEnumerator:
    """Active subdomain enumeration with brute force and validation"""
    
    def __init__(self, config: Config, accepted_status_codes: List[int] = None):
        self.config = config
        self.accepted_status_codes = accepted_status_codes or [200]
    
    def load_wordlist(self, wordlist_file: str = "wordlist.txt") -> List[str]:
        """Load wordlist for brute force"""
        try:
            with open(wordlist_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Wordlist file '{wordlist_file}' not found")
            return []
    
    def check_subdomain(self, word: str, domain: str) -> Optional[str]:
        """Check if a subdomain exists"""
        subdomain = f"{word}.{domain}"
        url = f"http://{subdomain}"

        try:
            res = requests.get(url, timeout=1)
            if res.status_code != 404:  # Brute force accepts any response except 404
                return subdomain
        except:
            pass
        return None
    
    def validate_subdomain(self, subdomain: str) -> Dict:
        """Validate a subdomain and get its status"""
        for scheme in ["http://", "https://"]:
            try:
                res = requests.get(f"{scheme}{subdomain}", timeout=3)
                if res.status_code in self.accepted_status_codes:
                    return {
                        "subdomain": subdomain,
                        "url": f"{scheme}{subdomain}",
                        "status": res.status_code,
                        "valid": True
                    }
            except:
                continue
        
        return {
            "subdomain": subdomain,
            "url": None,
            "status": None,
            "valid": False
        }
    
    def brute_force(self, domain: str, wordlist_file: str = "wordlist.txt") -> List[str]:
        """Perform brute force subdomain discovery"""
        print(f"\n💥 Brute Force Phase for {domain}...")
        
        words = self.load_wordlist(wordlist_file)
        if not words:
            return []
        
        print(f"Loaded {len(words)} words from wordlist")
        valid_subdomains = []
        
        def check_and_collect(word):
            result = self.check_subdomain(word, domain)
            if result:
                print(f"[+] Found: {result}")
                valid_subdomains.append(result)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_and_collect, words)
        
        print(f"Brute force completed. Found {len(valid_subdomains)} subdomains.")
        return valid_subdomains
    
    def validate_subdomains(self, subdomains: List[str]) -> Dict:
        """Validate discovered subdomains"""
        print(f"\n✅ Validation Phase...")
        
        validated = []
        unresolved = []
        
        for subdomain in subdomains:
            result = self.validate_subdomain(subdomain)
            if result["valid"]:
                validated.append(result)
                print(f"[+] {subdomain} - Status: {result['status']}")
            else:
                unresolved.append(subdomain)
                print(f"[-] {subdomain} - Unresolved")
        
        return {
            "validated": validated,
            "unresolved": unresolved
        }

# ============================================================================
# MAIN SUBSPYDER CLASS
# ============================================================================

class CompleteSubSpyder:
    """Complete subdomain enumeration tool combining all modules"""
    
    def __init__(self, accepted_status_codes: List[int] = None):
        self.config = Config()
        self.passive_enumerator = PassiveEnumerator(self.config)
        self.active_enumerator = ActiveEnumerator(self.config, accepted_status_codes)
        self.ai_predictor = AIPredictor(self.config)
        self.subdomain_validator = SubdomainValidator(self.config)
    
    def run_complete_enumeration(self, domain: str, wordlist_file: str = "wordlist.txt") -> Dict:
        """Run complete enumeration using all modules"""
        print(f"🚀 Starting Complete SubSpyder Enumeration for {domain}")
        print("=" * 60)
        
        results = {
            "target_domain": domain,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {}
        }
        
        # Module 1: Passive Enumeration
        passive_results = self.passive_enumerator.enumerate_passive(domain)
        results["modules"]["passive"] = passive_results
        
        # Module 2: Active Enumeration
        brute_results = self.active_enumerator.brute_force(domain, wordlist_file)
        validation_results = self.active_enumerator.validate_subdomains(brute_results)
        
        results["modules"]["active"] = {
            "bruteforce": brute_results,
            "validation": validation_results
        }
        
        # Combine all discovered subdomains
        all_discovered = set()
        all_discovered.update(passive_results["passive"])
        all_discovered.update(brute_results)
        
        # Module 3: AI Prediction
        if all_discovered:
            ai_predictions = self.ai_predictor.predict_subdomains(domain, list(all_discovered))
            results["modules"]["ai_prediction"] = {
                "predicted_subdomains": ai_predictions
            }
            all_discovered.update(ai_predictions)
        
        # Module 4: Subdomain Validation and Discord Notification
        if all_discovered:
            print(f"\n🔍 Running comprehensive validation on {len(all_discovered)} subdomains...")
            validation_results = asyncio.run(self.subdomain_validator.validate_subdomains(list(all_discovered)))
            results["modules"]["comprehensive_validation"] = validation_results
        
        return results
    
    def save_results(self, results: Dict, filename: str = None):
        """Save simplified results with just subdomains to JSON file"""
        if not filename:
            filename = self.config.get_setting('output_file', 'complete_subspyder_results.json')
        
        # Extract all subdomains from different modules
        all_subdomains = set()
        
        # Passive enumeration subdomains
        if "modules" in results and "passive" in results["modules"]:
            passive_subs = results["modules"]["passive"].get("passive", [])
            all_subdomains.update(passive_subs)
        
        # Brute force subdomains
        if "modules" in results and "active" in results["modules"]:
            brute_subs = results["modules"]["active"].get("bruteforce", [])
            all_subdomains.update(brute_subs)
        
        # AI predicted subdomains
        if "modules" in results and "ai_prediction" in results["modules"]:
            ai_subs = results["modules"]["ai_prediction"].get("predicted_subdomains", [])
            all_subdomains.update(ai_subs)
        
        # Create simplified JSON with just subdomains
        simplified_results = {
            "subdomains": sorted(list(all_subdomains))
        }
        
        with open(filename, 'w') as f:
            json.dump(simplified_results, f, indent=4)
        
        print(f"\n💾 Results saved to: {filename}")
        print(f"📊 Total subdomains found: {len(all_subdomains)}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def print_banner():
    """Print tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Complete SubSpyder                        ║
    ║              All Modules Merged - v1.1                       ║
    ║                                                              ║
    ║  🔍 Passive Enumeration  |  💥 Active Brute Force          ║
    ║  ✅ Subdomain Validation |  🤖 AI Prediction               ║
    ║  📢 Discord Notifications|  🔍 Comprehensive Validation    ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_help():
    """Print help information"""
    help_text = """
    Usage: python complete_subspyder.py <domain> [options]
    
    Examples:
      python complete_subspyder.py example.com
      python complete_subspyder.py github.com -o results.json
      python complete_subspyder.py example.com --status-codes 200,403,500
      python complete_subspyder.py example.com --wordlist custom_wordlist.txt
      python complete_subspyder.py --config
      python complete_subspyder.py --test-discord
      python complete_subspyder.py --help
    
    Options:
      -o, --output <file>    Specify output file (default: complete_subspyder_results.json)
      --status-codes <codes> Specify accepted HTTP status codes (default: 200)
      --wordlist <file>      Specify custom wordlist file (default: module-2/wordlist.txt)
      --config               Show API key configuration status
      --response-codes       Show server response codes information
      --test-discord         Test Discord webhook connectivity
      --help                 Show this help message
    
    The tool will:
    1. Perform passive enumeration from public sources
    2. Run brute force subdomain discovery
    3. Validate all discovered subdomains
    4. Use AI to predict additional subdomains
    5. Run comprehensive validation with Discord notifications
    6. Save comprehensive results to JSON file
    
    Discord Notifications:
    - Configure discord_webhook_url and enable_discord_notifications in subspyder_config.ini
    - Notifications include live/dead subdomain counts and status codes
    """
    print(help_text)

def print_response_codes():
    """Print server response codes information"""
    response_codes_text = """
    📊 SERVER RESPONSE CODES
    
    Brute Force Phase:
    - Accepts any response except 404 (Not Found)
    - This includes: 200, 301, 302, 403, 500, etc.
    - Purpose: Find subdomains that exist but may not be fully functional
    
    Validation Phase:
    - Accepts only HTTP 200 (OK) responses
    - Tests both HTTP and HTTPS protocols
    - Purpose: Ensure subdomains are fully functional
    
    AI Prediction Phase:
    - Accepts only HTTP 200 (OK) responses
    - Validates AI-predicted subdomains
    - Purpose: Only keep predictions that actually work
    
    Passive Enumeration:
    - Uses public APIs and databases
    - No HTTP validation required
    - Sources: crt.sh, VirusTotal, Wayback Machine, Shodan
    """
    print(response_codes_text)

def test_discord_webhook():
    """Test Discord webhook connectivity"""
    config = Config()
    webhook_url = config.get_setting('discord_webhook_url')
    enabled = config.get_setting('enable_discord_notifications', 'false').lower() == 'true'
    
    print("🔔 Discord Webhook Test")
    print("=" * 40)
    print(f"Webhook URL: {'Set' if webhook_url else 'Not set'}")
    print(f"Notifications Enabled: {enabled}")
    
    if not webhook_url:
        print("❌ No webhook URL configured")
        return False
    
    if not enabled:
        print("❌ Discord notifications are disabled")
        return False
    
    # Test payload
    test_payload = {
        "embeds": [{
            "title": "🧪 SubSpyder Discord Test",
            "description": "This is a test notification from SubSpyder",
            "color": 0x00ff00,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }]
    }
    
    try:
        print("📤 Sending test notification...")
        response = requests.post(webhook_url, json=test_payload, headers={'Content-Type': 'application/json'}, timeout=10)
        
        if response.status_code == 204:
            print("✅ Discord webhook test successful!")
            return True
        else:
            print(f"❌ Discord webhook test failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Discord webhook test error: {e}")
        return False

def main():
    """Main execution function"""
    import sys
    
    print_banner()
    
    # Parse command line arguments
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return
    
    if "--config" in sys.argv:
        config = Config()
        config.print_api_key_status()
        return
    
    if "--response-codes" in sys.argv:
        print_response_codes()
        return
    
    if "--test-discord" in sys.argv:
        test_discord_webhook()
        return
    
    domain = sys.argv[1]
    output_file = None
    accepted_status_codes = [200]  # Default
    wordlist_file = "module-2/wordlist.txt"  # Default
    
    # Parse status codes option
    if "--status-codes" in sys.argv:
        try:
            status_index = sys.argv.index("--status-codes")
            if status_index + 1 < len(sys.argv):
                status_codes_str = sys.argv[status_index + 1]
                accepted_status_codes = [int(code.strip()) for code in status_codes_str.split(",")]
                print(f"🔧 Using custom status codes: {accepted_status_codes}")
        except (ValueError, IndexError):
            print("❌ Invalid status codes format. Using default: [200]")
            accepted_status_codes = [200]
    
    # Parse wordlist option
    if "--wordlist" in sys.argv:
        try:
            wordlist_index = sys.argv.index("--wordlist")
            if wordlist_index + 1 < len(sys.argv):
                wordlist_file = sys.argv[wordlist_index + 1]
                print(f"📚 Using custom wordlist: {wordlist_file}")
        except (ValueError, IndexError):
            print("❌ Invalid wordlist format. Using default: module-2/wordlist.txt")
            wordlist_file = "module-2/wordlist.txt"
    
    # Parse output file option
    if "-o" in sys.argv or "--output" in sys.argv:
        try:
            output_index = sys.argv.index("-o") if "-o" in sys.argv else sys.argv.index("--output")
            if output_index + 1 < len(sys.argv):
                output_file = sys.argv[output_index + 1]
        except ValueError:
            pass
    
    # Initialize and run
    subspyder = CompleteSubSpyder(accepted_status_codes)
    
    try:
        results = subspyder.run_complete_enumeration(domain, wordlist_file)
        subspyder.save_results(results, output_file)
        
        print(f"\n✅ Complete enumeration finished for {domain}")
        print("Check the output file for detailed results!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Enumeration interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during enumeration: {e}")

if __name__ == "__main__":
    main() 