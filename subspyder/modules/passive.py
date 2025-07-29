"""
Passive subdomain enumeration module
"""

import requests
import re
import shodan
from typing import List, Dict
from urllib.parse import urlparse

from ..core.config import Config
from ..utils.helpers import clean_subdomain, deduplicate_subdomains


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
        unique_subs = deduplicate_subdomains(all_subdomains, domain)
        duplicates_removed = len(all_subdomains) - len(unique_subs)
        
        print(f"\nPassive enumeration completed:")
        print(f"- Total collected: {len(all_subdomains)}")
        print(f"- Unique found: {len(unique_subs)}")
        print(f"- Duplicates removed: {duplicates_removed}")
        print(f"- Sources used: {', '.join(sources_used)}")
        
        return {
            "passive": unique_subs
        } 