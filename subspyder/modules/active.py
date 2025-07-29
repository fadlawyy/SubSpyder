"""
Active subdomain enumeration module
"""

import requests
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

from ..core.config import Config


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