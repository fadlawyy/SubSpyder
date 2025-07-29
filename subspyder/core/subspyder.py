"""
Main SubSpyder class that orchestrates all enumeration modules
"""

import time
import json
from typing import List, Dict

from .config import Config
from ..modules.passive import PassiveEnumerator
from ..modules.active import ActiveEnumerator
from ..modules.ai_predictor import AIPredictor
from ..modules.validator import SubdomainValidator


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
            import asyncio
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
    
    def test_discord_webhook(self) -> bool:
        """Test Discord webhook connectivity"""
        return self.subdomain_validator.test_discord_webhook() 