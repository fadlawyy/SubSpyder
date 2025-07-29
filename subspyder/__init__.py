"""
SubSpyder - Advanced Subdomain Enumeration Tool

A comprehensive subdomain enumeration tool that combines multiple advanced techniques
for discovering subdomains of any target domain.

Author: SubSpyder Team
Version: 2.0.0
"""

from .core.subspyder import CompleteSubSpyder
from .core.config import Config
from .modules.passive import PassiveEnumerator
from .modules.active import ActiveEnumerator
from .modules.ai_predictor import AIPredictor
from .modules.validator import SubdomainValidator

__version__ = "2.0.0"
__author__ = "SubSpyder Team"
__description__ = "Advanced Subdomain Enumeration Tool"

# Main exports
__all__ = [
    "CompleteSubSpyder",
    "Config", 
    "PassiveEnumerator",
    "ActiveEnumerator",
    "AIPredictor",
    "SubdomainValidator"
]

# Convenience function for quick usage
def run_enumeration(domain: str, **kwargs):
    """
    Quick function to run subdomain enumeration
    
    Args:
        domain: Target domain to enumerate
        **kwargs: Additional arguments for CompleteSubSpyder
    
    Returns:
        Dict containing enumeration results
    """
    subspyder = CompleteSubSpyder(**kwargs)
    return subspyder.run_complete_enumeration(domain) 