"""
Helper functions for subdomain processing
"""

import re
from typing import List


def clean_subdomain(subdomain: str, domain: str) -> str:
    """Clean and normalize subdomain"""
    # Remove wildcards and invalid characters
    subdomain = re.sub(r'\*\.', '', subdomain)
    subdomain = re.sub(r'[^\w.-]', '', subdomain)
    
    # Ensure it's a valid subdomain of the target domain
    if subdomain.endswith(domain) and subdomain != domain:
        return subdomain.lower()
    return ""


def deduplicate_subdomains(subdomains: List[str], domain: str) -> List[str]:
    """Remove duplicates and normalize subdomains"""
    cleaned = set()
    for subdomain in subdomains:
        cleaned_sub = clean_subdomain(subdomain, domain)
        if cleaned_sub:
            cleaned.add(cleaned_sub)
    return sorted(list(cleaned))


def validate_domain(domain: str) -> bool:
    """Validate if a string is a valid domain"""
    if not domain:
        return False
    
    # Basic domain validation
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))


def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    # Remove protocol
    if '://' in url:
        url = url.split('://', 1)[1]
    
    # Remove path and query parameters
    domain = url.split('/')[0]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return domain.lower() 