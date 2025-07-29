import requests
import json
from concurrent.futures import ThreadPoolExecutor

target_domain = "uber.com"

with open("wordlist.txt", "r") as f:
    words = [line.strip() for line in f]

valid_subdomains = []

def check_subdomain(word):
    subdomain = f"{word}.{target_domain}"
    url = f"http://{subdomain}"

    try:
        res = requests.get(url, timeout=1)  
        if res.status_code != 404:
            print(f"[+] Found: {subdomain} (Status: {res.status_code})")
            valid_subdomains.append(subdomain)
    except:
        pass

print(f" Starting fast brute-force on {target_domain}...\n")

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(check_subdomain, words)

with open("brute_results.json", "w") as f:
    json.dump({"bruteforce": valid_subdomains}, f, indent=4)

print("\n Done! Results saved in brute_result.json")
