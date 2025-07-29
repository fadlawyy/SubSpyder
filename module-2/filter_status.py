import json
import requests

# Load subdomains from brute_result.json
with open("brute_results.json", "r") as f:
    data = json.load(f)
    subdomains = data.get("bruteforce", [])

validated = []
unresolved = []

print(" Checking status of found subdomains...\n")

for subdomain in subdomains:
    status = None
    for scheme in ["http://", "https://"]:
        try:
            res = requests.get(f"{scheme}{subdomain}", timeout=3)
            status = res.status_code
            validated.append({
                "subdomain": subdomain,
                "url": f"{scheme}{subdomain}",
                "status": status
            })
            print(f"[+] {subdomain} ({scheme.upper().replace(':', '')}) - Status: {status}")
            break
        except:
            continue

    if status is None:
        unresolved.append(subdomain)
        print(f"[-] {subdomain}  Unresolved")

# Save to filtered_result.json
with open("filtered_result.json", "w") as out_file:
    json.dump({
        "validated": validated,
        "unresolved": unresolved
    }, out_file, indent=4)

print("\n Done! Results saved in filtered_result.json")
