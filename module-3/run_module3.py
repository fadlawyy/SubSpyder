import json
from src.ai_predictor import query_gemini
from src.domain_type_detector import detect_website_type

def main():
    domain = "kareem.net"
    known_subdomains = ["www.kareem.net", "book.kareem.net", "help.kareem.net"]

    print(f"Domain: {domain}")
    print(f"Known Subdomains: {known_subdomains}")

    # Step 1: Detect website type
    website_type = detect_website_type(known_subdomains)
    print(f"Detected Website Type: {website_type}")

    # Step 2: Create the prompt
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

    print("\nCrafted Prompt:\n", prompt.strip())

    # Step 3: Query Gemini
    response_text = query_gemini(prompt)

    # Step 4: Clean response (remove ```json ... ``` if present)
    if response_text.strip().startswith("```"):
        response_text = response_text.strip().removeprefix("```json").removesuffix("```").strip()

    try:
        data = json.loads(response_text)
        print("\nPredicted Subdomains from Gemini AI:")
        print(json.dumps(data, indent=2))
    except json.JSONDecodeError:
        print("Invalid response format:\n", response_text)

if __name__ == "__main__":
    main()
