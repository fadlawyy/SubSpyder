import json
import requests

API_KEY = "AIzaSyC-r2l0Z6zEU6_VgKBOnBtf7yF_SvUPOOw"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def query_gemini(prompt: str) -> str:
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": API_KEY,
    }

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    try:
        response = requests.post(GEMINI_URL, headers=headers, json=payload)
        data = response.json()
        return data['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        print("Gemini API Error:", e)
        return json.dumps({"intelligence": []})

def detect_type_ai(subdomains: list) -> str:
    prompt = (
        f"Given these subdomains: {subdomains}, what type of website is this most likely to be?\n"
        "Choose ONE category only from this list:\n"
        "ecommerce, technical, blog, news, education, media, finance, gaming, travel, security, general.\n"
        "Respond ONLY with the category name."
    )

    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": API_KEY,
    }

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    try:
        response = requests.post(GEMINI_URL, headers=headers, json=payload)
        data = response.json()
        text = data['candidates'][0]['content']['parts'][0]['text'].strip().lower()

        allowed_categories = [
            "ecommerce", "technical", "blog", "news", "education",
            "media", "finance", "gaming", "travel", "security", "general"
        ]
        return text if text in allowed_categories else "general"

    except Exception as e:
        print("Gemini API Error:", e)
        return "general"
