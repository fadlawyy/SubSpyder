"""
AI-powered subdomain prediction module
"""

import json
import requests
from typing import List

from ..core.config import Config


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