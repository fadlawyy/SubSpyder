from src.ai_predictor import detect_type_ai

def detect_website_type(subdomains: list) -> str:
    return detect_type_ai(subdomains)
