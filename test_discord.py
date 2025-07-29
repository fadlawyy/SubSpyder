#!/usr/bin/env python3
"""
Discord Webhook Test Script for SubSpyder
Tests the Discord notification functionality
"""

import requests
import time
import configparser
import os

def test_discord_webhook():
    """Test Discord webhook connectivity"""
    
    # Load configuration
    config = configparser.ConfigParser()
    config.read('subspyder_config.ini')
    
    webhook_url = config.get('SETTINGS', 'discord_webhook_url', fallback='')
    enabled = config.get('SETTINGS', 'enable_discord_notifications', fallback='false').lower() == 'true'
    
    print("🔔 Discord Webhook Test")
    print("=" * 40)
    print(f"Webhook URL: {'Set' if webhook_url else 'Not set'}")
    print(f"Notifications Enabled: {enabled}")
    
    if not webhook_url:
        print("❌ No webhook URL configured")
        return False
    
    if not enabled:
        print("❌ Discord notifications are disabled")
        return False
    
    # Test payload
    test_payload = {
        "embeds": [{
            "title": "🧪 SubSpyder Discord Test",
            "description": "This is a test notification from SubSpyder\n\nIf you see this message, Discord notifications are working correctly!",
            "color": 0x00ff00,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "footer": {
                "text": "SubSpyder Test Notification"
            }
        }]
    }
    
    try:
        print("📤 Sending test notification...")
        response = requests.post(webhook_url, json=test_payload, headers={'Content-Type': 'application/json'}, timeout=10)
        
        if response.status_code == 204:
            print("✅ Discord webhook test successful!")
            print("📱 Check your Discord channel for the test message")
            return True
        else:
            print(f"❌ Discord webhook test failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Discord webhook test error: {e}")
        return False

if __name__ == "__main__":
    test_discord_webhook() 