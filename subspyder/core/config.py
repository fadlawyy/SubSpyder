"""
Configuration management for SubSpyder
"""

import os
import configparser
from typing import Optional


class Config:
    """Configuration class for API keys and settings"""
    
    def __init__(self, config_file: str = "subspyder_config.ini"):
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        self.config = configparser.ConfigParser()
        
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['API_KEYS'] = {
            'virustotal_api_key': '',
            'securitytrails_api_key': '',
            'shodan_api_key': '',
            'dnsdumpster_api_key': '',
            'criminalip_api_key': '',
            'gemini_api_key': 'AIzaSyC-r2l0Z6zEU6_VgKBOnBtf7yF_SvUPOOw'
        }
        
        self.config['SETTINGS'] = {
            'timeout': '10',
            'delay': '1',
            'output_file': 'complete_subspyder_results.json',
            'discord_webhook_url': '',
            'enable_discord_notifications': 'false'
        }
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        
        print(f"Created default config file: {self.config_file}")
        print("Please edit the file to add your API keys.")
    
    def get_api_key(self, key_name: str) -> Optional[str]:
        """Get API key from config or environment"""
        env_key = key_name.upper()
        return (self.config.get('API_KEYS', key_name, fallback='') or 
                os.getenv(env_key))
    
    def get_setting(self, key: str, default: str = '') -> str:
        """Get a setting value"""
        return self.config.get('SETTINGS', key, fallback=default)
    
    def print_api_key_status(self):
        """Print the status of API keys"""
        print("\n=== API Key Status ===")
        keys = ['virustotal_api_key', 'securitytrails_api_key', 'shodan_api_key', 
                'dnsdumpster_api_key', 'criminalip_api_key', 'gemini_api_key']
        
        for key in keys:
            api_key = self.get_api_key(key)
            status = '✅ Set' if api_key else '❌ Not set'
            print(f"{key.replace('_api_key', '').title()}: {status}")
        
        # Check Discord webhook
        webhook_url = self.get_setting('discord_webhook_url')
        discord_enabled = self.get_setting('enable_discord_notifications', 'false').lower() == 'true'
        webhook_status = '✅ Set' if webhook_url and discord_enabled else '❌ Not set/disabled'
        print(f"Discord Webhook: {webhook_status}") 