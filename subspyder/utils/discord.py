"""
Discord notification utilities for SubSpyder
"""

import requests
import time
import logging
from typing import Dict, List, Optional


class DiscordNotifier:
    """Discord notification handler"""
    
    def __init__(self, webhook_url: str, enabled: bool = True):
        self.webhook_url = webhook_url
        self.enabled = enabled
        self.log = logging.getLogger(__name__)
    
    def build_payload(self, results: List[Dict]) -> Dict:
        """Build Discord notification payload"""
        live = []
        dead = []
        
        for r in results:
            if r['ip']:
                info = f"**{r['domain']}** ({r['ip']})"
                codes = []
                if r['http_code']: 
                    codes.append(f"HTTP: {r['http_code']}")
                if r['https_code']: 
                    codes.append(f"HTTPS: {r['https_code']}")
                if codes:
                    info += " - " + " | ".join(codes)
                    live.append(info)
                else:
                    dead.append(info)
            else:
                dead.append(f"**{r['domain']}** - No IP")
        
        embed = {
            "title": "🌐 Subdomain Status Report",
            "color": 0x00ff00 if live else 0xff0000,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fields": []
        }
        
        if live:
            live_txt = "\n".join(live[:25])
            if len(live) > 25:
                live_txt += f"\n... and {len(live) - 25} more"
            embed["fields"].append({
                "name": f"✅ Live ({len(live)})", 
                "value": live_txt, 
                "inline": False
            })
        
        if dead:
            dead_txt = "\n".join(dead[:25])
            if len(dead) > 25:
                dead_txt += f"\n... and {len(dead) - 25} more"
            embed["fields"].append({
                "name": f"❌ Dead ({len(dead)})", 
                "value": dead_txt, 
                "inline": False
            })
        
        return {"embeds": [embed]}
    
    def send_notification(self, payload: Dict) -> bool:
        """Send Discord notification"""
        if not self.enabled or not self.webhook_url:
            return False
        
        try:
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                headers={'Content-Type': 'application/json'}, 
                timeout=30
            )
            
            if response.status_code == 204:
                self.log.info("Discord notification sent successfully")
                return True
            else:
                self.log.error(f"Discord error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.log.error(f"Discord send error: {e}")
            return False
    
    def send_test_notification(self) -> bool:
        """Send a test notification"""
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
        
        return self.send_notification(test_payload) 