"""
Subdomain validation and Discord notification module
"""

import socket
import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Optional

from ..core.config import Config
from ..utils.discord import DiscordNotifier


class SubdomainValidator:
    """Subdomain validation and Discord notification module"""
    
    def __init__(self, config: Config):
        self.config = config
        self.timeout = int(self.config.get_setting('timeout', '10'))
        
        # Setup Discord notifier
        webhook_url = self.config.get_setting('discord_webhook_url')
        discord_enabled = self.config.get_setting('enable_discord_notifications', 'false').lower() == 'true'
        self.discord_notifier = DiscordNotifier(webhook_url, discord_enabled)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.log = logging.getLogger(__name__)
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
        except Exception as e:
            self.log.error(f"Resolve error for {domain}: {e}")
            return None
    
    async def check_target(self, domain: str, session: aiohttp.ClientSession) -> Dict:
        """Check a single target domain"""
        result = {
            'domain': domain,
            'ip': None,
            'http_code': None,
            'https_code': None,
            'http_url': None,
            'https_url': None,
            'http_err': None,
            'https_err': None
        }

        result['ip'] = self.resolve_domain(domain)
        if result['ip']:
            http = f"http://{domain}"
            https = f"https://{domain}"
            try:
                async with session.get(http, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as res:
                    result['http_code'] = res.status
                    result['http_url'] = str(res.url)
            except Exception as e:
                result['http_err'] = str(e)
            try:
                async with session.get(https, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as res:
                    result['https_code'] = res.status
                    result['https_url'] = str(res.url)
            except Exception as e:
                result['https_err'] = str(e)
        return result
    
    async def check_targets(self, domains: List[str]) -> List[Dict]:
        """Check multiple targets asynchronously"""
        results = []
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.check_target(d, session) for d in domains]
            for i in range(0, len(tasks), 10):
                chunk = tasks[i:i+10]
                try:
                    chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                    for r in chunk_results:
                        if isinstance(r, Exception):
                            self.log.error(f"Batch error: {r}")
                        else:
                            results.append(r)
                except Exception as e:
                    self.log.error(f"Error during batch: {e}")
                await asyncio.sleep(0.5)
        return results
    
    async def validate_subdomains(self, subdomains: List[str]) -> Dict:
        """Validate subdomains and optionally send Discord notification"""
        print(f"\n🔍 Subdomain Validation Phase...")
        print(f"Checking {len(subdomains)} subdomains...")
        
        start_time = time.time()
        results = await self.check_targets(subdomains)
        elapsed_time = time.time() - start_time
        
        # Count live and dead subdomains
        live_count = sum(1 for d in results if d['ip'] and (d['http_code'] or d['https_code']))
        dead_count = len(results) - live_count
        
        print(f"Validation completed in {elapsed_time:.2f}s")
        print(f"✅ Live: {live_count}, ❌ Dead: {dead_count}")
        
        # Send Discord notification
        print(f"\n🔔 Discord Notification Phase...")
        payload = self.discord_notifier.build_payload(results)
        notification_sent = self.discord_notifier.send_notification(payload)
        
        if notification_sent:
            print("✅ Discord notification completed successfully")
        else:
            print("⚠️  Discord notification failed or was disabled")
        
        return {
            "validation_results": results,
            "live_count": live_count,
            "dead_count": dead_count,
            "elapsed_time": elapsed_time
        }
    
    def test_discord_webhook(self) -> bool:
        """Test Discord webhook connectivity"""
        return self.discord_notifier.send_test_notification() 