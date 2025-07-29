import json, socket, requests, asyncio, aiohttp, time, logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

WEBHOOK_URL = "https://discord.com/api/webhooks/1399723181274697919/AahX9uOBxXeRoLROOy2_ov2ShtTi4Ip7194qjOQZc5Uanf9g1lh0OZBfbtUqWkD8Lbvd"
TIMEOUT = 10

def load_targets(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            raw_list = data.get('subdomains', [])
            clean_list = [d.strip() for d in raw_list if d.strip() and d.strip() != "Subdomain"]
            log.info(f"Loaded {len(clean_list)} targets from {path}")
            return clean_list
    except Exception as e:
        log.error(f"Failed loading targets: {e}")
        return []

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
    except Exception as e:
        log.error(f"Resolve error for {domain}: {e}")
        return None

async def check_target(domain, session):
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

    result['ip'] = resolve_domain(domain)
    if result['ip']:
        http = f"http://{domain}"
        https = f"https://{domain}"
        try:
            async with session.get(http, timeout=aiohttp.ClientTimeout(total=TIMEOUT), allow_redirects=True) as res:
                result['http_code'] = res.status
                result['http_url'] = str(res.url)
        except Exception as e:
            result['http_err'] = str(e)
        try:
            async with session.get(https, timeout=aiohttp.ClientTimeout(total=TIMEOUT), allow_redirects=True) as res:
                result['https_code'] = res.status
                result['https_url'] = str(res.url)
        except Exception as e:
            result['https_err'] = str(e)
    return result

async def check_targets(domains):
    results = []
    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_target(d, session) for d in domains]
        for i in range(0, len(tasks), 10):
            chunk = tasks[i:i+10]
            try:
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                for r in chunk_results:
                    if isinstance(r, Exception):
                        log.error(f"Batch error: {r}")
                    else:
                        results.append(r)
            except Exception as e:
                log.error(f"Error during batch: {e}")
            await asyncio.sleep(0.5)
    return results

def build_discord_payload(results):
    live = []
    dead = []
    for r in results:
        if r['ip']:
            info = f"**{r['domain']}** ({r['ip']})"
            codes = []
            if r['http_code']: codes.append(f"HTTP: {r['http_code']}")
            if r['https_code']: codes.append(f"HTTPS: {r['https_code']}")
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
        embed["fields"].append({"name": f"✅ Live ({len(live)})", "value": live_txt, "inline": False})
    if dead:
        dead_txt = "\n".join(dead[:25])
        if len(dead) > 25:
            dead_txt += f"\n... and {len(dead) - 25} more"
        embed["fields"].append({"name": f"❌ Dead ({len(dead)})", "value": dead_txt, "inline": False})
    return {"embeds": [embed]}

def notify_discord(payload):
    try:
        res = requests.post(WEBHOOK_URL, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
        if res.status_code == 204:
            log.info("Notification sent")
            return True
        else:
            log.error(f"Discord error: {res.status_code} - {res.text}")
            return False
    except Exception as e:
        log.error(f"Send error: {e}")
        return False

async def run():
    log.info("Starting check...")
    domains = load_targets('../subspyder_results.json')
    if not domains:
        log.error("No domains found")
        return
    log.info(f"Checking {len(domains)} domains...")
    start = time.time()
    data = await check_targets(domains)
    log.info(f"Checked {len(data)} in {time.time() - start:.2f}s")
    up = sum(1 for d in data if d['ip'] and (d['http_code'] or d['https_code']))
    down = len(data) - up
    log.info(f"Up: {up}, Down: {down}")
    msg = build_discord_payload(data)
    notify_discord(msg)

if __name__ == "__main__":
    asyncio.run(run())
