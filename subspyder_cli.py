#!/usr/bin/env python3
"""
SubSpyder CLI - Command Line Interface

A comprehensive subdomain enumeration tool that combines multiple advanced techniques
for discovering subdomains of any target domain.

Usage: python subspyder_cli.py <domain>
"""

import sys
import time
from subspyder import CompleteSubSpyder, Config


def print_banner():
    """Print tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Complete SubSpyder                        ║
    ║              Modular Package - v2.0.0                        ║
    ║                                                              ║
    ║  🔍 Passive Enumeration  |  💥 Active Brute Force          ║
    ║  ✅ Subdomain Validation |  🤖 AI Prediction               ║
    ║  📢 Discord Notifications|  🔍 Comprehensive Validation    ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_help():
    """Print help information"""
    help_text = """
    Usage: python subspyder_cli.py <domain> [options]
    
    Examples:
      python subspyder_cli.py example.com
      python subspyder_cli.py github.com -o results.json
      python subspyder_cli.py example.com --status-codes 200,403,500
      python subspyder_cli.py example.com --wordlist custom_wordlist.txt
      python subspyder_cli.py --config
      python subspyder_cli.py --test-discord
      python subspyder_cli.py --help
    
    Options:
      -o, --output <file>    Specify output file (default: complete_subspyder_results.json)
      --status-codes <codes> Specify accepted HTTP status codes (default: 200)
      --wordlist <file>      Specify custom wordlist file (default: wordlist.txt)
      --config               Show API key configuration status
      --test-discord         Test Discord webhook connectivity
      --help                 Show this help message
    
    The tool will:
    1. Perform passive enumeration from public sources
    2. Run brute force subdomain discovery
    3. Validate all discovered subdomains
    4. Use AI to predict additional subdomains
    5. Run comprehensive validation with Discord notifications
    6. Save comprehensive results to JSON file
    
    Discord Notifications:
    - Configure discord_webhook_url and enable_discord_notifications in subspyder_config.ini
    - Notifications include live/dead subdomain counts and status codes
    """
    print(help_text)


def print_response_codes():
    """Print server response codes information"""
    response_codes_text = """
    📊 SERVER RESPONSE CODES
    
    Brute Force Phase:
    - Accepts any response except 404 (Not Found)
    - This includes: 200, 301, 302, 403, 500, etc.
    - Purpose: Find subdomains that exist but may not be fully functional
    
    Validation Phase:
    - Accepts only HTTP 200 (OK) responses
    - Tests both HTTP and HTTPS protocols
    - Purpose: Ensure subdomains are fully functional
    
    AI Prediction Phase:
    - Accepts only HTTP 200 (OK) responses
    - Validates AI-predicted subdomains
    - Purpose: Only keep predictions that actually work
    
    Passive Enumeration:
    - Uses public APIs and databases
    - No HTTP validation required
    - Sources: crt.sh, VirusTotal, Wayback Machine, Shodan
    """
    print(response_codes_text)


def test_discord_webhook():
    """Test Discord webhook connectivity"""
    config = Config()
    webhook_url = config.get_setting('discord_webhook_url')
    enabled = config.get_setting('enable_discord_notifications', 'false').lower() == 'true'
    
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
    
    # Test using the SubSpyder instance
    subspyder = CompleteSubSpyder()
    success = subspyder.test_discord_webhook()
    
    if success:
        print("✅ Discord webhook test successful!")
        print("📱 Check your Discord channel for the test message")
    else:
        print("❌ Discord webhook test failed")
    
    return success


def main():
    """Main execution function"""
    print_banner()
    
    # Parse command line arguments
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return
    
    if "--config" in sys.argv:
        config = Config()
        config.print_api_key_status()
        return
    
    if "--test-discord" in sys.argv:
        test_discord_webhook()
        return
    
    domain = sys.argv[1]
    output_file = None
    accepted_status_codes = [200]  # Default
    wordlist_file = "wordlist.txt"  # Default
    
    # Parse status codes option
    if "--status-codes" in sys.argv:
        try:
            status_index = sys.argv.index("--status-codes")
            if status_index + 1 < len(sys.argv):
                status_codes_str = sys.argv[status_index + 1]
                accepted_status_codes = [int(code.strip()) for code in status_codes_str.split(",")]
                print(f"🔧 Using custom status codes: {accepted_status_codes}")
        except (ValueError, IndexError):
            print("❌ Invalid status codes format. Using default: [200]")
            accepted_status_codes = [200]
    
    # Parse wordlist option
    if "--wordlist" in sys.argv:
        try:
            wordlist_index = sys.argv.index("--wordlist")
            if wordlist_index + 1 < len(sys.argv):
                wordlist_file = sys.argv[wordlist_index + 1]
                print(f"📚 Using custom wordlist: {wordlist_file}")
        except (ValueError, IndexError):
            print("❌ Invalid wordlist format. Using default: wordlist.txt")
            wordlist_file = "wordlist.txt"
    
    # Parse output file option
    if "-o" in sys.argv or "--output" in sys.argv:
        try:
            output_index = sys.argv.index("-o") if "-o" in sys.argv else sys.argv.index("--output")
            if output_index + 1 < len(sys.argv):
                output_file = sys.argv[output_index + 1]
        except ValueError:
            pass
    
    # Initialize and run
    subspyder = CompleteSubSpyder(accepted_status_codes)
    
    try:
        results = subspyder.run_complete_enumeration(domain, wordlist_file)
        subspyder.save_results(results, output_file)
        
        print(f"\n✅ Complete enumeration finished for {domain}")
        print("Check the output file for detailed results!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Enumeration interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during enumeration: {e}")


if __name__ == "__main__":
    main() 