#!/usr/bin/env python3
"""
Example usage of the SubSpyder package

This demonstrates how to use the refactored SubSpyder package
in your own Python scripts.
"""

from subspyder import CompleteSubSpyder, Config, run_enumeration


def example_basic_usage():
    """Basic usage example"""
    print("=== Basic Usage Example ===")
    
    # Simple one-liner
    results = run_enumeration("example.com")
    print(f"Found {len(results['modules']['passive']['passive'])} subdomains via passive enumeration")


def example_advanced_usage():
    """Advanced usage example with custom settings"""
    print("\n=== Advanced Usage Example ===")
    
    # Create instance with custom settings
    subspyder = CompleteSubSpyder(accepted_status_codes=[200, 403, 500])
    
    # Run enumeration
    results = subspyder.run_complete_enumeration(
        domain="example.com",
        wordlist_file="custom_wordlist.txt"
    )
    
    # Save results
    subspyder.save_results(results, "custom_results.json")
    
    print("Enumeration completed!")


def example_module_usage():
    """Example using individual modules"""
    print("\n=== Individual Module Usage ===")
    
    from subspyder import PassiveEnumerator, ActiveEnumerator, AIPredictor, SubdomainValidator
    from subspyder.core.config import Config
    
    config = Config()
    
    # Use passive enumeration only
    passive = PassiveEnumerator(config)
    passive_results = passive.enumerate_passive("example.com")
    print(f"Passive enumeration found: {len(passive_results['passive'])} subdomains")
    
    # Use AI prediction
    ai = AIPredictor(config)
    predictions = ai.predict_subdomains("example.com", ["www.example.com"])
    print(f"AI predicted: {len(predictions)} subdomains")


def example_discord_test():
    """Example Discord webhook testing"""
    print("\n=== Discord Webhook Test ===")
    
    subspyder = CompleteSubSpyder()
    success = subspyder.test_discord_webhook()
    
    if success:
        print("✅ Discord webhook is working!")
    else:
        print("❌ Discord webhook test failed")


if __name__ == "__main__":
    print("SubSpyder Package Examples")
    print("=" * 40)
    
    # Run examples
    example_basic_usage()
    example_advanced_usage()
    example_module_usage()
    example_discord_test()
    
    print("\n" + "=" * 40)
    print("Examples completed!")
    print("\nFor more information, see the README.md file.") 