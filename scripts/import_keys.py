"""
Simple script to import API keys from .env
"""

import os
from dotenv import load_dotenv
load_dotenv()

from security.api_key_manager import api_key_manager

print("🔑 Importing API keys from .env...\n")

# Get keys from .env
abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
openai_key = os.getenv("OPENAI_API_KEY")

# Import AbuseIPDB
if abuseipdb_key and abuseipdb_key not in ["your_key_here", "managed_by_security", "PASTE_YOUR_KEY_HERE", "skip_this"]:
    api_key_manager.add_key(
        service="abuseipdb",
        api_key=abuseipdb_key,
        description="AbuseIPDB Threat Intelligence",
        rate_limit=1000,
        rate_period="day"
    )
    print("✅ AbuseIPDB key imported!")
else:
    print("⚪ AbuseIPDB key not set or invalid")

# Skip OpenAI
if openai_key and openai_key not in ["your_key_here", "managed_by_security", "PASTE_YOUR_KEY_HERE", "skip_this"]:
    api_key_manager.add_key(
        service="openai",
        api_key=openai_key,
        description="OpenAI GPT-4",
        rate_limit=10000,
        rate_period="day"
    )
    print("✅ OpenAI key imported!")
else:
    print("⚪ OpenAI key skipped")

print("\n✅ Done! Keys are now encrypted and saved.")
print("\nYou can now run:")
print("  python main.py")
print("  streamlit run dashboard/app.py")
