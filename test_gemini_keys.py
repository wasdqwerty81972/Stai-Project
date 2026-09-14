#!/usr/bin/env python3
"""
Test script to verify Gemini API keys from .env.local
"""

import os
import sys
from pathlib import Path

# Load .env.local
env_path = Path(__file__).parent / ".env.local"
if env_path.exists():
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                name = name.strip()
                value = value.strip().strip('"').strip("'")
                if name and value:
                    os.environ.setdefault(name, value)

# Extract Gemini keys
gemini_keys = []
for i in range(1, 6):
    key = os.environ.get(f"GEMINI_API_KEY_{i}")
    if key:
        gemini_keys.append((i, key))

if not gemini_keys:
    print("❌ No Gemini API keys found in .env.local")
    sys.exit(1)

print(f"✓ Found {len(gemini_keys)} Gemini API key(s)")
print("-" * 60)

try:
    from google import genai
except ImportError:
    print("❌ google-genai package not installed")
    print("   Install with: pip install google-genai")
    sys.exit(1)

# Test each key
successful = []
failed = []

for key_num, api_key in gemini_keys:
    try:
        print(f"\nTesting GEMINI_API_KEY_{key_num}...", end=" ", flush=True)
        
        client = genai.Client(api_key=api_key)
        
        # Try to list available models first to see what's available
        models_to_try = [
            "gemini-3.1-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-pro", 
            "gemini-pro",
        ]
        
        response = None
        for model in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents="Say 'works' in 1 word."
                )
                break
            except Exception:
                continue
        
        if response is None:
            raise Exception("No working models found for this key")
        
        output = response.text if hasattr(response, 'text') else str(response.candidates[0].content.parts[0].text if response.candidates else "")
        
        print(f"✓ SUCCESS")
        print(f"   Response: {output[:60]}...")
        successful.append(key_num)
        
    except Exception as e:
        print(f"✗ FAILED")
        print(f"   Error: {str(e)[:100]}")
        failed.append((key_num, str(e)))

print("\n" + "=" * 60)
print("SUMMARY:")
print(f"  Successful: {len(successful)}/{len(gemini_keys)}")
if successful:
    print(f"  Working keys: GEMINI_API_KEY_{', GEMINI_API_KEY_'.join(map(str, successful))}")
if failed:
    print(f"  Failed keys: {len(failed)}")
    for num, _ in failed:
        print(f"    - GEMINI_API_KEY_{num}")

if successful:
    print("\n✓ At least one Gemini API key is working!")
    sys.exit(0)
else:
    print("\n❌ No working Gemini API keys found")
    sys.exit(1)
