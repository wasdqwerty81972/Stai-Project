#!/usr/bin/env python3
"""Validate Gemini API keys from ``.env.local`` when run directly."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    """Run an opt-in, live provider diagnostic without import side effects."""
    env_path = Path(__file__).parent / ".env.local"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))

    gemini_keys = [
        (index, key)
        for index in range(1, 6)
        if (key := os.environ.get(f"GEMINI_API_KEY_{index}"))
    ]
    if not gemini_keys:
        print("No Gemini API keys found in .env.local")
        return 1

    try:
        from google import genai
    except ImportError:
        print("google-genai package not installed; run pip install google-genai")
        return 1

    successful: list[int] = []
    for key_num, api_key in gemini_keys:
        try:
            client = genai.Client(api_key=api_key)
            response = None
            for model in (
                "gemini-3.1-flash-lite",
                "gemini-1.5-flash",
                "gemini-1.5-pro",
                "gemini-pro",
            ):
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents="Say 'works' in 1 word.",
                    )
                    break
                except Exception:
                    continue
            if response is None:
                raise RuntimeError("No working models found for this key")
            successful.append(key_num)
            print(f"GEMINI_API_KEY_{key_num}: working")
        except Exception as error:
            print(f"GEMINI_API_KEY_{key_num}: failed ({str(error)[:100]})")

    print(f"Working keys: {len(successful)}/{len(gemini_keys)}")
    return 0 if successful else 1


if __name__ == "__main__":
    sys.exit(main())
