"""
Playwright Web Reconnaissance & Evidence Capture Module
CyberAI Security Suite — Standalone Tool Component
"""

import asyncio
import json
import os
import sys
import time
from typing import Dict, Any

# Ensure nest_asyncio handles nested event loops (useful when called via GUI threads)
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass


class PlaywrightReconTool:
    """
    Standalone headless web reconnaissance engine.
    Extracts HTTP headers, DOM elements, script sources, and evidence screenshots.
    """

    def __init__(self, output_dir: str = "recon_outputs"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def execute_recon(
        self, target_url: str, capture_screenshot: bool = True, timeout_ms: int = 15000
    ) -> Dict[str, Any]:
        """Runs headless browser analysis on the target URL."""

        # Ensure target URL has a valid scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {
                "status": "error",
                "message": "Playwright library missing. Install via: pip install playwright && playwright install chromium",
            }

        timestamp = int(time.time())
        sanitized_host = target_url.split("//")[-1].replace("/", "_").replace(":", "_")
        screenshot_filename = os.path.join(self.output_dir, f"proof_{sanitized_host}_{timestamp}.png")

        results = {
            "status": "success",
            "target_url": target_url,
            "timestamp": timestamp,
            "http_status": None,
            "title": "",
            "headers": {},
            "links": [],
            "scripts": [],
            "cookies": [],
            "screenshot_path": None,
            "error": None,
        }

        try:
            async with async_playwright() as p:
                # Launch headless Chromium with standard desktop viewport
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent="CyberAI-SecuritySuite-Recon/1.0",
                    ignore_https_errors=True  # Helpful for security testing local/self-signed targets
                )
                page = await context.new_page()

                # Navigate to target
                response = await page.goto(target_url, timeout=timeout_ms, wait_until="domcontentloaded")

                if response:
                    results["http_status"] = response.status
                    results["headers"] = dict(response.headers)

                # Collect page metadata
                results["title"] = await page.title()

                # Extract outbound links, external scripts, and session cookies
                results["links"] = await page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
                results["scripts"] = await page.eval_on_selector_all("script[src]", "elements => elements.map(e => e.src)")
                results["cookies"] = await context.cookies()

                # Capture proof-of-concept screenshot
                if capture_screenshot:
                    await page.screenshot(path=screenshot_filename, full_page=False)
                    results["screenshot_path"] = screenshot_filename

                await browser.close()
                return results

        except Exception as err:
            results["status"] = "error"
            results["error"] = str(err)
            return results


def run_recon(target_url: str, capture_screenshot: bool = True) -> Dict[str, Any]:
    """Synchronous wrapper for easy execution from any Python thread or script."""
    engine = PlaywrightReconTool()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            return loop.run_until_complete(engine.execute_recon(target_url, capture_screenshot))
        else:
            return loop.run_until_complete(engine.execute_recon(target_url, capture_screenshot))
    except RuntimeError:
        return asyncio.run(engine.execute_recon(target_url, capture_screenshot))


# ============================================================================
# DIRECT CLI EXECUTION
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python playwright_recon.py <target_url>")
        print("Example: python playwright_recon.py https://example.com")
        sys.exit(1)

    url_arg = sys.argv[1]
    print(f"[*] Starting Playwright Recon on: {url_arg} ...")

    recon_output = run_recon(url_arg)

    # Print formatted JSON output to terminal
    print("\n[+] Reconnaissance Complete:")
    print(json.dumps(recon_output, indent=2))