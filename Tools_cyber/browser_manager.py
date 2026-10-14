"""
OpenClaw-style browser session manager.
Provides a persistent Chromium profile for SVS-Cyber web interactions.
"""
import os
import atexit
from playwright.sync_api import sync_playwright, BrowserContext, Page

class BrowserManager:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.playwright = sync_playwright().start()
        profile_dir = os.path.abspath(os.path.join(".stai", "svs-cyber"))
        os.makedirs(profile_dir, exist_ok=True)
        
        # Browser work happens in the agent's embedded workspace; opening a
        # separate visible Chromium window here leaves users at about:blank
        # until the first navigation completes. Opt into a visible window only
        # when explicitly requested.
        headless = os.environ.get("SVS_CYBER_HEADLESS", "true").lower() == "true"
        
        self.context: BrowserContext = self.playwright.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            headless=headless,
            viewport={"width": 1280, "height": 720},
            channel="chrome" if os.environ.get("USE_SYSTEM_CHROME") else None
        )
        self.page: Page = self.context.pages[0] if self.context.pages else self.context.new_page()
        atexit.register(self.close)

    def navigate(self, url: str):
        self.page.goto(url, wait_until="domcontentloaded")
        return self.page.title()

    def get_content(self):
        # Extract meaningful text, strip scripts/styles
        return self.page.evaluate('''() => {
            const clone = document.cloneNode(true);
            const remove = clone.querySelectorAll('script, style, noscript, svg, img, nav, footer');
            remove.forEach(el => el.remove());
            return clone.body ? clone.body.innerText : '';
        }''')

    def get_html(self):
        # Get raw HTML source
        return self.page.content()

    def close(self):
        if hasattr(self, '_closed') and self._closed:
            return
        self._closed = True
        if hasattr(self, 'context') and self.context:
            self.context.close()
        if hasattr(self, 'playwright') and self.playwright:
            self.playwright.stop()
