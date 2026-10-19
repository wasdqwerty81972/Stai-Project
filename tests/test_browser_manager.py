import os
from unittest.mock import Mock, patch

from Tools_cyber.browser_manager import BrowserManager


def test_browser_manager_is_headless_by_default():
    context = Mock()
    context.pages = []
    context.new_page.return_value = Mock()
    playwright = Mock()
    playwright.chromium.launch_persistent_context.return_value = context

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SVS_CYBER_HEADLESS", None)
        with patch("Tools_cyber.browser_manager.sync_playwright") as start_playwright:
            start_playwright.return_value.start.return_value = playwright
            manager = BrowserManager()
            manager.close()

    assert playwright.chromium.launch_persistent_context.call_args.kwargs["headless"] is True
