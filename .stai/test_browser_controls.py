"""
Test browser controls: scrolling, clicking, navigation, waiting, etc.
"""
import os
import time
from Tools_cyber.browser_manager import BrowserManager

bm = BrowserManager.get_instance()
page = bm.page

print("=== Testing Browser Controls ===")
print(f"Profile directory: {os.path.abspath('.stai/venkat')}")
print()

# Navigate to a page with scrollable content
print("--- Navigating to Wikipedia ---")
title = bm.navigate("https://en.wikipedia.org/wiki/Ransomware")
print(f"Title: {title}")

# Take initial screenshot
page.screenshot(path="D:/STAI 2/.stai/venkat_initial.png")
print("Initial screenshot saved")

# Test 1: Scroll down
print("\n--- Test 1: Scroll down ---")
page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
time.sleep(1)
page.screenshot(path="D:/STAI 2/.stai/venkat_scrolled_down.png")
print("Scrolled to bottom, screenshot saved")

# Test 2: Scroll up
print("\n--- Test 2: Scroll up ---")
page.evaluate("window.scrollTo(0, 0)")
time.sleep(0.5)
page.screenshot(path="D:/STAI 2/.stai/venkat_scrolled_up.png")
print("Scrolled to top, screenshot saved")

# Test 3: Scroll by specific amount
print("\n--- Test 3: Scroll by 500px ---")
page.evaluate("window.scrollBy(0, 500)")
time.sleep(0.5)
page.screenshot(path="D:/STAI 2/.stai/venkat_scroll_500.png")
print("Scrolled by 500px, screenshot saved")

# Test 4: Get scroll position
print("\n--- Test 4: Get scroll position ---")
scroll_info = page.evaluate("""() => ({
    scrollTop: window.scrollY,
    scrollHeight: document.body.scrollHeight,
    clientHeight: document.documentElement.clientHeight
})""")
print(f"Scroll position: {scroll_info}")

# Test 5: Find and click a link
print("\n--- Test 5: Click a link ---")
# Find first link in content
link_result = page.evaluate("""() => {
    const link = document.querySelector('#mw-content-text a[href]');
    if (link) {
        return { href: link.href, text: link.innerText };
    }
    return null;
}""")
if link_result:
    print(f"Found link: {link_result['text'][:50]} -> {link_result['href']}")
    page.click(f"a[href='{link_result['href']}']")
    page.wait_for_load_state("domcontentloaded")
    print(f"Clicked, new title: {page.title()}")
    page.screenshot(path="D:/STAI 2/.stai/venkat_after_click.png")
    print("Screenshot after click saved")

# Test 6: Go back
print("\n--- Test 6: Go back ---")
page.go_back()
page.wait_for_load_state("domcontentloaded")
print(f"Back to: {page.title()}")
page.screenshot(path="D:/STAI 2/.stai/venkat_after_back.png")
print("Screenshot after back saved")

# Test 7: Fill and submit search (if search box exists)
print("\n--- Test 7: Search on page ---")
# Wikipedia has a search box
try:
    page.fill("#searchInput", "LockBit ransomware")
    page.press("#searchInput", "Enter")
    page.wait_for_load_state("domcontentloaded")
    print(f"Search results title: {page.title()}")
    page.screenshot(path="D:/STAI 2/.stai/venkat_search.png")
    print("Search screenshot saved")
except Exception as e:
    print(f"Search test skipped: {e}")

# Test 8: Get page dimensions
print("\n--- Test 8: Page dimensions ---")
dimensions = page.evaluate("""() => ({
    width: document.documentElement.clientWidth,
    height: document.documentElement.clientHeight,
    scrollWidth: document.body.scrollWidth,
    scrollHeight: document.body.scrollHeight
})""")
print(f"Dimensions: {dimensions}")

# Test 9: Evaluate JavaScript - get all headings
print("\n--- Test 9: Extract headings ---")
headings = page.evaluate("""() => {
    return Array.from(document.querySelectorAll('h1, h2, h3')).map(h => ({
        tag: h.tagName,
        text: h.innerText.slice(0, 80)
    }));
}""")
print(f"Found {len(headings)} headings:")
for h in headings[:10]:
    print(f"  <{h['tag']}> {h['text']}")

# Test 10: Wait and screenshot final state
print("\n--- Test 10: Final state ---")
page.wait_for_timeout(1000)
page.screenshot(path="D:/STAI 2/.stai/venkat_final.png")
print("Final screenshot saved")

print("\n=== All Browser Control Tests Complete ===")
print("Screenshots saved in .stai/venkat_*.png")

# Keep browser open for inspection
print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nClosing...")
    bm.close()