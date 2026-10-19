"""
Test smooth scrolling that the user can visually see.
"""
import os
import time
from Tools_cyber.browser_manager import BrowserManager

bm = BrowserManager.get_instance()
page = bm.page

print("=== Visual Scrolling Test (SVS-Cyber Profile) ===")
print(f"Profile directory: {os.path.abspath('.stai/svs-cyber')}")
print()

# Navigate to a long page
print("--- Navigating to long Wikipedia page ---")
title = bm.navigate("https://en.wikipedia.org/wiki/Computer_security")
print(f"Title: {title}")

# Wait for page to fully load
page.wait_for_load_state("networkidle")
time.sleep(1)

# Test 1: Smooth scroll down with visible steps
print("\n--- Test 1: Smooth scroll down (watch the browser!) ---")
page.evaluate("""() => {
    const scrollStep = 300;
    const delay = 100;
    let currentPos = 0;
    const maxScroll = document.body.scrollHeight - window.innerHeight;
    
    function smoothScroll() {
        if (currentPos < maxScroll) {
            currentPos += scrollStep;
            if (currentPos > maxScroll) currentPos = maxScroll;
            window.scrollTo(0, currentPos);
            setTimeout(smoothScroll, delay);
        }
    }
    smoothScroll();
}""")

# Wait for smooth scroll to complete
print("Scrolling... (watch the browser window)")
time.sleep(3)

page.screenshot(path="D:/STAI 2/.stai/svs_smooth_scroll_down.png")
print("Smooth scroll down complete, screenshot saved")

# Test 2: Smooth scroll up
print("\n--- Test 2: Smooth scroll up ---")
page.evaluate("""() => {
    const scrollStep = 300;
    const delay = 100;
    let currentPos = window.scrollY;
    
    function smoothScrollUp() {
        if (currentPos > 0) {
            currentPos -= scrollStep;
            if (currentPos < 0) currentPos = 0;
            window.scrollTo(0, currentPos);
            setTimeout(smoothScrollUp, delay);
        }
    }
    smoothScrollUp();
}""")

print("Scrolling up... (watch the browser window)")
time.sleep(3)

page.screenshot(path="D:/STAI 2/.stai/svs_smooth_scroll_up.png")
print("Smooth scroll up complete, screenshot saved")

# Test 3: Scroll to specific element
print("\n--- Test 3: Scroll to specific section ---")
# Find a heading and scroll to it
page.evaluate("""() => {
    const heading = Array.from(document.querySelectorAll('h2, h3'))
        .find(h => h.innerText.toLowerCase().includes('threat') || 
                   h.innerText.toLowerCase().includes('vulnerab') ||
                   h.innerText.toLowerCase().includes('attack'));
    if (heading) {
        heading.scrollIntoView({ behavior: 'smooth', block: 'center' });
        heading.style.backgroundColor = '#ffff00';
    }
}""")

print("Scrolling to a threat/vulnerability section... (watch!)")
time.sleep(2)

page.screenshot(path="D:/STAI 2/.stai/svs_scroll_to_section.png")
print("Scrolled to section, screenshot saved")

# Test 4: Page down/up keys (like a real user)
print("\n--- Test 4: Page Down / Page Up keys ---")
for i in range(3):
    page.keyboard.press("PageDown")
    time.sleep(0.8)
page.screenshot(path="D:/STAI 2/.stai/svs_page_down.png")
print("Page Down x3, screenshot saved")

for i in range(3):
    page.keyboard.press("PageUp")
    time.sleep(0.8)
page.screenshot(path="D:/STAI 2/.stai/svs_page_up.png")
print("Page Up x3, screenshot saved")

# Test 5: Arrow key scrolling
print("\n--- Test 5: Arrow key scrolling ---")
for i in range(10):
    page.keyboard.press("ArrowDown")
    time.sleep(0.1)
page.screenshot(path="D:/STAI 2/.stai/svs_arrow_down.png")
print("Arrow Down x10, screenshot saved")

for i in range(10):
    page.keyboard.press("ArrowUp")
    time.sleep(0.1)
page.screenshot(path="D:/STAI 2/.stai/svs_arrow_up.png")
print("Arrow Up x10, screenshot saved")

print("\n=== All Visual Scrolling Tests Complete ===")
print("Check the browser - you should have seen smooth scrolling!")
print("Screenshots saved in .stai/svs_*.png")

# Keep browser open
print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nClosing...")
    bm.close()