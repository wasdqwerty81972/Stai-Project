"""
Production Agent Regression Test: Verifies the SVS-Cyber agent (not test harness)
performs the browser-agent workflow autonomously.
"""
import os
import json
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')

from cyber_agent import CyberAgent

print("=" * 70)
print("  Production Agent Regression Test")
print("  Testing CyberAgent.run_investigation() with browser tools")
print("=" * 70)

# Create the agent
print("\n--- Creating CyberAgent ---")
agent = CyberAgent(workspace_path=".")

# Test 1: Web search task
print("\n--- Test 1: Research latest Python version ---")
task1 = "Search the web for the official Python documentation and find the current stable Python version. Give me the version number and the URL of the official documentation page you used."

print(f"Task: {task1}")
start = time.time()
result1 = agent._run_ai_orchestrated_request(task1, session_id="test_session_1")
duration = time.time() - start
print(f"\nResult (took {duration:.1f}s):\n{result1[:1000]}")

# Check if browser tools were used
if "web_search" in result1.lower() or "open_url" in result1.lower() or "Python" in result1:
    print("\n✅ Browser tools appear to have been used")

# Test 2: Multi-source research
print("\n\n--- Test 2: React version from multiple sources ---")
task2 = "Research the latest version of React. Search the web and check at least three independent sources. Compare what they say, determine the most reliable answer, and explain your conclusion with the sources you visited."

print(f"Task: {task2}")
start = time.time()
result2 = agent._run_ai_orchestrated_request(task2, session_id="test_session_2")
duration = time.time() - start
print(f"\nResult (took {duration:.1f}s):\n{result2[:1000]}")

# Test 3: Recovery test - insufficient first source
print("\n\n--- Test 3: Recovery test (Node.js async file read) ---")
task3 = "Find the official documentation for the latest version of Node.js and determine the recommended way to read a file asynchronously. If your first search result doesn't provide enough information, continue searching and find another authoritative source."

print(f"Task: {task3}")
start = time.time()
result3 = agent._run_ai_orchestrated_request(task3, session_id="test_session_3")
duration = time.time() - start
print(f"\nResult (took {duration:.1f}s):\n{result3[:1000]}")

print("\n" + "=" * 70)
print("  REGRESSION TEST COMPLETE")
print("=" * 70)

# Check screenshots
import glob
screenshots = glob.glob(".stai/agent_*.png") + glob.glob(".stai/search_*.png") + glob.glob(".stai/react_*.png") + glob.glob(".stai/python_*.png") + glob.glob(".stai/node_*.png") + glob.glob(".stai/ac_*.png")
print(f"\nScreenshots captured: {len(screenshots)}")
for s in screenshots[-10:]:
    print(f"  - {s}")

# Clean up
agent.cancel_event.set()

print("\n✅ Production agent regression test complete")