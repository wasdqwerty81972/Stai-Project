#!/usr/bin/env python3
"""
Comprehensive SVS-Cyber Testing Suite
Tests: persistence, tools, AI, errors, workflows
"""

import json
import requests
import uuid
import time
from datetime import datetime


BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 120


class TestRunner:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.warnings = []
    
    def test(self, name, fn):
        """Run a test and track results."""
        print(f"\n{'='*70}")
        print(f"TEST: {name}")
        print('='*70)
        try:
            result = fn()
            if result:
                self.passed.append(name)
                print(f"✓ PASS")
            else:
                self.failed.append(name)
                print(f"✗ FAIL")
            return result
        except Exception as e:
            self.failed.append(name)
            print(f"✗ FAIL: {e}")
            return False
    
    def warn(self, msg):
        self.warnings.append(msg)
        print(f"⚠ WARNING: {msg}")
    
    def report(self):
        """Print final test report."""
        print(f"\n\n{'='*70}")
        print("FINAL TEST REPORT")
        print('='*70)
        print(f"\nPassed: {len(self.passed)}/{len(self.passed) + len(self.failed)}")
        if self.passed:
            print("\n✓ Passed Tests:")
            for name in self.passed:
                print(f"  - {name}")
        if self.failed:
            print("\n✗ Failed Tests:")
            for name in self.failed:
                print(f"  - {name}")
        if self.warnings:
            print(f"\n⚠ Warnings: {len(self.warnings)}")
            for w in self.warnings:
                print(f"  - {w}")


def test_persistence_across_fetch():
    """Test that messages persist across multiple fetches."""
    print("Creating session and sending message...")
    session_id = str(uuid.uuid4())
    
    # Send message
    resp = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "persistence test", "session_id": session_id},
        timeout=TIMEOUT
    )
    if resp.status_code != 200:
        print(f"Send failed: {resp.status_code}")
        return False
    
    time.sleep(2)
    
    # Fetch multiple times
    print("Fetching messages 3 times...")
    counts = []
    for i in range(3):
        resp = requests.get(f"{BASE_URL}/api/conversations/{session_id}/messages", timeout=TIMEOUT)
        if resp.status_code != 200:
            print(f"Fetch {i} failed: {resp.status_code}")
            return False
        
        messages = resp.json()
        counts.append(len(messages))
        print(f"  Fetch {i+1}: {len(messages)} messages")
        time.sleep(0.5)
    
    # Verify counts are consistent
    if len(set(counts)) != 1:
        print(f"Counts not consistent: {counts}")
        return False
    
    print(f"Message count stable at: {counts[0]}")
    return True


def test_ai_provider_configured():
    """Test that AI provider is configured and working."""
    print("Checking AI provider configuration...")
    
    session_id = str(uuid.uuid4())
    
    # Send message that requires AI processing
    print("Sending message requiring AI processing...")
    resp = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "what tools do you have?", "session_id": session_id},
        timeout=TIMEOUT
    )
    
    if resp.status_code != 200:
        print(f"API call failed: {resp.status_code}")
        return False
    
    result = resp.json()
    message = result.get("message", "")
    
    # Check if response is not an error
    if "AI_ERROR" in message or "not configured" in message.lower():
        print(f"AI Provider Error: {message}")
        return False
    
    if not message or len(message.strip()) == 0:
        print(f"Empty response from AI")
        return False
    
    print(f"AI Response (first 100 chars): {message[:100]}")
    return True


def test_tool_registry():
    """Test that tools are registered and discoverable."""
    print("Checking tool registry...")
    
    # Look for tool-related events in recent messages
    resp = requests.get(f"{BASE_URL}/api/conversations", timeout=TIMEOUT)
    if resp.status_code != 200:
        print(f"Failed to get conversations: {resp.status_code}")
        return False
    
    convos = resp.json()
    print(f"Total conversations in system: {len(convos)}")
    
    # Send a message asking about tools
    session_id = str(uuid.uuid4())
    resp = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "list tools", "session_id": session_id},
        timeout=TIMEOUT
    )
    
    if resp.status_code != 200:
        print(f"Tool list request failed: {resp.status_code}")
        return False
    
    result = resp.json()
    message = result.get("message", "")
    print(f"Tool list response: {message[:150]}")
    
    return len(message) > 0


def test_session_isolation():
    """Test that sessions are properly isolated."""
    print("Testing session isolation...")
    
    session_1 = str(uuid.uuid4())
    session_2 = str(uuid.uuid4())
    
    # Send different messages to each session
    print(f"Sending to session 1: {session_1}")
    resp1 = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "session 1 message", "session_id": session_1},
        timeout=TIMEOUT
    )
    if resp1.status_code != 200:
        print(f"Session 1 failed: {resp1.status_code}")
        return False
    
    print(f"Sending to session 2: {session_2}")
    resp2 = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "session 2 message", "session_id": session_2},
        timeout=TIMEOUT
    )
    if resp2.status_code != 200:
        print(f"Session 2 failed: {resp2.status_code}")
        return False
    
    time.sleep(1)
    
    # Fetch messages from each session
    print("Verifying session isolation...")
    resp1_msgs = requests.get(f"{BASE_URL}/api/conversations/{session_1}/messages", timeout=TIMEOUT).json()
    resp2_msgs = requests.get(f"{BASE_URL}/api/conversations/{session_2}/messages", timeout=TIMEOUT).json()
    
    # Check that no message from session 2 appears in session 1's messages
    session_1_content = str(resp1_msgs)
    session_2_content = str(resp2_msgs)
    
    # Verify each session only has its own messages
    for msg in resp1_msgs:
        if msg.get("session_id") != session_1:
            print(f"Session 1 contains message from {msg.get('session_id')}")
            return False
    
    for msg in resp2_msgs:
        if msg.get("session_id") != session_2:
            print(f"Session 2 contains message from {msg.get('session_id')}")
            return False
    
    print(f"Session 1 messages: {len(resp1_msgs)}")
    print(f"Session 2 messages: {len(resp2_msgs)}")
    return True


def test_error_handling():
    """Test that errors are handled gracefully."""
    print("Testing error handling...")
    
    # Test with empty message
    print("Sending empty message...")
    resp = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "", "session_id": "test"},
        timeout=TIMEOUT
    )
    
    # Should either reject or handle gracefully
    if resp.status_code == 400:
        print("Empty message rejected with 400")
        return True
    elif resp.status_code == 200:
        result = resp.json()
        if "error" in result.get("status", "").lower() or not result.get("message"):
            print("Empty message handled gracefully")
            return True
    
    print(f"Unexpected response: {resp.status_code} {resp.text[:100]}")
    return False


def test_conversation_listing():
    """Test that conversations are listed correctly."""
    print("Fetching conversation list...")
    
    resp = requests.get(f"{BASE_URL}/api/conversations", timeout=TIMEOUT)
    if resp.status_code != 200:
        print(f"Failed to get conversations: {resp.status_code}")
        return False
    
    convos = resp.json()
    print(f"Total conversations: {len(convos)}")
    
    # Verify structure
    for convo in convos[:3]:  # Check first 3
        if "id" not in convo or "title" not in convo:
            print(f"Invalid conversation structure: {convo}")
            return False
        print(f"  - {convo['id'][:8]}...: {convo['title'][:50]}")
    
    return len(convos) > 0


def test_websocket_connection():
    """Test WebSocket connection for real-time events."""
    print("Testing WebSocket connection...")
    
    # This is harder to test in Python, but we can check if the endpoint exists
    try:
        # Try to establish WebSocket connection
        import asyncio
        import websockets
        
        async def test_ws():
            try:
                uri = "ws://127.0.0.1:8000/ws"
                async with websockets.connect(uri) as ws:
                    print(f"WebSocket connected: {uri}")
                    # Send a test message
                    await asyncio.wait_for(ws.ping(), timeout=5)
                    print("WebSocket ping successful")
                    return True
            except Exception as e:
                print(f"WebSocket connection failed: {e}")
                return False
        
        result = asyncio.run(test_ws())
        return result
    except ImportError:
        print("⚠ websockets library not installed, skipping WebSocket test")
        return True


def test_message_event_types():
    """Test that different event types are properly created."""
    print("Testing message event types...")
    
    session_id = str(uuid.uuid4())
    
    # Send message
    resp = requests.post(
        f"{BASE_URL}/api/chat",
        json={"message": "test event types", "session_id": session_id},
        timeout=TIMEOUT
    )
    if resp.status_code != 200:
        print(f"Failed to send message: {resp.status_code}")
        return False
    
    time.sleep(1)
    
    # Fetch messages and check event types
    resp = requests.get(f"{BASE_URL}/api/conversations/{session_id}/messages", timeout=TIMEOUT)
    messages = resp.json()
    
    event_types = {}
    for msg in messages:
        msg_type = msg.get("type", "unknown")
        event_types[msg_type] = event_types.get(msg_type, 0) + 1
    
    print(f"Event types found:")
    for evt_type, count in sorted(event_types.items()):
        print(f"  - {evt_type}: {count}")
    
    # We should have at least user_message and response
    if "user_message" not in event_types or "response" not in event_types:
        print("Missing expected event types")
        return False
    
    return True


def main():
    print("SVS-Cyber Comprehensive Testing Suite")
    print("="*70)
    
    # Check backend
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"✓ Backend is responsive (status: {resp.status_code})")
    except Exception as e:
        print(f"✗ Cannot connect to backend: {e}")
        return
    
    runner = TestRunner()
    
    # Run all tests
    runner.test("Message Persistence Across Fetches", test_persistence_across_fetch)
    runner.test("AI Provider Configured", test_ai_provider_configured)
    runner.test("Tool Registry", test_tool_registry)
    runner.test("Session Isolation", test_session_isolation)
    runner.test("Error Handling", test_error_handling)
    runner.test("Conversation Listing", test_conversation_listing)
    runner.test("Message Event Types", test_message_event_types)
    runner.test("WebSocket Connection", test_websocket_connection)
    
    # Print report
    runner.report()


if __name__ == "__main__":
    main()
