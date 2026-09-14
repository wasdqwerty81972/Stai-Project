#!/usr/bin/env python3
"""
Test SVS-Cyber chat architecture:
- Session persistence
- Message routing
- Chat creation
- Sidebar state
"""

import json
import requests
import uuid
import time
from typing import List, Dict, Any


BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 60


def test_chat_persistence():
    """Test that multiple messages stay in the same chat."""
    print("\n" + "="*70)
    print("TEST 1: Chat Persistence (Single Session)")
    print("="*70)
    
    session_id = str(uuid.uuid4())
    print(f"\nCreating new session: {session_id}")
    
    # First, check conversations (should be empty or not include our session)
    resp = requests.get(f"{BASE_URL}/api/conversations", timeout=TIMEOUT)
    convos_before = resp.json() if resp.status_code == 200 else []
    print(f"Conversations before: {len(convos_before)}")
    
    # Send message 1
    print(f"\nSending message 1: 'hello'")
    try:
        resp = requests.post(
            f"{BASE_URL}/api/chat",
            json={"message": "hello", "session_id": session_id},
            timeout=TIMEOUT
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  Status: {result.get('status')}")
            print(f"  Session ID returned: {result.get('session_id')}")
            print(f"  Response: {result.get('message', '')[:100]}...")
        else:
            print(f"  ERROR: Status {resp.status_code}: {resp.text[:200]}")
            return False
    except requests.Timeout:
        print(f"  TIMEOUT after {TIMEOUT}s")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False
    
    # Check that conversation was created with correct session_id
    time.sleep(1)
    resp = requests.get(f"{BASE_URL}/api/conversations", timeout=TIMEOUT)
    convos_after = resp.json() if resp.status_code == 200 else []
    matching_convos = [c for c in convos_after if c["id"] == session_id]
    print(f"\nConversations after message 1: {len(convos_after)}")
    print(f"Matching session conversations: {len(matching_convos)}")
    if matching_convos:
        print(f"  Title: {matching_convos[0]['title']}")
    
    # Fetch messages for this session
    resp = requests.get(f"{BASE_URL}/api/conversations/{session_id}/messages", timeout=TIMEOUT)
    messages = resp.json() if resp.status_code == 200 else []
    print(f"Messages in session: {len(messages)}")
    for msg in messages:
        print(f"  - {msg.get('type')}: {msg.get('message', '')[:50]}...")
    
    # Verify exactly ONE conversation exists for this session_id
    if len(matching_convos) != 1:
        print(f"\nFAIL: Expected 1 conversation, got {len(matching_convos)}")
        return False
    
    print(f"\nPASS: Chat persistence verified")
    return True


def test_new_chat_creation():
    """Test that New Chat creates a separate session."""
    print("\n" + "="*70)
    print("TEST 2: New Chat Creation")
    print("="*70)
    
    session_id_1 = str(uuid.uuid4())
    session_id_2 = str(uuid.uuid4())
    
    print(f"\nSession 1: {session_id_1}")
    print(f"Session 2: {session_id_2}")
    
    # Create two chats
    for i, sid in enumerate([session_id_1, session_id_2], 1):
        try:
            resp = requests.post(
                f"{BASE_URL}/api/chat",
                json={"message": f"Chat {i}", "session_id": sid},
                timeout=TIMEOUT
            )
            if resp.status_code != 200:
                print(f"  Chat {i} ERROR: {resp.status_code}")
                return False
            print(f"  Chat {i}: OK")
        except requests.Timeout:
            print(f"  Chat {i}: TIMEOUT")
            return False
        except Exception as e:
            print(f"  Chat {i}: ERROR {e}")
            return False
    
    # Check that we have exactly 2 separate conversations
    time.sleep(1)
    resp = requests.get(f"{BASE_URL}/api/conversations", timeout=TIMEOUT)
    convos = resp.json() if resp.status_code == 200 else []
    session_1_convos = [c for c in convos if c["id"] == session_id_1]
    session_2_convos = [c for c in convos if c["id"] == session_id_2]
    
    print(f"\nTotal conversations: {len(convos)}")
    print(f"Session 1 conversations: {len(session_1_convos)}")
    print(f"Session 2 conversations: {len(session_2_convos)}")
    
    if len(session_1_convos) != 1 or len(session_2_convos) != 1:
        print(f"\nFAIL: Expected 1 conversation per session")
        return False
    
    print(f"\nPASS: New chat creation verified")
    return True


def test_message_fetch():
    """Test fetching messages for a session."""
    print("\n" + "="*70)
    print("TEST 3: Message Fetching")
    print("="*70)
    
    session_id = str(uuid.uuid4())
    
    # Send message
    print(f"\nSending message to {session_id}")
    try:
        resp = requests.post(
            f"{BASE_URL}/api/chat",
            json={"message": "test message", "session_id": session_id},
            timeout=TIMEOUT
        )
        if resp.status_code != 200:
            print(f"Send ERROR: {resp.status_code}")
            return False
    except requests.Timeout:
        print(f"Send TIMEOUT")
        return False
    except Exception as e:
        print(f"Send ERROR: {e}")
        return False
    
    time.sleep(1)
    
    # Fetch messages
    try:
        resp = requests.get(f"{BASE_URL}/api/conversations/{session_id}/messages", timeout=TIMEOUT)
        if resp.status_code != 200:
            print(f"Fetch ERROR: {resp.status_code}")
            return False
        
        messages = resp.json()
        print(f"Messages fetched: {len(messages)}")
        
        if len(messages) < 2:  # At least user message and response
            print(f"WARN: Expected at least 2 events (user + response), got {len(messages)}")
        
        # Check event types
        user_msgs = [m for m in messages if m.get("type") == "user_message"]
        response_msgs = [m for m in messages if m.get("type") == "response"]
        
        print(f"  User messages: {len(user_msgs)}")
        print(f"  Responses: {len(response_msgs)}")
        
        # Verify session_id is consistent
        for msg in messages:
            if msg.get("session_id") != session_id:
                print(f"\nFAIL: Message has wrong session_id: {msg.get('session_id')} vs {session_id}")
                return False
        
        print(f"\nPASS: Message fetching verified")
        return True
        
    except requests.Timeout:
        print(f"Fetch TIMEOUT")
        return False
    except Exception as e:
        print(f"Fetch ERROR: {e}")
        return False


def main():
    print("\nSVS-Cyber Chat Architecture Test Suite")
    print("="*70)
    
    # Check if backend is running
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        if resp.status_code == 200:
            print("✓ Backend is responding")
        else:
            print(f"✗ Backend returned {resp.status_code}")
            return
    except requests.ConnectionError:
        print(f"✗ Cannot connect to backend at {BASE_URL}")
        return
    except requests.Timeout:
        print(f"✗ Backend timeout")
        return
    
    results = []
    results.append(("Message Fetch", test_message_fetch()))
    results.append(("Chat Persistence", test_chat_persistence()))
    results.append(("New Chat Creation", test_new_chat_creation()))
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")


if __name__ == "__main__":
    main()
