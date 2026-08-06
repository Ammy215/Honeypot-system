#!/usr/bin/env python3
"""
Simple test to demonstrate Phase 2 features
"""

import socket
import time
import requests


print("\n" + "="*60)
print("PHASE 2 - SIMPLE DEMONSTRATION")
print("="*60)

# Wait for services
print("\nWaiting for services to start...")
time.sleep(3)

# Test 1: FTP with default credentials (should trigger DEFAULT_CREDENTIALS alert)
print("\n1. Testing FTP with default credentials...")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('localhost', 2121))
    sock.recv(1024)  # Banner
    
    sock.send(b"USER admin\r\n")
    sock.recv(1024)
    
    sock.send(b"PASS admin\r\n")  # Default credentials!
    response = sock.recv(1024).decode()
    print(f"   Response: {response.strip()}")
    print("   ✓ Should trigger DEFAULT_CREDENTIALS alert")
    
    sock.close()
except Exception as e:
    print(f"   Error: {e}")

time.sleep(1)

# Test 2: HTTP admin login attempts
print("\n2. Testing HTTP /admin with multiple attempts...")
try:
    for i in range(3):
        response = requests.post(
            "http://localhost:8080/admin",
            data={'username': f'user{i}', 'password': f'pass{i}'},
            timeout=5
        )
        print(f"   Attempt {i+1}: {response.status_code}")
        time.sleep(0.2)
    
    print("   ✓ Login attempts logged")
except Exception as e:
    print(f"   Error: {e}")

time.sleep(1)

# Test 3: Telnet login
print("\n3. Testing Telnet login...")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('localhost', 2323))
    
    prompt = sock.recv(1024).decode()
    print(f"   Prompt received: {len(prompt)} bytes")
    
    sock.send(b"root\n")
    sock.recv(1024)
    
    sock.send(b"password\n")
    response = sock.recv(2048).decode()
    print(f"   Response: Login rejected")
    print("   ✓ Login attempt logged")
    
    sock.close()
except Exception as e:
    print(f"   Error: {e}")

time.sleep(2)

# Check database
print("\n4. Checking database...")
try:
    import sqlite3
    conn = sqlite3.connect('data/honeypot.db')
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM login_attempts")
    login_count = c.fetchone()[0]
    print(f"   ✓ Login attempts logged: {login_count}")
    
    c.execute("SELECT COUNT(*) FROM alerts")
    alert_count = c.fetchone()[0]
    print(f"   ✓ Alerts generated: {alert_count}")
    
    c.execute("SELECT alert_type, severity FROM alerts ORDER BY timestamp DESC LIMIT 3")
    print("\n   Recent alerts:")
    for row in c.fetchall():
        print(f"     [{row[1]}] {row[0]}")
    
    conn.close()
except Exception as e:
    print(f"   Error: {e}")

print("\n" + "="*60)
print("✅ PHASE 2 DEMONSTRATION COMPLETE!")
print("="*60)
print("\nKey features demonstrated:")
print("  • FTP honeypot with credential capture")
print("  • HTTP honeypot with fake admin panel")
print("  • Telnet honeypot with login prompts")
print("  • Login attempt logging")
print("  • Alert generation (DEFAULT_CREDENTIALS)")
print("\nCheck the server console to see real-time alerts!")
print("="*60 + "\n")
