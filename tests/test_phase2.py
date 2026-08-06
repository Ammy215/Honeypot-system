#!/usr/bin/env python3
"""
Phase 2 Test Suite
Tests all honeypot services and detection capabilities
"""

import socket
import time
import requests


def test_ftp_honeypot(host='localhost', port=2121):
    """Test FTP honeypot with multiple login attempts"""
    print(f"\n{'='*60}")
    print(f"Testing FTP honeypot at {host}:{port}...")
    print('='*60)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        print("✓ Connected to FTP")
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"✓ Banner: {banner.strip()}")
        
        # Try multiple logins (trigger brute force detection)
        credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('test', 'test')
        ]
        
        for username, password in credentials:
            # Send USER
            sock.send(f"USER {username}\r\n".encode('utf-8'))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  USER {username}: {response.strip()}")
            
            # Send PASS
            sock.send(f"PASS {password}\r\n".encode('utf-8'))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  PASS: {response.strip()}")
            
            time.sleep(0.5)
        
        # QUIT
        sock.send(b"QUIT\r\n")
        sock.close()
        print("✓ FTP test completed")
        return True
        
    except Exception as e:
        print(f"❌ FTP test failed: {e}")
        return False


def test_telnet_honeypot(host='localhost', port=2323):
    """Test Telnet honeypot"""
    print(f"\n{'='*60}")
    print(f"Testing Telnet honeypot at {host}:{port}...")
    print('='*60)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        print("✓ Connected to Telnet")
        
        # Receive login prompt
        prompt = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"✓ Prompt: {prompt.strip()}")
        
        # Send username
        sock.send(b"root\n")
        time.sleep(0.5)
        
        # Receive password prompt
        pwd_prompt = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"✓ Password prompt: {pwd_prompt.strip()}")
        
        # Send password
        sock.send(b"password\n")
        time.sleep(2)
        
        # Receive failure message
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"✓ Response: {response.strip()}")
        
        sock.close()
        print("✓ Telnet test completed")
        return True
        
    except Exception as e:
        print(f"❌ Telnet test failed: {e}")
        return False


def test_http_honeypot(host='localhost', port=8080):
    """Test HTTP honeypot"""
    print(f"\n{'='*60}")
    print(f"Testing HTTP honeypot at {host}:{port}...")
    print('='*60)
    
    try:
        base_url = f"http://{host}:{port}"
        
        # Test admin page GET
        print("Testing GET /admin...")
        response = requests.get(f"{base_url}/admin", timeout=5)
        print(f"✓ Status: {response.status_code}")
        print(f"✓ Content length: {len(response.text)} bytes")
        if "Admin Login" in response.text:
            print("✓ Admin login page rendered")
        
        # Test admin page POST (multiple attempts to trigger brute force)
        print("\nTesting admin login attempts...")
        credentials = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'root', 'password': 'root'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'administrator', 'password': 'administrator'}
        ]
        
        for creds in credentials:
            response = requests.post(f"{base_url}/admin", data=creds, timeout=5)
            print(f"  {creds['username']}/{creds['password']}: {response.status_code}")
            time.sleep(0.3)
        
        # Test phpMyAdmin
        print("\nTesting GET /phpmyadmin...")
        response = requests.get(f"{base_url}/phpmyadmin", timeout=5)
        print(f"✓ Status: {response.status_code}")
        
        # Test WordPress
        print("\nTesting POST /wp-login.php...")
        response = requests.post(
            f"{base_url}/wp-login.php",
            data={'username': 'admin', 'password': 'admin'},
            timeout=5
        )
        print(f"✓ Status: {response.status_code}")
        
        # Test random path (reconnaissance)
        print("\nTesting GET /../../etc/passwd...")
        response = requests.get(f"{base_url}/../../etc/passwd", timeout=5)
        print(f"✓ Status: {response.status_code}")
        
        print("✓ HTTP test completed")
        return True
        
    except Exception as e:
        print(f"❌ HTTP test failed: {e}")
        return False


def rapid_fire_test(host='localhost', port=2121):
    """Rapid fire test to trigger automated attack detection"""
    print(f"\n{'='*60}")
    print(f"Testing RAPID FIRE detection (FTP)...")
    print('='*60)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Receive banner
        sock.recv(1024)
        
        # Send many attempts very quickly
        print("Sending 15 rapid login attempts...")
        for i in range(15):
            sock.send(f"USER test{i}\r\n".encode('utf-8'))
            sock.recv(1024)
            sock.send(f"PASS pass{i}\r\n".encode('utf-8'))
            sock.recv(1024)
            # No sleep - rapid fire!
        
        sock.close()
        print("✓ Rapid fire test completed")
        print("  (Should trigger AUTOMATED_ATTACK alert)")
        return True
        
    except Exception as e:
        print(f"❌ Rapid fire test failed: {e}")
        return False


def verify_database():
    """Verify database has logged everything"""
    print(f"\n{'='*60}")
    print("Verifying database...")
    print('='*60)
    
    try:
        import sqlite3
        conn = sqlite3.connect('data/honeypot.db')
        c = conn.cursor()
        
        # Check login attempts
        c.execute("SELECT COUNT(*) FROM login_attempts")
        login_count = c.fetchone()[0]
        print(f"✓ Login attempts logged: {login_count}")
        
        # Check alerts
        c.execute("SELECT COUNT(*) FROM alerts")
        alert_count = c.fetchone()[0]
        print(f"✓ Alerts generated: {alert_count}")
        
        # Show alerts by severity
        c.execute("""
            SELECT severity, COUNT(*) as cnt 
            FROM alerts 
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        """)
        
        print("\n  Alert breakdown:")
        for row in c.fetchall():
            print(f"    {row[0]}: {row[1]}")
        
        # Show recent alerts
        c.execute("""
            SELECT alert_type, severity, ip_address, description
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        
        print("\n  Recent alerts:")
        for row in c.fetchall():
            print(f"    [{row[1]}] {row[0]} from {row[2]}")
            print(f"      {row[3][:60]}...")
        
        # Check service stats
        c.execute("""
            SELECT service_name, total_connections, total_login_attempts
            FROM service_stats
            ORDER BY service_name
        """)
        
        print("\n  Service statistics:")
        for row in c.fetchall():
            print(f"    {row[0]}: {row[1]} connections, {row[2]} login attempts")
        
        conn.close()
        print("\n✓ Database verification completed")
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print(" "*15 + "PHASE 2 TEST SUITE")
    print("="*60)
    
    results = []
    
    # Wait for services to start
    print("\nWaiting 3 seconds for services to initialize...")
    time.sleep(3)
    
    # Test each service
    results.append(("FTP", test_ftp_honeypot()))
    time.sleep(1)
    
    results.append(("Telnet", test_telnet_honeypot()))
    time.sleep(1)
    
    results.append(("HTTP", test_http_honeypot()))
    time.sleep(1)
    
    results.append(("Rapid Fire", rapid_fire_test()))
    time.sleep(2)
    
    # Verify database
    results.append(("Database", verify_database()))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Phase 2 is complete!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
    
    print("="*60)
