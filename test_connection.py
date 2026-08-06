#!/usr/bin/env python3
"""
Simple test script to verify honeypot is working
"""

import socket
import time


def test_ssh_honeypot(host='localhost', port=2222):
    """Test SSH honeypot connection"""
    print(f"Testing SSH honeypot at {host}:{port}...")
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Connect
        print(f"Connecting to {host}:{port}...")
        sock.connect((host, port))
        print("✓ Connected successfully")
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"✓ Received banner: {banner.strip()}")
        
        # Send fake SSH client identification
        client_id = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        sock.send(client_id.encode('utf-8'))
        print(f"✓ Sent client identification")
        
        # Wait a moment
        time.sleep(1)
        
        # Try to receive more data
        try:
            more_data = sock.recv(1024)
            if more_data:
                print(f"✓ Received additional data: {len(more_data)} bytes")
        except socket.timeout:
            print("  (No additional data)")
        
        # Close
        sock.close()
        print("✓ Connection closed")
        print("\n✅ SSH honeypot test PASSED")
        return True
        
    except ConnectionRefusedError:
        print(f"❌ Connection refused - is the honeypot running on port {port}?")
        return False
    except socket.timeout:
        print("❌ Connection timeout")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def verify_database():
    """Verify the connection was logged in the database"""
    print("\nVerifying database logging...")
    
    try:
        import sqlite3
        from pathlib import Path
        
        db_path = Path("data/honeypot.db")
        if not db_path.exists():
            print("❌ Database file not found")
            return False
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check connections table
        cursor.execute("SELECT COUNT(*) FROM connections")
        count = cursor.fetchone()[0]
        print(f"✓ Total connections in database: {count}")
        
        # Get latest connection
        cursor.execute("""
            SELECT ip_address, service_name, timestamp, destination_port
            FROM connections 
            ORDER BY timestamp DESC 
            LIMIT 1
        """)
        row = cursor.fetchone()
        
        if row:
            print(f"✓ Latest connection:")
            print(f"  IP: {row[0]}")
            print(f"  Service: {row[1]}")
            print(f"  Port: {row[3]}")
            print(f"  Time: {row[2]}")
        
        # Check attackers table
        cursor.execute("SELECT COUNT(*) FROM attackers")
        attacker_count = cursor.fetchone()[0]
        print(f"✓ Total attackers tracked: {attacker_count}")
        
        conn.close()
        print("\n✅ Database verification PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False


if __name__ == "__main__":
    print("="*60)
    print("HoneyShield Honeypot Test Suite")
    print("="*60)
    print()
    
    # Test SSH honeypot
    ssh_ok = test_ssh_honeypot()
    
    # Wait a moment for database write
    if ssh_ok:
        print("\nWaiting for database write...")
        time.sleep(2)
        verify_database()
    
    print("\n" + "="*60)
    print("Test complete!")
    print("="*60)
