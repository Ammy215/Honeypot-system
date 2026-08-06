#!/usr/bin/env python3
"""
Phase 3 Test Suite - Threat Intelligence
"""

import time
import socket


def simulate_attack():
    """Simulate an attack to generate data for enrichment"""
    print("\n" + "="*60)
    print("Simulating Attack for Enrichment Testing")
    print("="*60)
    
    # Create attack from 8.8.8.8 (Google DNS - publicly routable IP for testing)
    # Note: In production, this would be real attacker IPs
    
    print("\n1. Simulating FTP brute force...")
    try:
        # We can't actually spoof the source IP, so we'll just create database entries
        # In real world, attackers would connect from various IPs
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 2121))
        sock.recv(1024)
        
        # Try multiple logins
        for i in range(5):
            sock.send(f"USER admin{i}\r\n".encode())
            sock.recv(1024)
            sock.send(f"PASS pass{i}\r\n".encode())
            sock.recv(1024)
            time.sleep(0.2)
        
        sock.close()
        print("   ✓ Generated attack traffic")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    time.sleep(2)


def test_geolocation():
    """Test geolocation enrichment"""
    print("\n" + "="*60)
    print("Testing Geolocation Enrichment")
    print("="*60)
    
    try:
        from honeypot.intelligence.geolocation import get_geolocation, get_country_flag
        
        # Test with a public IP (Google DNS)
        test_ip = "8.8.8.8"
        
        print(f"\n1. Getting geolocation for {test_ip}...")
        geo_data = get_geolocation(test_ip, use_cache=False)
        
        if geo_data:
            print(f"   ✓ Country: {geo_data.get('country')} ({geo_data.get('country_code')})")
            print(f"   ✓ City: {geo_data.get('city')}")
            print(f"   ✓ Region: {geo_data.get('region')}")
            print(f"   ✓ ISP: {geo_data.get('isp')}")
            print(f"   ✓ ASN: {geo_data.get('asn')}")
            print(f"   ✓ Coordinates: {geo_data.get('latitude')}, {geo_data.get('longitude')}")
            
            # Test flag emoji
            flag = get_country_flag(geo_data.get('country_code'))
            print(f"   ✓ Flag: {flag}")
            
            return True
        else:
            print("   ❌ Geolocation failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_abuseipdb():
    """Test AbuseIPDB reputation check"""
    print("\n" + "="*60)
    print("Testing AbuseIPDB Reputation Check")
    print("="*60)
    
    try:
        from honeypot.intelligence.abuseipdb import check_ip_reputation, get_reputation_verdict
        import config
        
        if not config.ABUSEIPDB_API_KEY or config.ABUSEIPDB_API_KEY == "your_key_here":
            print("   ⚠️  AbuseIPDB API key not configured")
            print("   ℹ️  Get free API key at https://www.abuseipdb.com/")
            print("   ℹ️  Add to .env: ABUSEIPDB_API_KEY=your_key")
            return None
        
        # Test with a known IP
        test_ip = "8.8.8.8"
        
        print(f"\n1. Checking reputation for {test_ip}...")
        rep_data = check_ip_reputation(test_ip, use_cache=False)
        
        if rep_data:
            score = rep_data.get('abuse_confidence_score', 0)
            reports = rep_data.get('total_reports', 0)
            verdict, color = get_reputation_verdict(score)
            
            print(f"   ✓ Abuse Score: {score}/100")
            print(f"   ✓ Total Reports: {reports}")
            print(f"   ✓ Verdict: {verdict}")
            print(f"   ✓ Is TOR: {rep_data.get('is_tor', False)}")
            
            return True
        else:
            print("   ❌ Reputation check failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_threat_scoring():
    """Test threat scoring"""
    print("\n" + "="*60)
    print("Testing Threat Scoring Engine")
    print("="*60)
    
    try:
        from honeypot.intelligence.threat_scorer import calculate_threat_score
        import sqlite3
        
        # Get an attacker from database
        conn = sqlite3.connect('data/honeypot.db')
        c = conn.cursor()
        c.execute("SELECT ip_address FROM attackers ORDER BY total_login_attempts DESC LIMIT 1")
        row = c.fetchone()
        conn.close()
        
        if not row:
            print("   ⚠️  No attackers in database yet")
            return None
        
        test_ip = row[0]
        
        print(f"\n1. Calculating threat score for {test_ip}...")
        result = calculate_threat_score(test_ip)
        
        print(f"   ✓ Threat Score: {result['score']}/100")
        print(f"   ✓ Verdict: {result['verdict']}")
        print(f"\n   Score Breakdown:")
        for factor, points in result['breakdown'].items():
            print(f"     • {factor}: +{points} points")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_ioc_detection():
    """Test IOC detection"""
    print("\n" + "="*60)
    print("Testing IOC Detection")
    print("="*60)
    
    try:
        from honeypot.intelligence.ioc_detector import add_ioc, check_ioc, get_ioc_stats
        
        # Add a test IOC
        test_ip = "192.0.2.1"  # Reserved test IP
        
        print(f"\n1. Adding test IOC: {test_ip}")
        success = add_ioc(test_ip, source="test")
        
        if success:
            print(f"   ✓ Added to IOC list")
        else:
            print(f"   ℹ️  Already in IOC list")
        
        # Check the IOC
        print(f"\n2. Checking if {test_ip} is in IOC list...")
        is_bad = check_ioc(test_ip)
        
        if is_bad:
            print(f"   ✓ Confirmed as known bad IP")
        else:
            print(f"   ❌ Not detected")
            return False
        
        # Get stats
        print(f"\n3. Getting IOC statistics...")
        stats = get_ioc_stats()
        print(f"   ✓ Total IOCs: {stats['total_iocs']}")
        print(f"   ✓ Total Matches: {stats['total_matches']}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_enrichment_pipeline():
    """Test full enrichment pipeline"""
    print("\n" + "="*60)
    print("Testing Enrichment Pipeline")
    print("="*60)
    
    try:
        from honeypot.intelligence.enrichment import enrich_attacker, get_enrichment_status
        import sqlite3
        
        # Get an attacker
        conn = sqlite3.connect('data/honeypot.db')
        c = conn.cursor()
        c.execute("SELECT ip_address FROM attackers LIMIT 1")
        row = c.fetchone()
        conn.close()
        
        if not row:
            print("   ⚠️  No attackers to enrich")
            return None
        
        test_ip = row[0]
        
        print(f"\n1. Enriching {test_ip}...")
        result = enrich_attacker(test_ip)
        
        print(f"   ✓ Enrichment completed in {result['enrichment_time']:.2f}s")
        print(f"   ✓ IOC Match: {result['ioc_match']}")
        print(f"   ✓ Geo Data: {'✓' if result['geo'] else '✗'}")
        print(f"   ✓ Reputation: {'✓' if result['reputation'] else '✗'}")
        print(f"   ✓ Threat Score: {result['threat_score']}/100 ({result['verdict']})")
        
        # Get overall status
        print(f"\n2. Getting enrichment status...")
        status = get_enrichment_status()
        
        print(f"   ✓ Total Attackers: {status['total_attackers']}")
        print(f"   ✓ Geo Enriched: {status['geo_enriched']} ({status['geo_enriched_pct']:.1f}%)")
        print(f"   ✓ Intel Enriched: {status['intel_enriched']} ({status['intel_enriched_pct']:.1f}%)")
        print(f"   ✓ Known Bad: {status['known_bad']}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def verify_database():
    """Verify enrichment data in database"""
    print("\n" + "="*60)
    print("Verifying Database Enrichment")
    print("="*60)
    
    try:
        import sqlite3
        
        conn = sqlite3.connect('data/honeypot.db')
        c = conn.cursor()
        
        # Check enriched attackers
        c.execute("""
            SELECT 
                ip_address,
                country,
                city,
                threat_score,
                verdict,
                abuseipdb_score,
                geo_enriched,
                intel_enriched
            FROM attackers
            WHERE geo_enriched = 1 OR intel_enriched = 1
            ORDER BY threat_score DESC
            LIMIT 5
        """)
        
        print("\nTop 5 Enriched Attackers:")
        print("-" * 60)
        
        for row in c.fetchall():
            ip, country, city, score, verdict, abuse, geo, intel = row
            print(f"\nIP: {ip}")
            if country:
                print(f"  Location: {city}, {country}")
            print(f"  Threat Score: {score}/100 ({verdict})")
            if abuse:
                print(f"  AbuseIPDB: {abuse}/100")
            print(f"  Enriched: Geo={'✓' if geo else '✗'} Intel={'✓' if intel else '✗'}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print(" "*15 + "PHASE 3 TEST SUITE")
    print(" "*10 + "Threat Intelligence Integration")
    print("="*60)
    
    results = []
    
    # Wait for services
    print("\nWaiting 3 seconds for services...")
    time.sleep(3)
    
    # Simulate some attack traffic first
    simulate_attack()
    time.sleep(2)
    
    # Run tests
    results.append(("Geolocation", test_geolocation()))
    time.sleep(2)
    
    results.append(("AbuseIPDB", test_abuseipdb()))
    time.sleep(2)
    
    results.append(("Threat Scoring", test_threat_scoring()))
    time.sleep(1)
    
    results.append(("IOC Detection", test_ioc_detection()))
    time.sleep(1)
    
    results.append(("Enrichment Pipeline", test_enrichment_pipeline()))
    time.sleep(1)
    
    results.append(("Database Verification", verify_database()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for name, result in results:
        if result is True:
            status = "✅ PASS"
        elif result is False:
            status = "❌ FAIL"
        else:
            status = "⚠️  SKIP (not configured)"
        
        print(f"{status} - {name}")
    
    passed = sum(1 for _, r in results if r is True)
    skipped = sum(1 for _, r in results if r is None)
    total = len(results) - skipped
    
    print(f"\nTotal: {passed}/{total} tests passed ({skipped} skipped)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Phase 3 is complete!")
    
    print("="*60)
