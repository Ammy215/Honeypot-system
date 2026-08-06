# 🚀 HoneyShield Quick Start Guide

## Installation (30 seconds)

```bash
# Install dependencies
pip install python-dotenv rich

# Initialize database
python -c "from database.db import init_db; init_db()"

# Start honeypot
python main.py
```

## Test It (1 minute)

### Option 1: Run Test Script
```bash
python test_simple.py
```

### Option 2: Manual Testing

**Test FTP (port 2121):**
```bash
nc localhost 2121
USER admin
PASS admin
QUIT
```

**Test HTTP (port 8080):**
```bash
# In browser
http://localhost:8080/admin

# Or with curl
curl -X POST http://localhost:8080/admin -d "username=admin&password=admin"
```

**Test Telnet (port 2323):**
```bash
nc localhost 2323
# Type: root
# Type: password
```

**Test SSH (port 2222):**
```bash
nc localhost 2222
# You'll see: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
```

## See the Results

### Real-Time Console
Watch the honeypot console - you'll see beautiful colored alerts like:

```
╭────────────────────────── 🚨 SECURITY ALERT - HIGH ──────────────────────────╮
│ CREDENTIAL_STUFFING                                                          │
│                                                                              │
│ IP: 127.0.0.1                                                                │
│ Severity: HIGH                                                               │
│                                                                              │
│ More than 5 different usernames from same IP in 10 minutes                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Check Database
```bash
python show_status.py
```

### View Logs
```bash
# Windows
type logs\honeypot.log
type logs\alerts.log

# Linux/Mac
tail -f logs/honeypot.log
tail -f logs/alerts.log
```

## What Gets Detected?

1. **Brute Force Attacks**
   - More than 10 login attempts in 5 minutes
   - Per-service thresholds

2. **Credential Stuffing**
   - More than 5 different usernames tried
   - Indicates automated credential testing

3. **Password Spray**
   - Many passwords tried for same username
   - Common in targeted attacks

4. **Default Credentials**
   - Detects 17 common default passwords:
     - admin/admin
     - root/root
     - admin/password
     - pi/raspberry
     - And more...

5. **Automated Tools**
   - Detects rapid-fire attacks (>3 attempts/second)
   - Indicates bot or script usage

6. **Multi-Service Attacks**
   - Same IP attacking multiple services
   - Indicates scanning behavior

## Database Schema

```sql
-- All attackers
SELECT * FROM attackers;

-- All connections
SELECT * FROM connections ORDER BY timestamp DESC;

-- All login attempts
SELECT * FROM login_attempts ORDER BY timestamp DESC;

-- All alerts
SELECT * FROM alerts ORDER BY timestamp DESC;

-- Alert summary
SELECT severity, COUNT(*) FROM alerts GROUP BY severity;
```

## Ports in Use

| Service | Port | Status |
|---------|------|--------|
| SSH     | 2222 | ✅ Active |
| FTP     | 2121 | ✅ Active |
| HTTP    | 8080 | ✅ Active |
| Telnet  | 2323 | ✅ Active |

## Troubleshooting

### Port Already in Use
If you get "Address already in use" error:

```bash
# Windows
netstat -ano | findstr :2222
netstat -ano | findstr :2121
netstat -ano | findstr :8080

# Linux/Mac
lsof -i :2222
lsof -i :2121
lsof -i :8080
```

Change ports in `config.py`:
```python
SERVICES = {
    "SSH":    {"port": 2222,  "enabled": True},
    "FTP":    {"port": 2121,  "enabled": True},
    "HTTP":   {"port": 8080,  "enabled": True},
    "Telnet": {"port": 2323,  "enabled": True},
}
```

### Database Locked
```bash
# Stop all running honeypot processes
# Delete database and reinitialize
rm data/honeypot.db
python -c "from database.db import init_db; init_db()"
```

### No Alerts Showing
- Check if you're triggering the thresholds (need multiple attempts)
- Try default credentials: admin/admin or root/root
- Check `logs/alerts.log` file

## Phase Status

- ✅ Phase 1: Foundation (Complete)
- ✅ Phase 2: Login Trap & Detection (Complete)
- ⏳ Phase 3: Threat Intelligence (Next)
- ⏳ Phase 4: Dashboard (Coming)
- ⏳ Phase 5: Correlation Engine (Coming)
- ⏳ Phase 6: AI Analyst (Coming)

## Quick Commands

```bash
# Start honeypot
python main.py

# Test all services
python test_simple.py

# Check database status
python show_status.py

# View database directly
sqlite3 data/honeypot.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10;"

# Clear all data and restart fresh
rm data/honeypot.db logs/*.log
python -c "from database.db import init_db; init_db()"
python main.py
```

## Next Steps

1. **Let it run** - Leave the honeypot running and see what real attackers try
2. **Monitor alerts** - Watch for different attack patterns
3. **Analyze data** - Use SQLite to query attack patterns
4. **Ready for Phase 3?** - Add geolocation and threat intelligence!

---

**Need Help?** Check these files:
- `README.md` - Full documentation
- `PHASE2_COMPLETE.md` - Phase 2 details
- `config.py` - Configuration options
