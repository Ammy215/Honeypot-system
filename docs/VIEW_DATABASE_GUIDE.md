# 📊 How to View Your Database

Complete guide to viewing and exploring your HoneyShield database.

---

## 🎯 Quick Answer

Your database is at: `data/honeypot.db` (SQLite file)

**3 Ways to View It**:
1. **🌐 Dashboard** (Easiest) - Beautiful web interface
2. **💻 DB Browser** (Visual) - GUI tool
3. **⌨️ Command Line** (Advanced) - SQLite commands

---

## Method 1: 🌐 Using the Dashboard (Recommended)

### This is the EASIEST way - everything visual!

**Step 1: Start Dashboard**
```bash
# Terminal 1: Start honeypot
python main.py

# Terminal 2: Start dashboard
streamlit run dashboard/app.py
```

**Step 2: Login**
- Open browser: http://localhost:8501
- Username: `admin`
- Password: (from setup)

**Step 3: Explore Data**

Navigate through pages:

#### 🔴 Live Feed
```
See: Recent attacks in real-time
Data: Last 50 connections
Columns: Time, IP, Service, Username, Password
```

#### 🌍 Attacker Intel
```
See: Detailed attacker profiles
Data: All attackers with geolocation, threat scores
Select: Choose an IP from dropdown
View: Full profile with all attempts
```

#### 📈 Analytics
```
See: Charts and graphs
Data: 
  - Attacks over time (timeline)
  - Top countries (pie chart)
  - Top services (bar chart)
  - Hourly heatmap
```

#### 🚨 Alerts
```
See: All security alerts
Data: Brute force alerts, suspicious activity
Filter: By severity, date range
```

#### 🔍 Threat Hunting
```
See: Search and correlate attacks
Data: Find specific IPs, usernames, passwords
Search: IOCs (Indicators of Compromise)
```

#### 🎪 Campaigns
```
See: Grouped attacks (coordinated campaigns)
Data: Related attackers working together
View: Campaign timeline, members, tactics
```

#### 🤖 AI Analysis
```
See: AI-generated threat reports
Data: GPT-4 analysis of attackers
Generate: Professional security reports
```

**Export Data**:
Most pages have an "Export CSV" button to download data!

---

## Method 2: 💻 Using DB Browser (Visual GUI)

### Best for exploring raw database

**Step 1: Install DB Browser for SQLite**

```bash
# Windows
# Download from: https://sqlitebrowser.org/dl/
# Install the .exe file

# Mac
brew install --cask db-browser-for-sqlite

# Linux (Ubuntu/Debian)
sudo apt-get install sqlitebrowser
```

**Step 2: Open Database**

1. Launch "DB Browser for SQLite"
2. Click "Open Database"
3. Navigate to your project folder
4. Open: `data/honeypot.db`

**Step 3: Explore Tables**

You'll see 8 tables:

```
Tables:
├── attackers          (All unique attacker IPs)
├── connections        (Every connection made)
├── login_attempts     (Every username/password tried)
├── commands           (Commands attackers ran)
├── file_uploads       (Files they uploaded)
├── alerts             (Security alerts)
├── campaigns          (Attack campaigns)
└── ioc                (Indicators of Compromise)
```

**Step 4: Browse Data**

Click on any table, then click "Browse Data" tab:

```
┌────┬─────────────────┬─────────┬──────────────┬──────────────┐
│ id │ ip_address      │ country │ threat_score │ verdict      │
├────┼─────────────────┼─────────┼──────────────┼──────────────┤
│ 1  │ 45.142.212.61   │ Russia  │ 87           │ CRITICAL     │
│ 2  │ 23.94.24.118    │ USA     │ 45           │ SUSPICIOUS   │
│ 3  │ 185.220.101.5   │ Germany │ 72           │ HIGH         │
└────┴─────────────────┴─────────┴──────────────┴──────────────┘
```

**Step 5: Run Queries**

Click "Execute SQL" tab:

```sql
-- See all attackers from Russia
SELECT * FROM attackers WHERE country = 'Russia';

-- See all SSH attacks
SELECT * FROM connections WHERE service_name = 'SSH';

-- See most common passwords
SELECT password, COUNT(*) as count 
FROM login_attempts 
GROUP BY password 
ORDER BY count DESC 
LIMIT 10;

-- See critical threats
SELECT * FROM attackers WHERE verdict = 'CRITICAL';
```

**Step 6: Export Data**

- Right-click on any table
- Click "Export as CSV"
- Save to file

---

## Method 3: ⌨️ Using Command Line (Advanced)

### For quick queries and scripts

**Step 1: Open SQLite Shell**

```bash
# Navigate to your project folder
cd "path/to/Honeypot Trap System"

# Open database
sqlite3 data/honeypot.db
```

**Step 2: Run Commands**

```sql
-- See all tables
.tables

-- See table structure
.schema attackers

-- See attackers
SELECT * FROM attackers;

-- See recent attacks (last 10)
SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10;

-- Count total attackers
SELECT COUNT(*) FROM attackers;

-- See most targeted service
SELECT service_name, COUNT(*) as count 
FROM connections 
GROUP BY service_name 
ORDER BY count DESC;

-- See all critical threats
SELECT ip_address, country, threat_score, verdict 
FROM attackers 
WHERE verdict = 'CRITICAL';

-- Exit
.quit
```

**Step 3: Export to CSV**

```bash
# From sqlite3 shell
.headers on
.mode csv
.output attackers.csv
SELECT * FROM attackers;
.quit
```

---

## Method 4: 🐍 Using Python Script

### Create custom reports

**Create a file: `view_database.py`**

```python
import sqlite3
import pandas as pd

# Connect to database
conn = sqlite3.connect('data/honeypot.db')

# Query attackers
attackers = pd.read_sql_query("SELECT * FROM attackers", conn)
print("\n📊 Total Attackers:", len(attackers))
print(attackers.head())

# Query by country
print("\n🌍 Attackers by Country:")
by_country = attackers.groupby('country').size().sort_values(ascending=False)
print(by_country.head(10))

# Query login attempts
attempts = pd.read_sql_query("SELECT * FROM login_attempts", conn)
print("\n🔐 Total Login Attempts:", len(attempts))

# Most common passwords
print("\n🔑 Top 10 Passwords:")
top_passwords = attempts.groupby('password').size().sort_values(ascending=False).head(10)
print(top_passwords)

# Most common usernames
print("\n👤 Top 10 Usernames:")
top_usernames = attempts.groupby('username').size().sort_values(ascending=False).head(10)
print(top_usernames)

# Critical threats
critical = attackers[attackers['verdict'] == 'CRITICAL']
print(f"\n⚠️ Critical Threats: {len(critical)}")
print(critical[['ip_address', 'country', 'threat_score']])

# Close connection
conn.close()
```

**Run it**:
```bash
python view_database.py
```

**Output**:
```
📊 Total Attackers: 47
   id      ip_address  country  threat_score     verdict
0   1  45.142.212.61   Russia            87    CRITICAL
1   2   23.94.24.118      USA            45  SUSPICIOUS
2   3  185.220.101.5  Germany            72        HIGH

🌍 Attackers by Country:
Russia     23
China      12
USA         7
...

🔐 Total Login Attempts: 1,249

🔑 Top 10 Passwords:
password123    145
admin          98
root           87
...

👤 Top 10 Usernames:
root      342
admin     198
user       87
...

⚠️ Critical Threats: 12
      ip_address  country  threat_score
45.142.212.61   Russia            87
...
```

---

## 📋 Database Schema (What's in Each Table)

### 1. attackers
```sql
CREATE TABLE attackers (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    country TEXT,
    city TEXT,
    isp TEXT,
    threat_score INTEGER,
    verdict TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    connection_count INTEGER,
    services_targeted TEXT
);
```

**What it stores**: Unique attacker IPs with geolocation and threat assessment

### 2. connections
```sql
CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    attacker_id INTEGER,
    service_name TEXT,
    service_port INTEGER,
    timestamp TIMESTAMP,
    duration INTEGER,
    data_sent INTEGER,
    data_received INTEGER
);
```

**What it stores**: Every connection attempt to honeypot services

### 3. login_attempts
```sql
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY,
    attacker_id INTEGER,
    connection_id INTEGER,
    username TEXT,
    password TEXT,
    service_name TEXT,
    success INTEGER,
    timestamp TIMESTAMP
);
```

**What it stores**: Every username/password combination tried

### 4. commands
```sql
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    attacker_id INTEGER,
    connection_id INTEGER,
    command TEXT,
    service_name TEXT,
    timestamp TIMESTAMP
);
```

**What it stores**: Commands attackers executed

### 5. file_uploads
```sql
CREATE TABLE file_uploads (
    id INTEGER PRIMARY KEY,
    attacker_id INTEGER,
    connection_id INTEGER,
    filename TEXT,
    file_size INTEGER,
    file_hash TEXT,
    timestamp TIMESTAMP
);
```

**What it stores**: Files attackers uploaded

### 6. alerts
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    attacker_id INTEGER,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    timestamp TIMESTAMP,
    acknowledged INTEGER
);
```

**What it stores**: Security alerts (brute force, suspicious activity, etc.)

### 7. campaigns
```sql
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY,
    campaign_type TEXT,
    description TEXT,
    attacker_count INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);
```

**What it stores**: Related attacks grouped as campaigns

### 8. ioc
```sql
CREATE TABLE ioc (
    id INTEGER PRIMARY KEY,
    ioc_type TEXT,
    value TEXT UNIQUE,
    description TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    hit_count INTEGER
);
```

**What it stores**: Indicators of Compromise (malicious IPs, hashes, etc.)

---

## 🔍 Useful SQL Queries

### Top 10 Attackers by Connections
```sql
SELECT 
    a.ip_address, 
    a.country, 
    COUNT(c.id) as connections
FROM attackers a
JOIN connections c ON a.id = c.attacker_id
GROUP BY a.id
ORDER BY connections DESC
LIMIT 10;
```

### Brute Force Activity (>10 attempts)
```sql
SELECT 
    a.ip_address,
    a.country,
    COUNT(la.id) as attempts
FROM attackers a
JOIN login_attempts la ON a.id = la.attacker_id
GROUP BY a.id
HAVING attempts > 10
ORDER BY attempts DESC;
```

### Attack Timeline (by hour)
```sql
SELECT 
    strftime('%Y-%m-%d %H:00', timestamp) as hour,
    COUNT(*) as attacks
FROM connections
GROUP BY hour
ORDER BY hour DESC
LIMIT 24;
```

### Most Targeted Services
```sql
SELECT 
    service_name,
    COUNT(*) as connections
FROM connections
GROUP BY service_name
ORDER BY connections DESC;
```

### Geographic Distribution
```sql
SELECT 
    country,
    COUNT(*) as attackers,
    AVG(threat_score) as avg_threat
FROM attackers
WHERE country IS NOT NULL
GROUP BY country
ORDER BY attackers DESC;
```

---

## 🎨 Creating Custom Views

### Python + Pandas (Data Analysis)

```python
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

conn = sqlite3.connect('data/honeypot.db')

# Load data
attackers = pd.read_sql_query("SELECT * FROM attackers", conn)
attempts = pd.read_sql_query("SELECT * FROM login_attempts", conn)

# Plot attackers by country
attackers.groupby('country').size().plot(kind='bar', figsize=(12,6))
plt.title('Attackers by Country')
plt.xlabel('Country')
plt.ylabel('Count')
plt.savefig('attackers_by_country.png')

# Plot attacks over time
connections = pd.read_sql_query("SELECT * FROM connections", conn)
connections['timestamp'] = pd.to_datetime(connections['timestamp'])
connections.set_index('timestamp').resample('H').size().plot(figsize=(12,6))
plt.title('Attacks Over Time')
plt.savefig('attacks_timeline.png')

conn.close()
```

---

## 🚀 Quick Commands Cheat Sheet

### View Database Size
```bash
# Windows PowerShell
Get-ChildItem "data\honeypot.db" | Select-Object Name, Length

# Linux/Mac
ls -lh data/honeypot.db
```

### Backup Database
```bash
# Simple copy
cp data/honeypot.db data/honeypot_backup_$(date +%Y%m%d).db

# Or use Python
python -c "from database.db_production import db_production; db_production.backup_database('backup.db')"
```

### Quick Stats
```bash
sqlite3 data/honeypot.db "SELECT COUNT(*) as total_attackers FROM attackers;"
sqlite3 data/honeypot.db "SELECT COUNT(*) as total_attempts FROM login_attempts;"
sqlite3 data/honeypot.db "SELECT COUNT(*) as critical_threats FROM attackers WHERE verdict='CRITICAL';"
```

### Export All Tables to CSV
```bash
# Create export script
cat > export_all.sh << 'EOF'
#!/bin/bash
for table in attackers connections login_attempts commands file_uploads alerts campaigns ioc
do
    sqlite3 -header -csv data/honeypot.db "SELECT * FROM $table;" > "export_$table.csv"
    echo "Exported $table"
done
EOF

chmod +x export_all.sh
./export_all.sh
```

---

## 🎯 Recommended Approach

**For most users, I recommend**:

1. **🌐 Use Dashboard** for daily monitoring
   - Beautiful visuals
   - Real-time updates
   - Easy to understand
   - No SQL knowledge needed

2. **💻 Use DB Browser** for deep dives
   - When you need raw data
   - For custom queries
   - To export specific data

3. **⌨️ Use Command Line** for automation
   - For scripts
   - For cron jobs
   - For quick stats

---

## ❓ Common Questions

### Q: Where is the database file?
**A:** `data/honeypot.db` in your project folder

### Q: Can I open it while honeypot is running?
**A:** Yes! SQLite supports multiple readers. Only issue is if you try to write while honeypot is writing.

### Q: How do I empty the database?
**A:** Delete `data/honeypot.db` - it will be recreated on next run

### Q: Can I use Excel?
**A:** Yes! Export to CSV from dashboard or DB Browser, then open in Excel

### Q: Database is too big, how to clean it?
**A:** 
```sql
-- Delete old data (older than 30 days)
DELETE FROM connections WHERE timestamp < date('now', '-30 days');
DELETE FROM login_attempts WHERE timestamp < date('now', '-30 days');

-- Then optimize
VACUUM;
```

### Q: How to restore from backup?
**A:**
```bash
# Stop honeypot and dashboard first
# Then replace database
cp backup.db data/honeypot.db
# Restart services
```

---

## 🎓 Summary

**Three Easy Ways**:
1. ✅ **Dashboard** - `streamlit run dashboard/app.py` → http://localhost:8501
2. ✅ **DB Browser** - Visual SQLite tool
3. ✅ **Command Line** - `sqlite3 data/honeypot.db`

**Best Practice**: Use dashboard for daily work, DB Browser for exploring!

---

Need help with specific queries or want to see specific data? Let me know! 🚀
