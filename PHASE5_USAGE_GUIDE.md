# 🔍 Phase 5 Usage Guide - Threat Hunting & Correlation

## Quick Start

### 1. Ensure System is Running

```bash
# Check if honeypot is running
# Should see: python main.py

# Check if dashboard is running
# Should see: python -m streamlit run dashboard/app.py

# If not running, start them:
python main.py                                  # Terminal 1
python -m streamlit run dashboard/app.py        # Terminal 2
```

### 2. Access Dashboard

Open your browser to: **http://localhost:8501**

### 3. Navigate to Phase 5 Pages

In the sidebar, you'll see two new pages:
- **🔍 Threat Hunting** (Page 5)
- **🎪 Campaigns** (Page 6)

---

## 🔍 Threat Hunting Page

### Mode 1: Campaign Detection

**Purpose**: Identify coordinated attack campaigns

**How to Use:**
1. Click "🔍 Threat Hunting" in sidebar
2. Select "Campaign Detection" in hunt mode
3. Adjust time window (1-168 hours)
4. Review campaign metrics at top
5. View campaign type distribution (pie chart)
6. Check campaign timeline (scatter plot)
7. Expand campaign cards for details
8. Filter by campaign type if needed

**What You'll See:**
- Total campaigns detected
- High severity campaign count
- Total IPs involved
- Campaign types (ASN, Credential, Timing, Target)
- For each campaign:
  - Type and severity
  - Attacker count
  - IP addresses involved
  - Services targeted
  - Start/end times
  - ASN or credential details

**Example Scenario:**
```
You see 3 campaigns detected:
1. ASN_COORDINATED - AS15169 - 5 IPs attacking together
2. CREDENTIAL_PATTERN - "admin/password123" used by 4 IPs
3. TARGET_FOCUSED - 8 IPs all hitting SSH service

This indicates potential botnet activity.
```

### Mode 2: Behavior Correlation

**Purpose**: Deep dive into individual attacker behavior

**How to Use:**
1. Select "Behavior Correlation" mode
2. Choose IP from dropdown (top 50 attackers shown)
3. Review behavioral score and metrics
4. Explore tabs:
   - **Attack Timeline**: See event sequence over time
   - **Service Patterns**: Which services in what order
   - **Credential Analysis**: Attack type classification
   - **Similar Attackers**: Find attackers with similar behavior

**Attack Timeline Tab:**
- Scatter plot of all events
- Color-coded by service
- Shows connections and login attempts
- Hover for details

**Service Patterns Tab:**
- Shows order of first service contact
- Hit counts per service
- Identifies scanning behavior
- Shows first/last hit times

**Credential Analysis Tab:**
- Attack type (credential stuffing, password spray, brute force, targeted)
- Unique usernames tried
- Unique passwords tried
- Total attempts
- List of usernames

**Similar Attackers Tab:**
- Adjust similarity threshold (0.0-1.0)
- Click "Find Similar" button
- See list of similar IPs with similarity scores
- Higher score = more similar behavior

**Example Scenario:**
```
Analyzing 192.168.1.100:
- Behavioral score: 75/100 (HIGH)
- Services: SSH → FTP → HTTP (scanning behavior)
- Credential attack: Brute force
- Peak hour: 2 AM (after hours)
- 3 similar attackers found with 0.85 similarity

This is a coordinated scanning campaign.
```

### Mode 3: Attack Chains

**Purpose**: Identify sequences of related attacks

**How to Use:**
1. Select "Attack Chains" mode
2. Set time window (10-180 minutes)
3. Review chain metrics
4. Check distribution histograms
5. Expand chain cards for details
6. View attack sequence tables

**Chain Metrics:**
- Total attack chains detected
- High severity chains
- Average chain length
- Unique attackers

**Distributions:**
- Chain length histogram (how many events per chain)
- Service diversity histogram (how many services)

**Chain Details:**
- IP address
- Number of events
- Duration in minutes
- Unique services count
- Severity level
- Full event sequence with timestamps

**Example Scenario:**
```
Chain detected for 10.0.0.50:
- Length: 12 events
- Duration: 15 minutes
- Services: SSH, FTP, HTTP
- Sequence: SSH connect → SSH login × 5 → FTP connect → HTTP /admin

This is a systematic service enumeration attack.
```

### Mode 4: IOC Search

**Purpose**: Hunt for specific indicators of compromise

**Search Types:**

#### IP Address Search
```
Enter: 192.168.1.*  or  10.0.0.
Finds: All IPs matching pattern
Shows: Country, threat score, verdict, connections, logins
```

#### Username Search
```
Enter: admin  or  root
Finds: All login attempts with that username
Shows: IPs trying it, services, attempt counts, timeline
Includes: Bar chart of top IPs
```

#### Password Pattern Search
```
Enter: password  or  123456
Finds: All login attempts with that password
Shows: IPs, services, attempt counts (password masked by default)
Option: Show password checkbox
```

#### ASN Search
```
Enter: AS15169  or  AS8075
Finds: All attackers from that ASN
Shows: IP list, countries, ISPs, threat scores
Includes: Statistics (total IPs, avg score, connections)
```

#### Country Search
```
Select: Country from dropdown
Finds: All attackers from that country
Shows: IPs, ISPs, threat scores, verdicts
Includes: Statistics and download option
```

**Example Scenarios:**

**Hunting for Common Usernames:**
```
Search: "admin"
Results: 45 IPs tried "admin"
Top IP: 1.2.3.4 with 89 attempts
Services: SSH (30), FTP (25), HTTP (34)
Action: Block this IP, investigate campaign
```

**Hunting by Country:**
```
Select: "China"
Results: 12 attackers from China
Avg Score: 67 (HIGH)
Critical: 5 IPs
Action: Review threat level, consider geo-blocking
```

---

## 🎪 Campaigns Page

### Overview Section

**Summary Metrics:**
- Active campaigns count
- High severity campaigns
- ASN campaigns
- Credential campaigns

**Visualizations:**
- Campaign type pie chart
- Severity distribution bar chart

### Top ASN Campaigns

Shows top 5 ASN-based campaigns with:
- ASN identifier
- Number of attacking IPs
- Total attempts
- Involved IP table with countries
- Services targeted

**How to Use:**
1. Scroll to "Top ASN Campaigns"
2. Expand campaign card
3. Review attacker count
4. Check IP list and countries
5. Note services being targeted

**Example:**
```
AS15169 Campaign:
- 8 attackers
- 234 total attempts
- Countries: US (3), CN (2), RU (3)
- Services: SSH, FTP, HTTP
- Assessment: Potential botnet
```

### Top Credential Campaigns

Shows top 5 credential-based campaigns with:
- Username and password
- Number of IPs using it
- Attempt count
- IP details with ISPs
- Services targeted

**How to Use:**
1. Scroll to "Top Credential Campaigns"
2. Expand campaign card
3. See which credential is popular
4. Check how many IPs are using it
5. Review IP origins

**Example:**
```
admin/admin123 Campaign:
- 6 attackers using this credential
- 156 attempts
- ISPs: Various cloud providers
- Services: All services
- Assessment: Credential stuffing attack
```

### All Campaigns Table

**Filters:**
- Type: ASN, Credential, Timing, Target
- Severity: HIGH, MEDIUM, LOW

**Table Columns:**
- Type (campaign type)
- Severity (color-coded)
- IPs (attacker count)
- Identifier (ASN, credential, service, or time)
- Description

**How to Use:**
1. Scroll to "All Detected Campaigns"
2. Use filters to narrow results
3. Review table (color-coded by severity)
4. Click "Download Campaign Report" for CSV

**Export:**
- CSV file with all campaign data
- Timestamp in filename
- All columns included

### Auto-Refresh

**Enable:**
1. Check "Auto-refresh" in sidebar
2. Page refreshes every 30 seconds
3. Keep browser window open

**Use Case:**
- Real-time monitoring
- SOC dashboard display
- Continuous surveillance

---

## 💡 Common Use Cases

### Use Case 1: Investigating a Suspicious IP

```
1. Go to Threat Hunting → IOC Search → IP Address
2. Enter the suspicious IP
3. Review threat score and verdict
4. Switch to Behavior Correlation mode
5. Select the same IP
6. Check Attack Timeline tab
7. Review Service Patterns tab
8. Check Credential Analysis tab
9. Find Similar Attackers

Decision: Block if score > 70, watch if 40-70, ignore if < 40
```

### Use Case 2: Detecting Botnet Activity

```
1. Go to Campaigns page
2. Look for ASN campaigns with high IP count
3. Expand top ASN campaigns
4. Check if IPs are from diverse countries
5. Go to Threat Hunting → Campaign Detection
6. Review timing patterns
7. Check if attacks are coordinated

Indicators of botnet:
- Multiple IPs from same ASN
- Attacks in same time window
- Same credentials across IPs
- Similar behavior patterns
```

### Use Case 3: Hunting for Credential Stuffing

```
1. Go to Threat Hunting → Campaign Detection
2. Filter by CREDENTIAL_PATTERN type
3. Review campaigns with high attacker counts
4. Note common credentials
5. Go to IOC Search → Username
6. Search for those usernames
7. Check which services are targeted

Action: Add credentials to detection rules
```

### Use Case 4: Analyzing Attack Evolution

```
1. Go to Campaigns page
2. Note current campaign types
3. Increase time window to 168 hours (1 week)
4. Compare campaign types over time
5. Go to Threat Hunting → Attack Chains
6. Set 60-minute window
7. Check if chains are getting longer
8. Review service targeting evolution

Insight: Are attacks getting more sophisticated?
```

### Use Case 5: SOC Dashboard

```
Setup:
1. Open Campaigns page in one browser tab
2. Enable auto-refresh
3. Open Threat Hunting in another tab
4. Set to Campaign Detection mode
5. Adjust time window to 24 hours

Monitor:
- Campaign count increasing? → Active attack
- High severity campaigns? → Immediate investigation
- New ASN campaigns? → Potential new threat actor
- Credential campaigns? → Check for data breaches
```

---

## 📊 Interpreting Results

### Campaign Severity Levels

**HIGH (Red):**
- ≥5 IPs in ASN campaign
- ≥5 IPs in credential campaign
- ≥10 IPs in timing/target campaigns
- **Action**: Immediate investigation required

**MEDIUM (Orange):**
- 3-4 IPs in ASN campaign
- 3-4 IPs in credential campaign
- 5-9 IPs in timing/target campaigns
- **Action**: Monitor and analyze

**LOW (Blue):**
- Below MEDIUM thresholds
- **Action**: Log and watch

### Behavioral Scores

**0-39 (LOW):**
- Minimal threat
- Single service targeting
- Few attempts
- Regular hours

**40-59 (MEDIUM):**
- Moderate threat
- Multiple services
- 20-50 attempts
- May be automated

**60-79 (HIGH):**
- Significant threat
- Extensive scanning
- 50+ attempts
- After-hours activity
- Likely automated

**80-100 (CRITICAL):**
- Immediate threat
- Advanced techniques
- Coordinated attack
- Multiple indicators
- Sophisticated actor

### Attack Chain Severity

**HIGH:**
- 3+ services in sequence
- Indicates thorough reconnaissance
- Systematic approach
- Potential breach attempt

**MEDIUM:**
- 2 services in sequence
- Basic enumeration
- Opportunistic attack

### Similarity Scores

**0.9-1.0:** Nearly identical behavior (same actor or botnet)  
**0.7-0.9:** Very similar (related actors or same campaign)  
**0.5-0.7:** Moderately similar (same technique)  
**< 0.5:** Different actors/techniques

---

## 🎯 Best Practices

### 1. Regular Hunting
- Review campaigns daily
- Check high severity alerts
- Hunt for new patterns weekly
- Update IOC lists regularly

### 2. Threshold Tuning
- Adjust time windows based on traffic
- Lower thresholds for quiet networks
- Raise thresholds for busy networks
- Document changes

### 3. Investigation Workflow
```
1. Start with Campaigns overview
2. Identify high severity campaigns
3. Drill down with Behavior Correlation
4. Use IOC Search for specific indicators
5. Check Attack Chains for sequences
6. Find Similar Attackers for attribution
7. Document findings
8. Take action (block, monitor, report)
```

### 4. Export and Share
- Export CSV for analysis
- Share campaign reports with team
- Use data for threat intel
- Feed into SIEM if available

### 5. Continuous Improvement
- Track false positives
- Adjust detection rules
- Update threat scoring
- Refine correlation algorithms

---

## 🚨 Troubleshooting

### No Campaigns Detected
**Possible Reasons:**
- Not enough attack data yet
- Time window too short
- Thresholds too high
- Single isolated attacks

**Solutions:**
- Increase time window
- Wait for more data
- Lower detection thresholds in code

### Slow Similar Attacker Search
**Possible Reasons:**
- Many attackers in database
- Complex similarity calculation
- High threshold (more comparisons)

**Solutions:**
- Use higher threshold (0.8 instead of 0.5)
- Limit attacker count in query
- Run search on specific IPs only

### Empty Attack Chains
**Possible Reasons:**
- Time window too short
- Single-service attacks only
- IPs not attacking multiple services

**Solutions:**
- Increase time window to 120+ minutes
- Wait for more diverse attacks
- Check if services are all running

---

## 📚 Reference

### API Examples

**Python Script:**
```python
from honeypot.detectors.campaign_detector import campaign_detector
from honeypot.detectors.correlation_engine import correlation_engine

# Detect campaigns
campaigns = campaign_detector.detect_campaigns(24)
print(f"Found {len(campaigns)} campaigns")

# Get summary
summary = campaign_detector.get_campaign_summary()
print(f"ASN campaigns: {summary['by_type'].get('ASN_COORDINATED', 0)}")

# Analyze IP
analysis = correlation_engine.correlate_attacker_behavior("1.2.3.4")
print(f"Behavioral score: {analysis['behavioral_score']}")

# Find similar
similar = correlation_engine.find_similar_attackers("1.2.3.4", 0.7)
print(f"Found {len(similar)} similar attackers")

# Detect chains
chains = correlation_engine.detect_attack_chains(60)
print(f"Found {len(chains)} attack chains")
```

### SQL Queries

**Find Campaign IPs:**
```sql
SELECT ip_address, COUNT(*) as services
FROM connections
WHERE timestamp >= datetime('now', '-24 hours')
GROUP BY ip_address
HAVING services >= 3;
```

**Check Credential Patterns:**
```sql
SELECT username, password_attempt, COUNT(DISTINCT ip_address) as ip_count
FROM login_attempts
WHERE timestamp >= datetime('now', '-24 hours')
GROUP BY username, password_attempt
HAVING ip_count >= 3;
```

---

**Phase 5 Status**: ✅ COMPLETE  
**Test Coverage**: 6/6 passing  
**Dashboard**: http://localhost:8501  
**Pages**: 🔍 Threat Hunting, 🎪 Campaigns

Happy hunting! 🎯
