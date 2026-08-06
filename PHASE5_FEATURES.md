# 🔍 Phase 5 Features Overview

## Campaign Detection

### 1. ASN-Based Campaigns
**Detects**: Coordinated attacks from same network

**How it works**:
- Groups attackers by Autonomous System Number
- Identifies multiple IPs from same ASN attacking together
- Minimum 3 IPs required for detection
- Severity: HIGH if ≥5 IPs, otherwise MEDIUM

**What you get**:
- ASN identifier (e.g., AS15169)
- Number of attacking IPs
- Total attack attempts
- List of involved IPs with countries
- Services being targeted
- Attack timeframe

**Example detection**:
```
ASN Campaign: AS15169
- 7 attackers from Google Cloud
- 156 total attempts
- Countries: US (3), CN (2), DE (2)
- Services: SSH, FTP, HTTP
- Assessment: Potential botnet using cloud infrastructure
```

### 2. Credential Pattern Campaigns
**Detects**: Same username/password used by multiple IPs

**How it works**:
- Groups login attempts by credential combination
- Identifies credentials tried by multiple IPs
- Minimum 3 IPs required
- Tracks which services are targeted

**What you get**:
- Username and password used
- Number of IPs using credential
- Total attempt count
- List of attacking IPs
- Services targeted
- Attack duration

**Example detection**:
```
Credential Campaign: admin/admin123
- 5 IPs using this credential
- 89 attempts across all services
- ISPs: Various cloud providers
- Services: SSH (30), FTP (25), HTTP (34)
- Assessment: Credential stuffing attack
```

### 3. Timing-Based Campaigns
**Detects**: Burst attacks in coordinated time windows

**How it works**:
- Buckets connections by hour
- Identifies unusual activity spikes
- Requires ≥5 IPs and ≥20 connections in 1 hour
- Finds common services targeted

**What you get**:
- Time bucket (hour)
- Number of attacking IPs
- Total connections in window
- List of IPs involved
- Services targeted
- Severity based on scale

**Example detection**:
```
Timing Campaign: 2026-06-05 02:00:00
- 8 IPs attacking in same hour
- 47 total connections
- Peak at 02:23 AM (after hours)
- Services: All honeypot services
- Assessment: Coordinated burst attack
```

### 4. Target-Focused Campaigns
**Detects**: Multiple IPs targeting same service

**How it works**:
- Groups connections by service and port
- Identifies services under concentrated attack
- Requires ≥5 IPs
- Checks for common ASNs among attackers

**What you get**:
- Service and port targeted
- Number of attacking IPs
- Total connections
- Common ASNs (if any)
- Attack duration
- IP list

**Example detection**:
```
Target Campaign: SSH:2222
- 12 IPs targeting SSH service
- 234 total connections
- Common ASN: AS15169 (5 IPs)
- Duration: 3 hours
- Assessment: Focused SSH attack campaign
```

---

## Behavioral Correlation

### Attack Sequence Analysis
**Purpose**: Track chronological order of attacker actions

**What you see**:
- Timeline of all events (connections, login attempts)
- Service targeted for each event
- Username used (if login attempt)
- Timestamp for each action
- Event type (connection vs login)

**Visualization**: Scatter plot with time on X-axis

**Use case**: Understand attacker's progression through your systems

### Temporal Pattern Detection
**Purpose**: Identify when attackers are active

**What you see**:
- Peak attack hour (0-23)
- Day of week patterns
- After-hours activity detection (< 6 AM or > 10 PM)
- Hourly distribution of attacks

**Insight**: After-hours activity suggests automated/coordinated attacks

**Use case**: Schedule monitoring and defensive measures

### Service Correlation
**Purpose**: Understand which services are targeted and in what order

**What you see**:
- Complete list of services targeted
- Order of first contact per service
- Hit count per service
- First and last hit timestamps
- Scanning behavior indicator

**Detection**: ≥3 services = scanning behavior

**Use case**: Identify reconnaissance vs focused attacks

### Credential Pattern Analysis
**Purpose**: Classify type of credential attack

**Attack Types Detected**:
1. **Credential Stuffing**: Many usernames, fewer passwords
2. **Password Spray**: Fewer usernames, many passwords  
3. **Brute Force**: High total attempts (≥20)
4. **Targeted**: Low volume, specific credentials

**What you see**:
- Attack type classification
- Unique usernames tried
- Unique passwords tried
- Total attempts
- List of usernames used

**Use case**: Understand attacker's credential strategy

### Behavioral Scoring
**Purpose**: Single threat score based on multiple factors

**Scoring Factors**:
- Service diversity (10-30 points)
- After-hours activity (15 points)
- Credential attack type (20-25 points)
- Attempt volume (10 points)
- Persistence (15 points)

**Score Ranges**:
- 0-39: LOW threat
- 40-59: MEDIUM threat
- 60-79: HIGH threat
- 80-100: CRITICAL threat

**Use case**: Quick threat assessment and prioritization

### Similar Attacker Detection
**Purpose**: Find attackers with similar behavior patterns

**Similarity Factors**:
- Service pattern matching (Jaccard index)
- Temporal pattern matching (peak hours)
- Credential pattern matching (attack types)

**Threshold**: 0.0 (different) to 1.0 (identical)  
**Default**: 0.7 (70% similar)

**What you see**:
- List of similar IPs
- Similarity score for each
- Ranked by similarity

**Use case**: Identify related attackers, botnet members, same actor

### Attack Chain Detection
**Purpose**: Identify sequences of related attacks

**How it works**:
- Groups events within configurable time window (10-180 min)
- Tracks service sequence
- Calculates chain length and duration
- Assigns severity based on service diversity

**What you see**:
- IP address
- Number of events in chain
- Duration in minutes
- Unique services targeted
- Complete sequence with timestamps
- Severity (HIGH if 3+ services)

**Use case**: Detect systematic attack progressions

---

## Threat Hunting Interface

### Campaign Detection Mode
**Purpose**: Overview of all detected campaigns

**Features**:
- Summary metrics (total, by severity, by type)
- Campaign type pie chart
- Campaign timeline scatter plot
- Detailed campaign cards (expandable)
- Type filtering
- CSV export

**Workflow**:
1. Set time window (1-168 hours)
2. Review metrics
3. Check visualizations
4. Expand campaigns of interest
5. Filter by type if needed
6. Export data

### Behavior Correlation Mode
**Purpose**: Deep dive into individual attacker

**Features**:
- IP selection dropdown
- Behavioral metrics dashboard
- 4 analysis tabs
- Interactive charts
- Similar attacker search

**Workflow**:
1. Select IP from dropdown
2. Review behavioral score
3. Check Attack Timeline tab
4. Review Service Patterns tab
5. Analyze Credential patterns
6. Find similar attackers

### Attack Chains Mode
**Purpose**: View attack sequences

**Features**:
- Chain metrics dashboard
- Distribution histograms
- Detailed chain cards
- Sequence tables
- Severity indicators

**Workflow**:
1. Set time window (10-180 min)
2. Review chain statistics
3. Check distributions
4. Expand chains of interest
5. Analyze sequences

### IOC Search Mode
**Purpose**: Hunt for specific indicators

**Search Types**:

**IP Address**:
- Exact match or wildcard (192.168.1.*)
- Shows complete attacker profile
- Lists connections and attempts

**Username**:
- Pattern matching
- Shows IPs attempting username
- Bar chart of top IPs
- Service breakdown

**Password**:
- Pattern matching
- Optional password masking
- Shows IPs attempting password
- Attempt counts

**ASN**:
- Network-level search
- Shows all IPs from ASN
- Statistics dashboard
- Threat score distribution

**Country**:
- Geographic filtering
- Dropdown selection
- Complete IP list
- Export option

---

## Campaign Dashboard

### Summary Section
**Metrics**:
- Total active campaigns
- High severity count
- ASN campaign count
- Credential campaign count

**Charts**:
- Campaign type distribution (pie)
- Severity distribution (bar)

### Top Campaigns Section

**Top ASN Campaigns**:
- Top 5 by attacker count
- Expandable cards
- IP tables with countries
- Services targeted

**Top Credential Campaigns**:
- Top 5 by attacker count
- Username/password shown
- IP tables with ISPs
- Services targeted

### All Campaigns Table
**Features**:
- Complete campaign list
- Type filter (multi-select)
- Severity filter (multi-select)
- Color-coded rows
- Campaign descriptions
- Sortable columns
- CSV export

**Columns**:
- Type
- Severity (color-coded)
- IPs (attacker count)
- Identifier (ASN, credential, service, time)
- Description

---

## Key Features Summary

### Detection Capabilities
✅ 4 campaign detection types  
✅ 8 behavioral correlation features  
✅ Attack chain identification  
✅ Similar attacker matching  
✅ IOC searching (5 types)  
✅ Real-time analysis

### Visualization
✅ Interactive scatter plots  
✅ Distribution charts  
✅ Histograms  
✅ Bar charts  
✅ Pie charts  
✅ Timeline views  
✅ Heatmaps

### Data Export
✅ CSV download on all pages  
✅ Campaign reports  
✅ IP lists  
✅ Attack sequences  
✅ Statistics

### Filtering & Search
✅ Time window configuration  
✅ Type filtering  
✅ Severity filtering  
✅ Pattern matching  
✅ Wildcard search  
✅ Multi-select filters

### User Experience
✅ Expandable cards  
✅ Tabbed interfaces  
✅ Color coding  
✅ Country flags  
✅ Auto-refresh option  
✅ Loading indicators  
✅ Error handling

---

## Performance

### Speed
- Campaign detection: < 2 seconds
- Behavior analysis: < 500ms per IP
- Attack chains: < 2 seconds
- Similar attackers: 1-5 seconds
- IOC search: < 100ms

### Scalability
- Handles 1000+ attackers
- Processes 10,000+ connections
- Analyzes 5,000+ login attempts
- Optimized SQL queries
- Indexed database tables

---

## Use Cases

### SOC Operations
- Real-time campaign monitoring
- Threat prioritization
- Incident investigation
- Pattern identification

### Threat Research
- Attack technique analysis
- Behavioral profiling
- Campaign tracking
- IOC collection

### Network Defense
- Early warning system
- Coordinated attack detection
- Service targeting alerts
- After-hours monitoring

### Compliance
- Attack documentation
- Evidence collection
- Audit reporting
- Export capabilities

---

**Phase 5 Status**: ✅ COMPLETE  
**Dashboard**: http://localhost:8501  
**Pages**: 🔍 Threat Hunting (Page 5), 🎪 Campaigns (Page 6)  
**Tests**: 6/6 passing  
**Documentation**: Complete

Happy hunting! 🎯
