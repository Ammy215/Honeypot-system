# 🚀 Phase 5 Quick Start Guide

## Start the System

### Step 1: Start Honeypot
```bash
python main.py
```
This starts all honeypot services on ports 2222, 2121, 8080, 2323.

### Step 2: Start Dashboard
```bash
python -m streamlit run dashboard/app.py
```
Dashboard will be available at http://localhost:8501

### Step 3: Access Phase 5 Features
Open your browser to: **http://localhost:8501**

Click on the sidebar to access:
- **🔍 Threat Hunting** (Page 5)
- **🎪 Campaigns** (Page 6)

---

## Quick Feature Access

### Campaign Detection
1. Go to **🎪 Campaigns** page
2. View summary metrics at top
3. Scroll to see:
   - Campaign type distribution
   - Severity distribution
   - Top ASN campaigns
   - Top credential campaigns
   - All campaigns table
4. Use filters to narrow results
5. Click "Download Campaign Report" for CSV

### Threat Hunting
1. Go to **🔍 Threat Hunting** page
2. Select hunting mode in sidebar:
   - **Campaign Detection**: View all detected campaigns
   - **Behavior Correlation**: Analyze individual attackers
   - **Attack Chains**: See attack sequences
   - **IOC Search**: Hunt for specific indicators

### Behavior Analysis
1. Go to **🔍 Threat Hunting**
2. Select "Behavior Correlation" mode
3. Choose IP from dropdown
4. Explore tabs:
   - Attack Timeline
   - Service Patterns
   - Credential Analysis
   - Similar Attackers

### IOC Search
1. Go to **🔍 Threat Hunting**
2. Select "IOC Search" mode
3. Choose search type:
   - IP Address (supports wildcards like 192.168.1.*)
   - Username
   - Password Pattern
   - ASN
   - Country
4. Enter search criteria
5. Review results

---

## Run Tests

```bash
# Test Phase 5 features
python test_phase5.py
```

Expected output: All 6/6 tests passing ✅

---

## Generate Attack Data (Optional)

To see Phase 5 in action with real data:

```bash
# Test SSH
nc localhost 2222

# Test FTP with multiple attempts
nc localhost 2121
USER admin
PASS password123
USER root
PASS 123456

# Test HTTP
curl http://localhost:8080/admin
curl http://localhost:8080/phpmyadmin
```

After generating attacks, refresh the dashboard to see:
- Campaigns detected
- Behavior patterns
- Attack chains
- Correlations

---

## Common Tasks

### View Campaign Summary
```python
from honeypot.detectors.campaign_detector import campaign_detector

summary = campaign_detector.get_campaign_summary()
print(f"Total campaigns: {summary['total_campaigns']}")
```

### Analyze Attacker
```python
from honeypot.detectors.correlation_engine import correlation_engine

analysis = correlation_engine.correlate_attacker_behavior("192.168.1.100")
print(f"Behavioral score: {analysis['behavioral_score']}")
```

### Detect Campaigns
```python
from honeypot.detectors.campaign_detector import campaign_detector

campaigns = campaign_detector.detect_campaigns(time_window_hours=24)
print(f"Found {len(campaigns)} campaigns")
```

### Find Similar Attackers
```python
from honeypot.detectors.correlation_engine import correlation_engine

similar = correlation_engine.find_similar_attackers("192.168.1.100", threshold=0.7)
print(f"Found {len(similar)} similar attackers")
```

---

## Troubleshooting

### Dashboard Not Loading
```bash
# Check if port 8501 is in use
netstat -ano | findstr :8501

# Kill process if needed, then restart
python -m streamlit run dashboard/app.py
```

### No Campaigns Detected
- **Cause**: Not enough attack data or time window too short
- **Solution**: 
  - Increase time window in dashboard
  - Generate more attack data
  - Wait for real attacks to accumulate

### Empty Attack Chains
- **Cause**: Attackers only hitting single service
- **Solution**:
  - Increase time window (try 120+ minutes)
  - Test multiple services from same IP
  - Wait for multi-service attacks

### No Similar Attackers Found
- **Cause**: Limited attacker diversity in database
- **Solution**:
  - Lower similarity threshold (try 0.5)
  - Wait for more attackers
  - Normal with limited data

---

## Documentation

- **Complete Guide**: `PHASE5_COMPLETE.md`
- **Usage Guide**: `PHASE5_USAGE_GUIDE.md`
- **Features**: `PHASE5_FEATURES.md`
- **Summary**: `PHASE5_SUMMARY.md`

---

## Status Check

```bash
# View database status
python show_status.py

# Run Phase 5 tests
python test_phase5.py

# Check processes
# Windows:
tasklist | findstr python

# Check if honeypot is listening
netstat -ano | findstr "2222 2121 8080 2323"
```

---

**Phase 5 Status**: ✅ COMPLETE  
**Dashboard**: http://localhost:8501  
**Pages**: 🔍 Threat Hunting, 🎪 Campaigns  
**Tests**: 6/6 passing

Ready to hunt! 🎯
