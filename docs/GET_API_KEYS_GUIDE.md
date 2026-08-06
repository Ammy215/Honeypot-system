# 🔑 How to Get API Keys - Step-by-Step Guide

This guide shows you exactly where and how to get each API key.

---

## 🎯 Quick Summary

| API Key | Required? | Cost | Time to Get | Purpose |
|---------|-----------|------|-------------|---------|
| **None!** | ❌ No | Free | 0 min | System works without any keys! |
| AbuseIPDB | ⭐ Recommended | Free | 2 min | Better threat intelligence |
| OpenAI | ⭐ Recommended | Paid | 5 min | AI-powered analysis |
| AlienVault OTX | ⚪ Optional | Free | 3 min | Additional threat intel |

**IMPORTANT**: The honeypot works perfectly WITHOUT any API keys! You just get fewer features.

---

## ✅ System Works Without API Keys!

### **What works WITHOUT any API keys:**

✅ All 4 honeypot services (SSH, FTP, HTTP, Telnet)  
✅ All attack recording (IPs, passwords, commands)  
✅ Database storage  
✅ Dashboard (all 7 pages)  
✅ Live feed monitoring  
✅ Brute force detection  
✅ Campaign detection  
✅ **Basic geolocation** (ip-api.com - FREE, no key needed!)  
✅ Threat scoring  
✅ Alerts  
✅ Export data  

### **What you MISS without API keys:**

❌ **AbuseIPDB**: No IP reputation data (but still works)  
❌ **OpenAI**: No AI-generated reports (but manual analysis works)  
❌ **OTX**: No AlienVault threat intel (optional anyway)  

### **Recommendation:**

**Start WITHOUT keys** → Use the system → **Add keys later if you want more features!**

---

## 🚀 Option 1: Use Without API Keys (Fastest)

Just run the setup and skip API key configuration:

```bash
python setup_production.py

# When asked about API keys:
Configure AbuseIPDB? [Y/n]: n
Configure OpenAI? [Y/n]: n
```

**Done!** System works perfectly for basic monitoring.

---

## 🌟 Option 2: Get FREE API Keys (Recommended)

If you want extra features, get these FREE keys:

### 1. 🛡️ AbuseIPDB (FREE - Recommended)

**What it does**: Tells you if an IP is known malicious

**How to get**:

1. **Go to**: https://www.abuseipdb.com/register
2. **Sign up** (free account):
   - Enter your email
   - Create password
   - Verify email
3. **Get API key**:
   - Login → Click your username (top right)
   - Click "API"
   - Copy your API key
4. **Free tier includes**:
   - 1,000 checks per day
   - Access to database
   - Plenty for honeypot!

**Time**: 2 minutes  
**Cost**: FREE forever

---

### 2. 🤖 OpenAI (Paid - Optional)

**What it does**: AI-powered threat analysis reports

**How to get**:

1. **Go to**: https://platform.openai.com/signup
2. **Sign up**:
   - Email or Google/Microsoft account
   - Verify email
3. **Add payment** (required even for trial):
   - Add credit card
   - Get $5 free trial credit (for new users)
4. **Get API key**:
   - Go to: https://platform.openai.com/api-keys
   - Click "Create new secret key"
   - Name it "HoneyShield"
   - Copy the key (shows only once!)

**Cost**:
- First $5: FREE (trial credit)
- After that: ~$0.002 per report (very cheap)
- $1 = ~500 AI reports
- Set spending limit to control costs

**Time**: 5 minutes  
**Cost**: Effectively FREE for personal use

---

### 3. 🌐 AlienVault OTX (FREE - Optional)

**What it does**: Additional threat intelligence

**How to get**:

1. **Go to**: https://otx.alienvault.com/accounts/signup
2. **Sign up** (free):
   - Email and password
   - Verify email
3. **Get API key**:
   - Login
   - Click your username → Settings
   - Copy "OTX Key"

**Time**: 3 minutes  
**Cost**: FREE forever

---

## 📝 Adding Keys to Your System

### Method 1: Using Setup Wizard (Easiest)

```bash
python setup_production.py

# When prompted:
Configure AbuseIPDB? [Y/n]: Y
Enter AbuseIPDB API key: [paste your key]
  ✅ AbuseIPDB key saved and encrypted!

Configure OpenAI? [Y/n]: Y
Enter OpenAI API key: [paste your key]
  ✅ OpenAI key saved and encrypted!
```

**Keys are automatically encrypted and saved securely!**

### Method 2: Manual Entry

```python
from security.api_key_manager import api_key_manager

# Add AbuseIPDB
api_key_manager.add_key(
    service="abuseipdb",
    api_key="your_abuseipdb_key_here",
    description="AbuseIPDB API",
    rate_limit=1000,
    rate_period="day"
)

# Add OpenAI
api_key_manager.add_key(
    service="openai",
    api_key="sk-your_openai_key_here",
    description="OpenAI GPT-4",
    rate_limit=10000,
    rate_period="day"
)

print("✅ Keys saved!")
```

### Method 3: Update .env File (Legacy)

```bash
# Edit .env file
ABUSEIPDB_API_KEY=your_actual_key_here
OPENAI_API_KEY=sk-your_actual_key_here

# Then import to encrypted storage
python -c "from security.api_key_manager import api_key_manager; api_key_manager.import_from_env()"
```

---

## 🔍 Verifying Your Keys Work

### Check if keys are configured:

```bash
python -c "from security.api_key_manager import api_key_manager; print(api_key_manager.list_keys())"
```

### Test AbuseIPDB:

```python
from utils.api_client import api_client

result = api_client.abuseipdb_check("8.8.8.8")
if result:
    print("✅ AbuseIPDB working!")
    print(f"Abuse Score: {result['data']['abuseConfidenceScore']}%")
else:
    print("❌ AbuseIPDB not working")
```

### Test OpenAI:

```python
from utils.api_client import api_client

result = api_client.openai_completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello!"}]
)
if result:
    print("✅ OpenAI working!")
    print(result['choices'][0]['message']['content'])
else:
    print("❌ OpenAI not working")
```

---

## 💰 Cost Breakdown

### Free Forever:
- ✅ **Honeypot system**: FREE
- ✅ **Geolocation**: FREE (ip-api.com)
- ✅ **AbuseIPDB**: FREE (1000/day)
- ✅ **AlienVault OTX**: FREE

### Paid (Optional):
- 💵 **OpenAI**: ~$0.002 per AI report
  - $1 = 500 reports
  - $5 = 2,500 reports
  - Most users spend $1-5/month

**Total cost for full features**: ~$1-5/month (optional!)

---

## 🎯 Recommended Approach

### For Learning/Testing:
```
✅ Start WITHOUT any keys
✅ Use system to understand it
✅ Add AbuseIPDB later (free)
✅ Add OpenAI if you want AI (optional)
```

### For Production Use:
```
✅ Get AbuseIPDB (free, 2 minutes)
✅ Maybe get OpenAI (if budget allows)
✅ Skip OTX (not critical)
```

### For Maximum Features:
```
✅ Get all 3 keys
✅ Set OpenAI spending limit ($5/month)
✅ Enjoy full intelligence!
```

---

## ❓ FAQ

### Q: Can I use the system without any keys?
**A:** YES! It works great. You just miss some extra intel.

### Q: Which key is most important?
**A:** AbuseIPDB (free) gives you IP reputation data. Very useful!

### Q: Is OpenAI worth it?
**A:** If you want AI reports, yes. But manual analysis works fine too.

### Q: Will I be charged without knowing?
**A:** No! Set spending limits on OpenAI. AbuseIPDB is always free.

### Q: Can I add keys later?
**A:** YES! Add them anytime using `python setup_production.py`

### Q: Are my keys secure?
**A:** YES! They're encrypted with Fernet encryption and stored securely.

### Q: What if I lose my keys?
**A:** Just generate new ones from the service's website.

### Q: Can I share my database without exposing keys?
**A:** YES! Keys are stored separately and encrypted.

---

## 🚨 Security Warnings

### ⚠️ NEVER:
- ❌ Commit API keys to Git
- ❌ Share keys in screenshots
- ❌ Post keys online
- ❌ Email keys in plain text
- ❌ Store keys in insecure locations

### ✅ ALWAYS:
- ✅ Use the encrypted storage (our system)
- ✅ Set spending limits (OpenAI)
- ✅ Rotate keys periodically
- ✅ Monitor usage
- ✅ Backup master encryption key

---

## 📞 Support Links

### AbuseIPDB:
- Sign up: https://www.abuseipdb.com/register
- Docs: https://www.abuseipdb.com/api
- Support: https://www.abuseipdb.com/contact

### OpenAI:
- Sign up: https://platform.openai.com/signup
- API keys: https://platform.openai.com/api-keys
- Pricing: https://openai.com/pricing
- Docs: https://platform.openai.com/docs
- Support: https://help.openai.com

### AlienVault OTX:
- Sign up: https://otx.alienvault.com/accounts/signup
- Docs: https://otx.alienvault.com/api
- Support: https://otx.alienvault.com/contact

---

## ✅ Summary

**Bottom Line**: 
- System works WITHOUT keys! ✅
- Add AbuseIPDB for better intel (free, 2 min) ⭐
- Add OpenAI for AI reports (optional, ~$1-5/month) ⭐
- Skip OTX unless you really want it ⚪

**My Recommendation**:
1. Start without keys → Learn the system
2. Add AbuseIPDB after a day or two
3. Add OpenAI if you like it

**Start now**: `python main.py` → Works immediately! 🚀

---

**Remember: You don't need ANY keys to start using HoneyShield!**

The system is designed to work great without them. Keys just add extra features.
