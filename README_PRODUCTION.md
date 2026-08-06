# 🍯 HoneyShield Intelligence Platform - Production Edition

> Enterprise-grade honeypot system with AI-powered threat analysis and comprehensive security

[![Security](https://img.shields.io/badge/Security-Production--Ready-green)](PRODUCTION_SECURITY_STATUS.md)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

---

## 🚀 Quick Start (3 Minutes)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run setup wizard
python setup_production.py

# 3. Start honeypot
python main.py

# 4. Start dashboard (new terminal)
streamlit run dashboard/app.py

# 5. Open browser and login
# http://localhost:8501
# Username: admin
# Password: (from setup)
```

**That's it!** 🎉

---

## 📋 What's New in Production Edition

### 🔒 Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Authentication** | ✅ | Role-based access control (admin/analyst/viewer) |
| **API Key Encryption** | ✅ | Fernet encryption for all API keys |
| **Audit Logging** | ✅ | Comprehensive security event logging |
| **Database Security** | ✅ | Connection pooling, query validation, WAL mode |
| **Session Management** | ✅ | Secure tokens with configurable timeout |
| **Rate Limiting** | ✅ | Per-service API rate limits |

### 🛡️ Security Architecture

```
User → Login Page → Authentication → Dashboard
                    ↓
              Session Token
                    ↓
    ┌───────────────┴────────────────┐
    │                                │
Encrypted API Keys          Production DB
Rate Limited Access       Connection Pool
Audit Logging            Query Validation
```

---

## 🎯 Core Features

### Honeypot Services
- 🔌 **SSH** (port 2222) - Fake SSH server
- 📁 **FTP** (port 2121) - Fake FTP server
- 🌐 **HTTP** (port 8080) - Fake web server
- 📡 **Telnet** (port 2323) - Fake Telnet server

### Threat Intelligence
- 🌍 **Geolocation** - Track attacker origins
- 📊 **AbuseIPDB Integration** - IP reputation checks
- 🎯 **Threat Scoring** - 18-factor risk assessment
- 🚨 **Brute Force Detection** - 9 detection rules
- 🎪 **Campaign Detection** - 4 campaign types
- 🔍 **Behavioral Analysis** - 8 behavioral features

### Dashboard Pages
1. **🔴 Live Feed** - Real-time attack monitoring
2. **🌍 Attacker Intel** - Detailed attacker profiles
3. **📈 Analytics** - Visual threat analysis
4. **🚨 Alerts** - Security alert management
5. **🔍 Threat Hunting** - IOC search and correlation
6. **🎪 Campaigns** - Campaign tracking
7. **🤖 AI Analysis** - GPT-4 powered threat reports

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) | **Complete deployment guide** |
| [PRODUCTION_SECURITY_STATUS.md](PRODUCTION_SECURITY_STATUS.md) | **Security implementation details** |
| [HOW_IT_WORKS.md](HOW_IT_WORKS.md) | **System architecture explanation** |
| [PRODUCTION_UPGRADE_PLAN.md](PRODUCTION_UPGRADE_PLAN.md) | **Security requirements and planning** |

---

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Authentication
ENABLE_AUTHENTICATION=true
SESSION_TIMEOUT_HOURS=8

# Database
USE_PRODUCTION_DB=true
DB_POOL_SIZE=5

# Security
ENABLE_AUDIT_LOGGING=true
ENABLE_RATE_LIMITING=true
DASHBOARD_RATE_LIMIT=100

# API Keys (managed by security module)
ABUSEIPDB_API_KEY=managed_by_security
OPENAI_API_KEY=managed_by_security
```

### User Roles

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Admin** | Full access + user management | System administrators |
| **Analyst** | View + export + analysis | Security analysts |
| **Viewer** | View only | Read-only monitoring |

---

## 🔑 Security Management

### Setup Production Security

```bash
# Interactive setup wizard
python setup_production.py
```

This will configure:
- ✅ Environment settings
- ✅ Encrypted API keys
- ✅ Admin user account
- ✅ Database initialization
- ✅ Security verification

### Check Security Status

```bash
# Comprehensive security audit
python check_security.py
```

Checks:
- ✅ Authentication configuration
- ✅ API key encryption
- ✅ Database integrity
- ✅ Audit logging
- ✅ Failed login attempts
- ✅ Suspicious activity

### Manage Users

```python
from auth.auth_manager import auth_manager

# Create user
auth_manager.create_user("user1", "password", "analyst", "user@email.com")

# List users
users = auth_manager.list_users()

# Change password
auth_manager.change_password("user1", "old_pass", "new_pass")

# Deactivate user
auth_manager.update_user("user1", active=False)
```

### Manage API Keys

```python
from security.api_key_manager import api_key_manager

# Add key (encrypted automatically)
api_key_manager.add_key(
    service="abuseipdb",
    api_key="your_key",
    description="AbuseIPDB API",
    rate_limit=1000,
    rate_period="day"
)

# Get key (with rate limiting)
key = api_key_manager.get_key("abuseipdb")

# Rotate key
api_key_manager.rotate_key("abuseipdb", "new_key")

# List keys
keys = api_key_manager.list_keys()
```

---

## 📊 Monitoring

### Real-Time Logs

```bash
# Watch audit log
tail -f logs/audit.log

# Watch for failed logins
tail -f logs/audit.log | grep login_failure

# Watch honeypot activity
tail -f logs/honeypot.log
```

### Query Audit Events

```python
from security.audit_logger import audit_logger

# Failed logins
failed = audit_logger.get_failed_logins(limit=100)

# User activity
activity = audit_logger.get_user_activity("admin")

# Suspicious events
suspicious = audit_logger.get_suspicious_activity()
```

### Database Statistics

```python
from database.db_production import db_production as db

# Get stats
stats = db.get_statistics()
print(f"Queries: {stats['total_queries']}")
print(f"Success rate: {stats['success_rate']:.2f}%")

# Check integrity
if db.check_integrity():
    print("✅ Database OK")

# Create backup
db.backup_database("backups/honeypot_backup.db")
```

---

## 🔧 Maintenance

### Daily

```bash
# Check system health
python check_security.py

# Review audit logs
tail -n 100 logs/audit.log
```

### Weekly

```bash
# Create backup
python -c "from database.db_production import db_production; db_production.backup_database('backups/weekly.db')"

# Check database
python -c "from database.db_production import db_production; print(db_production.check_integrity())"

# Clean expired sessions
python -c "from auth.auth_manager import auth_manager; auth_manager.cleanup_expired_sessions()"
```

### Monthly

```bash
# Optimize database
python -c "from database.db_production import db_production; db_production.vacuum_database()"

# Security audit
python check_security.py > security_audit_$(date +%Y%m%d).txt
```

---

## 🎓 Usage Scenarios

### Scenario 1: Personal Learning

**Setup**: Local machine, localhost only

```bash
# Simple setup
python setup_production.py
# Authentication optional
# ENABLE_AUTHENTICATION=false in .env

# Run services
python main.py
streamlit run dashboard/app.py
```

### Scenario 2: Team Network

**Setup**: Network deployment, multiple users

```bash
# Full security setup
python setup_production.py
# ENABLE_AUTHENTICATION=true
# Create multiple user accounts

# Access control
- Admin: Full access
- Analysts: View + export
- Viewers: View only
```

### Scenario 3: Internet-Facing

**Setup**: Production server, public internet

```bash
# Maximum security
python setup_production.py
# All security features enabled
# HTTPS/SSL required
# Firewall configured
# Regular backups
```

---

## 🚨 Security Best Practices

### ✅ DO

- Use strong passwords (12+ characters)
- Enable authentication in production
- Regular database backups
- Review audit logs frequently
- Rotate API keys periodically
- Keep dependencies updated
- Monitor failed login attempts
- Use HTTPS for internet deployment

### ❌ DON'T

- Never commit `.env` to git
- Never disable authentication in production
- Never share API keys
- Never use default passwords
- Never skip backups
- Never expose without HTTPS
- Never ignore security alerts
- Never run as root (unless required)

---

## 🐛 Troubleshooting

### Can't Login

```bash
# Check if authentication is enabled
python -c "import config; print(config.ENABLE_AUTHENTICATION)"

# Check admin exists
python -c "from auth.auth_manager import auth_manager; print(auth_manager.list_users())"

# Reset password
python setup_production.py
# Select "Change admin password"
```

### API Requests Failing

```bash
# Check API keys
python -c "from security.api_key_manager import api_key_manager; print(api_key_manager.list_keys())"

# Test key
python -c "from utils.api_client import api_client; print(api_client.get_api_key('abuseipdb'))"
```

### Database Issues

```bash
# Check integrity
python -c "from database.db_production import db_production; print(db_production.check_integrity())"

# Restore backup
cp backups/latest.db data/honeypot.db
```

---

## 📁 File Structure

```
honeypot-system/
├── auth/                    # Authentication system
│   ├── auth_manager.py     # User management, RBAC
│   ├── users.json          # User database
│   └── sessions.json       # Active sessions
│
├── security/                # Security components
│   ├── api_key_manager.py  # Encrypted key storage
│   ├── audit_logger.py     # Security event logging
│   ├── .master_key         # Encryption key (BACKUP!)
│   └── api_keys.enc        # Encrypted API keys
│
├── database/                # Database management
│   ├── db_production.py    # Production DB manager
│   └── ...
│
├── dashboard/               # Web dashboard
│   ├── app.py              # Main app
│   ├── login.py            # Login page
│   └── pages/              # Dashboard pages
│
├── honeypot/                # Honeypot services
│   ├── services/           # SSH, FTP, HTTP, Telnet
│   ├── intelligence/       # Threat intelligence
│   ├── detectors/          # Attack detection
│   └── ai/                 # AI analysis
│
├── setup_production.py      # Setup wizard
├── check_security.py        # Security checker
└── main.py                  # Main application
```

---

## 🎯 Key Files to Backup

| File | Purpose | Backup Priority |
|------|---------|-----------------|
| `security/.master_key` | API key encryption | **CRITICAL** |
| `data/honeypot.db` | All honeypot data | **HIGH** |
| `auth/users.json` | User accounts | **HIGH** |
| `.env` | Configuration | **MEDIUM** |
| `logs/audit.json` | Audit trail | **MEDIUM** |

**⚠️ Without `.master_key`, you CANNOT decrypt API keys!**

---

## 📈 System Requirements

### Minimum

- Python 3.8+
- 2 GB RAM
- 1 GB disk space
- Windows/Linux/macOS

### Recommended

- Python 3.9+
- 4 GB RAM
- 5 GB disk space
- Linux (Ubuntu 20.04+)

### Dependencies

```bash
# Core
streamlit, fastapi, uvicorn
requests, aiohttp

# Security
cryptography, bcrypt

# AI
openai, langchain

# Visualization
plotly, pandas

# Logging
rich
```

---

## 🌟 Feature Highlights

### What Makes It Production-Ready?

1. **🔒 Enterprise Security**
   - Password hashing with 100k iterations
   - API key encryption at rest
   - Role-based access control
   - Comprehensive audit logging

2. **⚡ Performance**
   - Database connection pooling
   - WAL mode for concurrency
   - Query caching
   - Optimized queries

3. **🛡️ Protection**
   - SQL injection prevention
   - Rate limiting per service
   - Session timeout
   - Query validation

4. **📊 Observability**
   - Real-time monitoring
   - Audit log queries
   - Database statistics
   - Security status checks

5. **🔧 Maintainability**
   - Setup wizard
   - Security checker
   - Automated backups
   - Clear documentation

---

## 🤝 Support

### Documentation
- **Deployment**: [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)
- **Security**: [PRODUCTION_SECURITY_STATUS.md](PRODUCTION_SECURITY_STATUS.md)
- **Architecture**: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)

### Tools
```bash
python setup_production.py    # Setup wizard
python check_security.py      # Security audit
python main.py                # Start honeypot
streamlit run dashboard/app.py # Start dashboard
```

### Getting Help

1. Check documentation
2. Review logs (`logs/audit.log`, `logs/honeypot.log`)
3. Run security checker
4. Verify configuration

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

Built with:
- [Streamlit](https://streamlit.io) - Dashboard framework
- [Cryptography](https://cryptography.io) - Encryption
- [OpenAI](https://openai.com) - AI analysis
- [AbuseIPDB](https://abuseipdb.com) - Threat intelligence

---

## 🚀 Get Started Now!

```bash
# Clone repository
git clone <your-repo>
cd honeypot-system

# Setup production
pip install -r requirements.txt
python setup_production.py

# Start services
python main.py  # Terminal 1
streamlit run dashboard/app.py  # Terminal 2

# Login and explore!
# http://localhost:8501
```

---

**🔒 Secure. Intelligent. Production-Ready. 🔒**

**Built with ❤️ for Security Professionals**

