# 🚀 Production Deployment Guide

Complete guide for deploying HoneyShield in production with maximum security.

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Security Architecture](#security-architecture)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Authentication Setup](#authentication-setup)
6. [API Key Management](#api-key-management)
7. [Database Management](#database-management)
8. [Monitoring & Auditing](#monitoring--auditing)
9. [Maintenance](#maintenance)
10. [Troubleshooting](#troubleshooting)

---

## 🚦 Quick Start

### Prerequisites
- Python 3.8+
- pip
- Administrative access
- API keys (AbuseIPDB, OpenAI)

### 1-Minute Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run production setup wizard
python setup_production.py

# Start honeypot
python main.py

# Start dashboard (new terminal)
streamlit run dashboard/app.py
```

The setup wizard will guide you through:
- ✅ API key encryption
- ✅ Admin user creation
- ✅ Database configuration
- ✅ Security settings

---

## 🔒 Security Architecture

### Components

```
┌─────────────────────────────────────────────┐
│         Dashboard (Streamlit)               │
│  • Login Page (auth/auth_manager.py)       │
│  • Session Management                       │
│  • Role-Based Access Control                │
└─────────────┬───────────────────────────────┘
              │
              ├─── Authentication Layer
              │    • Password Hashing (PBKDF2)
              │    • Session Tokens
              │    • Permission Checks
              │
              ├─── API Key Manager
              │    • Encrypted Storage (Fernet)
              │    • Rate Limiting
              │    • Usage Tracking
              │
              ├─── Production Database
              │    • Connection Pooling
              │    • Query Validation
              │    • WAL Mode
              │
              └─── Audit Logger
                   • All Security Events
                   • JSON + Text Logs
                   • Query Interface
```

### Security Layers

| Layer | Component | Protection |
|-------|-----------|------------|
| **1. Access Control** | auth_manager.py | Authentication, RBAC, Sessions |
| **2. Data Protection** | api_key_manager.py | Encrypted API keys, Rate limits |
| **3. Database Security** | db_production.py | Query validation, Pooling |
| **4. Audit Trail** | audit_logger.py | All events logged |
| **5. Network** | HTTPS/SSL | Encrypted transport |

---

## 📦 Installation Steps

### Step 1: Clone and Setup

```bash
# Clone repository
git clone <your-repo>
cd honeypot-system

# Create virtual environment (recommended)
python -m venv venv

# Activate
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run Setup Wizard

```bash
python setup_production.py
```

The wizard will:
1. ✅ Check all requirements
2. ✅ Create `.env` configuration
3. ✅ Encrypt and store API keys
4. ✅ Create admin user
5. ✅ Initialize database
6. ✅ Create backups

### Step 3: Verify Installation

```bash
# Check database
python -c "from database.db_production import db_production; print(db_production.check_integrity())"

# Check auth system
python -c "from auth.auth_manager import auth_manager; print(len(auth_manager.users))"

# Check API keys
python -c "from security.api_key_manager import api_key_manager; print(len(api_key_manager.list_keys()))"
```

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

### Security Settings (config.py)

Key security configurations:

```python
# Authentication
ENABLE_AUTHENTICATION = True  # ALWAYS true in production
SESSION_TIMEOUT_HOURS = 8     # Auto-logout after 8 hours

# Database
USE_PRODUCTION_DB = True      # Use production database manager
DB_POOL_SIZE = 5              # Connection pool size

# Rate Limiting
ENABLE_RATE_LIMITING = True
DASHBOARD_RATE_LIMIT = 100    # Requests per minute
```

### Disabling Authentication (NOT RECOMMENDED)

Only for local testing:

```bash
# In .env
ENABLE_AUTHENTICATION=false
```

**⚠️ WARNING**: Never disable authentication in production!

---

## 🔐 Authentication Setup

### User Roles

| Role | Permissions | Use Case |
|------|-------------|----------|
| **admin** | Full access, manage users, modify settings | System administrators |
| **analyst** | View data, export reports, run analysis | Security analysts |
| **viewer** | View dashboards only | Read-only monitoring |

### Creating Users

#### Via Setup Script (Recommended)

```bash
python setup_production.py
# Follow prompts to create admin user
```

#### Programmatically

```python
from auth.auth_manager import auth_manager

# Create admin
auth_manager.create_user(
    username="admin",
    password="secure_password_here",
    role="admin",
    email="admin@company.com"
)

# Create analyst
auth_manager.create_user(
    username="analyst1",
    password="analyst_password",
    role="analyst",
    email="analyst@company.com"
)

# Create viewer
auth_manager.create_user(
    username="viewer1",
    password="viewer_password",
    role="viewer",
    email="viewer@company.com"
)
```

### Default Credentials

On first run, a default admin is created:

```
Username: admin
Password: <random - check auth/default_credentials.txt>
```

**⚠️ CHANGE IMMEDIATELY AFTER FIRST LOGIN!**

### Password Management

```python
from auth.auth_manager import auth_manager

# Change password
auth_manager.change_password(
    username="admin",
    old_password="old_pass",
    new_password="new_secure_pass"
)

# Deactivate user
auth_manager.update_user("analyst1", active=False)

# Delete user
auth_manager.delete_user("viewer1")
```

### Session Management

Sessions automatically expire after `SESSION_TIMEOUT_HOURS` (default: 8 hours).

```python
# Manual cleanup of expired sessions
auth_manager.cleanup_expired_sessions()

# View active sessions
sessions = auth_manager.get_active_sessions()
```

---

## 🔑 API Key Management

### Adding API Keys

#### Via Setup Script (Recommended)

```bash
python setup_production.py
# Follow prompts for API key configuration
```

#### Programmatically

```python
from security.api_key_manager import api_key_manager

# Add AbuseIPDB key
api_key_manager.add_key(
    service="abuseipdb",
    api_key="your_key_here",
    description="AbuseIPDB Threat Intel",
    rate_limit=1000,
    rate_period="day"
)

# Add OpenAI key
api_key_manager.add_key(
    service="openai",
    api_key="sk-your_key_here",
    description="OpenAI GPT-4",
    rate_limit=10000,
    rate_period="day"
)
```

### Using API Keys

API keys are automatically retrieved and rate-limited:

```python
from utils.api_client import api_client

# Make AbuseIPDB request
result = api_client.abuseipdb_check("1.2.3.4")

# Make OpenAI request
result = api_client.openai_completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Analyze this attack"}]
)
```

### Key Rotation

```python
from security.api_key_manager import api_key_manager

# Rotate key
api_key_manager.rotate_key("abuseipdb", "new_key_here")

# Deactivate key (without deleting)
api_key_manager.deactivate_key("openai")

# Reactivate
api_key_manager.activate_key("openai")
```

### Importing from .env

Migrate existing keys from .env:

```python
from security.api_key_manager import api_key_manager

# Import all keys from environment
imported = api_key_manager.import_from_env()
print(f"Imported {imported} keys")
```

### Key Storage

Keys are encrypted using Fernet (symmetric encryption):

```
security/
├── .master_key           # Master encryption key (BACKUP THIS!)
└── api_keys.enc         # Encrypted API keys
```

**⚠️ CRITICAL**: Backup `.master_key` securely! Loss = unable to decrypt keys.

---

## 💾 Database Management

### Production Database Features

- ✅ Connection pooling (5 connections)
- ✅ WAL mode (better concurrency)
- ✅ Query validation (SQL injection prevention)
- ✅ Transaction support
- ✅ Automatic backups
- ✅ Integrity checks

### Using Production Database

```python
from database.db_production import db_production as db

# Execute SELECT query
results = db.execute_query(
    "SELECT * FROM attackers WHERE verdict = ?",
    ("CRITICAL",)
)

# Execute INSERT/UPDATE/DELETE
row_id = db.execute_update(
    "INSERT INTO attackers (ip_address, first_seen) VALUES (?, ?)",
    ("1.2.3.4", "2024-01-01 00:00:00")
)

# Batch operations
db.execute_many(
    "INSERT INTO login_attempts (attacker_id, username) VALUES (?, ?)",
    [(1, "admin"), (1, "root"), (1, "test")]
)

# Transactions
success = db.execute_transaction([
    ("UPDATE attackers SET threat_score = ? WHERE id = ?", (95, 1)),
    ("INSERT INTO alerts (attacker_id, severity) VALUES (?, ?)", (1, "HIGH"))
])
```

### Backups

```python
from database.db_production import db_production as db
from datetime import datetime

# Create backup
backup_path = f"data/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
db.backup_database(backup_path)

# Restore backup (manually)
# 1. Stop honeypot and dashboard
# 2. Replace data/honeypot.db with backup
# 3. Restart services
```

### Automated Backups

Add to cron (Linux) or Task Scheduler (Windows):

```bash
# Daily backup at 2 AM
0 2 * * * python -c "from database.db_production import db_production; db_production.backup_database('backups/daily.db')"
```

### Database Maintenance

```python
from database.db_production import db_production as db

# Check integrity
if db.check_integrity():
    print("✅ Database OK")
else:
    print("❌ Database corrupted!")

# Optimize (reclaim space)
db.vacuum_database()

# Get statistics
stats = db.get_statistics()
print(f"Total queries: {stats['total_queries']}")
print(f"Error rate: {stats['errors'] / stats['total_queries'] * 100:.2f}%")
```

---

## 📊 Monitoring & Auditing

### Audit Logging

All security events are logged to:
- `logs/audit.log` (human-readable)
- `logs/audit.json` (machine-readable)

### Logged Events

| Event Type | Description |
|------------|-------------|
| `login_success` | Successful authentication |
| `login_failure` | Failed login attempt |
| `logout` | User logout |
| `permission_denied` | Access denied |
| `data_exported` | Data export operation |
| `api_key_used` | API key accessed |
| `config_changed` | Configuration modified |
| `suspicious_activity` | Anomaly detected |

### Querying Audit Logs

```python
from security.audit_logger import audit_logger

# Get failed logins
failed = audit_logger.get_failed_logins(limit=50)

# Get user activity
activity = audit_logger.get_user_activity("admin", limit=100)

# Get suspicious activity
suspicious = audit_logger.get_suspicious_activity()

# Custom query
events = audit_logger.query_events(
    event_type="login_failure",
    start_time="2024-01-01T00:00:00",
    limit=100
)
```

### Manual Logging

```python
from security.audit_logger import audit_logger

# Log custom event
audit_logger.log_event(
    event_type="config_changed",
    username="admin",
    ip_address="192.168.1.100",
    details={"setting": "rate_limit", "old": 100, "new": 200},
    severity="INFO"
)

# Convenience methods
audit_logger.log_login_success("user1", "192.168.1.5")
audit_logger.log_permission_denied("user2", "api_keys", "view")
audit_logger.log_suspicious_activity("attacker", "1.2.3.4", "Too many requests")
```

### Real-time Monitoring

```bash
# Watch audit log in real-time
tail -f logs/audit.log

# Watch for failed logins
tail -f logs/audit.log | grep login_failure

# Watch for critical events
tail -f logs/audit.log | grep CRITICAL
```

### Metrics and Stats

```python
from security.api_key_manager import api_key_manager
from database.db_production import db_production as db

# API usage stats
usage = api_key_manager.get_usage_stats()

# Database stats
db_stats = db.get_statistics()

# Key information
keys = api_key_manager.list_keys()
for key in keys:
    print(f"{key['service']}: {key['usage_count']} uses")
```

---

## 🔧 Maintenance

### Daily Tasks

```bash
# 1. Check system status
python -c "from database.db_production import db_production; print(db_production.get_statistics())"

# 2. Review audit logs
tail -n 100 logs/audit.log

# 3. Check for failed logins
python -c "from security.audit_logger import audit_logger; print(len(audit_logger.get_failed_logins()))"
```

### Weekly Tasks

```bash
# 1. Create backup
python -c "from database.db_production import db_production; db_production.backup_database('backups/weekly.db')"

# 2. Check database integrity
python -c "from database.db_production import db_production; print(db_production.check_integrity())"

# 3. Review user accounts
python -c "from auth.auth_manager import auth_manager; print(auth_manager.list_users())"

# 4. Cleanup expired sessions
python -c "from auth.auth_manager import auth_manager; auth_manager.cleanup_expired_sessions()"
```

### Monthly Tasks

```bash
# 1. Rotate API keys (if required by policy)
# Done manually through setup_production.py

# 2. Optimize database
python -c "from database.db_production import db_production; db_production.vacuum_database()"

# 3. Archive old audit logs
# Move logs/audit.json to archive/

# 4. Security audit
# Review all admin actions
# Check for anomalies
```

### Updating Dependencies

```bash
# Check for updates
pip list --outdated

# Update specific package
pip install --upgrade streamlit

# Update all (test in dev first!)
pip install --upgrade -r requirements.txt
```

---

## 🐛 Troubleshooting

### Authentication Issues

**Problem**: Can't login to dashboard

```bash
# Check if authentication is enabled
python -c "import config; print(config.ENABLE_AUTHENTICATION)"

# Check if admin user exists
python -c "from auth.auth_manager import auth_manager; print(auth_manager.list_users())"

# Reset admin password
python setup_production.py
# Select "Change admin password"
```

**Problem**: Session expired too quickly

```bash
# Check session timeout
python -c "import config; print(config.SESSION_TIMEOUT_HOURS)"

# Increase timeout in .env
# SESSION_TIMEOUT_HOURS=24
```

### API Key Issues

**Problem**: API requests failing

```bash
# Check if keys are configured
python -c "from security.api_key_manager import api_key_manager; print(api_key_manager.list_keys())"

# Test specific key
python -c "from utils.api_client import api_client; print(api_client.get_api_key('abuseipdb'))"

# Check rate limits
python -c "from security.api_key_manager import api_key_manager; print(api_key_manager.get_usage_stats())"
```

**Problem**: Master key lost

If `security/.master_key` is lost, API keys cannot be recovered:

```bash
# Delete encrypted keys
rm security/api_keys.enc
rm security/.master_key

# Re-run setup
python setup_production.py
# Add keys again
```

### Database Issues

**Problem**: Database locked

```bash
# Check for stale connections
lsof data/honeypot.db  # Linux
handle data/honeypot.db  # Windows

# Restart services
# Stop honeypot and dashboard, then restart
```

**Problem**: Database corrupted

```bash
# Check integrity
python -c "from database.db_production import db_production; print(db_production.check_integrity())"

# Restore from backup
cp backups/latest.db data/honeypot.db

# If no backup, try SQLite recovery
sqlite3 data/honeypot.db ".dump" | sqlite3 data/honeypot_recovered.db
```

### Performance Issues

**Problem**: Dashboard slow

```bash
# Increase database pool size in .env
DB_POOL_SIZE=10

# Optimize database
python -c "from database.db_production import db_production; db_production.vacuum_database()"

# Check query count
python -c "from database.db_production import db_production; print(db_production.query_count)"
```

---

## 🔒 Security Best Practices

### DO

✅ Always use authentication in production
✅ Use HTTPS (see below for setup)
✅ Backup `.master_key` securely
✅ Regular database backups
✅ Review audit logs frequently
✅ Use strong passwords (12+ characters)
✅ Rotate API keys periodically
✅ Keep dependencies updated
✅ Monitor for suspicious activity
✅ Limit dashboard access by IP

### DON'T

❌ Never commit `.env` to git
❌ Never expose dashboard to internet without HTTPS
❌ Never share API keys
❌ Never use default passwords
❌ Never disable audit logging in production
❌ Never run as root (unless necessary)
❌ Never store passwords in plain text
❌ Never skip backups

---

## 🌐 HTTPS Setup (Coming Soon)

For production deployment, enable HTTPS:

### Option 1: Self-Signed Certificate (Development)

```bash
# Generate certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run dashboard with SSL
streamlit run dashboard/app.py --server.sslCertFile cert.pem --server.sslKeyFile key.pem
```

### Option 2: Let's Encrypt (Production)

```bash
# Install certbot
# Linux: sudo apt install certbot
# Windows: Use WSL or download from certbot.eff.org

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in /etc/letsencrypt/live/yourdomain.com/
```

### Option 3: Reverse Proxy (Recommended)

Use Nginx or Apache as reverse proxy with SSL:

```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 📚 Additional Resources

- [HOW_IT_WORKS.md](HOW_IT_WORKS.md) - System architecture
- [PRODUCTION_UPGRADE_PLAN.md](PRODUCTION_UPGRADE_PLAN.md) - Security requirements
- [PROJECT_COMPLETE.md](PROJECT_COMPLETE.md) - Full documentation

---

## 🆘 Support

If you encounter issues:

1. Check logs: `logs/audit.log`, `logs/honeypot.log`
2. Review this guide
3. Check database integrity
4. Verify API key configuration
5. Test authentication system

For development issues, check the code documentation in each module.

---

**Built with ❤️ for Security Professionals**

🔒 Stay Secure! 🔒
