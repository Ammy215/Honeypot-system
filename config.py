import os
from dotenv import load_dotenv
load_dotenv()

# ── Honeypot Services ──────────────────────────────────
HONEYPOT_HOST = "0.0.0.0"

SERVICES = {
    "SSH":    {"port": 2222,  "enabled": True},   # Use 2222 not 22 (avoid root requirement)
    "FTP":    {"port": 2121,  "enabled": True},   # Use 2121 not 21
    "HTTP":   {"port": 8080,  "enabled": True},
    "Telnet": {"port": 2323,  "enabled": True},   # Use 2323 not 23
    "SMTP":   {"port": 2525,  "enabled": False},  # Enable in phase 2
    "RDP":    {"port": 3389,  "enabled": False},  # Enable in phase 2
}

# ── Database (v1, legacy dashboard/auth — unchanged) ─────
DATABASE_PATH = "data/honeypot.db"

# ── Database (v2 async core, HONEYSHIELD_PROJECT.md §5) ──
# Postgres in prod when set; falls back to local SQLite for dev when empty.
DATABASE_URL = os.getenv("DATABASE_URL", "")
SQLITE_PATH = os.getenv("SQLITE_PATH", "./data/honeyshield_dev.db")

# ── Logging ─────────────────────────────────────────────
LOG_DIR = "logs/"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

# ── Threat Intelligence APIs ─────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")  # re-introduced in v2 phase 3 — actually used this time
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# ── Geolocation ──────────────────────────────────────────
GEOIP_API_URL = "http://ip-api.com/json"   # Free, no key needed
GEOIP_RATE_LIMIT = 45                       # Requests per minute

# ── Enrichment cache TTLs (v2 phase 3) ────────────────────
# Bounds re-checks to what each API's rate limit can sustain; values match
# the caching strategy already used elsewhere (Project 4 in CLAUDE_CONTEXT.md).
GEO_CACHE_TTL_SECONDS = 24 * 60 * 60        # 24h — geolocation rarely changes
ABUSEIPDB_CACHE_TTL_SECONDS = 60 * 60       # 1h  — free tier easily sustains hourly re-checks
OTX_CACHE_TTL_SECONDS = 6 * 60 * 60         # 6h  — pulse data updates slowly

# ── Detection Thresholds ──────────────────────────────────
BRUTE_FORCE_THRESHOLD = 10         # Login attempts per 5 minutes
RAPID_FIRE_THRESHOLD = 3           # Attempts per second
MULTI_SERVICE_THRESHOLD = 2        # Services before flagging
CREDENTIAL_STUFFING_THRESHOLD = 5  # Unique usernames per 10 minutes

# ── Dashboard ────────────────────────────────────────────
DASHBOARD_REFRESH_SECONDS = 15
DASHBOARD_PORT = 8501

# ── Connection Limits ────────────────────────────────────
MAX_CONNECTIONS_PER_IP = 100      # Block after this many
MAX_TOTAL_CONNECTIONS = 500       # Global ceiling (async core, spec §6.5)
CONNECTION_TIMEOUT_SECONDS = 30
MAX_LOGIN_ATTEMPTS_PER_SESSION = 10

# ── Security ─────────────────────────────────────────────
ENABLE_AUTHENTICATION = os.getenv("ENABLE_AUTHENTICATION", "true").lower() == "true"
SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "8"))
ENABLE_AUDIT_LOGGING = os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true"
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"
DASHBOARD_RATE_LIMIT = int(os.getenv("DASHBOARD_RATE_LIMIT", "100"))  # Requests per minute

# ── Production Database ──────────────────────────────────
USE_PRODUCTION_DB = os.getenv("USE_PRODUCTION_DB", "true").lower() == "true"
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))

# ── IOC ──────────────────────────────────────────────────
IOC_FILE_PATH = "ioc/known_bad_ips.txt"
IOC_CHECK_ENABLED = True

# ── Fake Service Banners ──────────────────────────────────
BANNERS = {
    "SSH":    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "FTP":    "220 ProFTPD 1.3.5e Server (ProFTPD Default Installation) [127.0.0.1]",
    "SMTP":   "220 mail.example.com ESMTP Postfix (Ubuntu)",
    "Telnet": "\r\nUbuntu 20.04.6 LTS\r\nlocalhost login: ",
}
