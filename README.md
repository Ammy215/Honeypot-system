# 🍯 HoneyShield Intelligence Platform

Advanced honeypot trap system and threat intelligence platform built for learning cybersecurity fundamentals.

## Overview

HoneyShield is a complete honeypot platform that attracts, captures, analyzes, and visualizes attacker behavior. Built entirely from scratch using raw Python sockets, SQLite, and modern data visualization tools.

## Technology Stack

- **Core Language**: Python 3.8+
- **Networking**: Raw Python socket programming (TCP)
- **Database**: SQLite with raw SQL (no ORM)
- **Dashboard**: Streamlit + Plotly
- **Data Analysis**: Pandas
- **Threat Intelligence**: AbuseIPDB, AlienVault OTX, ip-api.com
- **AI Analysis**: OpenAI GPT-4 + LangChain

## Features

### Phase 1 - Foundation ✅
- [x] Raw TCP socket-based honeypot services
- [x] SSH honeypot (port 2222)
- [x] SQLite database with full schema
- [x] Connection logging and tracking
- [x] Multithreaded connection handling
- [x] Structured logging to console and file

### Phase 2 - Login Trap & Detection ✅
- [x] FTP honeypot (port 2121)
- [x] Telnet honeypot (port 2323)
- [x] HTTP honeypot (port 8080)
- [x] Credential capture system
- [x] Brute force detection (9 detection rules)
- [x] Alert generation engine with Rich formatting
- [x] Real-time threat detection
- [x] Multi-service attack correlation

### Phase 3 - Threat Intelligence ✅
- [x] IP geolocation enrichment (ip-api.com)
- [x] AbuseIPDB reputation checks
- [x] Weighted threat scoring (0-100, 18 factors)
- [x] IOC detection and management
- [x] Automatic enrichment pipeline
- [x] Threat verdict classification (4 levels)
- [x] Background enrichment processing

### Phase 4 - Dashboard ✅
- [x] Streamlit multi-page application (5 pages)
- [x] Real-time attack feed with auto-refresh
- [x] Interactive world map with attack origins
- [x] Attacker intelligence profiles with IP search
- [x] Analytics with 7 Plotly chart types
- [x] Alert management interface
- [x] CSV data export
- [x] Advanced filters and sorting

### Phase 5 - Correlation Engine ✅
- [x] Attack campaign detection (4 types)
- [x] Behavioral correlation engine
- [x] Attack chain detection
- [x] Similar attacker identification
- [x] Threat hunting interface
- [x] IOC search capabilities
- [x] Campaign visualization dashboard

### Phase 6 - AI Analyst ✅
- [x] OpenAI GPT-4 integration
- [x] AI-powered attacker analysis
- [x] Automated threat reports
- [x] Natural language alert summaries
- [x] Executive summary generation
- [x] Report export (text files)
- [x] AI Analysis dashboard page

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd honeypot-trap-system

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env and add your API keys

# Initialize database
python -c "from database.db import init_db; init_db()"
```

## Usage

### Start the Honeypot

```bash
python main.py
```

The honeypot will start listening on configured ports:
- SSH: port 2222
- FTP: port 2121
- HTTP: port 8080
- Telnet: port 2323

### Test Connection

```bash
# Test SSH honeypot
nc localhost 2222

# Test FTP honeypot
nc localhost 2121
USER admin
PASS admin

# Test HTTP honeypot (browser or curl)
curl http://localhost:8080/admin

# Test Telnet honeypot
nc localhost 2323
```

### View Database

```bash
# Check connections
sqlite3 data/honeypot.db "SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10;"

# Check attackers
sqlite3 data/honeypot.db "SELECT * FROM attackers;"
```

### Start Dashboard

```bash
# Start the interactive web dashboard
python -m streamlit run dashboard/app.py

# or if streamlit is in PATH
streamlit run dashboard/app.py
```

Visit `http://localhost:8501` to view the dashboard.

**Dashboard Features:**
- 🔴 Live Feed - Real-time attack monitoring
- 🌍 Attacker Intel - IP profiles and world map
- 📈 Analytics - Charts and trend analysis
- 🚨 Alerts - Security alert management

## Project Structure

```
honeypot-trap-system/
├── honeypot/              # Core honeypot services
│   ├── core/              # Base classes and server manager
│   ├── services/          # Individual honeypot services
│   ├── detectors/         # Threat detection engines
│   ├── intelligence/      # Threat intel integrations
│   ├── alerting/          # Alert generation and rules
│   └── ai/                # AI-powered analysis
├── database/              # Database layer
│   ├── schema.sql         # Full database schema
│   ├── db.py              # Connection and query manager
│   └── queries/           # Organized query modules
├── dashboard/             # Streamlit dashboard
│   ├── app.py             # Main entry point
│   ├── pages/             # Dashboard pages
│   └── components/        # Reusable UI components
├── logs/                  # Application logs
├── data/                  # SQLite database file
├── ioc/                   # IOC lists
├── config.py              # Configuration constants
├── main.py                # Application entry point
└── requirements.txt       # Python dependencies
```

## Database Schema

- **attackers**: Core attacker identity and profile
- **connections**: Every TCP connection attempt
- **login_attempts**: All credential attempts
- **attacker_commands**: Commands sent by attackers
- **alerts**: Generated security alerts
- **ai_reports**: AI-generated threat reports
- **service_stats**: Service activity tracking
- **ioc_matches**: Known IOC matches

## Configuration

Edit `config.py` to customize:
- Service ports and enabled status
- Detection thresholds
- API endpoints
- Connection limits
- Logging levels

## API Keys

Required for full functionality:
- **AbuseIPDB**: Get free key at https://www.abuseipdb.com/
- **AlienVault OTX**: Get free key at https://otx.alienvault.com/
- **OpenAI**: Required for AI analyst features

Add keys to `.env` file.

## Security Notes

⚠️ **Important**: This is a honeypot system designed to attract attacks.

- Run in isolated network environment
- Do not expose to production networks
- Use non-standard ports (2222, 2121, etc.) to avoid requiring root
- Monitor resource usage
- Review captured data regularly

## Learning Objectives

This project teaches:
1. Raw TCP socket programming in Python
2. Multithreaded network service design
3. SQLite database design and raw SQL
4. Security threat detection algorithms
5. API integration for threat intelligence
6. Data visualization with Plotly
7. Real-time dashboards with Streamlit
8. AI integration for security analysis

## Development Phases

Each phase builds incrementally:
1. **Foundation**: Sockets + Database + Logging
2. **Login Trap**: Multiple services + Detection
3. **Intelligence**: API integration + Scoring
4. **Dashboard**: Visualization + Real-time UI
5. **Correlation**: Advanced detection + Hunting
6. **AI Analyst**: OpenAI + Automated reports

## License

MIT License - See LICENSE file for details

## Contributing

This is a learning project. Contributions welcome!

## Disclaimer

This software is for educational purposes only. Use responsibly and ethically. The authors are not responsible for misuse or damage caused by this software.
