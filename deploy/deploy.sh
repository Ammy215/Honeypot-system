#!/usr/bin/env bash
#
# HoneyShield v2 — VPS provisioning script (HONEYSHIELD_PROJECT.md section 8).
#
# Run this ON the target server (Oracle Cloud "Always Free" instance, per the
# deployment plan), as root, from an already-checked-out copy of this repo at
# the install directory (default /opt/honeyshield). It does NOT clone or copy
# the repo itself — see docs/DEPLOYMENT.md for that step.
#
# What it does:
#   1. Creates a non-root system user to run the services as.
#   2. Sets up a Python venv and installs requirements.txt.
#   3. Installs and starts the two systemd services (deploy/*.service).
#   4. Configures ufw: allow the admin SSH port + the 4 honeypot ports only,
#      default-deny everything else. The dashboard port (8501) is
#      deliberately never opened — it's reachable only via Cloudflare Tunnel
#      or an SSH tunnel, never a public port (section 6.2).
#
# Safety: a wrong ADMIN_SSH_PORT here can lock you out of the server over
# SSH. There is no default for it — the script refuses to run without it,
# and pauses for interactive confirmation immediately before enabling ufw.
#
# Usage:
#   cd /opt/honeyshield
#   sudo ADMIN_SSH_PORT=2200 ./deploy/deploy.sh

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/honeyshield}"
HONEYSHIELD_USER="${HONEYSHIELD_USER:-honeyshield}"
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-}"
HONEYPOT_PORTS=(2222 2121 8080 2323)   # must match config.py SERVICES (enabled: True) exactly

# ── Preflight checks ───────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run this as root (sudo)." >&2
    exit 1
fi

if [[ -z "${ADMIN_SSH_PORT}" ]]; then
    echo "ERROR: ADMIN_SSH_PORT is not set." >&2
    echo "This must be your real, non-default sshd port (section 6.1) —" >&2
    echo "there is no safe default, since guessing wrong can lock you out." >&2
    echo "Usage: sudo ADMIN_SSH_PORT=2200 ./deploy/deploy.sh" >&2
    exit 1
fi

if [[ "$(pwd)" != "${INSTALL_DIR}" ]]; then
    echo "ERROR: run this script from ${INSTALL_DIR} (the repo checkout), not $(pwd)." >&2
    echo "Set INSTALL_DIR=... if you deliberately placed the repo elsewhere." >&2
    exit 1
fi

if [[ ! -f "main.py" || ! -f "dashboard/app.py" ]]; then
    echo "ERROR: main.py / dashboard/app.py not found in $(pwd) — is this really the repo checkout?" >&2
    exit 1
fi

if [[ ! -f ".env" ]]; then
    echo "ERROR: .env not found in $(pwd)." >&2
    echo "Copy it to the server first (see docs/DEPLOYMENT.md) — never commit it." >&2
    exit 1
fi

echo "== HoneyShield deploy =="
echo "  Install dir:     ${INSTALL_DIR}"
echo "  Service user:    ${HONEYSHIELD_USER}"
echo "  Admin SSH port:  ${ADMIN_SSH_PORT}"
echo "  Honeypot ports:  ${HONEYPOT_PORTS[*]}"
echo

# ── 1. System user ─────────────────────────────────────────────────────
if ! id -u "${HONEYSHIELD_USER}" &>/dev/null; then
    echo "-- Creating system user ${HONEYSHIELD_USER}"
    useradd --system --create-home --shell /usr/sbin/nologin "${HONEYSHIELD_USER}"
else
    echo "-- User ${HONEYSHIELD_USER} already exists, skipping"
fi

mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

# ── 2. Python venv + dependencies ──────────────────────────────────────
if [[ ! -d "${INSTALL_DIR}/.venv" ]]; then
    echo "-- Creating venv"
    python3 -m venv "${INSTALL_DIR}/.venv"
fi

echo "-- Installing dependencies"
"${INSTALL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"

echo "-- Fixing ownership"
chown -R "${HONEYSHIELD_USER}:${HONEYSHIELD_USER}" "${INSTALL_DIR}"

# ── 3. systemd services ────────────────────────────────────────────────
echo "-- Installing systemd units"
cp "${INSTALL_DIR}/deploy/honeyshield.service" /etc/systemd/system/honeyshield.service
cp "${INSTALL_DIR}/deploy/honeyshield-dashboard.service" /etc/systemd/system/honeyshield-dashboard.service
systemctl daemon-reload
systemctl enable honeyshield.service honeyshield-dashboard.service
systemctl restart honeyshield.service honeyshield-dashboard.service

# ── 4. Firewall ─────────────────────────────────────────────────────────
if ! command -v ufw &>/dev/null; then
    echo "ERROR: ufw is not installed. On Ubuntu: apt-get install -y ufw" >&2
    exit 1
fi

echo
echo "== About to configure ufw =="
echo "This will allow ONLY: SSH admin port ${ADMIN_SSH_PORT}, and honeypot ports ${HONEYPOT_PORTS[*]}."
echo "Everything else — including the dashboard port 8501 — will be denied by default."
echo "If ${ADMIN_SSH_PORT} is NOT the port you are connected on right now, you will be locked out."
read -r -p "Type 'yes' to continue: " confirm
if [[ "${confirm}" != "yes" ]]; then
    echo "Aborted before touching ufw. Nothing else was changed." >&2
    exit 1
fi

echo "-- Allowing admin SSH port ${ADMIN_SSH_PORT} first"
ufw allow "${ADMIN_SSH_PORT}/tcp" comment "admin SSH"

for port in "${HONEYPOT_PORTS[@]}"; do
    echo "-- Allowing honeypot port ${port}"
    ufw allow "${port}/tcp" comment "honeypot"
done

ufw default deny incoming
ufw default allow outgoing
ufw --force enable

# ── 5. Summary ──────────────────────────────────────────────────────────
echo
echo "== Service status =="
systemctl --no-pager status honeyshield.service honeyshield-dashboard.service || true

echo
echo "== ufw status =="
ufw status verbose

echo
echo "== Done =="
echo "Next steps (see docs/DEPLOYMENT.md):"
echo "  1. From another machine, confirm 8501 is unreachable at this server's public IP."
echo "  2. Also confirm the Oracle Cloud Security List/NSG allows the same ports —"
echo "     ufw alone is not enough, Oracle filters at the cloud network layer too."
echo "  3. Set up Cloudflare Tunnel + Access (deploy/cloudflare-tunnel.md) or an SSH"
echo "     tunnel to reach the dashboard."
echo "  4. Start the 24-48h live validation window."
