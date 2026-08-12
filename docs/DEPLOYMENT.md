# Deployment Checklist — HoneyShield v2

This replaces the old v1 deployment guide (generic `setup_production.py`
wizard, no specific host) with the actual zero-cost deployment plan from
HONEYSHIELD_PROJECT.md section 8: Oracle Cloud "Always Free" + systemd +
Supabase Postgres + Cloudflare Tunnel, $0/month ongoing.

**Nothing in this checklist has been run against a live server.** No VPS
credentials have been provided to this project yet. Everything below is
scaffolding — unit files, a provisioning script, and this checklist — ready
to execute once a server exists. Steps that specifically require real
server access are marked **[NEEDS SERVER ACCESS]**.

---

## 0. Prerequisites (do these first, no server needed)

- [ ] An Oracle Cloud account (email + card for identity verification only —
      the Always Free tier itself never charges).
- [ ] A Supabase account + a new project (free tier) for the production
      Postgres database.
- [ ] Your real API keys ready to paste into `.env` on the server:
      `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GEMINI_API_KEY`. **Do not reuse
      the AbuseIPDB key currently in local dev `.env` without rotating it
      first** — it sat unprotected on disk before this project's hardening
      pass (see the Phase 1 cleanup notes).
- [ ] (Optional, for Cloudflare Tunnel + Access) A domain added to
      Cloudflare, free plan.

## 1. Create the Oracle Cloud "Always Free" instance **[NEEDS SERVER ACCESS]**

- [ ] Console → Compute → Instances → Create instance.
- [ ] Image: Ubuntu 22.04 or 24.04 LTS.
- [ ] Shape: either the x86 **VM.Standard.E2.1.Micro** (1 GB RAM — what the
      systemd unit files' `MemoryMax` values in `deploy/` are sized for) or
      an ARM **Ampere A1** shape (up to 24 GB RAM free, if available in your
      region — raise `MemoryMax` in the `.service` files if you use this).
- [ ] Generate/attach an SSH key pair — save the private key, you'll need it
      for every subsequent step.
- [ ] Note the instance's public IP.
- [ ] **Configure the VCN Security List / Network Security Group** to allow
      inbound TCP on your chosen admin SSH port, plus 2222, 2121, 8080, 2323.
      **This is a separate firewall from `ufw`, at the cloud network layer —
      forgetting it is the single most common reason a honeypot never
      receives any traffic despite `ufw`/systemd being perfectly correct.**
- [ ] Pick your admin SSH port now (anything other than 22, per section
      6.1) — you'll pass it to `deploy.sh` as `ADMIN_SSH_PORT`.

## 2. Set up the Supabase Postgres database **[NEEDS SERVER ACCESS: no —
   this step is done from Supabase's own console, not the VPS]**

- [ ] In the Supabase project's SQL editor, run the contents of
      `database/schema_postgres.sql` from this repo to create all tables.
- [ ] Copy the connection string (Project Settings → Database → Connection
      string → URI) — this becomes `DATABASE_URL` in `.env`.

## 3. Copy the repo and `.env` to the server **[NEEDS SERVER ACCESS]**

```bash
ssh -p <ADMIN_SSH_PORT> ubuntu@<vps-ip>
sudo mkdir -p /opt/honeyshield && sudo chown ubuntu:ubuntu /opt/honeyshield
git clone https://github.com/Ammy215/Honeypot-system.git /opt/honeyshield
cd /opt/honeyshield
```

Then copy `.env` over separately — **never through git** (it's gitignored
and holds real secrets). From your own machine:

```bash
scp -P <ADMIN_SSH_PORT> .env ubuntu@<vps-ip>:/opt/honeyshield/.env
```

Edit the server's `.env` to set `DATABASE_URL` (from step 2) so the app
uses Postgres instead of the local SQLite dev fallback.

- [ ] `.env` copied and `DATABASE_URL` set.
- [ ] Confirm `.env` permissions are restrictive: `chmod 600 /opt/honeyshield/.env`.

## 4. Run `deploy.sh` **[NEEDS SERVER ACCESS]**

```bash
cd /opt/honeyshield
sudo ADMIN_SSH_PORT=<your admin port> ./deploy/deploy.sh
```

This creates the `honeyshield` system user, sets up the venv, installs and
starts both systemd services, and configures `ufw`. It will pause and ask
for interactive `yes` confirmation immediately before touching `ufw` —
read that prompt carefully, since a wrong `ADMIN_SSH_PORT` can lock you out.

- [ ] Script completed without errors.
- [ ] `systemctl status honeyshield.service honeyshield-dashboard.service`
      both show `active (running)`.

## 5. Verify the firewall **[NEEDS SERVER ACCESS]**

```bash
sudo ufw status verbose
```

- [ ] Exactly these ports are allowed: your admin SSH port, 2222, 2121,
      8080, 2323.
- [ ] Port 8501 (dashboard) does **not** appear in the allow list at all.
- [ ] Default policy is `deny (incoming)`, `allow (outgoing)`.

## 6. Verify the dashboard is unreachable except through the tunnel **[NEEDS SERVER ACCESS]**

From a **different machine** (not the VPS itself):

```bash
curl -m 5 http://<vps-public-ip>:8501
# expect: connection timed out / refused — NOT a Streamlit response
```

- [ ] Confirmed timeout/refusal from outside.
- [ ] From the VPS itself, `curl -I http://127.0.0.1:8501` still returns
      `HTTP/1.1 200 OK` — confirms the dashboard is actually running, just
      not reachable externally.

## 7. Set up dashboard access

Follow `deploy/cloudflare-tunnel.md` in full (Cloudflare Tunnel + Access),
or use the simpler SSH-tunnel alternative documented at the bottom of that
same file if you don't want to set up a domain.

- [ ] Dashboard reachable via the chosen method.
- [ ] If using Cloudflare Access: confirmed the Access login page appears
      *before* HoneyShield's own login — two independent walls.

## 8. Live validation window (24–48h) **[NEEDS SERVER ACCESS to observe, but
   requires no action beyond waiting]**

Per HONEYSHIELD_PROJECT.md's testing strategy: this is the one thing that
can't be shortcut or simulated locally — it's the actual proof the project
works against real internet traffic, not synthetic test connections.

- [ ] Leave both services running for 24–48 hours untouched.
- [ ] Periodically check for real scanner activity:
      ```bash
      sqlite3 data/honeyshield_dev.db "SELECT COUNT(*) FROM connections;"   # if still on SQLite
      # or query Supabase directly if DATABASE_URL is set
      ```
      or just open the Live Feed / Attacker Intel dashboard pages.
- [ ] Confirm the full pipeline works end to end on **real, non-test IPs**:
      connections captured → geolocation/AbuseIPDB/OTX enrichment populates
      → threat score/verdict calculates → alerts fire for any real
      brute-force/multi-service/credential-stuffing behavior you observe.
- [ ] Note how long it took for the first unsolicited connection to arrive
      (typically minutes to hours per the project's own expectations) —
      this is useful data for the eventual write-up.

## 9. Known gaps, deliberately out of scope for this phase

- **Backups** (section 8.5: nightly Postgres → Cloudflare R2 cron) — not
  built yet. Needs your own R2 bucket + credentials; flagged here rather
  than silently skipped.
- **Multi-analyst RBAC** (section 8.6) — explicitly deferred in the spec
  itself ("that's a v2 problem, not now" — well, this *is* v2, but the spec
  still treats it as a future add-on, not part of this deployment).
