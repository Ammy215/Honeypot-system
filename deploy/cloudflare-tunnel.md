# Cloudflare Tunnel + Access — Dashboard Exposure

Per HONEYSHIELD_PROJECT.md section 8b: the dashboard is bound to `127.0.0.1`
on the VPS (see `.streamlit/config.toml`) and never given a public port.
Cloudflare Tunnel reaches it from outside without opening any inbound port
on the server; Cloudflare Access puts a login wall (your email, one-time
code) in front of the tunnel URL, so a leaked link alone isn't enough to get
in. Both are free.

This is a setup guide, not a script — it's written so you (or a future
session with real server access) can follow it step by step against an
actual VPS. Nothing here has been run against a live server.

**Prerequisite:** a domain added to your Cloudflare account (free plan is
fine). Cloudflare Tunnel's persistent named tunnels + Access policies need a
domain to attach the hostname to — the quick anonymous `trycloudflare.com`
tunnels don't support Access.

If you don't want to use a domain at all, skip straight to the **SSH tunnel
alternative** at the bottom — it costs nothing either and is simpler for
single-person, own-machine-only access.

---

## 1. Install `cloudflared` on the VPS

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
cloudflared --version
```

(Use `cloudflared-linux-arm64.deb` instead if the VPS is an Oracle Ampere A1 / ARM instance.)

## 2. Authenticate and create the tunnel

```bash
cloudflared tunnel login          # opens a browser link — authorize against your Cloudflare account/domain
cloudflared tunnel create honeyshield-dashboard
```

This writes a tunnel credentials file to `~/.cloudflared/<tunnel-id>.json` and prints the tunnel ID — note it.

## 3. Configure the tunnel

Create `/etc/cloudflared/config.yml`:

```yaml
tunnel: <tunnel-id-from-step-2>
credentials-file: /root/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: dashboard.yourdomain.com
    service: http://127.0.0.1:8501
  - service: http_status:404
```

Replace `dashboard.yourdomain.com` with a subdomain of your Cloudflare-managed domain.

## 4. Route DNS to the tunnel

```bash
cloudflared tunnel route dns honeyshield-dashboard dashboard.yourdomain.com
```

This creates the CNAME record automatically — no manual DNS editing needed.

## 5. Run the tunnel as a service

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared
```

At this point `https://dashboard.yourdomain.com` reaches the dashboard —
but with no Access policy yet, anyone with the URL can load it (they'd
still hit HoneyShield's own admin login, but add Access anyway per the
threat model in section 6b: "if the dashboard ever gets a public URL,
anyone with that link gets in — unless there's auth in front of it").

## 6. Add Cloudflare Access in front of it

In the Cloudflare dashboard:

1. Go to **Zero Trust** → **Access** → **Applications** → **Add an application**.
2. Type: **Self-hosted**.
3. Application domain: `dashboard.yourdomain.com` (the hostname from step 3).
4. Add a policy, e.g. name it "Owner only":
   - Action: **Allow**
   - Include rule: **Emails** → your own email address (add any co-analyst
     emails here too if you ever have them — this is the RBAC on-ramp
     mentioned in section 8.6, without building anything yet)
5. Save.

Now visiting `dashboard.yourdomain.com` first hits Cloudflare's login page
(email + one-time code sent to that address) *before* it ever reaches
Streamlit, and only then does HoneyShield's own admin login apply. Two
independent walls.

## 7. Verify

- From your own machine: visit `https://dashboard.yourdomain.com` — you
  should see the Cloudflare Access login page first.
- From the VPS itself: `curl -I http://127.0.0.1:8501` should still succeed
  (the dashboard itself hasn't changed) — Access is enforced at Cloudflare's
  edge, not by Streamlit.
- Confirm directly hitting the VPS's public IP on port 8501 still fails —
  Cloudflare Tunnel doesn't open an inbound port, so there's nothing to hit
  there regardless.

---

## Alternative: SSH tunnel (no domain, no Cloudflare account needed)

If you're the only person who'll ever check the dashboard and don't want to
set up a domain:

```bash
ssh -L 8501:localhost:8501 you@<vps-ip> -p <ADMIN_SSH_PORT>
```

Then open `http://localhost:8501` in your local browser. Nothing is exposed
publicly at all — the tunnel only exists while that SSH session is open.
This is what section 8b calls out as the simpler option when the Cloudflare
layer isn't needed.
