---
title: "Building a Resilient Personal Roaming Gateway on Arch Linux: Native Modern Stack, Dynamic Port Hopping, and Effortless Long-Term Maintenance"
date: 2026-06-17T20:17:02+08:00
draft: false
tags:
  - Others
---

> **Abstract**: When setting up a reliable and performant personal roaming gateway, simplicity, long-term stability, and low maintenance overhead are the top priorities. This guide documents an end-to-end deployment on **Arch Linux** using the native **mihomo** core (a clean, native architecture utilizing `listeners.hysteria2` and `proxies.hysteria2`), the **Hysteria2 (QUIC)** protocol, **ECH (Encrypted Client Hello)** SNI obfuscation, **nftables dynamic port hopping**, and a **lighttpd static site fallback**.

---

## Why Choose Arch Linux?

When provisioning a VPS for network relays, many people default to Debian or Ubuntu. However, point-release distributions face major version upgrades every few years (such as jumping from Debian 11 to 12, or Ubuntu 20.04 to 22.04 and 24.04). Inevitably, distribution upgrades come with package dependency conflicts, configuration syntax changes, or even network interface breakage—often forcing administrators to back up and reinstall from scratch.

Arch Linux adopts a rolling-release model, **completely eliminating the headache of major version upgrades**. Once set up, you only need to spend two minutes a month logging in via SSH to run `sudo pacman -Syu`. The entire system, underlying kernel, and toolchains stay continuously up-to-date and in sync with upstream. As long as your VPS remains powered on, this gateway will run quietly and reliably for years without ever needing a teardown or reinstallation.

---

## Table of Contents
1. [Architecture & Traffic Model](#1-architecture--traffic-model)
2. [Prerequisites & Global Placeholder Reference](#2-prerequisites--global-placeholder-reference)
3. [Step 0: Initializing a Non-Root Admin User](#step-0-initializing-a-non-root-admin-user)
4. [Step 1: SSH Hardening (Custom Port & Public Key Authentication)](#step-1-ssh-hardening-custom-port--public-key-authentication)
5. [Step 2: System Hardening & Environment Initialization (`01-setup-system.sh`)](#step-2-system-hardening--environment-initialization-01-setup-systemsh)
6. [Step 3: nftables Advanced Firewall Configuration (Port Hopping & Scan Trap)](#step-3-nftables-advanced-firewall-configuration-port-hopping--scan-trap)
7. [Step 4: Automated Let's Encrypt Certificate Issuance & lighttpd Deployment](#step-4-automated-lets-encrypt-certificate-issuance--lighttpd-deployment)
8. [Step 5: Installing the mihomo Core Binary (`02-install-mihomo.sh`)](#step-5-installing-the-mihomo-core-binary-02-install-mihomosh)
9. [Step 6: Generating ECH Keypair & Launching the Server Daemon](#step-6-generating-ech-keypair--launching-the-server-daemon)
10. [Step 7: Cross-Platform Client Deployment Guide (Desktop & Mobile)](#step-7-cross-platform-client-deployment-guide-desktop--mobile)
11. [Step 8: Verification & Troubleshooting](#step-8-verification--troubleshooting)
12. [Step 9: Seamless Hot Upgrades (`upgrade-mihomo.sh`)](#step-9-seamless-hot-upgrades-upgrade-mihomosh)

---

## 1. Architecture & Traffic Model

The guiding principles of this deployment are **minimal attack surface exposure, protocol-conforming traffic simulation, active defensive hardening, and high network resilience**.

### 1.1 Traffic Flow Diagram

```text
Client mihomo (Desktop TUN / Mobile VpnService)
        │
        │ [1] UDP Dynamic Port Hopping Traffic (Range: <HOP_PORT_START>-<HOP_PORT_END>)
        │     TLS Handshake with ECH (Outer SNI: <OUTER_ECH_DOMAIN>, Encrypted Inner SNI: <YOUR_DOMAIN>)
        ▼
Server Public Network Interface (<WAN_INTERFACE>)
        │
        ├─► [nftables Filter Chain]
        │    ├─ Invalid TCP flags / malformed packets ──► DROP
        │    ├─ Unauthorized TCP scan hitting traps ──► Add to scan_blacklist (1 hour ban)
        │    ├─ SSH rate limiting (<CUSTOM_SSH_PORT>) ──► Ban IP if > 4 new connections/min
        │    └─ Inbound IPv6 external traffic ──► DROP (eliminate side-channel leaks)
        │
        └─► [nftables NAT Chain (PREROUTING)]
             └─ DNAT <HOP_PORT_START>-<HOP_PORT_END>/udp ──► 127.0.0.1:<MIHOMO_LOCAL_PORT>
                                                               │
                                                               ▼
                                                   mihomo Server Daemon
                             (Runs as restricted user, strictly bound to 127.0.0.1:<MIHOMO_LOCAL_PORT>/udp)
                                                               │
                           ┌───────────────────────────────────┴───────────────────────────────────┐
                           ▼                                                                       ▼
                 [Valid Hysteria2 Auth]                                                [Probe / Unauthenticated]
                 Decrypted inner ECH matches                                           masquerade fallback to local
                 High-speed BBR forwarding out                                         https://127.0.0.1:443
                                                                                                   │
                                                                                                   ▼
                                                                                            lighttpd Static Site
                                                                                     (Serves legit site, A+ TLS grade)
```

### 1.2 Core Architectural Advantages

1. **Zero Public Port Exposure**: The mihomo service does not bind directly to any public IP address; it listens exclusively on `127.0.0.1`. External port scanners cannot discover any listening proxy ports on the public interface.
2. **UDP Dynamic Port Hopping**: Clients randomly cycle through high-order ports within `<HOP_PORT_START>-<HOP_PORT_END>`. The Linux kernel dynamically rewrites destination addresses to the local listener via `nftables DNAT`. This balances the transmission load and avoids throttling caused by single-port UDP anomalies.
3. **ECH (Encrypted Client Hello)**: The true hostname `<YOUR_DOMAIN>` is completely encrypted within the TLS payload. Observers on the public transit link only see a benign, high-reputation outer domain (`<OUTER_ECH_DOMAIN>`), preventing plain-text SNI inspection.
4. **Active Probe Fallback (Masquerade)**: Any unauthenticated or exploratory HTTP/HTTPS requests hitting the port are natively redirected back to the local `lighttpd` static web server, behaving like a standard HTTP/2 web presence.
5. **Kernel Sandboxing & Proactive Defense**: Systemd isolates the daemon by dropping all unnecessary Linux capabilities. Concurrently, `nftables` sets port scanning traps that immediately blacklist any IP scanning unexposed TCP ports.

---

## 2. Prerequisites & Global Placeholder Reference

To safeguard sensitive credentials, replace the following placeholders with your actual parameters before running any commands:

| Placeholder | Description & Recommended Value | Example |
|---|---|---|
| `<YOUR_SUDO_USER>` | Non-root administrative user for the server | `admin` or `ops` |
| `<SERVER_IP>` | Server public IPv4 address | `198.51.100.1` |
| `<WAN_INTERFACE>` | Primary public network interface name | `eth0`, `ens3`, or `ens18` |
| `<CUSTOM_SSH_PORT>` | High-order custom SSH port | `54321` |
| `<YOUR_DOMAIN>` | Your registered domain for the gateway / fallback site | `nodes.example.com` |
| `<OUTER_ECH_DOMAIN>` | Benign public domain used as outer ECH SNI | `cloudflare.com` |
| `<YOUR_EMAIL>` | Email address for Let's Encrypt notifications | `admin@example.com` |
| `<YOUR_CLOUDFLARE_API_TOKEN>` | Cloudflare API Token with `Zone - DNS - Edit` permissions | 32+ character string |
| `<MIHOMO_LOCAL_PORT>` | Local loopback UDP port for mihomo | `18000` |
| `<HOP_PORT_START>-<HOP_PORT_END>` | UDP Port hopping range | `40000-50000` |
| `<YOUR_STRONG_PASSWORD>` | Strong password for Hysteria2 authentication | Generate via `openssl rand -base64 32` |
| `<YOUR_CONTROLLER_SECRET>` | Secret token for external-controller API | Generate via `openssl rand -base64 16` |
| `<YOUR_ECH_CONFIG_BASE64>` | Single-line base64 public ECH Config string | Base64 string |
| `<YOUR_ECH_PRIVATE_KEY>` | Multi-line private ECH Key block | PEM block with BEGIN/END markers |

---

## Step 0: Initializing a Non-Root Admin User

Following the principle of least privilege, avoid performing routine management as `root`. Log into your VPS and create a sudo-enabled user:

```bash
# 1. Log in as root, create a dedicated admin user, and append to the wheel group
useradd -m -G wheel -s /bin/bash <YOUR_SUDO_USER>

# 2. Set a strong password
passwd <YOUR_SUDO_USER>

# 3. Grant sudo privileges to the wheel group
EDITOR=nano visudo
# Locate: # %wheel ALL=(ALL:ALL) ALL
# Uncomment the line: %wheel ALL=(ALL:ALL) ALL
# Save and exit (Ctrl+O, Enter, Ctrl+X)

# 4. Switch to the newly created user
su - <YOUR_SUDO_USER>
```

> [!TIP]
> Append your local SSH public key to `/home/<YOUR_SUDO_USER>/.ssh/authorized_keys` now so that public key authentication works right away.

---

## Step 1: SSH Hardening (Custom Port & Public Key Authentication)

Automated scanners continuously target port 22. Harden your SSH daemon using a modular drop-in configuration under `/etc/ssh/sshd_config.d/`:

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# Custom high-order port (must match nftables rules)
Port <CUSTOM_SSH_PORT>

# Enforce public key authentication only
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey

# Prohibit direct root logins
PermitRootLogin prohibit-password

# Session and authentication limits
MaxAuthTries 3
MaxSessions 2

# Keepalive and idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
```

Validate and restart SSH:
```bash
sudo sshd -t
sudo systemctl restart sshd
```

> [!CAUTION]
> **Do not close your current terminal session yet!** Open a new terminal on your local machine to verify connectivity:
> ```bash
> ssh -p <CUSTOM_SSH_PORT> <YOUR_SUDO_USER>@<SERVER_IP>
> ```
> Proceed only after verifying that public key authentication works as expected.

---

## Step 2: System Hardening & Environment Initialization (`01-setup-system.sh`)

This step installs essential dependencies, sets up dedicated isolated system users, configures directories with strict access permissions, and applies network stack sysctl tunings.

### 2.1 Script Implementation

Create a temporary script `01-setup-system.sh` on the server:

```bash
cat << 'EOF' > 01-setup-system.sh
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must run as root: sudo bash 01-setup-system.sh" >&2
  exit 1
fi

if ! command -v pacman >/dev/null 2>&1; then
  echo "Error: This script is tailored for Arch Linux. pacman not found!" >&2
  exit 1
fi

echo ">> [1/6] Installing system dependencies..."
pacman -S --needed --noconfirm nftables lighttpd certbot certbot-dns-cloudflare curl openssl ca-certificates

echo ">> [2/6] Configuring dedicated system user and security group..."
if ! id mihomo >/dev/null 2>&1; then
  useradd -r -s /usr/bin/nologin -M mihomo
fi

if ! getent group ssl-cert >/dev/null 2>&1; then
  groupadd -r ssl-cert
fi

usermod -aG ssl-cert mihomo
usermod -aG ssl-cert http

echo ">> [3/6] Setting up protected directories and permissions..."
mkdir -p /etc/mihomo
chown root:mihomo /etc/mihomo
chmod 750 /etc/mihomo

mkdir -p /var/lib/mihomo
chown mihomo:mihomo /var/lib/mihomo
chmod 750 /var/lib/mihomo

mkdir -p /etc/ssl/mihomo
chown -R root:ssl-cert /etc/ssl/mihomo
chmod 750 /etc/ssl/mihomo

mkdir -p /srv/http/disguise
chown -R http:http /srv/http/disguise
chmod 755 /srv/http/disguise

echo ">> [4/6] Applying kernel network tuning & local routing..."
WAN_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
WAN_IFACE="${WAN_IFACE:-<WAN_INTERFACE>}"

SYSCTL_FILE=/etc/sysctl.d/99-mihomo-security.conf
cat > "$SYSCTL_FILE" << SYSCTL_EOF
# Enable localnet routing for DNAT to 127.0.0.1 (Required for port hopping)
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.${WAN_IFACE}.route_localnet = 1

# SYN Flood mitigation
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096

# Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.${WAN_IFACE}.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# Ignore broadcast ping
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# File system and kernel pointer protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
SYSCTL_EOF

sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

echo ">> [5/6] Restricting journal log retention..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-mihomo-limit.conf << 'JOURNAL_EOF'
[Journal]
SystemMaxUse=256M
MaxRetentionSec=1month
JOURNAL_EOF
systemctl restart systemd-journald || true

echo ">> [6/6] Initializing Certbot deploy hook directory..."
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
chmod 750 /etc/letsencrypt/renewal-hooks/deploy
systemctl daemon-reload

echo ">> System hardening and environment setup complete."
EOF
```

### 2.2 Execution
```bash
sudo bash 01-setup-system.sh
rm -f 01-setup-system.sh
```

---

## Step 3: nftables Advanced Firewall Configuration (Port Hopping & Scan Trap)

`nftables` provides native, high-performance packet filtering and translation:
1. **UDP Port Hopping DNAT**: Incoming UDP packets on `<HOP_PORT_START>-<HOP_PORT_END>` are rewritten to `127.0.0.1:<MIHOMO_LOCAL_PORT>`.
2. **SSH Rate Limiting**: Exceeding 4 new connections per minute results in an automatic 1-hour IP ban.
3. **Port Scan Trap**: Any connection attempt to non-whitelisted TCP ports immediately triggers an automatic 1-hour ban.
4. **Packet Sanitization**: Invalid TCP flag combinations (NULL, Xmas, etc.) are immediately dropped.

Edit `/etc/nftables.conf`:

```bash
sudo nano /etc/nftables.conf
```

Paste the following ruleset:

```txt
#!/usr/sbin/nft -f

flush ruleset

# -------------------------------------------------------------
# Variable Definitions
# -------------------------------------------------------------
define WAN_IFACE   = "<WAN_INTERFACE>"
define SSH_PORT    = <CUSTOM_SSH_PORT>
define HTTP_PORT   = 80
define HTTPS_PORT  = 443
define HY2_PORT    = <MIHOMO_LOCAL_PORT>
define HY2_RANGE   = <HOP_PORT_START>-<HOP_PORT_END>

# -------------------------------------------------------------
# Filter Table (inet filter)
# -------------------------------------------------------------
table inet filter {
    # Dynamic scan blacklist (automatic 1-hour expiration)
    set scan_blacklist {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }

    # SSH connection rate tracker
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Drop packets from blacklisted IPs immediately
        ip saddr @scan_blacklist drop

        # 2. Allow established and related connections
        ct state established,related accept

        # 3. Allow loopback traffic
        iif "lo" accept

        # 4. Drop all inbound external IPv6 traffic
        meta nfproto ipv6 drop

        # 5. Drop invalid connection states
        ct state invalid drop

        # 6. Drop malformed TCP flag combinations (NULL, Xmas, SYN-FIN, etc.)
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|ack) != syn ct state new drop

        # 7. ICMP rate limiting (allows network diagnostics while mitigating floods)
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } limit rate 5/second accept
        ip protocol icmp drop

        # 8. SSH brute-force protection
        tcp dport $SSH_PORT ct state new add @ssh_ratelimit { ip saddr limit rate 4/minute burst 4 packets } accept
        tcp dport $SSH_PORT ct state new add @scan_blacklist { ip saddr } drop

        # 9. Whitelist HTTP & HTTPS ports for the fallback site
        tcp dport { $HTTP_PORT, $HTTPS_PORT } accept

        # 10. Allow DNAT-translated Hysteria2 UDP packets
        # Note: Packets must already have their destination translated to 127.0.0.1
        ip daddr 127.0.0.1 udp dport $HY2_PORT accept

        # 11. Port scan trap (external interface only)
        # Any new TCP connection touching an unopened port triggers an automatic ban
        iifname $WAN_IFACE tcp flags & syn == syn ct state new add @scan_blacklist { ip saddr } drop

        # 12. Default drop
        drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}

# -------------------------------------------------------------
# NAT Table (Port Hopping Forwarding)
# -------------------------------------------------------------
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname $WAN_IFACE udp dport $HY2_RANGE dnat to 127.0.0.1:$HY2_PORT
    }
}
```

Apply and enable the firewall:
```bash
sudo chmod 644 /etc/nftables.conf
sudo nft -c -f /etc/nftables.conf
sudo systemctl enable --now nftables
sudo systemctl status nftables
```

> [!NOTE]
> Check currently banned IPs anytime with:
> ```bash
> sudo nft list set inet filter scan_blacklist
> ```

---

## Step 4: Automated Let's Encrypt Certificate Issuance & lighttpd Deployment

To achieve an A+ TLS grade for the fallback site and ensure that private keys remain readable only by the `ssl-cert` group, we use Certbot with an automated deploy hook.

### 4.1 Cloudflare DNS API Token Configuration

Using Let's Encrypt via DNS-01 challenge is straightforward: it avoids occupying port 80 and handles renewal completely in the background:

1. In the Cloudflare Dashboard, go to **My Profile** -> **API Tokens** -> **Create Token**.
2. Select the **Edit zone DNS** template, assign `Zone - DNS - Edit`, and select your target zone.
3. Save the credential on the server with restricted permissions:
   ```bash
   sudo mkdir -p /etc/letsencrypt
   sudo tee /etc/letsencrypt/cloudflare.ini << 'EOF'
   dns_cloudflare_api_token = <YOUR_CLOUDFLARE_API_TOKEN>
   EOF
   sudo chown root:root /etc/letsencrypt/cloudflare.ini
   sudo chmod 600 /etc/letsencrypt/cloudflare.ini
   ```

### 4.2 Deploy Hook for Automatic Permissions & Service Reload

Create `/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh`:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: deploy hook must run as root." >&2
    exit 1
fi

TARGET_DIR="/etc/ssl/mihomo"
if [ ! -d "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
    chown root:ssl-cert "$TARGET_DIR"
    chmod 750 "$TARGET_DIR"
fi

if [ -z "${RENEWED_LINEAGE:-}" ]; then
    DOMAIN="${1:-}"
    if [ -n "$DOMAIN" ] && [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN"
    else
        echo "Error: Certificate lineage not found." >&2
        exit 1
    fi
fi

echo ">> Distributing certificate files to $TARGET_DIR ..."
cp -f "$RENEWED_LINEAGE/fullchain.pem" "$TARGET_DIR/fullchain.pem"
cp -f "$RENEWED_LINEAGE/privkey.pem"   "$TARGET_DIR/privkey.pem"

# Restrict permissions: private key to 640 root:ssl-cert, public certificate to 644
chown root:ssl-cert "$TARGET_DIR/privkey.pem" "$TARGET_DIR/fullchain.pem"
chmod 640 "$TARGET_DIR/privkey.pem"
chmod 644 "$TARGET_DIR/fullchain.pem"

# Reload web server and relay daemon
systemctl is-active --quiet lighttpd && systemctl reload-or-restart lighttpd || true
systemctl is-active --quiet mihomo && systemctl reload-or-restart mihomo || true

logger -t certbot-deploy-hook "Let's Encrypt certificates deployed and services reloaded."
EOF

sudo chown root:root /etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
sudo chmod 750 /etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

### 4.3 Initial Certificate Issuance

Issue the certificate with a single standard Certbot command:

```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  --email <YOUR_EMAIL> \
  --agree-tos \
  --no-eff-email \
  -d <YOUR_DOMAIN> \
  --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

**Enable the Systemd Auto-Renewal Timer**:
Arch Linux includes `certbot-renew.timer` out of the box. It checks certificate expiration twice a day and automatically renews within 30 days of expiry:
```bash
sudo systemctl enable --now certbot-renew.timer
sudo systemctl list-timers | grep certbot
```

### 4.4 Configuring lighttpd Fallback Site

1. **Place Static Web Content**:
   Add a standard static HTML template into `/srv/http/disguise/` (ensure `index.html` exists):
   ```bash
   sudo chown -R http:http /srv/http/disguise
   sudo chmod -R 755 /srv/http/disguise
   ```

2. **Configure `/etc/lighttpd/lighttpd.conf`**:
   ```bash
   sudo nano /etc/lighttpd/lighttpd.conf
   ```

   ```lighttpd
   server.modules = (
       "mod_openssl",
       "mod_redirect",
       "mod_setenv",
       "mod_access"
   )

   server.username      = "http"
   server.groupname     = "http"
   server.document-root = "/srv/http/disguise"
   server.pid-file      = "/run/lighttpd.pid"
   server.errorlog      = "/var/log/lighttpd/error.log"

   # Disguise server signature
   server.tag           = "nginx"

   mimetype.assign = (
       ".html" => "text/html; charset=utf-8",
       ".htm"  => "text/html; charset=utf-8",
       ".css"  => "text/css; charset=utf-8",
       ".js"   => "application/javascript; charset=utf-8",
       ".json" => "application/json; charset=utf-8",
       ".png"  => "image/png",
       ".jpg"  => "image/jpeg",
       ".svg"  => "image/svg+xml",
       ".ico"  => "image/x-icon",
       ".txt"  => "text/plain; charset=utf-8"
   )

   index-file.names = ( "index.html", "index.htm" )

   # Redirect HTTP (port 80) to HTTPS
   server.port = 80
   $HTTP["scheme"] == "http" {
       url.redirect-code = 301
       url.redirect = (
           "" => "https://${url.authority}${url.path}${qsa}"
       )
   }

   # Secure HTTPS configuration on port 443
   $SERVER["socket"] == ":443" {
       ssl.engine  = "enable"
       ssl.pemfile = "/etc/ssl/mihomo/fullchain.pem"
       ssl.privkey = "/etc/ssl/mihomo/privkey.pem"

       # Enforce TLS 1.2+ with modern cipher suites
       ssl.openssl.ssl-conf-cmd = (
           "MinProtocol" => "TLSv1.2",
           "Options"     => "-ServerPreference",
           "CipherString" => "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
       )

       # Security response headers (A+ rating)
       setenv.add-response-header = (
           "Strict-Transport-Security" => "max-age=31536000; includeSubDomains; preload",
           "X-Content-Type-Options"    => "nosniff",
           "X-Frame-Options"           => "DENY",
           "X-XSS-Protection"          => "1; mode=block",
           "Content-Security-Policy"   => "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
           "Referrer-Policy"           => "strict-origin-when-cross-origin",
           "Permissions-Policy"        => "interest-cohort=()"
       )

       # Virtual host binding
       $HTTP["host"] == "<YOUR_DOMAIN>" {
           server.document-root = "/srv/http/disguise"
       }

       # Block raw IP or unauthorized host probes
       $HTTP["host"] != "<YOUR_DOMAIN>" {
           url.access-deny = ( "" )
       }
   }
   ```

3. **Hosts Resolution & Service Activation**:
   ```bash
   sudo chown root:root /etc/lighttpd/lighttpd.conf
   sudo chmod 644 /etc/lighttpd/lighttpd.conf

   # Ensure local masquerade requests resolve to 127.0.0.1
   echo "127.0.0.1 <YOUR_DOMAIN>" | sudo tee -a /etc/hosts

   # Verify syntax and start service
   sudo lighttpd -tt -f /etc/lighttpd/lighttpd.conf
   sudo systemctl enable --now lighttpd
   ```

---

## Step 5: Installing the mihomo Core Binary (`02-install-mihomo.sh`)

Create an architecture-adaptive installation script `02-install-mihomo.sh`:

```bash
cat << 'EOF' > 02-install-mihomo.sh
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must run as root: sudo bash 02-install-mihomo.sh" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  TARGET_ARCH="linux-amd64-compatible" ;;
  aarch64) TARGET_ARCH="linux-arm64" ;;
  *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo ">> Fetching latest mihomo release tag..."
LATEST_TAG=$(curl -sSL "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4)
DOWNLOAD_URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/mihomo-${TARGET_ARCH}-${LATEST_TAG}.gz"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo ">> Downloading mihomo (${LATEST_TAG} / ${TARGET_ARCH})..."
curl -sSL -o "$TMP_DIR/mihomo.gz" "$DOWNLOAD_URL"

echo ">> Extracting and installing to /usr/local/bin/mihomo ..."
gzip -dc "$TMP_DIR/mihomo.gz" > "$TMP_DIR/mihomo"
install -m 755 "$TMP_DIR/mihomo" /usr/local/bin/mihomo

/usr/local/bin/mihomo -v
echo ">> Installation successful."
EOF

sudo bash 02-install-mihomo.sh
rm -f 02-install-mihomo.sh
```

---

## Step 6: Generating ECH Keypair & Launching the Server Daemon

### 6.1 Generating ECH Keypair

Use an unassociated high-reputation domain (such as `<OUTER_ECH_DOMAIN>`, e.g., `cloudflare.com`) as the outer SNI shield:

```bash
mihomo generate ech-keypair <OUTER_ECH_DOMAIN>
```

**Example Output**:
```text
Config: <YOUR_ECH_CONFIG_BASE64>

Key: 
-----BEGIN ECH KEYS-----
<YOUR_ECH_PRIVATE_KEY_LINES>
-----END ECH KEYS-----
```

- **Config**: Public key string used in client configuration.
- **Key**: Private key block used in the server configuration.

### 6.2 Hardened Systemd Service Unit

Create `/etc/systemd/system/mihomo.service`:

```ini
[Unit]
Description=mihomo Server Daemon (Hysteria2 Listener, Least Privilege)
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=120s
StartLimitBurst=5

[Service]
Type=simple
User=mihomo
Group=mihomo
SupplementaryGroups=ssl-cert
Environment="SAFE_PATHS=/etc/ssl/mihomo:/etc/mihomo"

# Drop all high-risk capabilities; grant only port binding capability
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Filesystem and process isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
LockPersonality=true
PrivateDevices=true

# System call filtering (Seccomp)
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Working directory and file access restrictions
WorkingDirectory=/var/lib/mihomo
StateDirectory=mihomo
ReadWritePaths=/var/lib/mihomo
ReadOnlyPaths=/etc/mihomo /etc/ssl/mihomo

LimitNPROC=500
LimitNOFILE=1000000

Restart=on-failure
RestartSec=5s

ExecStartPre=/usr/bin/sleep 1s
ExecStart=/usr/local/bin/mihomo -d /var/lib/mihomo -f /etc/mihomo/config.yaml
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

Reload systemd:
```bash
sudo chown root:root /etc/systemd/system/mihomo.service
sudo chmod 644 /etc/systemd/system/mihomo.service
sudo systemctl daemon-reload
```

### 6.3 Server Configuration `/etc/mihomo/config.yaml`

Create `/etc/mihomo/config.yaml`:

```yaml
log-level: warning
ipv6: false
find-process-mode: off

external-controller: 127.0.0.1:9090
secret: <YOUR_CONTROLLER_SECRET>

profile:
  store-selected: false
  store-fake-ip: false

listeners:
  - name: hy2-in
    type: hysteria2
    # Strictly listen on loopback interface
    port: <MIHOMO_LOCAL_PORT>
    listen: 127.0.0.1

    # Authentication credentials
    users:
      hy2-user: "<YOUR_STRONG_PASSWORD>"

    up: 100
    down: 100
    ignore-client-bandwidth: true

    # Fallback to local static website
    masquerade: "https://<YOUR_DOMAIN>"

    alpn:
      - h3

    certificate: /etc/ssl/mihomo/fullchain.pem
    private-key: /etc/ssl/mihomo/privkey.pem

    # Paste the ECH private key block generated in Step 6.1
    ech-key: |
      -----BEGIN ECH KEYS-----
      <YOUR_ECH_PRIVATE_KEY>
      -----END ECH KEYS-----
```

Set permissions and launch:
```bash
sudo chown root:mihomo /etc/mihomo/config.yaml
sudo chmod 640 /etc/mihomo/config.yaml

# Test configuration syntax
sudo -u mihomo /usr/local/bin/mihomo -t -d /var/lib/mihomo -f /etc/mihomo/config.yaml

# Start and enable the service
sudo systemctl enable --now mihomo
sudo systemctl status mihomo
```

---

## Step 7: Cross-Platform Client Deployment Guide (Desktop & Mobile)

This setup tailors two separate, fully audited configuration profiles according to the differing network stacks and power-consumption characteristics of desktop and mobile platforms:
- **Desktop Profile (`mihomo-desktop.yaml`)**: Enables native transparent TUN routing, TCP concurrency, and standard keep-alive timeouts. Because all network traffic is routed through the virtual TUN interface, domestic traffic is cleanly and comprehensively resolved by `GEOSITE,CN` and `GEOIP,CN`.
- **Mobile Profile (`mihomo-mobile.yaml`)**: **Omits the `tun` section entirely** (leaving virtual interface management to the mobile operating system's native `VpnService` to prevent double-TUN battery drain), enables `quic-go-disable-gso: true` to bypass cellular base station UDP fragmentation flaws, and utilizes short keep-alive heartbeats to prevent idle drops. Furthermore, it incorporates explicit `DOMAIN-SUFFIX` direct routing rules for high-frequency domestic apps (such as Bilibili, WeChat, QQ) to prevent private in-app HTTPDNS implementations from bypassing system DNS and triggering account fraud-prevention flags.

### 7.1 Linux Desktop Deployment & Full Configuration (TUN Transparent Mode)

On the client Linux machine, execute the environment initialization:

1. **Setup TUN Permissions (`setup-client.sh`)**:
   ```bash
   sudo pacman -S --needed iproute2 curl openssl ca-certificates
   sudo useradd -r -s /usr/bin/nologin -M mihomo || true
   sudo mkdir -p /etc/mihomo /var/lib/mihomo
   sudo chown root:mihomo /etc/mihomo && sudo chmod 750 /etc/mihomo
   sudo chown mihomo:mihomo /var/lib/mihomo && sudo chmod 750 /var/lib/mihomo

   # Grant restricted mihomo user permissions to operate TUN devices
   sudo tee /etc/udev/rules.d/90-mihomo-tun.rules << 'EOF'
   KERNEL=="tun", GROUP="mihomo", MODE="0660"
   EOF
   sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=tun
   ```

2. **Install mihomo Core Binary**:
   Run the same `02-install-mihomo.sh` script as on the server to install the binary to `/usr/local/bin/mihomo`.

3. **Client Systemd Service Unit (Grants CAP_NET_ADMIN for TUN)**:
   Create `/etc/systemd/system/mihomo.service`:
   ```ini
   [Unit]
   Description=mihomo Client Daemon (TUN Mode)
   After=network.target network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=mihomo
   Group=mihomo
   CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
   AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   WorkingDirectory=/var/lib/mihomo
   StateDirectory=mihomo
   ReadWritePaths=/var/lib/mihomo
   ReadOnlyPaths=/etc/mihomo
   ExecStart=/usr/local/bin/mihomo -d /var/lib/mihomo -f /etc/mihomo/config.yaml
   Restart=on-failure
   RestartSec=5s

   [Install]
   WantedBy=multi-user.target
   ```
   Reload systemd: `sudo systemctl daemon-reload`.

4. **Desktop Full Profile (`mihomo-desktop.yaml`)**:
   Save the following complete configuration to `/etc/mihomo/config.yaml`:

```yaml

mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
unified-delay: true
tcp-concurrent: true
find-process-mode: off

keep-alive-interval: 30
keep-alive-idle: 600
disable-keep-alive: false

geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
  asn: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

experimental:
  quic-go-disable-gso: false
  quic-go-disable-ecn: true
  dialer-ip4p-convert: false

# Static hosts mapping for DoH endpoints: Bypasses bootstrap queries & prevents DNS poisoning
hosts:
  'dns.quad9.net':
    - 9.9.9.9
    - 149.112.112.112
  'protective.joindns4.eu':
    - 86.54.11.1
    - 86.54.11.201

# ---- TUN Mode ----
tun:
  enable: true
  stack: mixed
  dns-hijack:
    - "any:53"
  auto-route: true
  auto-detect-interface: true
  strict-route: true
  route-exclude-address:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8
    - 169.254.0.0/16
    - 224.0.0.0/4
    - 240.0.0.0/4
  mtu: 1500

# ---- DNS ----
dns:
  enable: true
  cache-algorithm: arc
  prefer-h3: false
  use-hosts: true
  use-system-hosts: true
  respect-rules: true
  listen: 127.0.0.1:1053
  ipv6: false

  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29

  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - GEOSITE,CN,real-ip
    - GEOSITE,private,real-ip
    - GEOSITE,apple,real-ip
    - GEOSITE,onedrive,real-ip
    - GEOSITE,category-ntp,real-ip
    - GEOSITE,connectivity-check,real-ip
    - DOMAIN,<YOUR_DOMAIN>,real-ip
    - MATCH,fake-ip

  nameserver-policy:
    "geosite:cn,private,apple,onedrive,microsoft@cn":
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    "geosite:google,youtube,telegram,gfw,geolocation-!cn":
      - https://dns.quad9.net/dns-query
      - https://protective.joindns4.eu/dns-query

  nameserver:
    - https://dns.quad9.net/dns-query
    - https://protective.joindns4.eu/dns-query

  fallback:
    - https://protective.joindns4.eu/dns-query
    - https://dns.quad9.net/dns-query

  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite:
      - gfw
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
      - 127.0.0.1/32
      - 100.64.0.0/10

  # Node domain resolution: Domestic DoH (encrypted transport against inspection)
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query

  direct-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  direct-nameserver-follow-policy: false

# ---- Proxy Node ----
proxies:
  - name: HY2-Port-Hopping
    type: hysteria2
    server: <YOUR_DOMAIN>
    ports: <HOP_PORT_START>-<HOP_PORT_END>
    hop-interval: 30
    password: "<YOUR_STRONG_PASSWORD>"
    up: 200
    down: 100
    sni: <YOUR_DOMAIN>
    skip-cert-verify: false
    alpn:
      - h3
    ech-opts:
      enable: true
      config: "<YOUR_ECH_CONFIG_BASE64>"

# ---- Proxy Groups ----
proxy-groups:
  - name: 代理
    type: select
    proxies:
      - 自动选择
      - HY2-Port-Hopping
      - DIRECT
  - name: 自动选择
    type: url-test
    proxies:
      - HY2-Port-Hopping
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50


rules:
  # Ad blocking
  - GEOSITE,category-ads-all,REJECT

  # Direct connection to node domain (prevents loops)
  - DOMAIN,<YOUR_DOMAIN>,DIRECT


  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,private,DIRECT


  - GEOSITE,google,代理
  - GEOSITE,youtube,代理
  - GEOSITE,telegram,代理
  - GEOSITE,github,代理
  - GEOSITE,openai,代理
  - GEOSITE,anthropic,代理
  - IP-CIDR,160.79.104.0/21,代理,no-resolve
  - GEOIP,telegram,代理


  - GEOSITE,microsoft@cn,DIRECT
  - GEOSITE,apple-cn,DIRECT
  - GEOSITE,steam@cn,DIRECT
  - GEOSITE,category-games@cn,DIRECT

 
  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT


  - GEOSITE,geolocation-!cn,代理


  - MATCH,代理
```

Enable and verify:
```bash
sudo chown root:mihomo /etc/mihomo/config.yaml
sudo chmod 640 /etc/mihomo/config.yaml
sudo systemctl enable --now mihomo
sudo systemctl status mihomo
```

---

### 7.2 Mobile Full Profile (`mihomo-mobile.yaml` / Android & iOS Power-Optimized)

For mobile clients (Clash Meta for Android, Flclash, Sing-box, Loon, Shadowrocket, etc.), save or import the following complete configuration:

```yaml
mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
unified-delay: true
tcp-concurrent: false
find-process-mode: off

# Mobile-specific keep-alive: Prevents carrier mobile base stations from evicting NAT states
keep-alive-interval: 25
keep-alive-idle: 120
disable-keep-alive: false

geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
  asn: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

experimental:
  # Disabling GSO and ECN is strongly advised on cellular mobile networks
  quic-go-disable-gso: true
  quic-go-disable-ecn: true
  dialer-ip4p-convert: false

# Static hosts mapping for DoH endpoints: Bypasses bootstrap queries & prevents DNS poisoning
hosts:
  'dns.quad9.net':
    - 9.9.9.9
    - 149.112.112.112
  'protective.joindns4.eu':
    - 86.54.11.1
    - 86.54.11.201

# Note: Mobile configurations omit the 'tun:' block entirely.
# The virtual network interface is delegated to the mobile OS VpnService.

# ---- DNS ----
dns:
  enable: true
  cache-algorithm: arc
  prefer-h3: false
  use-hosts: true
  use-system-hosts: true
  respect-rules: true
  listen: 127.0.0.1:1053
  ipv6: false

  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29

  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - GEOSITE,CN,real-ip
    - GEOSITE,private,real-ip
    - GEOSITE,apple,real-ip
    - GEOSITE,onedrive,real-ip
    - GEOSITE,category-ntp,real-ip
    - GEOSITE,connectivity-check,real-ip
    - DOMAIN,<YOUR_DOMAIN>,real-ip
    - MATCH,fake-ip

  nameserver-policy:
    "geosite:cn,private,apple,onedrive,microsoft@cn":
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    "geosite:google,youtube,telegram,gfw,geolocation-!cn":
      - https://dns.quad9.net/dns-query
      - https://protective.joindns4.eu/dns-query

  nameserver:
    - https://dns.quad9.net/dns-query
    - https://protective.joindns4.eu/dns-query

  fallback:
    - https://protective.joindns4.eu/dns-query
    - https://dns.quad9.net/dns-query

  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite:
      - gfw
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
      - 127.0.0.1/32
      - 100.64.0.0/10

  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query

  direct-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  direct-nameserver-follow-policy: false

# ---- Proxy Node ----
proxies:
  - name: HY2-Port-Hopping
    type: hysteria2
    server: <YOUR_DOMAIN>
    ports: <HOP_PORT_START>-<HOP_PORT_END>
    hop-interval: 30
    password: "<YOUR_STRONG_PASSWORD>"
    up: 100
    down: 100
    sni: <YOUR_DOMAIN>
    skip-cert-verify: false
    alpn:
      - h3
    ech-opts:
      enable: true
      config: "<YOUR_ECH_CONFIG_BASE64>"

# ---- Proxy Groups ----
proxy-groups:
  - name: 代理
    type: select
    proxies:
      - 自动选择
      - HY2-Port-Hopping
      - DIRECT
  - name: 自动选择
    type: url-test
    proxies:
      - HY2-Port-Hopping
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

rules:
  # Ad blocking
  - GEOSITE,category-ads-all,REJECT

  # Direct connection to node domain (prevents loops)
  - DOMAIN,<YOUR_DOMAIN>,DIRECT


  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,private,DIRECT

 
  - GEOSITE,google,代理
  - GEOSITE,youtube,代理
  - GEOSITE,telegram,代理
  - GEOSITE,github,代理
  - GEOSITE,openai,代理
  - GEOSITE,anthropic,代理
  - IP-CIDR,160.79.104.0/21,代理,no-resolve
  - GEOIP,telegram,代理


  - GEOSITE,microsoft@cn,DIRECT
  - GEOSITE,apple-cn,DIRECT
  - GEOSITE,steam@cn,DIRECT
  - GEOSITE,category-games@cn,DIRECT


  - GEOSITE,bilibili,DIRECT
  - DOMAIN-SUFFIX,bilibili.com,DIRECT
  - DOMAIN-SUFFIX,biliapi.net,DIRECT
  - DOMAIN-SUFFIX,hdslb.com,DIRECT
  - DOMAIN-SUFFIX,bilivideo.com,DIRECT
  - DOMAIN-SUFFIX,bilivideo.cn,DIRECT
  - DOMAIN-SUFFIX,acgvideo.com,DIRECT
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - DOMAIN-SUFFIX,gtimg.cn,DIRECT
  - DOMAIN-SUFFIX,weixin.qq.com,DIRECT


  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT


  - GEOSITE,geolocation-!cn,代理


  - MATCH,代理
```

---

### 7.3 Windows / macOS GUI Client Setup

On Windows or macOS, graphical clients like **Mihomo Party**, **Clash Verge Rev**, or **Flclash** are recommended:
1. Create a new local profile, copy and paste the complete content of `mihomo-desktop.yaml` above into it;
2. Verify that `<YOUR_DOMAIN>`, `<HOP_PORT_START>-<HOP_PORT_END>`, `<YOUR_STRONG_PASSWORD>`, and `<YOUR_ECH_CONFIG_BASE64>` are appropriately filled in;
3. Save and activate the profile, then toggle "System Proxy" or "TUN Mode / Service Mode" on the dashboard for system-wide routing.

---

## Step 8: Verification & Troubleshooting

### 8.1 Diagnostic Commands

Run the following checks on the server:

```bash
# 1. Verify nftables rules and NAT translations
sudo nft list ruleset

# 2. Check local listening ports (verify 127.0.0.1 binding and web ports)
sudo ss -tulnp | grep -E '(<MIHOMO_LOCAL_PORT>|80|443|<CUSTOM_SSH_PORT>)'

# 3. Test the fallback website and SSL certificate
curl -Iv https://<YOUR_DOMAIN>

# 4. Monitor live daemon logs
sudo journalctl -u mihomo -f -n 50 --no-pager
```

### 8.2 Common Issues & Resolutions

| Symptom | Probable Cause | Solution |
|---|---|---|
| Client times out; no handshake logs on server | Kernel drops cross-interface routing to 127.0.0.1 | Check `sysctl net.ipv4.conf.all.route_localnet`; verify it is set to `1` |
| Client times out; no handshake logs on server | Interface name mismatch | Confirm `WAN_IFACE` in `/etc/nftables.conf` exactly matches `ip -br link` |
| SSH connection suddenly dropped or blocked | Triggered rate-limit trap | Over 4 connections/min triggers an auto-ban. Unban your IP: `sudo nft delete element inet filter scan_blacklist { <YOUR_CLIENT_IP> }` |
| mihomo fails to start (permission denied on cert) | Incorrect key permissions or user groups | Ensure key permissions are `640 root:ssl-cert` and `mihomo` is in the `ssl-cert` group |
| Fallback site returns 403 Forbidden | Request missing matching Host header | Expected behavior; visiting via browser with the full domain name loads correctly |

---

## Step 9: Seamless Hot Upgrades (`upgrade-mihomo.sh`)

When new upstream versions are released, perform an in-place upgrade without downtime using this script:

```bash
cat << 'EOF' > upgrade-mihomo.sh
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must run as root: sudo bash upgrade-mihomo.sh" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  TARGET_ARCH="linux-amd64-compatible" ;;
  aarch64) TARGET_ARCH="linux-arm64" ;;
  *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

LATEST_TAG=$(curl -sSL "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4)
echo ">> Latest available version: $LATEST_TAG"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sSL -o "$TMP_DIR/mihomo.gz" "https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/mihomo-${TARGET_ARCH}-${LATEST_TAG}.gz"
gzip -dc "$TMP_DIR/mihomo.gz" > "$TMP_DIR/mihomo"
chmod +x "$TMP_DIR/mihomo"

# Overwrite binary and seamlessly restart service
install -m 755 "$TMP_DIR/mihomo" /usr/local/bin/mihomo
systemctl restart mihomo
systemctl status mihomo --no-pager
echo ">> Successfully upgraded mihomo to $LATEST_TAG"
EOF

sudo bash upgrade-mihomo.sh
rm -f upgrade-mihomo.sh
```

---

## Conclusion

For a personal roaming gateway, reliability and zero-headache operation trump everything else. Arch Linux provides the ideal foundation here: its rolling-release model eliminates the dread of breaking configurations during major distribution upgrades. An occasional two-minute monthly update keeps your entire platform pristine, while the one-click hot-upgrade script handles the daemon smoothly. This deployment gives you a resilient, quiet, and dependable gateway you can rely on long-term.
