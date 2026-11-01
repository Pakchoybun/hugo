---
title: Deploying Mihomo (Hysteria2) Behind PF and Hiawatha on FreeBSD 15
date: 2026-09-26T13:05:02+08:00
draft: false
tags:
  - Others
---
# Hardening FreeBSD 15 as an Ultra-Stealth Proxy Node: A Complete Production Architecture with mihomo (Hysteria2), Hiawatha, and PF

Running an evasion-resistant proxy node on public clouds requires more than just launching a proxy binary. Modern active-probing engines, deep packet inspection (DPI), port scanning, and cloud provider network abuse monitors require defense-in-depth across the operating system kernel, packet filter, TLS pipeline, and web masquerade layer.

This guide provides a comprehensive, production-tested blueprint for deploying **mihomo (Hysteria2 protocol)** behind **Hiawatha Web Server** and FreeBSD's native **PF (Packet Filter)** on **FreeBSD 15 (amd64)**. The entire architecture is 100% filesystem-agnostic (fully compatible with standard UFS/FFS as well as ZFS).

All sensitive credentials, domain names, and IP addresses in this guide have been sanitized with RFC-compliant documentation placeholders (`proxy.example.com`, `198.51.100.10`).

---

## 1. Architecture Overview & Traffic Flow

```text
Client Traffic (UDP Port Hopping: 39999-50001)
         │
         ▼
FreeBSD Public Interface (e.g., vtnet0)
         │
         ├─► [PF Firewall] ──► Drop IPv6 probes (`block drop in quick inet6`)
         │                 ──► Instant drop if in `<scan_blacklist>`
         │                 ──► Rate-limit SSH brute force (auto-blacklist)
         │
         └─► [PF Inline Redirection (rdr-to)]
                   39999-50001/udp ──► 127.0.0.1:18921 (Loopback)
                                             │
                                             ▼
                                  [mihomo Daemon (Hysteria2)]
                                  - Unprivileged user `mihomo`
                                  - Bound strictly to 127.0.0.1:18921/udp
                                  - External controller (9090) disabled
                                  - Outbound egress restricted from <private_nets>
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [Valid Auth Token]                         [Invalid / Probe / Web]
         Safe outbound Internet egress                Fallback to local loopback
         (Double-layer RFC1918 block)                 https://127.0.0.1:443
                                                                   │
                                                                   ▼
                                                       [Hiawatha Web Server]
                                                       - Port 80 (HTTP 301 -> 443)
                                                       - Port 443 (ZeroSSL + SNI)
                                                       - Built-in SQLi/XSS/CSRF shield
```

### Key Security Objectives

1. **Zero External Surface for Proxy Daemon**: The proxy core listens exclusively on `127.0.0.1:18921/udp`. External scanners cannot reach the port directly.
2. **Dynamic UDP Port Hopping**: Traffic hits a designated range (e.g., `39999:50001`), which PF translates inline (`rdr-to`) directly to `127.0.0.1:18921`.
3. **Loopback-Isolated Masquerade**: Active probes and unauthenticated handshakes fall back to Hiawatha serving legitimate static content over TLS. Mapping the domain to `127.0.0.1` in `/etc/hosts` prevents hair-pinning through public DNS or external interfaces.
4. **Outbound SSRF & Netscan Protection**: Both PF kernel rules and mihomo routing rules strictly block proxy egress to private subnets, CGNAT, loopback, and cloud metadata endpoints (`169.254.169.254`).
5. **Atomic, Zero-Leak Certificate Lifecycle**: Private keys never hit `/tmp`. ZeroSSL certificates are merged using atomic permissions (`640 root:ssl-cert`) inside protected directories.
6. **Kernel Anti-Probing & Process Isolation**: FreeBSD's `security.bsd.*` and `net.inet.tcp/udp.blackhole` parameters prevent inter-user process snooping and silently drop scanning probes.

---

## 2. Port Allocation Matrix

| Port / Protocol | Service | Exposure | Security Policy |
| :--- | :--- | :--- | :--- |
| `[CUSTOM_SSH_PORT]/tcp` | OpenSSH | Public | Public-key only, max 4 conns/min before PF auto-blacklist |
| `80/tcp` | Hiawatha Web | Public | HTTP 301 redirect to HTTPS via `RequireTLS` |
| `443/tcp` | Hiawatha Web | Public | ZeroSSL TLS 1.3/1.2 masquerade site |
| `18921/udp` | mihomo core | Localhost (`127.0.0.1`) | Receives redirected UDP packets only; unexposed to WAN |
| `39999-50001/udp` | Port Hop Range | Public (via PF) | Evaluated through PF blacklist first, then forwarded |
| `IPv6 (All)` | - | Blocked | `block drop in quick inet6` |

---

## 3. Step 0: Non-Root Operator & OpenSSH Hardening

Always administer FreeBSD via a dedicated `wheel` user rather than direct `root` login.

### 1. Set Root Password and Create Operator Account

```bash
# Ensure root has a strong local password for single-user emergency VNC recovery
passwd root

# Create administrative user (e.g., 'operator')
pw useradd operator -m -G wheel -s /bin/sh
chmod 750 /home/operator
passwd operator
```

Allow `wheel` members to use `sudo`:
```bash
visudo
# Uncomment:
# %wheel ALL=(ALL:ALL) ALL
```

### 2. Configure OpenSSH Hardening

OpenSSH enforces **first-match-wins** when parsing configuration files. Ensure `Include` directives sit at the top of `/etc/ssh/sshd_config`.

```bash
sudo mkdir -p /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
Port 28622
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Ensure the Include line is at the top of sshd_config
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
  sudo sh -c '{ printf "Include /etc/ssh/sshd_config.d/*.conf\n\n"; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.new && mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config'
fi

sudo chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/99-hardening.conf

# Verify configuration before reloading
sudo sshd -t
sudo sshd -T | grep -E '^(port|permitrootlogin) '
sudo service sshd reload
```

---

## 4. Step 1: Base System Hardening (`01-setup-system.sh`)

Save this script as `01-setup-system.sh` and execute with `sudo sh 01-setup-system.sh`. It automates dependencies installation, account isolation, kernel parameter tuning, and log rotation.

```bash
#!/usr/bin/env sh
# ==============================================================================
# 01-setup-system.sh - FreeBSD 15 System Environment & Kernel Hardening
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must be run as root." >&2
  exit 1
fi

LOGIN_USER="${SUDO_USER:-}"
if [ -z "$LOGIN_USER" ] || [ "$LOGIN_USER" = "root" ]; then
  LOGIN_USER="$(logname 2>/dev/null || true)"
fi

echo "=================================================="
echo " [Step 1/6] Installing system dependencies (pkg)..."
echo "=================================================="
pkg update
pkg install -y hiawatha py311-certbot py311-certbot-dns-cloudflare curl ca_root_nss sudo wget

echo "=================================================="
echo " [Step 2/6] Configuring service accounts and group isolation..."
echo "=================================================="
if ! pw group show ssl-cert >/dev/null 2>&1; then
  pw groupadd ssl-cert
  echo ">> Created group: ssl-cert"
fi

if ! pw user show mihomo >/dev/null 2>&1; then
  pw useradd mihomo -s /usr/sbin/nologin -d /nonexistent -c "mihomo service user"
  echo ">> Created service user: mihomo"
fi

# Add both mihomo and Hiawatha's worker (www) to ssl-cert to share certificates
pw groupmod ssl-cert -m mihomo
pw groupmod ssl-cert -m www

# Lock redundant UID 0 account (toor)
if pw user show toor >/dev/null 2>&1; then
  pw lock toor
  echo ">> Locked toor account"
fi

# Harden console TTY: single-user mode requires root password
if [ -f /etc/ttys ]; then
  sed -i '' -E 's/^(console[[:space:]]+.*[[:space:]]+)secure/\1insecure/' /etc/ttys 2>/dev/null || true
  echo ">> Hardened /etc/ttys console security level (insecure)"
  ROOT_HASH="$(awk -F: '$1=="root"{print $2; exit}' /etc/master.passwd 2>/dev/null || true)"
  if [ -z "$ROOT_HASH" ] || [ "$ROOT_HASH" = "*" ] || [ "$ROOT_HASH" = "!" ]; then
    echo "   [Notice] Root does not have a local password set! Run 'sudo passwd root' for VNC rescue."
  fi
fi

echo "=================================================="
echo " [Step 3/6] Initializing protected directory hierarchy..."
echo "=================================================="
mkdir -p /usr/local/etc/mihomo
chown root:mihomo /usr/local/etc/mihomo
chmod 750 /usr/local/etc/mihomo

mkdir -p /var/db/mihomo
chown mihomo:mihomo /var/db/mihomo
chmod 750 /var/db/mihomo

# Standard backup directory (compliant with FreeBSD hier(7))
install -d -m 700 -o root -g wheel /var/backups/mihomo

mkdir -p /usr/local/etc/ssl/mihomo
chown -R root:ssl-cert /usr/local/etc/ssl/mihomo
chmod 750 /usr/local/etc/ssl/mihomo

mkdir -p /usr/local/www/hiawatha
chown -R www:www /usr/local/www/hiawatha
chmod 755 /usr/local/www/hiawatha

mkdir -p /var/log/hiawatha
chown www:www /var/log/hiawatha
chmod 750 /var/log/hiawatha

# Tighten file permissions on sensitive configs
[ -f /etc/crontab ] && chmod 600 /etc/crontab
[ -d /etc/cron.d ] && chmod 750 /etc/cron.d
[ -d /usr/local/etc/sudoers.d ] && chmod 750 /usr/local/etc/sudoers.d
[ -f /etc/ssh/sshd_config ] && chmod 600 /etc/ssh/sshd_config
[ -d /etc/ssh/sshd_config.d ] && chmod 600 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
if [ -n "$LOGIN_USER" ] && [ "$LOGIN_USER" != "root" ] && [ -d "/home/$LOGIN_USER" ]; then
  chmod 750 "/home/$LOGIN_USER"
  echo ">> Tightened permissions for /home/$LOGIN_USER -> 750"
fi

echo "=================================================="
echo " [Step 4/6] Applying sysctl kernel hardening..."
echo "=================================================="
SYSCTL_FILE="/etc/sysctl.conf"
touch "$SYSCTL_FILE"

if ! grep -q "====== mihomo security tuning ======" "$SYSCTL_FILE"; then
  printf '\n# ====== mihomo security tuning ======\n' >> "$SYSCTL_FILE"
fi

set_sysctl() {
  key="$1"
  val="$2"
  sysctl "$key=$val" >/dev/null 2>&1 || true
  if grep -q "^[[:space:]]*${key}=" "$SYSCTL_FILE" 2>/dev/null; then
    sed -i '' -E "s|^[[:space:]]*${key}=.*|${key}=${val}|" "$SYSCTL_FILE"
  else
    echo "${key}=${val}" >> "$SYSCTL_FILE"
  fi
}

# TCP/IP stack anti-scanning and silent blackhole
set_sysctl "net.inet.tcp.syncookies" "1"
set_sysctl "net.inet.tcp.blackhole" "2"
set_sysctl "net.inet.udp.blackhole" "1"
set_sysctl "net.inet.icmp.icmplim" "50"
set_sysctl "net.inet.ip.redirect" "0"
set_sysctl "net.inet.ip.sourceroute" "0"
set_sysctl "net.inet.ip.accept_sourceroute" "0"
set_sysctl "net.inet.tcp.drop_synfin" "1"
set_sysctl "net.inet.ip.random_id" "1"
set_sysctl "net.inet.ip.process_options" "0"
set_sysctl "net.inet.icmp.drop_redirect" "1"
set_sysctl "net.inet.tcp.icmp_may_rst" "0"
set_sysctl "net.inet6.ip6.redirect" "0"
set_sysctl "net.inet6.icmp6.rediraccept" "0"

# Process boundary isolation (security.bsd.*)
set_sysctl "security.bsd.see_other_uids" "0"
set_sysctl "security.bsd.see_other_gids" "0"
set_sysctl "security.bsd.unprivileged_proc_debug" "0"
set_sysctl "security.bsd.unprivileged_read_msgbuf" "0"
set_sysctl "security.bsd.hardlink_check_uid" "1"
set_sysctl "security.bsd.hardlink_check_gid" "1"
echo ">> Sysctl parameters applied and persisted."

echo "=================================================="
echo " [Step 5/6] Configuring Hiawatha log rotation..."
echo "=================================================="
cat > /etc/newsyslog.conf.d/hiawatha.conf << 'EOF'
# logfilename                    [owner:group]  mode  count  size   when  flags
/var/log/hiawatha/access.log     www:www        640   3      10240  *     ZNC
/var/log/hiawatha/error.log      www:www        640   3      5120   *     ZNC
/var/log/hiawatha/system.log     www:www        640   3      5120   *     ZNC
/var/log/hiawatha/garbage.log    www:www        640   3      5120   *     ZNC
/var/log/hiawatha/exploit.log    www:www        640   3      5120   *     ZNC
EOF
chmod 644 /etc/newsyslog.conf.d/hiawatha.conf

echo "=================================================="
echo " [Step 6/6] Registering firewall table auto-expiration in root crontab..."
echo "=================================================="
mkdir -p /usr/local/etc/letsencrypt/renewal-hooks/deploy
chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy

CURRENT_CRON="$(crontab -u root -l 2>/dev/null || true)"
if ! printf '%s\n' "$CURRENT_CRON" | grep -q 'scan_blacklist.*expire'; then
  {
    [ -n "$CURRENT_CRON" ] && printf '%s\n' "$CURRENT_CRON"
    printf '# Expire PF scan_blacklist records older than 24 hours daily at 04:00\n'
    printf '0 4 * * * /sbin/pfctl -t scan_blacklist -T expire 86400 >/dev/null 2>&1\n'
  } | crontab -u root -
  echo ">> Added scan_blacklist auto-expiration task to root crontab"
fi

echo ">> System setup complete."
```

---

## 5. Step 2: Packet Filter (PF) Configuration (`/etc/pf.conf`)

FreeBSD 15 adopts the modern OpenBSD-style inline redirection (`pass in ... rdr-to`) syntax. Redirection occurs alongside filtering, eliminating the legacy `rdr pass` bypass flaw.

Save the following content to `/etc/pf.conf`:

```pf
# /etc/pf.conf
# FreeBSD 15 pf firewall rules tailored for Hysteria2 port hopping & anti-probing

# ================= Macros =================
ext_if = "vtnet0"                # Replace with your external interface (e.g., vtnet0, em0)
ssh_port = "28622"               # Your custom SSH port
mihomo_udp_port = "18921"        # Local mihomo listening port
jump_port_range = "39999:50001"  # Hysteria2 UDP port hopping range

# ================= Tables =================
# Stores dynamic attackers (scanners, SSH brute-forcers)
table <scan_blacklist> persist

# Private subnets, loopback, CGNAT, and cloud metadata endpoints
table <private_nets> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }

# ================= Global Options =================
set block-policy drop
set skip on lo0

# Traffic normalization
scrub in on $ext_if all fragment reassemble

# ================= Filtering & Redirection =================
# 1. Silently drop all IPv6 traffic immediately
block drop in quick inet6

# 2. Drop blacklisted traffic before any evaluation or NAT redirection
block drop in quick from <scan_blacklist> to any

# 3. Anti-spoofing
antispoof quick for $ext_if

# 4. Default policy: Drop incoming, allow outgoing
block in all
pass out all keep state

# 5. Outbound containment for user 'mihomo':
#    Allow system DNS lookup, but strictly block private/metadata traversal
pass out quick on $ext_if inet proto { tcp, udp } from any to any port 53 user mihomo keep state
block drop out quick on $ext_if inet proto { tcp, udp } from any to <private_nets> user mihomo

# 6. Modern FreeBSD 15 inline port hopping redirection:
pass in on $ext_if proto udp from any to any port $jump_port_range \
    rdr-to 127.0.0.1 port $mihomo_udp_port keep state

# 7. Expose Hiawatha HTTP and HTTPS
pass in on $ext_if proto tcp from any to any port { 80, 443 } keep state

# 8. Expose SSH with connection-rate throttling
pass in on $ext_if proto tcp from any to any port $ssh_port \
    keep state (max-src-conn 4, max-src-conn-rate 4/60, \
    overload <scan_blacklist> flush global)

# 9. ICMP ping rate control
pass in on $ext_if proto icmp all icmp-type echoreq keep state (max-src-states 5)
```

Enable and start PF:
```bash
sudo chmod 600 /etc/pf.conf
sudo pfctl -nf /etc/pf.conf
sudo sysrc pf_enable="YES"
sudo service pf start
sudo pfctl -f /etc/pf.conf
```

---

## 6. Step 3: ZeroSSL Certificate Lifecycle & Deploy Hook

Hiawatha requires a consolidated PEM file containing the private key followed by the certificate chain (`cat privkey.pem fullchain.pem`). Writing sensitive cryptographic keys to shared `/tmp` space creates symlink and unprivileged read vulnerabilities. 

### 1. Cloudflare DNS-01 Credentials

```bash
sudo mkdir -p /usr/local/etc/letsencrypt
sudo tee /usr/local/etc/letsencrypt/cloudflare.ini << 'EOF'
dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN
EOF
sudo chmod 600 /usr/local/etc/letsencrypt/cloudflare.ini
```

### 2. ZeroSSL ACME Registration

Register your account with ZeroSSL External Account Binding (EAB):
```bash
sudo certbot register \
  --email admin@example.com \
  --server https://acme.zerossl.com/v2/DV90 \
  --eab-kid YOUR_ZEROSSL_EAB_KID \
  --eab-hmac-key YOUR_ZEROSSL_EAB_HMAC_KEY \
  --agree-tos
```

### 3. Atomic Deploy Hook (`certbot-deploy-hook.sh`)

Save this script as `/usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh`:

```bash
#!/usr/bin/env sh
# ==============================================================================
# certbot-deploy-hook.sh - FreeBSD Hiawatha & mihomo Atomic TLS Distribution
# ==============================================================================
set -eu

DEFAULT_DOMAIN="proxy.example.com"

if [ -n "${1:-}" ]; then
  CERT_DIR="/usr/local/etc/letsencrypt/live/$1"
elif [ -n "${RENEWED_LINEAGE:-}" ] && [ -d "${RENEWED_LINEAGE}" ]; then
  CERT_DIR="${RENEWED_LINEAGE}"
else
  DOMAIN="$DEFAULT_DOMAIN"
  if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "proxy.example.com" ]; then
    if [ -d /usr/local/etc/letsencrypt/live ]; then
      DOMAIN="$(ls -1 /usr/local/etc/letsencrypt/live 2>/dev/null | grep -v '^README$' | head -1 || true)"
    fi
  fi
  CERT_DIR="/usr/local/etc/letsencrypt/live/$DOMAIN"
fi

DEST_DIR="/usr/local/etc/ssl/mihomo"
HIAWATHA_PEM="$DEST_DIR/hiawatha.pem"
TMP_PEM="$DEST_DIR/.hiawatha.pem.tmp.$$"

if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
  echo "[-] Error: Missing certificate files in $CERT_DIR" >&2
  exit 1
fi

trap 'rm -f "$TMP_PEM"' EXIT INT TERM

# Ensure destination directory exists with proper permissions
install -d -m 750 -o root -g ssl-cert "$DEST_DIR"

# 1. Install standard certificates with atomic permissions for mihomo
install -m 640 -o root -g ssl-cert "$CERT_DIR/fullchain.pem" "$DEST_DIR/fullchain.pem"
install -m 640 -o root -g ssl-cert "$CERT_DIR/privkey.pem" "$DEST_DIR/privkey.pem"

# 2. Merge private key and fullchain inside target directory under umask 077
(
  umask 077
  cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$TMP_PEM"
)
chown root:ssl-cert "$TMP_PEM"
chmod 640 "$TMP_PEM"
mv -f "$TMP_PEM" "$HIAWATHA_PEM"

# 3. Reload running services
if service hiawatha status >/dev/null 2>&1; then
  service hiawatha restart >/dev/null 2>&1 || true
fi

if service mihomo status >/dev/null 2>&1; then
  service mihomo restart >/dev/null 2>&1 || true
fi

echo "TLS deploy hook completed successfully."
```

```bash
sudo chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

> **Important**: Do not leave `.bak` or backup files in `renewal-hooks/deploy/`. Certbot executes every executable file in that directory during renewals!

### 4. Issue Certificate and Configure Cron

```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /usr/local/etc/letsencrypt/cloudflare.ini \
  --server https://acme.zerossl.com/v2/DV90 \
  -d proxy.example.com \
  --deploy-hook /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

Add automatic renewal to root's crontab:
```bash
sudo crontab -e
# Append:
0 3,15 * * * /usr/local/bin/certbot renew --quiet
```

---

## 7. Step 4: Web Masquerade Site (Hiawatha)

Hiawatha is designed specifically for security and low resource consumption. It features out-of-the-box protection against SQL injection, XSS, and CSRF attacks.

### 1. Configure `/usr/local/etc/hiawatha/hiawatha.conf`

```text
# /usr/local/etc/hiawatha/hiawatha.conf
# Hiawatha Web Server configuration for FreeBSD 15

# ================= Global Settings =================
ServerId = www
ConnectionsTotal = 1000
ConnectionsPerIP = 50
SystemLogfile = /var/log/hiawatha/system.log
GarbageLogfile = /var/log/hiawatha/garbage.log
ExploitLogfile = /var/log/hiawatha/exploit.log

# Cloak webserver banner
ServerString = Webserver

# ================= Security & Bans =================
# BanOnGarbage is intentionally disabled: Hysteria2 masquerade traffic originates from 127.0.0.1.
# Enabling BanOnGarbage would cause localhost to ban itself.
BanOnMaxPerIP = 60
BanOnMaxReqSize = 300
BanOnSQLi = 120
KickOnBan = yes
RebanDuringBan = yes

# ================= Port Bindings =================
# HTTP (80)
Binding {
    Port = 80
    Interface = 0.0.0.0
}

# HTTPS (443)
Binding {
    Port = 443
    Interface = 0.0.0.0
    TLScertFile = /usr/local/etc/ssl/mihomo/hiawatha.pem
}

# ================= Virtual Host =================
VirtualHost {
    Hostname = proxy.example.com
    WebsiteRoot = /usr/local/www/hiawatha
    StartFile = index.html
    AccessLogfile = /var/log/hiawatha/access.log
    ErrorLogfile = /var/log/hiawatha/error.log

    # Force HTTP -> HTTPS 301 Redirect + HSTS (31 days)
    RequireTLS = yes, 2678400

    ShowIndex = no

    # Built-in security shields
    PreventXSS = prevent
    PreventSQLi = prevent
    PreventCSRF = prevent

    # HTTP Response Header Hardening
    CustomHeaderClient = X-Frame-Options: SAMEORIGIN
    CustomHeaderClient = X-Content-Type-Options: nosniff
    CustomHeaderClient = Referrer-Policy: strict-origin-when-cross-origin
}
```

### 2. Configure Local Host Loopback

Prevent DNS queries from hairpinning out to public resolvers when mihomo falls back to the masquerade web site:

```bash
grep -qF "proxy.example.com" /etc/hosts || printf '\n127.0.0.1 proxy.example.com\n' | sudo tee -a /etc/hosts
```

Deploy a static site to `/usr/local/www/hiawatha/index.html`, then start Hiawatha:

```bash
sudo sysrc hiawatha_enable="YES"
sudo service hiawatha start
```

---

## 8. Step 5: Core Proxy Service (mihomo)

### 1. Download and Install mihomo Binary (`02-install-mihomo.sh`)

Save this script as `02-install-mihomo.sh` and execute with `sudo sh 02-install-mihomo.sh`:

```bash
#!/usr/bin/env sh
# ==============================================================================
# 02-install-mihomo.sh - mihomo Binary Downloader & Installer (FreeBSD 15)
# ==============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must be run as root: sudo sh 02-install-mihomo.sh" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/mihomo_install.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Detect architecture
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac

echo ">> Querying latest release tag from GitHub..."
LATEST_TAG="$(curl -sI https://github.com/MetaCubeX/mihomo/releases/latest \
  | grep -i '^location:' | tr -d '\r' | sed -E 's#.*/tag/##' || true)"

if [ -z "$LATEST_TAG" ]; then
  echo ">> Fallback: Trying GitHub API..."
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

LATEST_TAG="${MIHOMO_TAG:-$LATEST_TAG}"

if [ -z "$LATEST_TAG" ]; then
  echo "Error: Failed to fetch latest tag. Set MIHOMO_TAG manually." >&2
  exit 1
fi

echo ">> Target version: $LATEST_TAG ($ARCH)"
ASSET="mihomo-freebsd-${ARCH}-${LATEST_TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/${ASSET}"
DEST_GZ="$WORK_DIR/mihomo.gz"

echo ">> Downloading $URL ..."
if ! curl -fL --retry 3 --retry-delay 2 -o "$DEST_GZ" "$URL"; then
  echo "Error: Download failed." >&2
  exit 1
fi

if [ -n "${MIHOMO_SHA256:-}" ]; then
  echo ">> Verifying SHA256..."
  ACTUAL_SHA="$(sha256 -q "$DEST_GZ" 2>/dev/null || sha256sum "$DEST_GZ" | cut -d' ' -f1)"
  if [ "$ACTUAL_SHA" != "$MIHOMO_SHA256" ]; then
    echo "Error: SHA256 mismatch! Expected: $MIHOMO_SHA256, got: $ACTUAL_SHA" >&2
    exit 1
  fi
  echo ">> SHA256 checksum OK."
fi

echo ">> Decompressing and verifying..."
gunzip -c "$DEST_GZ" > "$WORK_DIR/mihomo"
chmod 755 "$WORK_DIR/mihomo"

if ! "$WORK_DIR/mihomo" -v >/dev/null 2>&1; then
  echo "Error: Binary failed to execute." >&2
  exit 1
fi

install -m 755 -o root -g wheel "$WORK_DIR/mihomo" /usr/local/bin/mihomo

# Link Geo databases if present
if [ -d "/var/db/mihomo" ]; then
  for f in geoip.dat geosite.dat country.mmdb GeoLite2-ASN.mmdb; do
    if [ -f "/usr/local/etc/mihomo/$f" ] && [ ! -e "/var/db/mihomo/$f" ]; then
      ln -sf "/usr/local/etc/mihomo/$f" "/var/db/mihomo/$f"
      chown -h mihomo:mihomo "/var/db/mihomo/$f" 2>/dev/null || true
    fi
  done
fi

echo "=================================================="
echo " [Done] mihomo binary installed successfully!"
/usr/local/bin/mihomo -v
echo "=================================================="
```

### 2. Generate ECH Keypair

```bash
mihomo generate ech-keypair cloudflare.com
```

### 3. Server Configuration (`/usr/local/etc/mihomo/config.yaml`)

```yaml
# /usr/local/etc/mihomo/config.yaml
# Production Hysteria2 Server Configuration for FreeBSD 15

log-level: warning
ipv6: false

# Disable process lookup to minimize syscall overhead
find-process-mode: off

# External controller disabled for zero local surface
# external-controller: 127.0.0.1:9090

profile:
  store-selected: false
  store-fake-ip: false

listeners:
  - name: hy2-in
    type: hysteria2
    port: 18921
    listen: 127.0.0.1

    users:
      hy2-user: "YOUR_GENERATED_STRONG_PASSWORD"

    up: 100
    down: 100

    ignore-client-bandwidth: true

    # Web masquerade destination (resolves to 127.0.0.1 via /etc/hosts)
    masquerade: "https://proxy.example.com"

    alpn:
      - h3

    certificate: /usr/local/etc/ssl/mihomo/fullchain.pem
    private-key: /usr/local/etc/ssl/mihomo/privkey.pem

    # ECH Private Key
    ech-key: |
      -----BEGIN PRIVATE KEY-----
      YOUR_ECH_PRIVATE_KEY
      -----END PRIVATE KEY-----

# Outbound Egress Isolation:
# Blocks private RFC1918 subnets, loopback, and cloud metadata without needing GeoIP databases
rules:
  - DOMAIN,localhost,REJECT
  - DOMAIN-SUFFIX,local,REJECT
  - DOMAIN-SUFFIX,internal,REJECT
  - DOMAIN-SUFFIX,lan,REJECT
  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve
  - IP-CIDR,10.0.0.0/8,REJECT,no-resolve
  - IP-CIDR,172.16.0.0/12,REJECT,no-resolve
  - IP-CIDR,192.168.0.0/16,REJECT,no-resolve
  - IP-CIDR,169.254.0.0/16,REJECT,no-resolve
  - IP-CIDR,100.64.0.0/10,REJECT,no-resolve
  - IP-CIDR6,::1/128,REJECT,no-resolve
  - IP-CIDR6,fc00::/7,REJECT,no-resolve
  - IP-CIDR6,fe80::/10,REJECT,no-resolve
  - MATCH,DIRECT
```

Apply correct permissions and test syntax:
```bash
sudo chmod 640 /usr/local/etc/mihomo/config.yaml
sudo chown root:mihomo /usr/local/etc/mihomo/config.yaml
sudo /usr/local/bin/mihomo -t -d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml
sudo chown -R mihomo:mihomo /var/db/mihomo
```

### 4. Create FreeBSD rc.d Service (`/usr/local/etc/rc.d/mihomo`)

Save this file as `/usr/local/etc/rc.d/mihomo`:

```sh
#!/bin/sh
#
# PROVIDE: mihomo
# REQUIRE: NETWORKING pf
# KEYWORD: shutdown
#
# Configuration:
# In /etc/rc.conf:
# mihomo_enable="YES"
#
# Path: /usr/local/etc/rc.d/mihomo
# Permissions: chmod 755 /usr/local/etc/rc.d/mihomo

. /etc/rc.subr

name="mihomo"
rcvar="mihomo_enable"

load_rc_config $name
: ${mihomo_enable:="NO"}
: ${mihomo_run_user:="mihomo"}

pidfile="/var/run/${name}.pid"

# Elevate descriptor limits in root context before daemon drops privileges
mihomo_limits="-n 200000"

# Use FreeBSD native daemon supervisor:
#   -r : Respawn child automatically 1s after crash
#   -P : Supervise PID file for clean service control
#   -S -T : Route stdout/stderr to syslog (tag 'mihomo')
#   -u : Drop privileges to unprivileged service user
command="/usr/sbin/daemon"
procname="/usr/sbin/daemon"
mihomo_command="/usr/local/bin/mihomo"
mihomo_args="-d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml"
command_args="-r -S -T ${name} -P ${pidfile} -u ${mihomo_run_user} ${mihomo_command} ${mihomo_args}"

run_rc_command "$1"
```

```bash
sudo chmod 755 /usr/local/etc/rc.d/mihomo
sudo sysrc mihomo_enable="YES"
sudo service mihomo start
sudo service mihomo status
```

---

## 9. Step 6: Full-Stack Health & Security Verification Suite (`99-verify.sh`)

Save this script as `99-verify.sh`. It checks daemons, port exposure, FreeBSD 15 `rdr-to` PF rules, kernel sysctls, octal bitmask permissions, and performs a live SNI loopback handshake.

```bash
#!/usr/bin/env sh
# ==============================================================================
# 99-verify.sh (mihomo-verify) - FreeBSD 15 Full-Stack Audit Tool
# ==============================================================================
# Usage:
#   sudo sh 99-verify.sh            # Run audit once
#   sudo sh 99-verify.sh --install  # Install permanently as /usr/local/sbin/mihomo-verify
#   sudo mihomo-verify              # Run routine checks anytime
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  printf '[-] Error: Must be run as root: sudo sh %s\n' "$0" >&2
  exit 1
fi

if [ "${1:-}" = "--install" ]; then
  install -m 755 -o root -g wheel "$0" /usr/local/sbin/mihomo-verify
  printf '[+] Installed audit utility: /usr/local/sbin/mihomo-verify\n'
fi

TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0

c_green='\033[32m'
c_red='\033[31m'
c_yellow='\033[33m'
c_blue='\033[34m'
c_bold='\033[1m'
c_reset='\033[0m'

pass() {
  printf "  [ ${c_green}PASS${c_reset} ] %s\n" "$1"
  TOTAL_PASS=$((TOTAL_PASS + 1))
}

warn() {
  printf "  [ ${c_yellow}WARN${c_reset} ] %s\n" "$1"
  TOTAL_WARN=$((TOTAL_WARN + 1))
}

fail() {
  printf "  [ ${c_red}FAIL${c_reset} ] %s\n" "$1"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
}

info() {
  printf "${c_bold}${c_blue}==>${c_reset} ${c_bold}%s${c_reset}\n" "$1"
}

# Automatically extract configured masquerade domain
MASQ_DOMAIN=""
if [ -f /usr/local/etc/mihomo/config.yaml ]; then
  MASQ_DOMAIN="$(sed -nE 's|^[[:space:]]*masquerade:[[:space:]]*"?https?://([^"/:[:space:]]+).*|\1|p' /usr/local/etc/mihomo/config.yaml | head -1 || true)"
fi
if [ -z "$MASQ_DOMAIN" ] && [ -f /usr/local/etc/hiawatha/hiawatha.conf ]; then
  MASQ_DOMAIN="$(sed -nE 's|^[[:space:]]*Hostname[[:space:]]*=[[:space:]]*([^[:space:],#]+).*|\1|p' /usr/local/etc/hiawatha/hiawatha.conf | head -1 || true)"
fi

printf "\n================================================================================\n"
printf "  FreeBSD 15 Proxy Node Full-Stack Audit - %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
printf "================================================================================\n\n"

# ------------------------------------------------------------------------------
# 1. Daemon Status
# ------------------------------------------------------------------------------
info "1. Core Service Status"

if service pf status >/dev/null 2>&1; then
  pass "pf Firewall Service: Running (Enabled)"
else
  fail "pf Firewall Service is not active"
fi

if service hiawatha status >/dev/null 2>&1; then
  HIA_PID="$(service hiawatha status 2>/dev/null | awk '{print $NF}' | tr -d '.' || true)"
  pass "Hiawatha Web Server: Running (PID: ${HIA_PID:-Running})"
else
  fail "Hiawatha Web Server is not running"
fi

if service mihomo status >/dev/null 2>&1; then
  MI_PID="$(service mihomo status 2>/dev/null | awk '{print $NF}' | tr -d '.' || true)"
  if grep -q -- '-r' /usr/local/etc/rc.d/mihomo 2>/dev/null; then
    pass "mihomo Core Service: Running (PID: ${MI_PID:-Running}, Crash auto-restart enabled)"
  else
    pass "mihomo Core Service: Running (PID: ${MI_PID:-Running})"
  fi
else
  fail "mihomo service is not running"
fi

# ------------------------------------------------------------------------------
# 2. Port Listeners & Exposure
# ------------------------------------------------------------------------------
printf "\n"
info "2. Network Exposure & Port Verification"

if sockstat -4l | grep -q '127\.0\.0\.1:18921'; then
  if sockstat -4l | grep ':18921 ' | grep -qv '127\.0\.0\.1:18921'; then
    warn "18921/udp is bound to non-loopback address"
  else
    pass "mihomo Listen: Bound strictly to 127.0.0.1:18921/udp (Zero WAN surface)"
  fi
else
  fail "127.0.0.1:18921/udp listener not found"
fi

if sockstat -4l | grep -q ':9090 '; then
  warn "External controller port 9090 is listening; recommend disabling"
else
  pass "External Controller (9090): Closed"
fi

if sockstat -4l | grep -q ':80 ' && sockstat -4l | grep -q ':443 '; then
  pass "Hiawatha Ports: 80/tcp and 443/tcp active"
else
  warn "Hiawatha is not listening on both ports 80 and 443"
fi

SSH_PORT="$(/usr/sbin/sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || echo "unknown")"
ROOT_LOGIN="$(/usr/sbin/sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2; exit}' || echo "unknown")"
if [ "$ROOT_LOGIN" = "no" ]; then
  pass "SSH Policy: PermitRootLogin = no (Port: $SSH_PORT)"
else
  warn "SSH PermitRootLogin is currently $ROOT_LOGIN"
fi

# ------------------------------------------------------------------------------
# 3. Packet Filter Rules
# ------------------------------------------------------------------------------
printf "\n"
info "3. Packet Filter Rules & Outbound Isolation"

PF_RULES="$(/sbin/pfctl -sr 2>/dev/null || true)"
PF_TABLES="$(/sbin/pfctl -s Tables 2>/dev/null || true)"

if printf '%s\n' "$PF_RULES" | grep -q 'block drop in quick inet6'; then
  pass "IPv6 Defense: block drop in quick inet6 active"
else
  warn "IPv6 drop rule missing"
fi

if printf '%s\n' "$PF_TABLES" | grep -q 'scan_blacklist'; then
  BL_COUNT="$(/sbin/pfctl -t scan_blacklist -T show 2>/dev/null | wc -l | tr -d ' ')"
  pass "Dynamic Blacklist: <scan_blacklist> loaded (Count: $BL_COUNT)"
else
  fail "Table <scan_blacklist> not found in PF"
fi

if printf '%s\n' "$PF_TABLES" | grep -q 'private_nets'; then
  pass "Outbound Table: <private_nets> loaded"
else
  warn "Table <private_nets> not found"
fi

# Notice: FreeBSD pfctl -sr expands 'user mihomo' to numeric UID
if printf '%s\n' "$PF_RULES" | grep -qE 'block drop out quick .* to <private_nets> user'; then
  pass "Kernel Egress Isolation: block drop out quick ... to <private_nets> active"
else
  warn "Kernel outbound private_nets isolation for user mihomo missing"
fi

# Check FreeBSD 15 inline rdr-to vs legacy rdr
if printf '%s\n' "$PF_RULES" | grep -qE '(pass|match) in .*proto udp .*rdr-to 127\.0\.0\.1 port 18921'; then
  RDR_ORDER_OK="$(printf '%s\n' "$PF_RULES" | awk '
    /block drop in quick.*<scan_blacklist>/ { seen_bl = 1 }
    /(pass|match) in .*proto udp .*rdr-to 127\.0\.0\.1 port 18921/ {
      print (seen_bl ? "1" : "0")
      exit
    }
  ')"
  if [ "$RDR_ORDER_OK" = "1" ]; then
    pass "UDP Port Hopping: FreeBSD 15 rdr-to 127.0.0.1:18921 active & protected by blacklist"
  else
    warn "rdr-to is active, but block drop from scan_blacklist should precede it"
  fi
elif /sbin/pfctl -sn 2>/dev/null | grep -q 'rdr .* -> 127.0.0.1 port 18921'; then
  if /sbin/pfctl -sn 2>/dev/null | grep -q 'rdr pass '; then
    warn "Legacy rdr contains 'pass' keyword which may bypass blacklist"
  else
    pass "UDP Port Hopping: Legacy NAT rdr -> 127.0.0.1:18921 active"
  fi
else
  fail "No UDP redirection rule to 127.0.0.1:18921 detected"
fi

# ------------------------------------------------------------------------------
# 4. Sysctl Anti-Probing
# ------------------------------------------------------------------------------
printf "\n"
info "4. Kernel Anti-Probing & Isolation (sysctl)"

check_sysctl() {
  key="$1"
  exp="$2"
  desc="$3"
  act="$(sysctl -n "$key" 2>/dev/null || echo "UNSET")"
  if [ "$act" = "$exp" ]; then
    pass "$desc ($key = $act)"
  else
    warn "$desc mismatch ($key current: $act, expected: $exp)"
  fi
}

check_sysctl "security.bsd.see_other_uids" "0" "Process View Isolation"
check_sysctl "security.bsd.unprivileged_proc_debug" "0" "Unprivileged Debug Ban"
check_sysctl "security.bsd.unprivileged_read_msgbuf" "0" "Kernel Ring Buffer Protection"
check_sysctl "net.inet.tcp.blackhole" "2" "TCP Silent Blackhole"
check_sysctl "net.inet.udp.blackhole" "1" "UDP Silent Blackhole"
check_sysctl "net.inet.tcp.drop_synfin" "1" "SYN+FIN Probe Drop"
check_sysctl "net.inet.ip.random_id" "1" "IP ID Randomization"
check_sysctl "net.inet.ip.process_options" "0" "IP Options Drop"

# ------------------------------------------------------------------------------
# 5. Accounts & Permissions
# ------------------------------------------------------------------------------
printf "\n"
info "5. Account Security & Permissions"

if pw user show toor 2>/dev/null | grep -q '\*LOCKED\*'; then
  pass "Redundant UID 0 Account (toor): Locked"
else
  warn "Account toor is not locked"
fi

if grep -qE '^console[[:space:]]+.*[[:space:]]+insecure' /etc/ttys 2>/dev/null; then
  pass "Console TTY Mode: insecure (Single-user mode requires root password)"
  ROOT_HASH="$(awk -F: '$1=="root"{print $2; exit}' /etc/master.passwd 2>/dev/null || true)"
  if [ -z "$ROOT_HASH" ] || [ "$ROOT_HASH" = "*" ] || [ "$ROOT_HASH" = "!" ]; then
    warn "Root does not have a local password! Run 'sudo passwd root'"
  else
    pass "VNC Emergency Access: Root password hash set"
  fi
else
  warn "/etc/ttys console is not in insecure mode"
fi

check_perm() {
  file="$1"
  max_mode="$2"
  desc="$3"
  if [ -e "$file" ]; then
    mode="$(stat -f "%OLp" "$file" 2>/dev/null || stat -c "%a" "$file" 2>/dev/null || echo "777")"
    if [ $(( 0$mode & ~0$max_mode )) -eq 0 ]; then
      pass "$desc: $file (Mode: $mode <= $max_mode)"
    else
      warn "$desc has loose permissions: $file (Current: $mode, Target: $max_mode)"
    fi
  fi
}

check_perm "/etc/crontab" "600" "System crontab"
check_perm "/etc/pf.conf" "600" "PF firewall config"
check_perm "/etc/ssh/sshd_config" "600" "OpenSSH config"
check_perm "/usr/local/etc/mihomo/config.yaml" "640" "mihomo config"
check_perm "/usr/local/etc/ssl/mihomo/fullchain.pem" "640" "TLS fullchain"
check_perm "/usr/local/etc/ssl/mihomo/privkey.pem" "640" "TLS privkey"
check_perm "/usr/local/etc/ssl/mihomo/hiawatha.pem" "640" "Hiawatha combined PEM"

# ------------------------------------------------------------------------------
# 6. Scheduled Maintenance
# ------------------------------------------------------------------------------
printf "\n"
info "6. Scheduled Maintenance & Log Rotation"

ROOT_CRON="$(crontab -u root -l 2>/dev/null || true)"

if printf '%s\n' "$ROOT_CRON" | grep -q 'certbot.*renew'; then
  pass "Certbot Auto-Renewal: Registered in crontab"
else
  warn "Certbot auto-renewal task missing from root crontab"
fi

if printf '%s\n' "$ROOT_CRON" | grep -q 'scan_blacklist.*expire'; then
  pass "Blacklist Auto-Expiration: Registered in crontab (24h TTL)"
else
  warn "Table scan_blacklist expiration task missing"
fi

if [ -f "/etc/newsyslog.conf.d/hiawatha.conf" ]; then
  pass "Hiawatha Log Rotation: /etc/newsyslog.conf.d/hiawatha.conf active"
else
  warn "Hiawatha log rotation config missing"
fi

# ------------------------------------------------------------------------------
# 7. TLS Validity & Loopback End-to-End Test
# ------------------------------------------------------------------------------
printf "\n"
info "7. TLS Validity & Loopback E2E Test"

PEM_FILE="/usr/local/etc/ssl/mihomo/fullchain.pem"
if [ -f "$PEM_FILE" ] && command -v openssl >/dev/null 2>&1; then
  END_DATE_RAW="$(LC_ALL=C openssl x509 -enddate -noout -in "$PEM_FILE" 2>/dev/null | cut -d= -f2 || true)"
  END_EPOCH="$(LC_ALL=C date -j -f "%b %e %T %Y %Z" "$END_DATE_RAW" "+%s" 2>/dev/null || LC_ALL=C date -d "$END_DATE_RAW" "+%s" 2>/dev/null || echo "0")"
  NOW_EPOCH="$(date "+%s")"

  if [ "$END_EPOCH" -gt 0 ]; then
    if [ "$END_EPOCH" -gt "$NOW_EPOCH" ]; then
      DAYS_LEFT=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
      if [ "$DAYS_LEFT" -gt 15 ]; then
        pass "TLS Certificate Status: Valid (Expires: $END_DATE_RAW, $DAYS_LEFT days remaining)"
      else
        warn "TLS Certificate expiring soon: $DAYS_LEFT days remaining"
      fi
    else
      fail "TLS Certificate expired on $END_DATE_RAW"
    fi
  else
    if openssl x509 -checkend 1296000 -noout -in "$PEM_FILE" >/dev/null 2>&1; then
      pass "TLS Certificate Status: Valid (> 15 days)"
    else
      fail "TLS Certificate expired or invalid"
    fi
  fi
else
  warn "Certificate file or openssl binary not found"
fi

if [ -n "$MASQ_DOMAIN" ] && [ "$MASQ_DOMAIN" != "proxy.example.com" ]; then
  if awk -v dom="$MASQ_DOMAIN" '
    /^[[:space:]]*#/ { next }
    $1 == "127.0.0.1" {
      for (i = 2; i <= NF; i++) {
        if ($i == dom) { found = 1; exit }
      }
    }
    END { exit(found ? 0 : 1) }
  ' /etc/hosts 2>/dev/null; then
    pass "Loopback Host Mapping (/etc/hosts): 127.0.0.1 -> $MASQ_DOMAIN"
  else
    warn "/etc/hosts missing 127.0.0.1 -> $MASQ_DOMAIN mapping"
  fi

  if command -v curl >/dev/null 2>&1; then
    HTTP_CODE="$(curl --resolve "${MASQ_DOMAIN}:443:127.0.0.1" -s -o /dev/null -w "%{http_code}" "https://${MASQ_DOMAIN}/" 2>/dev/null || echo "000")"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
      pass "E2E Masquerade Loopback Test (SNI + Cert + VirtualHost): HTTP $HTTP_CODE"
    else
      warn "Loopback masquerade check returned HTTP $HTTP_CODE"
    fi
  fi
fi

# ------------------------------------------------------------------------------
# Summary Report
# ------------------------------------------------------------------------------
printf "\n================================================================================\n"
printf "  Audit Summary Report:\n"
printf "    ${c_green}PASS : %d${c_reset}\n" "$TOTAL_PASS"
printf "    ${c_yellow}WARN : %d${c_reset}\n" "$TOTAL_WARN"
printf "    ${c_red}FAIL : %d${c_reset}\n" "$TOTAL_FAIL"
printf "================================================================================\n"

if [ "$TOTAL_FAIL" -eq 0 ]; then
  printf "  ${c_bold}${c_green}All core defenses and services are operating normally!${c_reset}\n\n"
  exit 0
else
  printf "  ${c_bold}${c_red}Found %d issue(s). Review details above.${c_reset}\n\n" "$TOTAL_FAIL"
  exit 1
fi
```

Install and execute:
```bash
sudo sh 99-verify.sh --install
sudo mihomo-verify
```

---

## 10. Step 7: Zero-Downtime Upgrades (`03-upgrade-mihomo.sh`)

Save this script as `03-upgrade-mihomo.sh` and execute with `sudo sh 03-upgrade-mihomo.sh`. It checks GitHub for new releases, pre-tests the binary and existing configuration in an isolated sandbox, automatically rolls back if health checks fail, and maintains rotating backups in `/var/backups/mihomo/`.

```bash
#!/usr/bin/env sh
# ==============================================================================
# 03-upgrade-mihomo.sh - Zero-Downtime Upgrade & Automated Rollback (FreeBSD 15)
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Must be run as root: sudo sh 03-upgrade-mihomo.sh" >&2
  exit 1
fi

BIN_PATH="/usr/local/bin/mihomo"
BACKUP_ROOT="/var/backups/mihomo"

if [ ! -x "$BIN_PATH" ]; then
  echo "Error: $BIN_PATH not found. Run 02-install-mihomo.sh first." >&2
  exit 1
fi

FORCE="${1:-}"

WORK_DIR="$(mktemp -d /tmp/mihomo_upgrade.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac

CURRENT_VERSION_RAW="$("$BIN_PATH" -v 2>&1 || true)"
CURRENT_TAG="$(printf '%s\n' "$CURRENT_VERSION_RAW" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
echo ">> Current running version: ${CURRENT_TAG:-Unknown}"

echo ">> Querying latest release from GitHub..."
LATEST_TAG="$(curl -sI https://github.com/MetaCubeX/mihomo/releases/latest \
  | grep -i '^location:' | tr -d '\r' | sed -E 's#.*/tag/##' || true)"

if [ -z "$LATEST_TAG" ]; then
  echo ">> Trying GitHub API..."
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

LATEST_TAG="${MIHOMO_TAG:-$LATEST_TAG}"

if [ -z "$LATEST_TAG" ]; then
  echo "Error: Failed to fetch latest release tag." >&2
  exit 1
fi

echo ">> Online latest version: $LATEST_TAG"

if [ -n "$CURRENT_TAG" ] && [ "$CURRENT_TAG" = "$LATEST_TAG" ] && [ "$FORCE" != "--force" ]; then
  echo ">> mihomo is already up to date ($CURRENT_TAG)."
  exit 0
fi

ASSET="mihomo-freebsd-${ARCH}-${LATEST_TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/${ASSET}"
DEST_GZ="$WORK_DIR/mihomo.gz"

echo ">> Downloading $URL ..."
if ! curl -fL --retry 3 --retry-delay 2 -o "$DEST_GZ" "$URL"; then
  echo "Error: Download failed." >&2
  exit 1
fi

if [ -n "${MIHOMO_SHA256:-}" ]; then
  echo ">> Verifying SHA256..."
  ACTUAL_SHA="$(sha256 -q "$DEST_GZ" 2>/dev/null || sha256sum "$DEST_GZ" | cut -d' ' -f1)"
  if [ "$ACTUAL_SHA" != "$MIHOMO_SHA256" ]; then
    echo "Error: SHA256 mismatch!" >&2
    exit 1
  fi
  echo ">> Checksum verified."
fi

echo ">> Decompressing and validating sandbox binary..."
gunzip -c "$DEST_GZ" > "$WORK_DIR/mihomo"
chmod 755 "$WORK_DIR/mihomo"

if ! "$WORK_DIR/mihomo" -v >/dev/null 2>&1; then
  echo "Error: New binary failed execution check. Aborting." >&2
  exit 1
fi

if [ -f "/usr/local/etc/mihomo/config.yaml" ] && [ -d "/var/db/mihomo" ]; then
  if ! "$WORK_DIR/mihomo" -t -d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml >/dev/null 2>&1; then
    echo "Error: New binary failed configuration pre-flight check. Aborting." >&2
    exit 1
  fi
fi

install -d -m 700 -o root -g wheel "$BACKUP_ROOT"
BACKUP_PATH="${BACKUP_ROOT}/mihomo.bak-$(date +%Y%m%d_%H%M%S)"

WAS_RUNNING=0
if service mihomo status >/dev/null 2>&1; then
  WAS_RUNNING=1
  echo ">> Stopping mihomo service..."
  service mihomo stop >/dev/null 2>&1 || true
  sleep 1
fi

echo ">> Backing up current binary to: $BACKUP_PATH"
cp -pf "$BIN_PATH" "$BACKUP_PATH"
chmod 700 "$BACKUP_PATH"

echo ">> Installing new binary to $BIN_PATH ..."
install -m 755 -o root -g wheel "$WORK_DIR/mihomo" "$BIN_PATH"

# Re-link Geo databases if applicable
if [ -d "/var/db/mihomo" ]; then
  for f in geoip.dat geosite.dat country.mmdb GeoLite2-ASN.mmdb; do
    if [ -f "/usr/local/etc/mihomo/$f" ] && [ ! -e "/var/db/mihomo/$f" ]; then
      ln -sf "/usr/local/etc/mihomo/$f" "/var/db/mihomo/$f"
      chown -h mihomo:mihomo "/var/db/mihomo/$f" 2>/dev/null || true
    fi
  done
fi

if [ "$WAS_RUNNING" -eq 1 ]; then
  echo ">> Restarting mihomo service and verifying ports..."
  if service mihomo start && sleep 1 \
     && service mihomo status >/dev/null 2>&1 \
     && sockstat -4l | grep -q '127\.0\.0\.1:18921'; then
    echo ">> mihomo service restarted successfully."
  else
    echo "Warning: Service failed health check! Rolling back..." >&2
    service mihomo stop >/dev/null 2>&1 || true
    install -m 755 -o root -g wheel "$BACKUP_PATH" "$BIN_PATH"
    service mihomo start >/dev/null 2>&1 || true
    echo "Restored previous working binary." >&2
    exit 1
  fi
fi

# Rotate backups: Retain only the latest 2 copies
OLD_BAKS="$(ls -1t "${BACKUP_ROOT}"/mihomo.bak-* 2>/dev/null || true)"
OLD_COUNT="$(printf '%s\n' "$OLD_BAKS" | grep -v '^[[:space:]]*$' | wc -l | tr -d ' ')"
if [ "$OLD_COUNT" -gt 2 ]; then
  printf '%s\n' "$OLD_BAKS" | tail -n +3 | while IFS= read -r old_file; do
    [ -f "$old_file" ] && rm -f "$old_file" && echo ">> Rotated old backup: $old_file"
  done
fi

LEGACY_BAKS="$(ls -1t /usr/local/bin/mihomo.bak-* 2>/dev/null || true)"
if [ -n "$LEGACY_BAKS" ]; then
  printf '%s\n' "$LEGACY_BAKS" | while IFS= read -r legacy_file; do
    [ -f "$legacy_file" ] && rm -f "$legacy_file" && echo ">> Cleaned legacy backup: $legacy_file"
  done
fi

echo "=================================================="
echo " [Done] mihomo upgraded successfully!"
"$BIN_PATH" -v
echo " Backup stored in: $BACKUP_PATH"
echo "=================================================="
```

---

## 11. Operational Playbook & Verification Testing

### 1. Verification Commands

```bash
# Check running status of Packet Filter
sudo pfctl -sr
sudo pfctl -t scan_blacklist -T show

# Check listening ports
sudo sockstat -l | grep -E '(18921|80|443|28622)'

# Verify TLS certificate & masquerade endpoint
curl --resolve "proxy.example.com:443:127.0.0.1" -Iv "https://proxy.example.com/"

# Monitor mihomo log entries
sudo tail -f /var/log/messages | grep mihomo
```

### 2. Simulating Adversarial Attacks

1. **Active Protocol Probe**:
   Visiting `https://proxy.example.com/` returns the legitimate Hiawatha web page with HTTP 200/301. Non-matching HTTP methods return Hiawatha's standard HTTP 405/501 errors without leaking backend proxy signatures.
2. **Port Scanner Blackholing**:
   Scanning unopened TCP/UDP ports produces zero response (no `RST` or `ICMP Port Unreachable` packets sent back) thanks to FreeBSD's `blackhole` sysctl settings.
3. **SSH Brute-Force Rate Limiting**:
   More than 4 connection attempts within 60 seconds automatically places the attacking IP into `<scan_blacklist>`, cutting off all traffic to the server for 24 hours.
4. **Egress Netscan Prevention**:
   Any proxy connection attempting to probe AWS/GCP/Azure internal metadata (`169.254.169.254`) or local RFC1918 subnets is immediately dropped by the kernel with zero egress packets escaping the public interface.

---

## Conclusion

By combining FreeBSD 15's native packet filter (`rdr-to`), kernel process boundaries (`security.bsd.*`), a secure web server (Hiawatha), and atomic certificate deployment, this setup achieves:

- **Total Local Isolation**: Zero public exposure of backend proxy ports.
- **DPI Resistance**: Robust Hysteria2 obfuscation combined with seamless web masquerade fallback.
- **Provider Compliance**: Strict egress filtering preventing unintentional scans of internal cloud networks.
- **Maintenance Resilience**: Crash auto-restart, automated log rotation, dynamic blacklist aging, and one-command self-auditing.
