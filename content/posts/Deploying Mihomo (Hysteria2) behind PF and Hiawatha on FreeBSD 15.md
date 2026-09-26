---
title: Deploying Mihomo (Hysteria2) Behind PF and Hiawatha on FreeBSD 15
date: 2026-09-26T13:05:02+08:00
draft: false
tags:
  - Others
---

This guide covers setting up a FreeBSD 15 server running Mihomo (Hysteria2 inbound) behind FreeBSD PF port hopping and a Hiawatha web camouflage site.

Replace placeholders such as `[YOUR_DOMAIN]`, `[YOUR_EMAIL]`, `[YOUR_SSH_PORT]`, `[YOUR_IFACE]`, `[YOUR_PASSWORD]`, and `[YOUR_SERVER_IP]` before running commands or applying configurations.

<!--more-->

## 1. System Environment & User Setup

### Unprivileged User Setup

Create an unprivileged user in the `wheel` group for administration:

```bash
pw useradd freebsduser -m -G wheel -s /bin/sh
passwd freebsduser

visudo
# Uncomment: %wheel ALL=(ALL:ALL) ALL

su - freebsduser
```

---

## 2. Port Map & Topology

```text
Client (Mihomo)
   │  UDP Port Hopping Range: 20000-21000
   ▼
FreeBSD Interface ([YOUR_IFACE])
   │
   ├─ PF Firewall Filter (Antispoof, rate-limiting)
   │
   └─ PF Port Redirection (rdr-to): 20000-21000/udp ──► 127.0.0.1:10000
                                                         │
                                                         ▼
                                             Mihomo Server Daemon
                                             (User: mihomo, Listens: 127.0.0.1:10000/udp)
                                                         │
               ┌─────────────────────────────────────────┴─────────────────────────────────────────┐
               ▼                                                                                   ▼
      [Valid Hysteria2 Auth]                                                             [Unauthenticated Probe]
      Proxy outbound                                                                     masquerade fallback
                                                                                         https://127.0.0.1:443
                                                                                                   │
                                                                                                   ▼
                                                                                           Hiawatha Camouflage Site
```

### Port Allocations

| Port / Protocol       | Purpose            | Status                   | Description                             |
| --------------------- | ------------------ | ------------------------ | --------------------------------------- |
| `[YOUR_SSH_PORT]/tcp` | SSH Management     | Open                     | Rate-limited by PF                      |
| `80/tcp`              | HTTP Redirect      | Open                     | Hiawatha 301 redirect to 443            |
| `443/tcp`             | HTTPS Camouflage   | Open                     | Hiawatha web server                     |
| `10000/udp`           | Mihomo Inbound     | Local only (`127.0.0.1`) | Receives redirected UDP traffic from PF |
| `20000-21000/udp`     | Port Hopping Range | Open (rdr)               | External UDP entry point                |

---

## 3. SSH Hardening

Ensure `sshd` includes configuration snippets and apply hardening rules.

```bash
grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \
  echo "Include /etc/ssh/sshd_config.d/*.conf" | sudo tee -a /etc/ssh/sshd_config
sudo mkdir -p /etc/ssh/sshd_config.d

sudo tee /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
Port [YOUR_SSH_PORT]
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

sudo sshd -t
sudo service sshd restart
```

---

## 4. System Setup Script (`01-setup-system.sh`)

This script installs packages, creates system users and groups, configures directory permissions, applies kernel parameters via `sysctl`, and sets up cron jobs.

Create `01-setup-system.sh`:

```bash
#!/usr/bin/env sh
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: must run as root." >&2
  exit 1
fi

pkg bootstrap -y 2>/dev/null || true
pkg update -f
pkg install -y hiawatha curl ca_root_nss sudo

if ! pkg install -y py313-certbot py313-certbot-dns-cloudflare 2>/dev/null; then
  if ! pkg install -y py312-certbot py312-certbot-dns-cloudflare 2>/dev/null; then
    pkg install -y py311-certbot py311-certbot-dns-cloudflare
  fi
fi

if ! pw group show ssl-cert >/dev/null 2>&1; then
  pw groupadd ssl-cert
fi

if ! pw user show mihomo >/dev/null 2>&1; then
  pw useradd mihomo -s /usr/sbin/nologin -d /nonexistent -c "mihomo service user"
fi

pw groupmod ssl-cert -m mihomo,www

mkdir -p /usr/local/etc/mihomo
chown root:mihomo /usr/local/etc/mihomo
chmod 750 /usr/local/etc/mihomo

mkdir -p /var/db/mihomo
chown mihomo:mihomo /var/db/mihomo
chmod 750 /var/db/mihomo

mkdir -p /usr/local/etc/ssl/mihomo
chown -R root:ssl-cert /usr/local/etc/ssl/mihomo
chmod 750 /usr/local/etc/ssl/mihomo

mkdir -p /usr/local/www/hiawatha
chown -R root:wheel /usr/local/www/hiawatha
chmod 755 /usr/local/www/hiawatha

mkdir -p /var/log/hiawatha
chown root:wheel /var/log/hiawatha
chmod 755 /var/log/hiawatha

SYSCTL_FILE=/etc/sysctl.conf
if ! grep -q "net.inet.tcp.syncookies" "$SYSCTL_FILE"; then
  cat >> "$SYSCTL_FILE" << 'EOF'

# ====== Mihomo tuning ======
net.inet.tcp.syncookies=1
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
net.inet.icmp.icmplim=50
net.inet.ip.redirect=0
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
kern.ipc.maxsockbuf=8388608
net.inet.udp.maxdgram=65535
net.inet.udp.recvspace=4194304
EOF
  /sbin/sysctl -f "$SYSCTL_FILE" >/dev/null 2>&1 || true
fi

kldload accf_http >/dev/null 2>&1 || true
kldload accf_data >/dev/null 2>&1 || true

LOADER_CONF=/boot/loader.conf
touch "$LOADER_CONF"
if ! grep -q "accf_http_load" "$LOADER_CONF"; then
  echo 'accf_http_load="YES"' >> "$LOADER_CONF"
fi
if ! grep -q "accf_data_load" "$LOADER_CONF"; then
  echo 'accf_data_load="YES"' >> "$LOADER_CONF"
fi

mkdir -p /usr/local/etc/letsencrypt/renewal-hooks/deploy
chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy

if ! grep -q "scan_blacklist -T expire" /etc/crontab; then
  echo "*/5 * * * * root /sbin/pfctl -t scan_blacklist -T expire 3600 >/dev/null 2>&1" >> /etc/crontab
fi
```

Run the script:

```bash
sudo sh 01-setup-system.sh
```

---

## 5. Firewall Configuration (`/etc/pf.conf`)

This configuration uses FreeBSD 15 PF syntax to redirect UDP traffic on ports `20000-21000` to `127.0.0.1:10000`, rate-limit SSH connections, and drop unauthenticated probes.

Edit `/etc/pf.conf`:

```conf
# /etc/pf.conf

ext_if = [YOUR_IFACE]
ssh_port = [YOUR_SSH_PORT]
mihomo_udp_port = 10000
jump_port_range = "20000-21000"

table <scan_blacklist> persist

set block-policy drop
set skip on lo0
set reassemble yes no-df
set syncookies adaptive (start 25%, end 12%)

match in on $ext_if all scrub (no-df max-mss 1440 random-id reassemble tcp)

antispoof quick for $ext_if
block in quick on $ext_if from urpf-failed to any
block in quick from no-route to any

block in quick from <scan_blacklist> to any
block in all
pass out all keep state

# Hysteria2 Port Hopping
pass in on $ext_if proto udp from any to any port $jump_port_range \
    rdr-to 127.0.0.1 port $mihomo_udp_port \
    keep state (max 50000, source-track rule, max-src-states 500)

# Hiawatha Web Camouflage
pass in on $ext_if proto tcp from any to any port { 80, 443 } keep state

# SSH Limit
pass in on $ext_if proto tcp from any to any port $ssh_port \
    keep state (max-src-conn 15, max-src-conn-rate 15/60, \
    overload <scan_blacklist> flush global)

# ICMP
pass in on $ext_if inet proto icmp all icmp-type echoreq keep state (max-src-states 5)
pass in on $ext_if inet6 proto icmp6 all icmp6-type echoreq keep state (max-src-states 5)
```

Test and enable PF:

```bash
sudo pfctl -nf /etc/pf.conf
sudo sysrc pf_enable="YES"
sudo service pf start
sudo pfctl -f /etc/pf.conf
```

---

## 6. Certificates & Web Camouflage Setup

### Cloudflare API Token & ZeroSSL EAB Registration

```bash
sudo mkdir -p /usr/local/etc/letsencrypt
sudo tee /usr/local/etc/letsencrypt/cloudflare.ini << 'EOF'
dns_cloudflare_api_token = [YOUR_CLOUDFLARE_TOKEN]
EOF
sudo chmod 600 /usr/local/etc/letsencrypt/cloudflare.ini

sudo certbot register \
  --email [YOUR_EMAIL] \
  --server https://acme.zerossl.com/v2/DV90 \
  --eab-kid [YOUR_EAB_KID] \
  --eab-hmac-key [YOUR_EAB_HMAC_KEY] \
  --agree-tos
```

### Certbot Deploy Hook Script

Create `/usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh`:

```bash
#!/usr/bin/env sh
set -e

DOMAIN="[YOUR_DOMAIN]"
CERT_DIR="${RENEWED_LINEAGE:-/usr/local/etc/letsencrypt/live/$DOMAIN}"
DEST_DIR="/usr/local/etc/ssl/mihomo"
HIAWATHA_PEM="$DEST_DIR/hiawatha.pem"

mkdir -p "$DEST_DIR"

cp "$CERT_DIR/fullchain.pem" "$DEST_DIR/fullchain.pem"
cp "$CERT_DIR/privkey.pem" "$DEST_DIR/privkey.pem"

# Hiawatha requires private key followed by fullchain in a single file
cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$HIAWATHA_PEM"

chown root:ssl-cert "$DEST_DIR/fullchain.pem" "$DEST_DIR/privkey.pem" "$HIAWATHA_PEM"
chmod 640 "$DEST_DIR/fullchain.pem" "$DEST_DIR/privkey.pem" "$HIAWATHA_PEM"
chown root:ssl-cert "$DEST_DIR"
chmod 750 "$DEST_DIR"

if [ -f "$DEST_DIR/ech.key" ]; then
    chown root:ssl-cert "$DEST_DIR/ech.key"
    chmod 640 "$DEST_DIR/ech.key"
fi

if service hiawatha status >/dev/null 2>&1; then
    service hiawatha restart >/dev/null 2>&1 || true
fi

if service mihomo status >/dev/null 2>&1; then
    service mihomo restart >/dev/null 2>&1 || true
fi
```

Issue the certificate:

```bash
sudo chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh

sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /usr/local/etc/letsencrypt/cloudflare.ini \
  --server https://acme.zerossl.com/v2/DV90 \
  -d [YOUR_DOMAIN] \
  --deploy-hook /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

### Hiawatha Web Server Configuration

Edit `/usr/local/etc/hiawatha/hiawatha.conf`:

```conf
ServerId = www
ConnectionsTotal = 1000
ConnectionsPerIP = 50
SystemLogfile = /var/log/hiawatha/system.log
GarbageLogfile = /var/log/hiawatha/garbage.log
ExploitLogfile = /var/log/hiawatha/exploit.log
ServerString = none

BanlistMask = deny 127.0.0.1, deny ::1

BanOnGarbage = 300
BanOnInvalidURL = 60
BanOnMaxPerIP = 60
BanOnMaxReqSize = 300
BanOnSQLi = 120
BanOnFlooding = 25/1:60
KickOnBan = yes
RebanDuringBan = yes

Binding {
    Port = 80
    Interface = 0.0.0.0
    MaxRequestSize = 64
    EnableAccf = yes
}

Binding {
    Port = 443
    Interface = 0.0.0.0
    TLScertFile = /usr/local/etc/ssl/mihomo/hiawatha.pem
    MaxRequestSize = 512
    EnableAccf = yes
}

# Catch-all default host
Hostname = 127.0.0.1
WebsiteRoot = /usr/local/www/hiawatha
StartFile = index.html
AccessLogfile = /var/log/hiawatha/access.log
ErrorLogfile = /var/log/hiawatha/error.log
ShowIndex = no
FollowSymlinks = no
AllowDotFiles = no

# Virtual Host
VirtualHost {
    Hostname = [YOUR_DOMAIN]
    WebsiteRoot = /usr/local/www/hiawatha
    StartFile = index.html
    AccessLogfile = /var/log/hiawatha/access.log
    ErrorLogfile = /var/log/hiawatha/error.log

    RequireTLS = yes, 31536000; includeSubDomains; preload
    ShowIndex = no
    FollowSymlinks = no
    AllowDotFiles = no
    RandomHeader = 200

    PreventXSS = prevent
    PreventSQLi = prevent
    PreventCSRF = prevent

    CustomHeaderClient = X-Frame-Options: SAMEORIGIN
    CustomHeaderClient = X-Content-Type-Options: nosniff
    CustomHeaderClient = Referrer-Policy: strict-origin-when-cross-origin
    CustomHeaderClient = Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
}
```

Add domain to `/etc/hosts` and start Hiawatha:

```bash
echo "127.0.0.1 [YOUR_DOMAIN]" | sudo tee -a /etc/hosts
sudo sysrc hiawatha_enable="YES"
sudo service hiawatha start
```

---

## 7. Mihomo Installation & Service Setup

### Binary Installation Script (`02-install-mihomo.sh`)

Create `02-install-mihomo.sh`:

```bash
#!/usr/bin/env sh
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: must run as root." >&2
  exit 1
fi

WORK_DIR="/tmp/.mihomo_install_tmp"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac

LATEST_TAG="$(curl -sI https://github.com/MetaCubeX/mihomo/releases/latest \
  | grep -i '^location:' | tr -d '\r' | sed -E 's#.*/tag/##' || true)"

if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

LATEST_TAG="${MIHOMO_TAG:-$LATEST_TAG}"
ASSET="mihomo-freebsd-${ARCH}-${LATEST_TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/${ASSET}"
DEST_GZ="$WORK_DIR/mihomo.gz"

curl -fL --retry 3 --retry-delay 2 -o "$DEST_GZ" "$URL"
gunzip -c "$DEST_GZ" > "$WORK_DIR/mihomo"
chmod 755 "$WORK_DIR/mihomo"
install -m 755 -o root -g wheel "$WORK_DIR/mihomo" /usr/local/bin/mihomo

/usr/local/bin/mihomo -v
```

Execute:

```bash
sudo sh 02-install-mihomo.sh
```

### Server Configuration (`/usr/local/etc/mihomo/config.yaml`)

Edit `/usr/local/etc/mihomo/config.yaml`:

```yaml
mode: rule
log-level: warning
ipv6: false
find-process-mode: off
tcp-concurrent: true

profile:
  store-selected: false
  store-fake-ip: false

listeners:
  - name: hy2-in
    type: hysteria2
    listen: 127.0.0.1
    port: 10000

    users:
      hy2-user: "[YOUR_PASSWORD]"

    up: 100
    down: 100
    ignore-client-bandwidth: true
    handshake-timeout: 15s

    masquerade: "https://[YOUR_DOMAIN]"

    alpn:
      - h3

    certificate: /usr/local/etc/ssl/mihomo/fullchain.pem
    private-key: /usr/local/etc/ssl/mihomo/privkey.pem
    ech-key: /usr/local/etc/ssl/mihomo/ech.key

rules:
  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve
  - IP-CIDR,169.254.0.0/16,REJECT,no-resolve
  - IP-CIDR,10.0.0.0/8,REJECT,no-resolve
  - IP-CIDR,172.16.0.0/12,REJECT,no-resolve
  - IP-CIDR,192.168.0.0/16,REJECT,no-resolve
  - IP-CIDR6,::1/128,REJECT,no-resolve
  - IP-CIDR6,fc00::/7,REJECT,no-resolve
  - IP-CIDR6,fe80::/10,REJECT,no-resolve
  - MATCH,DIRECT
```

Set permissions:

```bash
sudo chmod 640 /usr/local/etc/mihomo/config.yaml
sudo chown root:mihomo /usr/local/etc/mihomo/config.yaml
```

### FreeBSD Init Script (`/usr/local/etc/rc.d/mihomo`)

Create `/usr/local/etc/rc.d/mihomo`:

```sh
#!/bin/sh
#
# PROVIDE: mihomo
# REQUIRE: NETWORKING pf
# KEYWORD: shutdown

. /etc/rc.subr

name="mihomo"
rcvar="mihomo_enable"

runas_user="mihomo"
pidfile="/var/run/${name}.pid"

mihomo_limits="-n 200000"
mihomo_env="SAFE_PATHS=/usr/local/etc/ssl/mihomo:/usr/local/etc/mihomo"

command="/usr/sbin/daemon"
mihomo_command="/usr/local/bin/mihomo"
procname="${mihomo_command}"
mihomo_args="-d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml"

command_args="-S -T ${name} -p ${pidfile} -u ${runas_user} /usr/bin/env ${mihomo_env} ${mihomo_command} ${mihomo_args}"

load_rc_config $name
: ${mihomo_enable:="NO"}

run_rc_command "$1"
```

Set script permissions and start the service:

```bash
sudo chown root:wheel /usr/local/etc/rc.d/mihomo
sudo chmod 555 /usr/local/etc/rc.d/mihomo

sudo sysrc mihomo_enable="YES"
sudo service mihomo start
sudo service mihomo status
```

---

## 8. DNS-over-TLS (DoT) & DNSSEC Setup

Configure `local-unbound` for DNS-over-TLS and DNSSEC validation.

### DoT Configuration

Create `/var/unbound/conf.d/dot.conf`:

```bash
sudo tee /var/unbound/conf.d/dot.conf << 'EOF'
server:
    tls-cert-bundle: "/usr/local/share/certs/ca-root-nss.crt"

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
EOF
```

### DNSSEC Configuration

Create `/var/unbound/conf.d/dnssec.conf`:

```bash
sudo tee /var/unbound/conf.d/dnssec.conf << 'EOF'
server:
    auto-trust-anchor-file: "/var/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
EOF

sudo -u unbound /usr/sbin/unbound-anchor -a "/var/unbound/root.key" || true
```

### Enable Resolver

```bash
sudo sysrc local_unbound_enable="YES"
sudo service local-unbound setup
sudo service local-unbound start

sudo tee /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
options edns0
EOF
```

---

## 9. Mobile Client Configuration (`mihomo-mobile.yaml`)

Configuration file for Android or iOS Mihomo clients:

```yaml
mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: true
unified-delay: true
tcp-concurrent: false
find-process-mode: off

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
  quic-go-disable-gso: true
  quic-go-disable-ecn: true
  dialer-ip4p-convert: false

hosts:
  '[YOUR_DOMAIN]': [YOUR_SERVER_IP]
  'dns.quad9.net':
    - 9.9.9.9
    - 149.112.112.112
  'cloudflare-dns.com':
    - 1.1.1.1
    - 1.0.0.1

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
    - DOMAIN,[YOUR_DOMAIN],real-ip
    - MATCH,fake-ip

  nameserver-policy:
    "geosite:cn,private,apple,onedrive,microsoft@cn":
      - 223.5.5.5
      - 119.29.29.29
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    "geosite:google,youtube,telegram,gfw,geolocation-!cn":
      - https://dns.quad9.net/dns-query
      - https://cloudflare-dns.com/dns-query

  nameserver:
    - https://dns.quad9.net/dns-query
    - https://cloudflare-dns.com/dns-query

  fallback:
    - https://cloudflare-dns.com/dns-query
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
    - 223.5.5.5
    - 119.29.29.29

  direct-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  direct-nameserver-follow-policy: false

proxies:
  - name: HY2-Hop
    type: hysteria2
    server: [YOUR_DOMAIN]
    ports: 20000-21000
    hop-interval: 30
    password: "[YOUR_PASSWORD]"
    up: 100
    down: 100
    sni: [YOUR_DOMAIN]
    skip-cert-verify: false
    alpn:
      - h3
    ech-opts:
      enable: true
      config: "[YOUR_ECH_CONFIG]"

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - HY2-Hop
      - DIRECT
  - name: Auto
    type: url-test
    proxies:
      - HY2-Hop
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

rules:
  - GEOSITE,category-ads-all,REJECT
  - DOMAIN,[YOUR_DOMAIN],DIRECT

  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,private,DIRECT

  - GEOSITE,google,Proxy
  - GEOSITE,youtube,Proxy
  - GEOSITE,telegram,Proxy
  - GEOSITE,github,Proxy
  - GEOSITE,openai,Proxy
  - GEOSITE,anthropic,Proxy
  - IP-CIDR,160.79.104.0/21,Proxy,no-resolve
  - GEOIP,telegram,Proxy

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

  - AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,CN)),REJECT

  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT
  - GEOSITE,geolocation-!cn,Proxy
  - MATCH,Proxy
```

---

## 10. Verification

Check running status:

```bash
sudo pfctl -sr
sudo sockstat -l | grep -E '(10000|80|443|[YOUR_SSH_PORT])'
curl -Iv https://[YOUR_DOMAIN]
tail -f /var/log/messages | grep mihomo
```

Verify DNSSEC resolution:

```bash
# Valid signed zone (must display 'ad' flag)
drill -D freebsd.org @127.0.0.1

# Failed signed zone (must return SERVFAIL)
drill -D dnssec-failed.org @127.0.0.1
```
