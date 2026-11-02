---
title: FreeBSD安装mihomo记录
date: 2026-09-26T13:05:02+08:00
draft: false
tags:
  - Others
---
# FreeBSD 15 部署 mihomo (Hysteria2) + Hiawatha + PF 代理节点记录


本文记录了一套在 **FreeBSD 15 (amd64)** 上的完整部署与加固方案：
- 底层使用 FreeBSD 原生 **PF (Packet Filter)** 防火墙实现端口跳跃与入站/出站双向隔离；
- Web 伪装层选用轻量且默认防御策略严格的 **Hiawatha**；
- 代理核心采用 **mihomo** 运行 **Hysteria2** 协议，通过本地回环与伪装站形成闭环；
- 配套全自动化的 ZeroSSL 证书申请、部署与健康回滚机制。

整套方案基于标准 POSIX / FreeBSD 原生机制设计，**完全兼容传统的 UFS/FFS 文件系统**（对 ZFS 无任何硬性依赖），内存开销低，适合配置有限的轻量 VPS。

> **说明**：本文中的域名、公网 IP 及密钥等敏感信息均已替换为标准测试占位符（如 `proxy.example.com`、`198.51.100.10`、端口 `28622`），实际部署时请替换为你自己的真实配置。

---

## 1. 整体架构与流量走向

```text
客户端流量 (UDP 端口跳跃范围: 39999-50001)
         │
         ▼
FreeBSD 外网网卡 (例如 vtnet0)
         │
         ├─► [PF 防火墙规则链]
         │        ├── 阻断所有 IPv6 探测 (block drop in quick inet6)
         │        ├── 优先丢弃黑名单中的来源 IP (<scan_blacklist>)
         │        └── SSH 暴力破解自动拉黑 (1分钟超4次连接)
         │
         └─► [PF 内联端口转发 (rdr-to)]
                   39999-50001/udp ──► 127.0.0.1:18921 (仅限本地回环)
                                             │
                                             ▼
                                  [mihomo 守护进程 (Hysteria2)]
                                  - 运行于受限系统账户 mihomo
                                  - 仅绑定 127.0.0.1:18921/udp，公网不可直连
                                  - 关闭 9090 外部控制接口，收敛本地暴露面
                                  - 内核层与规则层双重阻断向内网/元数据发包
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [认证合法的代理流量]                           [未认证探测 / 伪装回落]
         正常转发访问外网互联网                              通过回环访问本机 HTTPS 伪装站
         (出站拦截私有网段与云元数据)                        https://127.0.0.1:443
                                                                   │
                                                                   ▼
                                                       [Hiawatha Web 伪装站]
                                                       - 80/tcp 强制跳转 443
                                                       - 443/tcp 承载正式 ZeroSSL 证书
                                                       - 自带 XSS / SQLi / CSRF 应用层防护
```

### 核心设计

1. **服务不直接对外暴露端口**：mihomo 仅监听 `127.0.0.1:18921/udp`。公网暴露的只有 Web 伪装站（80/443）、限频后的 SSH，以及由 PF 负责转发的 UDP 跳跃端口范围。
2. **现代内联转发语法 (`rdr-to`)**：使用 FreeBSD 15 原生支持的 `pass in ... rdr-to`，规避旧版 `rdr pass` 自动放行导致绕过黑名单的缺陷，确保进入 `<scan_blacklist>` 的 IP 无法通过跳跃端口打满带宽。
3. **闭环本地伪装回落**：探测流量回落至 Hiawatha 时，通过 `/etc/hosts` 将伪装域名硬解析到 `127.0.0.1`，避免回落流量绕行公网 DNS 或外网网卡导致延迟增加与来源 IP 异常。
4. **出站隔离防御（防机房 Abuse 警告）**：在 PF 防火墙对 `user mihomo` 强制阻断发往私有地址（10/8, 172.16/12, 192.168/16）、CGNAT（100.64/10）及云元数据（169.254.169.254）的报文，防止代理节点被利用扫描云服务商内部网络。
5. **原子化与自动化证书链路**：证书合并（私钥+证书链）全程在受控目录内通过 `umask 077` 和隐藏临时文件完成，不落 `/tmp`。更新后执行实际 TLS SNI 握手指纹比对，失败自动回滚旧证书。

---

## 2. 端口规划

| 端口 / 协议 | 服务 | 公网状态 | 说明 |
| :--- | :--- | :--- | :--- |
| `[CUSTOM_SSH_PORT]/tcp` | OpenSSH | 开放 | 仅限密钥认证，PF 限制单 IP 每分钟最多新建 4 个连接，超限自动拉黑 |
| `80/tcp` | Hiawatha Web | 开放 | HTTP 301 强制跳转至 443 (启用 HSTS) |
| `443/tcp` | Hiawatha Web | 开放 | 伪装站 HTTPS，搭载 ZeroSSL 证书 |
| `18921/udp` | mihomo core | 本地绑定 | 仅绑定 `127.0.0.1`，外部扫描器无法直接发起握手 |
| `39999-50001/udp` | 跳跃端口范围 | 开放 (PF) | 由 PF 防火墙转至 `127.0.0.1:18921`，受黑名单前置阻断 |
| `IPv6 全部流量` | - | 全阻断 | 显式静默丢弃，消除 IPv6 侧的主动嗅探与指纹特征 |

---

## 3. 准备工作与 OpenSSH 加固

生产环境中应避免使用 `root` 账户直接远程登录，建议创建专用的管理运维用户并配置 `sudo`。

### 1. 设置 root 密码并创建管理员用户

```bash
# 为 root 设置本地密码（供后续开启 insecure 控制台后在 VNC 紧急救援时使用）
passwd root

# 创建管理员账户（以 operator 为例）并加入 wheel 组
pw useradd operator -m -G wheel -s /bin/sh
chmod 750 /home/operator
passwd operator
```

通过 `visudo` 授予 `wheel` 组免/需密 `sudo` 权限：
```bash
visudo
# 找到并取消注释：
# %wheel ALL=(ALL:ALL) ALL
```

### 2. 配置 OpenSSH 加固

> **注意**：OpenSSH 在解析配置文件时遵循**首条匹配优先（First-Match-Wins）**原则。如果直接在主配置末尾追加 `Include`，子配置文件中的指令可能会被主配置上方的默认项覆盖。因此必须确保 `Include` 位于 `/etc/ssh/sshd_config` 的最顶部。

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

# 确保 Include 指令位于主配置最上方
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
  sudo sh -c '{ printf "Include /etc/ssh/sshd_config.d/*.conf\n\n"; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.new && mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config'
fi

sudo chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/99-hardening.conf

# 语法测试并核验有效生效配置（确认端口和 PermitRootLogin=no）
sudo sshd -t
sudo sshd -T | grep -E '^(port|permitrootlogin) '
sudo service sshd reload
```

---

## 4. 系统底层加固与环境初始化 (`01-setup-system.sh`)

创建并执行 `01-setup-system.sh`。该脚本负责安装基础软件包、建立隔离组与用户、收紧文件权限、配置内核防探测 `sysctl` 参数，并注册定时日志与黑名单老化任务。

```bash
nano 01-setup-system.sh
# 粘贴下方脚本内容并保存
sudo sh 01-setup-system.sh
rm -f 01-setup-system.sh
```

### 脚本完整内容：

```bash
#!/usr/bin/env sh
# ==============================================================================
# 01-setup-system.sh - FreeBSD 15 系统环境初始化与内核加固
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：必须使用 root 权限运行此脚本：sudo sh $0" >&2
  exit 1
fi

LOGIN_USER="${SUDO_USER:-}"
if [ -z "$LOGIN_USER" ] || [ "$LOGIN_USER" = "root" ]; then
  LOGIN_USER="$(logname 2>/dev/null || true)"
fi

echo "=================================================="
echo " [步骤 1/6] 安装软件包依赖 (pkg)..."
echo "=================================================="
pkg update
pkg install -y hiawatha py311-certbot py311-certbot-dns-cloudflare curl ca_root_nss sudo wget

echo "=================================================="
echo " [步骤 2/6] 创建受限服务账户、安全组与控制台加固..."
echo "=================================================="
# 创建证书安全组：仅允许加入该组的用户读取私钥与证书
if ! pw group show ssl-cert >/dev/null 2>&1; then
  pw groupadd ssl-cert
  echo ">> 已创建安全组：ssl-cert"
fi

# 创建独立受限系统账户：禁用交互式登录（nologin）与无有效家目录
if ! pw user show mihomo >/dev/null 2>&1; then
  pw useradd mihomo -s /usr/sbin/nologin -d /nonexistent -c "mihomo service user"
  echo ">> 已创建服务账户：mihomo"
fi

# 将 mihomo 和 Hiawatha 的运行账户 (www) 均加入 ssl-cert 组以共享证书读取权
pw groupmod ssl-cert -m mihomo
pw groupmod ssl-cert -m www

# 锁定 FreeBSD 冗余的 UID 0 备用账户 (toor)，消除潜在空密码或被利用风险
if pw user show toor >/dev/null 2>&1; then
  pw lock toor
  echo ">> 已锁定 toor 账户"
fi

# 控制台设为 insecure：单用户维护模式下强制要求输入 root 密码，防止物理/VNC 控制台免密提权
if [ -f /etc/ttys ]; then
  sed -i '' -E 's/^(console[[:space:]]+.*[[:space:]]+)secure/\1insecure/' /etc/ttys 2>/dev/null || true
  echo ">> 已加固 /etc/ttys 控制台安全等级 (insecure)"
  ROOT_HASH="$(awk -F: '$1=="root"{print $2; exit}' /etc/master.passwd 2>/dev/null || true)"
  if [ -z "$ROOT_HASH" ] || [ "$ROOT_HASH" = "*" ] || [ "$ROOT_HASH" = "!" ]; then
    echo "   [提醒] 检测到 root 尚未设置本地密码！请务必执行 sudo passwd root 以备 VNC 单用户救援。"
  fi
fi

echo "=================================================="
echo " [步骤 3/6] 初始化受保护目录结构与最小权限控制..."
echo "=================================================="
# 配置目录：属主 root:mihomo，权限 750
mkdir -p /usr/local/etc/mihomo
chown root:mihomo /usr/local/etc/mihomo
chmod 750 /usr/local/etc/mihomo

# 运行时数据目录：属主 mihomo:mihomo，权限 750
mkdir -p /var/db/mihomo
chown mihomo:mihomo /var/db/mihomo
chmod 750 /var/db/mihomo

# 备份根目录：符合 FreeBSD hier(7) 规范，权限 700 仅 root 可读写
install -d -m 700 -o root -g wheel /var/backups/mihomo

# 证书目录：属主 root:ssl-cert，权限 750
mkdir -p /usr/local/etc/ssl/mihomo
chown -R root:ssl-cert /usr/local/etc/ssl/mihomo
chmod 750 /usr/local/etc/ssl/mihomo

# 伪装站网页根目录
mkdir -p /usr/local/www/hiawatha
chown -R www:www /usr/local/www/hiawatha
chmod 755 /usr/local/www/hiawatha

# Hiawatha 日志目录
mkdir -p /var/log/hiawatha
chown www:www /var/log/hiawatha
chmod 750 /var/log/hiawatha

# 收紧敏感配置文件权限（消除常见安全合规告警）
[ -f /etc/crontab ] && chmod 600 /etc/crontab
[ -d /etc/cron.d ] && chmod 750 /etc/cron.d
[ -d /usr/local/etc/sudoers.d ] && chmod 750 /usr/local/etc/sudoers.d
[ -f /etc/ssh/sshd_config ] && chmod 600 /etc/ssh/sshd_config
[ -d /etc/ssh/sshd_config.d ] && chmod 600 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
if [ -n "$LOGIN_USER" ] && [ "$LOGIN_USER" != "root" ] && [ -d "/home/$LOGIN_USER" ]; then
  chmod 750 "/home/$LOGIN_USER"
  echo ">> 已收紧运维用户家目录权限: /home/$LOGIN_USER -> 750"
fi

echo "=================================================="
echo " [步骤 4/6] 注入并动态生效 FreeBSD sysctl 内核防探测参数..."
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

# 1. 协议栈防扫描黑洞与抗畸形探针：
#    - blackhole=2 (TCP) / 1 (UDP): 收到针对未开放端口的 SYN/UDP 请求时直接静默丢弃，不发 RST 或 ICMP Port Unreachable
#    - drop_synfin=1: 丢弃常用于操作系统指纹探测的 SYN+FIN 畸形扫描包
#    - random_id=1: IP 报文 ID 伪随机化，增加基于 IP ID 序列分析系统特征的难度
#    - process_options=0: 忽略并丢弃所有包含 IP Option 的报文，抵御源路由伪造
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

# 2. 进程与用户信息隔离 (FreeBSD security.bsd.*)：
#    - see_other_uids/gids=0: 非 root 用户执行 ps/sockstat 时只能看到自己的进程与连接，杜绝服务间横向嗅探
#    - unprivileged_proc_debug=0: 禁止普通用户通过 ptrace/procfs 调试其他进程
#    - unprivileged_read_msgbuf=0: 禁止非 root 用户读取 dmesg 内核缓冲区，防止系统报错与内存地址泄露
set_sysctl "security.bsd.see_other_uids" "0"
set_sysctl "security.bsd.see_other_gids" "0"
set_sysctl "security.bsd.unprivileged_proc_debug" "0"
set_sysctl "security.bsd.unprivileged_read_msgbuf" "0"
set_sysctl "security.bsd.hardlink_check_uid" "1"
set_sysctl "security.bsd.hardlink_check_gid" "1"
echo ">> 内核参数已生效并持久化至 $SYSCTL_FILE"

echo "=================================================="
echo " [步骤 5/6] 配置 Hiawatha 伪装站日志自动压缩轮转..."
echo "=================================================="
# 使用 FreeBSD 原生 newsyslog，日志文件达到 10MB/5MB 时自动使用 gzip 压缩归档，仅保留最近 3 份
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
echo " [步骤 6/6] 初始化证书 Hook 目录与防火墙黑名单定时老化..."
echo "=================================================="
mkdir -p /usr/local/etc/letsencrypt/renewal-hooks/deploy
chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy

# 注册 root crontab：每天凌晨 04:00 自动释放 scan_blacklist 中封禁满 24 小时的 IP，防止状态表无限膨胀
CURRENT_CRON="$(crontab -u root -l 2>/dev/null || true)"
if ! printf '%s\n' "$CURRENT_CRON" | grep -q 'scan_blacklist.*expire'; then
  {
    [ -n "$CURRENT_CRON" ] && printf '%s\n' "$CURRENT_CRON"
    printf '# 每天凌晨 04:00 自动清理 scan_blacklist 表中满 24h 的老化 IP\n'
    printf '0 4 * * * /sbin/pfctl -t scan_blacklist -T expire 86400 >/dev/null 2>&1\n'
  } | crontab -u root -
  echo ">> 已注册 scan_blacklist 自动老化定时任务"
fi

echo "=================================================="
echo " [完成] FreeBSD 服务端底层加固初始化完毕。"
echo "=================================================="
```

---

## 5. Packet Filter (PF) 防火墙配置 (`/etc/pf.conf`)

FreeBSD 15 引入了与现代 OpenBSD 一致的内联转发语法（`pass in ... rdr-to`）。该语法将转发与放行合并在同一条规则中处理，彻底解决了旧版 `rdr pass` 会跳过后续过滤规则导致黑名单失效的缺陷。

将以下内容写入 `/etc/pf.conf`：

```pf
# /etc/pf.conf
# FreeBSD 15 专为 Hysteria2 端口跳跃与双向出入站加固定制的 PF 规则

# ================= 宏定义 =================
ext_if = "vtnet0"                # 外网出口网卡，例如 vtnet0, em0
ssh_port = "28622"               # 自定义 SSH 端口
mihomo_udp_port = "18921"        # mihomo 本地真实监听 UDP 端口
jump_port_range = "39999:50001"  # Hysteria2 端口跳跃范围

# ================= 表定义 =================
# 动态黑名单表：存放触发 SSH 限频或手动加入的恶意 IP
table <scan_blacklist> persist

# 私有网段与云服务元数据表：包含 RFC1918 私网、CGNAT 及 169.254/16
table <private_nets> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }

# ================= 全局选项 =================
# 未显式允许的报文直接静默丢弃 (drop)，不返回 TCP RST 或 ICMP 拒绝
set block-policy drop
# 跳过本地回环接口，避免进程内部通信受阻
set skip on lo0

# 流量归一化：重组分片报文，防御基于重叠分片的 IDS/防火墙绕过探针
scrub in on $ext_if all fragment reassemble

# ================= 过滤与内联端口转发规则 =================
# 1. 彻底封禁并静默丢弃所有入站 IPv6 流量，消除 IPv6 侧的主动嗅探与特征泄露
block drop in quick inet6

# 2. 迅速丢弃黑名单中的来源 IP（规则置顶，优先于所有放行与转发规则）
block drop in quick from <scan_blacklist> to any

# 3. 反 IP 地址欺骗（严格丢弃伪造了本机或内网源 IP 的伪造包）
antispoof quick for $ext_if

# 4. 默认策略：拒绝一切未显式允许的入站报文，允许合法出站并保持状态
block in all
pass out all keep state

# 5. 出站内网隔离：针对 mihomo 代理用户强制限制出站目标
#    - 允许向外网 DNS 服务器（53 端口）发起正常解析
#    - 内核级直接丢弃任何发往私有内网或云元数据地址的报文，防止代理被用作 SSRF 或机房扫描器
pass out quick on $ext_if inet proto { tcp, udp } from any to any port 53 user mihomo keep state
block drop out quick on $ext_if inet proto { tcp, udp } from any to <private_nets> user mihomo

# 6. FreeBSD 15 现代内联端口转发：
#    客户端访问 39999-50001 的 UDP 报文将被原子性重定向至本地回环 127.0.0.1:18921
pass in on $ext_if proto udp from any to any port $jump_port_range \
    rdr-to 127.0.0.1 port $mihomo_udp_port keep state

# 7. 开放 Web 伪装站端口 (Hiawatha 监听)
pass in on $ext_if proto tcp from any to any port { 80, 443 } keep state

# 8. 开放 SSH 端口并启用连接频率限制：
#    单 IP 在 60 秒内新建连接超过 4 次时，该 IP 将被自动注入 scan_blacklist 并切断当前已有会话
pass in on $ext_if proto tcp from any to any port $ssh_port \
    keep state (max-src-conn 4, max-src-conn-rate 4/60, \
    overload <scan_blacklist> flush global)

# 9. 限制 ICMP Ping 状态条目数，避免 ICMP 泛洪消耗防火墙连接状态表
pass in on $ext_if proto icmp all icmp-type echoreq keep state (max-src-states 5)
```

加载并启用 PF：
```bash
sudo chmod 600 /etc/pf.conf
# 预检规则语法是否正确
sudo pfctl -nf /etc/pf.conf
# 启用服务并即时载入
sudo sysrc pf_enable="YES"
sudo service pf start
sudo pfctl -f /etc/pf.conf
```

---

## 6. ZeroSSL 证书自动化与原子部署 Hook (`certbot-deploy-hook.sh`)

Hiawatha 要求其 SSL 配置文件为一个合并的 PEM 文件（私钥在上，公钥链在下）。传统的做法往往是将文件拷贝至 `/tmp` 临时合并，这在多用户操作系统中存在竞争与信息泄露风险。

此处的部署 Hook 包含以下设计：
- **前置校验**：替换前使用 `openssl` 检验新证书有效性，并提取证书与私钥的公钥比对一致性，防止损坏或未匹配的证书被部署；
- **零 `/tmp` 落地**：在受限目录 `/usr/local/etc/ssl/mihomo/` 内通过 `umask 077` 生成隐藏临时文件，赋权 `640 root:ssl-cert` 后通过同文件系统 `mv -f` 原生系统调用实现原子切换；
- **健康检查与指纹比对**：服务重启后，脚本通过真实 TLS 握手抓取 443 端口返回的证书 SHA-256 指纹，确保 Hiawatha 确实加载了新证书；同时监控 `mihomo` 进程在观察窗口内的 PID 稳定性，防止进程陷入崩溃拉起循环；
- **自动回滚机制**：部署前自动快照当前可用证书至 `/var/backups/mihomo/tls-prev/`，服务未能通过健康检查时自动恢复旧证书并重载，确保业务不中断。

### 1. 配置 Cloudflare DNS-01 API Token
```bash
sudo mkdir -p /usr/local/etc/letsencrypt
sudo tee /usr/local/etc/letsencrypt/cloudflare.ini << 'EOF'
dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN
EOF
sudo chmod 600 /usr/local/etc/letsencrypt/cloudflare.ini
```

### 2. 注册 ZeroSSL ACME EAB 账户
```bash
sudo certbot register \
  --email admin@example.com \
  --server https://acme.zerossl.com/v2/DV90 \
  --eab-kid YOUR_ZEROSSL_EAB_KID \
  --eab-hmac-key YOUR_ZEROSSL_EAB_HMAC_KEY \
  --agree-tos
```

### 3. 安装部署 Hook 脚本
创建 `/usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh`：

```bash
#!/usr/bin/env sh
# ==============================================================================
# certbot-deploy-hook.sh - FreeBSD Hiawatha & mihomo 证书分发脚本
#   (前置校验 + 原子替换 + 真实握手核验 + 失败自动回滚)
# ==============================================================================
set -eu

# 固定 PATH 路径，防止 cron 环境下因精简环境缺少 /usr/sbin 导致 service 找不到
PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
export PATH

DEFAULT_DOMAIN="proxy.example.com"
DEST_DIR="/usr/local/etc/ssl/mihomo"
HIAWATHA_PEM="$DEST_DIR/hiawatha.pem"
PREV_DIR="/var/backups/mihomo/tls-prev"
MIHOMO_LISTEN="${MIHOMO_LISTEN:-127.0.0.1:18921}"
TAG="mihomo-deploy-hook"

log() {
  printf '%s\n' "$*"
  logger -t "$TAG" -p daemon.notice -- "$*" 2>/dev/null || true
}

err() {
  printf '[-] %s\n' "$*" >&2
  logger -t "$TAG" -p daemon.err -- "$*" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# 0. 解析证书路径：优先接收参数，次选 Certbot 注入的 $RENEWED_LINEAGE
# ------------------------------------------------------------------------------
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

SRC_CERT="$CERT_DIR/fullchain.pem"
SRC_KEY="$CERT_DIR/privkey.pem"

SNI_NAME="${RENEWED_DOMAINS:-}"
SNI_NAME="${SNI_NAME%% *}"
[ -n "$SNI_NAME" ] || SNI_NAME="$(basename "$CERT_DIR")"
SNI_NAME="${SNI_NAME#\*.}"

if [ ! -f "$SRC_CERT" ] || [ ! -f "$SRC_KEY" ]; then
  err "未在 $CERT_DIR 找到有效证书文件"
  exit 1
fi

# ------------------------------------------------------------------------------
# 1. 替换前校验：确保证书未过期且公私钥配对，否则绝不动线上文件
# ------------------------------------------------------------------------------
if ! openssl x509 -in "$SRC_CERT" -noout -checkend 0 >/dev/null 2>&1; then
  err "新证书无法解析或已过期：$SRC_CERT"
  exit 1
fi

CERT_PUB="$(openssl x509 -in "$SRC_CERT" -noout -pubkey 2>/dev/null || true)"
KEY_PUB="$(openssl pkey -in "$SRC_KEY" -pubout 2>/dev/null || true)"
if [ -z "$CERT_PUB" ] || [ "$CERT_PUB" != "$KEY_PUB" ]; then
  err "证书与私钥公钥不匹配，拒绝执行替换"
  exit 1
fi

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}
NEW_FP="$(fingerprint "$SRC_CERT")"

# ------------------------------------------------------------------------------
# 2. 快照当前运行中的旧证书，为失败回滚提供依据
# ------------------------------------------------------------------------------
HIA_RUNNING=0
MI_RUNNING=0
service hiawatha status >/dev/null 2>&1 && HIA_RUNNING=1
service mihomo status >/dev/null 2>&1 && MI_RUNNING=1

HAVE_PREV=0
if [ -f "$DEST_DIR/fullchain.pem" ] && [ -f "$DEST_DIR/privkey.pem" ] && [ -f "$HIAWATHA_PEM" ]; then
  install -d -m 700 -o root -g wheel "$PREV_DIR"
  for f in fullchain.pem privkey.pem hiawatha.pem; do
    cp -p "$DEST_DIR/$f" "$PREV_DIR/$f"
  done
  HAVE_PREV=1
fi

# ------------------------------------------------------------------------------
# 3. 受保护目录内原子性暂存与 mv 替换
# ------------------------------------------------------------------------------
TMP_FC="$DEST_DIR/.fullchain.pem.tmp.$$"
TMP_PK="$DEST_DIR/.privkey.pem.tmp.$$"
TMP_HP="$DEST_DIR/.hiawatha.pem.tmp.$$"
trap 'rm -f "$TMP_FC" "$TMP_PK" "$TMP_HP"' EXIT INT TERM

install -d -m 750 -o root -g ssl-cert "$DEST_DIR"

swap_in() {
  install -m 640 -o root -g ssl-cert "$1" "$TMP_FC"
  install -m 640 -o root -g ssl-cert "$2" "$TMP_PK"
  if [ -n "${3:-}" ]; then
    install -m 640 -o root -g ssl-cert "$3" "$TMP_HP"
  else
    (
      umask 077
      cat "$2" "$1" > "$TMP_HP"
    )
    chown root:ssl-cert "$TMP_HP"
    chmod 640 "$TMP_HP"
  fi
  mv -f "$TMP_FC" "$DEST_DIR/fullchain.pem"
  mv -f "$TMP_PK" "$DEST_DIR/privkey.pem"
  mv -f "$TMP_HP" "$HIAWATHA_PEM"
}

# ------------------------------------------------------------------------------
# 4. 服务健康校验逻辑
# ------------------------------------------------------------------------------
# 验证 Hiawatha：通过本地 127.0.0.1:443 握手比对实际返回的叶子证书指纹
check_hiawatha() {
  expected="$1"
  i=0
  while [ "$i" -lt 10 ]; do
    served="$(timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$SNI_NAME" </dev/null 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
    if [ -n "$served" ] && [ "$served" = "$expected" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

# 验证 mihomo：因 daemon -r 监管器在子进程崩溃时 status 仍为运行，
# 故通过监听端口与 3 秒内子进程 PID 的恒定性确认其未陷入崩溃重启循环
check_mihomo() {
  i=0
  while [ "$i" -lt 10 ]; do
    if sockstat -4l | grep -qF "$MIHOMO_LISTEN"; then
      break
    fi
    i=$((i + 1))
    sleep 1
  done
  [ "$i" -lt 10 ] || return 1

  p1="$(pgrep -u mihomo -x mihomo | head -1 || true)"
  sleep 3
  p2="$(pgrep -u mihomo -x mihomo | head -1 || true)"
  [ -n "$p1" ] && [ "$p1" = "$p2" ] && sockstat -4l | grep -qF "$MIHOMO_LISTEN"
}

reload_services() {
  expected_fp="$1"
  rc=0

  if [ "$HIA_RUNNING" -eq 1 ]; then
    if ! service hiawatha restart >/dev/null 2>&1; then
      err "Hiawatha 重启失败"
      rc=1
    elif ! check_hiawatha "$expected_fp"; then
      err "Hiawatha 重启成功但未提供预期证书指纹 $expected_fp"
      rc=1
    fi
  fi

  if [ "$MI_RUNNING" -eq 1 ]; then
    if ! service mihomo restart >/dev/null 2>&1; then
      err "mihomo 重启失败"
      rc=1
    elif ! check_mihomo; then
      err "mihomo 监听异常或子进程处于崩溃重启循环"
      rc=1
    fi
  fi

  return "$rc"
}

# ------------------------------------------------------------------------------
# 5. 执行替换与失败自动回滚
# ------------------------------------------------------------------------------
swap_in "$SRC_CERT" "$SRC_KEY" ""

if reload_services "$NEW_FP"; then
  log "证书更新成功：新指纹 $NEW_FP 已被正常加载。"
  exit 0
fi

if [ "$HAVE_PREV" -eq 0 ]; then
  err "新证书加载失败且无历史备份，请人工排查！"
  exit 1
fi

PREV_FP="$(fingerprint "$PREV_DIR/fullchain.pem")"
err "健康检查未通过，正在回滚至旧证书 $PREV_FP ..."
swap_in "$PREV_DIR/fullchain.pem" "$PREV_DIR/privkey.pem" "$PREV_DIR/hiawatha.pem"

if reload_services "$PREV_FP"; then
  err "已恢复至旧证书，服务运行正常。请排查新证书后手动重试。"
  exit 1
fi

err "回滚后服务仍异常，需立即人工介入！"
exit 2
```

```bash
sudo chmod 750 /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

> **注意**：不要在 `renewal-hooks/deploy/` 目录下放置带有执行权限的 `.bak` 备份文件，Certbot 在续期触发时会遍历并执行该目录下**所有**可执行脚本。

### 4. 首次签发与定时自动续期
```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /usr/local/etc/letsencrypt/cloudflare.ini \
  --server https://acme.zerossl.com/v2/DV90 \
  -d proxy.example.com \
  --deploy-hook /usr/local/etc/letsencrypt/renewal-hooks/deploy/mihomo-deploy-hook.sh
```

在 `root` 的 crontab 中追加续期计划：
```bash
sudo crontab -e
# 追加以下任务（每天 03:00 与 15:00 自动检查续期）：
0 3,15 * * * /usr/local/bin/certbot renew --quiet
```

---

## 7. Web 伪装站配置 (Hiawatha)

Hiawatha 是一款注重安全性的轻量级 Web 服务器，适合作为伪装节点。

### 1. 配置 `/usr/local/etc/hiawatha/hiawatha.conf`

```text
# /usr/local/etc/hiawatha/hiawatha.conf
# Hiawatha Web Server 配置

# ================= 全局配置 =================
ServerId = www
ConnectionsTotal = 1000
ConnectionsPerIP = 50
SystemLogfile = /var/log/hiawatha/system.log
GarbageLogfile = /var/log/hiawatha/garbage.log
ExploitLogfile = /var/log/hiawatha/exploit.log

# 隐藏具体的 Web 服务器版本指纹
ServerString = Webserver

# ================= 防护规则 =================
# 注意：BanOnGarbage 必须禁用！因为 Hysteria2 masquerade 伪装回落来源 IP 为 127.0.0.1，
# 若开启该项会导致本地回环地址被 Hiawatha 自身加入 Ban 列表从而引发自锁。
BanOnMaxPerIP = 60
BanOnMaxReqSize = 300
BanOnSQLi = 120
KickOnBan = yes
RebanDuringBan = yes

# ================= 监听绑定 =================
# 80 端口用于跳转
Binding {
    Port = 80
    Interface = 0.0.0.0
}

# 443 端口提供 HTTPS 伪装站
Binding {
    Port = 443
    Interface = 0.0.0.0
    TLScertFile = /usr/local/etc/ssl/mihomo/hiawatha.pem
}

# ================= 虚拟主机配置 =================
VirtualHost {
    Hostname = proxy.example.com
    WebsiteRoot = /usr/local/www/hiawatha
    StartFile = index.html
    AccessLogfile = /var/log/hiawatha/access.log
    ErrorLogfile = /var/log/hiawatha/error.log

    # 强制 301 重定向到 HTTPS，并下发 31 天 HSTS 响应头
    RequireTLS = yes, 2678400

    # 关闭目录列表浏览
    ShowIndex = no

    # 开启内置 Web 应用攻击防御（返回 404，不给扫描器提供回显指纹）
    PreventXSS = prevent
    PreventSQLi = prevent
    PreventCSRF = prevent

    # 安全响应头强化
    CustomHeaderClient = X-Frame-Options: SAMEORIGIN
    CustomHeaderClient = X-Content-Type-Options: nosniff
    CustomHeaderClient = Referrer-Policy: strict-origin-when-cross-origin
}
```

### 2. 配置 `/etc/hosts` 本地回环解析与站点启动

为确保 `mihomo` 在将未认证请求重定向回伪装站时不经过公网 DNS 绕行，在 `/etc/hosts` 中加入本地域名回环映射：

```bash
grep -qF "proxy.example.com" /etc/hosts || printf '\n127.0.0.1 proxy.example.com\n' | sudo tee -a /etc/hosts
```

在 `/usr/local/www/hiawatha/index.html` 放置静态网页内容后启动服务：
```bash
sudo sysrc hiawatha_enable="YES"
sudo service hiawatha start
```

---

## 8. 核心代理服务部署 (mihomo)

### 1. 下载并安装二进制 (`02-install-mihomo.sh`)

创建并运行 `02-install-mihomo.sh`。该脚本自动查询 GitHub 最新发布版本并完成哈希与可执行预检：

```bash
#!/usr/bin/env sh
# ==============================================================================
# 02-install-mihomo.sh - mihomo 核心二进制下载与安装
# ==============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：必须使用 root 权限运行：sudo sh $0" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/mihomo_install.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "未适配的架构：$ARCH_RAW" >&2; exit 1 ;;
esac

echo ">> 查询 GitHub 最新版本 tag..."
LATEST_TAG="$(curl -sI https://github.com/MetaCubeX/mihomo/releases/latest \
  | grep -i '^location:' | tr -d '\r' | sed -E 's#.*/tag/##' || true)"

if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

LATEST_TAG="${MIHOMO_TAG:-$LATEST_TAG}"

if [ -z "$LATEST_TAG" ]; then
  echo "错误：获取最新版本失败，请手动指定 MIHOMO_TAG" >&2
  exit 1
fi

echo ">> 目标版本：$LATEST_TAG ($ARCH)"
ASSET="mihomo-freebsd-${ARCH}-${LATEST_TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/${ASSET}"
DEST_GZ="$WORK_DIR/mihomo.gz"

echo ">> 下载 $URL ..."
if ! curl -fL --retry 3 --retry-delay 2 -o "$DEST_GZ" "$URL"; then
  echo "错误：下载失败" >&2
  exit 1
fi

if [ -n "${MIHOMO_SHA256:-}" ]; then
  echo ">> 校验 SHA256 完整性..."
  ACTUAL_SHA="$(sha256 -q "$DEST_GZ" 2>/dev/null || sha256sum "$DEST_GZ" | cut -d' ' -f1)"
  if [ "$ACTUAL_SHA" != "$MIHOMO_SHA256" ]; then
    echo "错误：SHA256 校验不匹配！" >&2
    exit 1
  fi
fi

gunzip -c "$DEST_GZ" > "$WORK_DIR/mihomo"
chmod 755 "$WORK_DIR/mihomo"

# 沙箱预检能否正常执行
if ! "$WORK_DIR/mihomo" -v >/dev/null 2>&1; then
  echo "错误：下载的文件无法正常执行" >&2
  exit 1
fi

install -m 755 -o root -g wheel "$WORK_DIR/mihomo" /usr/local/bin/mihomo

# 若有 Geo 数据库则建立软连接
if [ -d "/var/db/mihomo" ]; then
  for f in geoip.dat geosite.dat country.mmdb GeoLite2-ASN.mmdb; do
    if [ -f "/usr/local/etc/mihomo/$f" ] && [ ! -e "/var/db/mihomo/$f" ]; then
      ln -sf "/usr/local/etc/mihomo/$f" "/var/db/mihomo/$f"
      chown -h mihomo:mihomo "/var/db/mihomo/$f" 2>/dev/null || true
    fi
  done
fi

echo "=================================================="
echo " [完成] mihomo 安装成功："
/usr/local/bin/mihomo -v
echo "=================================================="
```

### 2. 生成 ECH 密钥对
```bash
mihomo generate ech-keypair cloudflare.com
```

### 3. 服务端配置文件 (`/usr/local/etc/mihomo/config.yaml`)

```yaml
# /usr/local/etc/mihomo/config.yaml
# FreeBSD 15 Hysteria2 生产配置

log-level: warning
ipv6: false

# 禁用进程查找模式，减轻 FreeBSD 系统调用开销
find-process-mode: off

# 默认关闭外部控制端口 (9090)，收敛本地监听暴露面
# external-controller: 127.0.0.1:9090

profile:
  store-selected: false
  store-fake-ip: false

listeners:
  - name: hy2-in
    type: hysteria2
    # 仅绑定本地回环端口，外部通过 PF 端口跳跃映射进本端口
    port: 18921
    listen: 127.0.0.1

    users:
      hy2-user: "YOUR_GENERATED_STRONG_PASSWORD"

    up: 100
    down: 100

    ignore-client-bandwidth: true

    # 未认证与主动探测流量 fallback 回落至本地 Hiawatha 伪装站
    masquerade: "https://proxy.example.com"

    alpn:
      - h3

    certificate: /usr/local/etc/ssl/mihomo/fullchain.pem
    private-key: /usr/local/etc/ssl/mihomo/privkey.pem

    # 填入生成的 ECH 私钥
    ech-key: |
      -----BEGIN PRIVATE KEY-----
      YOUR_ECH_PRIVATE_KEY
      -----END PRIVATE KEY-----

# 出站规则层阻断：拦截所有私有网段、本地回环和云元数据地址
# 采用纯 CIDR 规则，不依赖外部 GeoIP 数据库
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

收紧配置权限并沙箱测试配置：
```bash
sudo chmod 640 /usr/local/etc/mihomo/config.yaml
sudo chown root:mihomo /usr/local/etc/mihomo/config.yaml
sudo /usr/local/bin/mihomo -t -d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml
sudo chown -R mihomo:mihomo /var/db/mihomo
```

### 4. 守护进程服务脚本 (`/usr/local/etc/rc.d/mihomo`)

FreeBSD 原生提供了 `/usr/sbin/daemon` 守护工具。我们利用 `-r` 实现核心崩溃 1 秒自动拉起，利用 `-P` 实现监管进程 PID 锁控制，并在 root 环境完成最大文件描述符提权后再安全降权至 `mihomo` 用户执行。

写入 `/usr/local/etc/rc.d/mihomo`：

```sh
#!/bin/sh
#
# PROVIDE: mihomo
# REQUIRE: NETWORKING pf
# KEYWORD: shutdown

. /etc/rc.subr

name="mihomo"
rcvar="mihomo_enable"

load_rc_config $name
: ${mihomo_enable:="NO"}
: ${mihomo_run_user:="mihomo"}

pidfile="/var/run/${name}.pid"

# 在 root 阶段提升文件描述符限制，再由 daemon -u 降权至普通用户
mihomo_limits="-n 200000"

# 使用 FreeBSD 原生 daemon 守护进程：
#   -r : 核心异常退出后 1 秒内自动拉起
#   -P : 监管并维护 PID 文件，确保 service stop/restart 信号能正确收发
#   -S -T : 标准输出与错误重定向至 syslog (tag: mihomo)
#   -u : 降权至受限账户运行子进程
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

## 9. 全栈自动化健康审计工具 (`99-verify.sh`)

将巡检脚本安装至 `/usr/local/sbin/mihomo-verify`，可一键全面核验服务运行状态、监听暴露面、PF 过滤与内联 `rdr-to` 规则链、内核参数、八进制权限掩码及伪装站本地 TLS 回环连通性。

写入 `99-verify.sh`：

```bash
#!/usr/bin/env sh
# ==============================================================================
# 99-verify.sh (mihomo-verify) - FreeBSD 15 节点全栈自检工具
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  printf '[-] 必须使用 root 权限执行：sudo sh %s\n' "$0" >&2
  exit 1
fi

if [ "${1:-}" = "--install" ]; then
  install -m 755 -o root -g wheel "$0" /usr/local/sbin/mihomo-verify
  printf '[+] 已安装常驻命令：/usr/local/sbin/mihomo-verify\n'
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

pass() { printf "  [ ${c_green}PASS${c_reset} ] %s\n" "$1"; TOTAL_PASS=$((TOTAL_PASS + 1)); }
warn() { printf "  [ ${c_yellow}WARN${c_reset} ] %s\n" "$1"; TOTAL_WARN=$((TOTAL_WARN + 1)); }
fail() { printf "  [ ${c_red}FAIL${c_reset} ] %s\n" "$1"; TOTAL_FAIL=$((TOTAL_FAIL + 1)); }
info() { printf "${c_bold}${c_blue}==>${c_reset} ${c_bold}%s${c_reset}\n" "$1"; }

MASQ_DOMAIN=""
if [ -f /usr/local/etc/mihomo/config.yaml ]; then
  MASQ_DOMAIN="$(sed -nE 's|^[[:space:]]*masquerade:[[:space:]]*"?https?://([^"/:[:space:]]+).*|\1|p' /usr/local/etc/mihomo/config.yaml | head -1 || true)"
fi
if [ -z "$MASQ_DOMAIN" ] && [ -f /usr/local/etc/hiawatha/hiawatha.conf ]; then
  MASQ_DOMAIN="$(sed -nE 's|^[[:space:]]*Hostname[[:space:]]*=[[:space:]]*([^[:space:],#]+).*|\1|p' /usr/local/etc/hiawatha/hiawatha.conf | head -1 || true)"
fi

printf "\n================================================================================\n"
printf "  FreeBSD 15 代理与伪装节点全栈自检 - %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
printf "================================================================================\n\n"

# 1. 核心服务状态
info "1. 系统核心服务运行状态"
service pf status >/dev/null 2>&1 && pass "pf 防火墙服务：运行正常" || fail "pf 防火墙未运行"
service hiawatha status >/dev/null 2>&1 && pass "Hiawatha Web 伪装站：运行正常" || fail "Hiawatha 未运行"
if service mihomo status >/dev/null 2>&1; then
  grep -q -- '-r' /usr/local/etc/rc.d/mihomo 2>/dev/null \
    && pass "mihomo 核心服务：运行正常 (已启用崩溃自动拉起)" \
    || pass "mihomo 核心服务：运行正常"
else
  fail "mihomo 服务未在运行"
fi

# 2. 端口监听核验
printf "\n"
info "2. 端口监听与暴露面安全核验"
if sockstat -4l | grep -q '127\.0\.0\.1:18921'; then
  sockstat -4l | grep ':18921 ' | grep -qv '127\.0\.0\.1:18921' \
    && warn "18921/udp 绑定了非回环地址" \
    || pass "mihomo 核心监听：安全绑定 127.0.0.1:18921/udp (公网不可直接嗅探)"
else
  fail "未检测到 127.0.0.1:18921/udp 监听"
fi

sockstat -4l | grep -q ':9090 ' && warn "9090 控制端口处于监听状态，建议关闭" || pass "外部控制端口 (9090)：已关闭"
sockstat -4l | grep -q ':80 ' && sockstat -4l | grep -q ':443 ' \
  && pass "Hiawatha 伪装端口：80 与 443 正常监听" || warn "Hiawatha 未同时监听 80 与 443"

ROOT_LOGIN="$(/usr/sbin/sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2; exit}' || echo "unknown")"
[ "$ROOT_LOGIN" = "no" ] && pass "SSH 登录策略：PermitRootLogin = no" || warn "SSH PermitRootLogin 为 $ROOT_LOGIN"

# 3. 防火墙规则链检测
printf "\n"
info "3. pf 防火墙规则链与出站隔离检测"
PF_RULES="$(/sbin/pfctl -sr 2>/dev/null || true)"
PF_TABLES="$(/sbin/pfctl -s Tables 2>/dev/null || true)"

printf '%s\n' "$PF_RULES" | grep -q 'block drop in quick inet6' \
  && pass "IPv6 阻断规则：block drop in quick inet6 已生效" || warn "缺少 IPv6 阻断规则"

if printf '%s\n' "$PF_TABLES" | grep -q 'scan_blacklist'; then
  BL_COUNT="$(/sbin/pfctl -t scan_blacklist -T show 2>/dev/null | wc -l | tr -d ' ')"
  pass "动态黑名单表 <scan_blacklist>：生效中 (封禁 IP 数: $BL_COUNT)"
else
  fail "未找到 <scan_blacklist> 防火墙表"
fi

printf '%s\n' "$PF_TABLES" | grep -q 'private_nets' \
  && pass "出站防护表 <private_nets>：已加载" || warn "未找到 <private_nets> 防护表"

printf '%s\n' "$PF_RULES" | grep -qE 'block drop out quick .* to <private_nets> user' \
  && pass "内核级出站隔离：阻断代理进程发往私有网段与元数据" || warn "未检测到针对 mihomo 用户的出站隔离规则"

if printf '%s\n' "$PF_RULES" | grep -qE '(pass|match) in .*proto udp .*rdr-to 127\.0\.0\.1 port 18921'; then
  RDR_ORDER_OK="$(printf '%s\n' "$PF_RULES" | awk '
    /block drop in quick.*<scan_blacklist>/ { seen_bl = 1 }
    /(pass|match) in .*proto udp .*rdr-to 127\.0\.0\.1 port 18921/ {
      print (seen_bl ? "1" : "0")
      exit
    }
  ')"
  [ "$RDR_ORDER_OK" = "1" ] \
    && pass "端口跳跃转发 (FreeBSD 15 原生 rdr-to)：生效且受黑名单前置阻断保护" \
    || warn "rdr-to 已生效，但建议确保 block drop from <scan_blacklist> 位于其上方"
else
  fail "未检测到指向 127.0.0.1:18921 的 UDP 转发规则"
fi

# 4. 内核 sysctl 参数核验
printf "\n"
info "4. FreeBSD 内核防探测与进程隔离参数"
check_sysctl() {
  act="$(sysctl -n "$1" 2>/dev/null || echo "UNSET")"
  [ "$act" = "$2" ] && pass "$3 ($1 = $act)" || warn "$3 未对齐 ($1: 当前 $act, 预期 $2)"
}
check_sysctl "security.bsd.see_other_uids" "0" "进程视图隔离 (防跨用户查看)"
check_sysctl "security.bsd.unprivileged_proc_debug" "0" "非特权调试禁用"
check_sysctl "security.bsd.unprivileged_read_msgbuf" "0" "内核 dmesg 缓冲区读取保护"
check_sysctl "net.inet.tcp.blackhole" "2" "TCP 静默黑洞防扫描"
check_sysctl "net.inet.udp.blackhole" "1" "UDP 静默黑洞防扫描"
check_sysctl "net.inet.tcp.drop_synfin" "1" "SYN+FIN 畸形探针丢弃"
check_sysctl "net.inet.ip.random_id" "1" "IP 报文 ID 伪随机化"
check_sysctl "net.inet.ip.process_options" "0" "IP Option 报文丢弃"

# 5. 权限与账户基线
printf "\n"
info "5. 账户安全与敏感配置权限核验"
pw user show toor 2>/dev/null | grep -q '\*LOCKED\*' \
  && pass "冗余 UID 0 账户 (toor)：已锁定" || warn "toor 账户未锁定"

if grep -qE '^console[[:space:]]+.*[[:space:]]+insecure' /etc/ttys 2>/dev/null; then
  pass "控制台模式：insecure (单用户维护模式要求输入 root 密码)"
  ROOT_HASH="$(awk -F: '$1=="root"{print $2; exit}' /etc/master.passwd 2>/dev/null || true)"
  [ -z "$ROOT_HASH" ] || [ "$ROOT_HASH" = "*" ] || [ "$ROOT_HASH" = "!" ] \
    && warn "root 未设置本地密码！请运行 sudo passwd root 以备紧急救援" \
    || pass "VNC 救援保障：root 已设置本地密码哈希"
else
  warn "/etc/ttys 控制台非 insecure 模式"
fi

check_perm() {
  if [ -e "$1" ]; then
    mode="$(stat -f "%OLp" "$1" 2>/dev/null || stat -c "%a" "$1" 2>/dev/null || echo "777")"
    [ $(( 0$mode & ~0$2 )) -eq 0 ] && pass "$3: $1 (权限: $mode <= $2)" || warn "$3 权限过宽: $1 (当前: $mode, 建议: $2)"
  fi
}
check_perm "/etc/crontab" "600" "系统 crontab"
check_perm "/etc/pf.conf" "600" "PF 防火墙配置"
check_perm "/etc/ssh/sshd_config" "600" "OpenSSH 配置"
check_perm "/usr/local/etc/mihomo/config.yaml" "640" "mihomo 配置"
check_perm "/usr/local/etc/ssl/mihomo/fullchain.pem" "640" "TLS 公钥证书链"
check_perm "/usr/local/etc/ssl/mihomo/privkey.pem" "640" "TLS 私钥"
check_perm "/usr/local/etc/ssl/mihomo/hiawatha.pem" "640" "Hiawatha 合并 PEM"

# 6. 定时运维任务
printf "\n"
info "6. 定时运维与日志轮转任务"
ROOT_CRON="$(crontab -u root -l 2>/dev/null || true)"
printf '%s\n' "$ROOT_CRON" | grep -q 'certbot.*renew' \
  && pass "Certbot 自动续期任务：已注册" || warn "缺少 Certbot 自动续期任务"
printf '%s\n' "$ROOT_CRON" | grep -q 'scan_blacklist.*expire' \
  && pass "黑名单自动老化任务：已注册 (24h TTL)" || warn "缺少 scan_blacklist 老化任务"
[ -f "/etc/newsyslog.conf.d/hiawatha.conf" ] \
  && pass "Hiawatha 日志自动轮转：已配置" || warn "未找到 Hiawatha 日志轮转配置"

# 7. TLS 证书与本地伪装闭环实测
printf "\n"
info "7. TLS 证书有效状态与伪装回环实测"
PEM_FILE="/usr/local/etc/ssl/mihomo/fullchain.pem"
if [ -f "$PEM_FILE" ] && command -v openssl >/dev/null 2>&1; then
  END_DATE_RAW="$(LC_ALL=C openssl x509 -enddate -noout -in "$PEM_FILE" 2>/dev/null | cut -d= -f2 || true)"
  # 强制 LC_ALL=C 防止中文系统解析英文字符月份失败
  END_EPOCH="$(LC_ALL=C date -j -f "%b %e %T %Y %Z" "$END_DATE_RAW" "+%s" 2>/dev/null || LC_ALL=C date -d "$END_DATE_RAW" "+%s" 2>/dev/null || echo "0")"
  NOW_EPOCH="$(date "+%s")"

  if [ "$END_EPOCH" -gt 0 ]; then
    DAYS_LEFT=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
    [ "$DAYS_LEFT" -gt 15 ] \
      && pass "TLS 证书状态正常 (剩余有效期: $DAYS_LEFT 天)" \
      || warn "TLS 证书即将到期 (剩余: $DAYS_LEFT 天)"
  else
    openssl x509 -checkend 1296000 -noout -in "$PEM_FILE" >/dev/null 2>&1 \
      && pass "TLS 证书状态正常 (> 15 天)" || fail "TLS 证书即将到期或已过期"
  fi
fi

if [ -n "$MASQ_DOMAIN" ] && [ "$MASQ_DOMAIN" != "proxy.example.com" ]; then
  if awk -v dom="$MASQ_DOMAIN" '
    /^[[:space:]]*#/ { next }
    $1 == "127.0.0.1" { for (i=2; i<=NF; i++) if ($i == dom) { found=1; exit } }
    END { exit(found ? 0 : 1) }
  ' /etc/hosts 2>/dev/null; then
    pass "域名本地回环解析 (/etc/hosts): 127.0.0.1 -> $MASQ_DOMAIN"
  else
    warn "/etc/hosts 缺少 127.0.0.1 -> $MASQ_DOMAIN 回环解析"
  fi

  if command -v curl >/dev/null 2>&1; then
    HTTP_CODE="$(curl --resolve "${MASQ_DOMAIN}:443:127.0.0.1" -s -o /dev/null -w "%{http_code}" "https://${MASQ_DOMAIN}/" 2>/dev/null || echo "000")"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ] \
      && pass "伪装站端到端闭环实测 (SNI + 证书链校验 + VirtualHost): HTTP $HTTP_CODE" \
      || warn "伪装站闭环访问返回 HTTP $HTTP_CODE"
  fi
fi

printf "\n================================================================================\n"
printf "  自检汇总报告：\n"
printf "    ${c_green}PASS : %d${c_reset}\n" "$TOTAL_PASS"
printf "    ${c_yellow}WARN : %d${c_reset}\n" "$TOTAL_WARN"
printf "    ${c_red}FAIL : %d${c_reset}\n" "$TOTAL_FAIL"
printf "================================================================================\n"

[ "$TOTAL_FAIL" -eq 0 ] && exit 0 || exit 1
```

安装并执行自检：
```bash
sudo sh 99-verify.sh --install
sudo mihomo-verify
```

---

## 10. 平滑升级与版本备份维护 (`03-upgrade-mihomo.sh`)

创建 `/usr/local/sbin/upgrade-mihomo`，该脚本用于后续代理核心的版本升级。包含以下机制：
- 自动对比本地版本与 GitHub Release 最新正式版本；
- 新版本二进制在独立临时目录下进行沙箱可执行测试，并结合当前线上 `config.yaml` 跑语法预检；
- 旧版本归档备份至 `/var/backups/mihomo/`（权限 700），并自动轮转（仅保留最新 2 份，自动回收老备份）；
- 若新版本启动或端口监听绑定异常，自动秒级回滚旧版本二进制并拉起服务。

> **重要提示**：运行升级脚本时会短暂重启 `mihomo`。请确保当前是通过**直连 SSH**（不要挂载当前节点本身的代理网络）登录服务器执行升级，避免因代理通道中断导致 SSH 终端会话闪断。

写入 `03-upgrade-mihomo.sh`：

```bash
#!/usr/bin/env sh
# ==============================================================================
# 03-upgrade-mihomo.sh - mihomo 平滑升级与异常自动回滚
# ==============================================================================
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：必须使用 root 权限执行：sudo sh $0" >&2
  exit 1
fi

BIN_PATH="/usr/local/bin/mihomo"
BACKUP_ROOT="/var/backups/mihomo"
FORCE="${1:-}"

if [ ! -x "$BIN_PATH" ]; then
  echo "错误：未找到已安装的 $BIN_PATH，请先完成初始安装" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/mihomo_upgrade.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "未适配的架构：$ARCH_RAW" >&2; exit 1 ;;
esac

CURRENT_TAG="$("$BIN_PATH" -v 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
echo ">> 当前运行版本：${CURRENT_TAG:-未知}"

echo ">> 查询 GitHub 最新版本..."
LATEST_TAG="$(curl -sI https://github.com/MetaCubeX/mihomo/releases/latest \
  | grep -i '^location:' | tr -d '\r' | sed -E 's#.*/tag/##' || true)"

if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

LATEST_TAG="${MIHOMO_TAG:-$LATEST_TAG}"

if [ -z "$LATEST_TAG" ]; then
  echo "错误：无法获取线上版本号" >&2
  exit 1
fi

echo ">> 线上版本：$LATEST_TAG"

if [ -n "$CURRENT_TAG" ] && [ "$CURRENT_TAG" = "$LATEST_TAG" ] && [ "$FORCE" != "--force" ]; then
  echo ">> 当前已是最新版本 ($CURRENT_TAG)，无需重复升级。"
  exit 0
fi

ASSET="mihomo-freebsd-${ARCH}-${LATEST_TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${LATEST_TAG}/${ASSET}"
DEST_GZ="$WORK_DIR/mihomo.gz"

echo ">> 正在下载 $URL ..."
if ! curl -fL --retry 3 --retry-delay 2 -o "$DEST_GZ" "$URL"; then
  echo "错误：下载失败" >&2
  exit 1
fi

gunzip -c "$DEST_GZ" > "$WORK_DIR/mihomo"
chmod 755 "$WORK_DIR/mihomo"

# 二进制可执行测试
if ! "$WORK_DIR/mihomo" -v >/dev/null 2>&1; then
  echo "错误：新二进制执行测试失败，已中止升级，旧版本未改动" >&2
  exit 1
fi

# 结合当前配置做语法测试
if [ -f "/usr/local/etc/mihomo/config.yaml" ] && [ -d "/var/db/mihomo" ]; then
  if ! "$WORK_DIR/mihomo" -t -d /var/db/mihomo -f /usr/local/etc/mihomo/config.yaml >/dev/null 2>&1; then
    echo "错误：新版本无法通过当前 config.yaml 语法预检，中止升级" >&2
    exit 1
  fi
fi

install -d -m 700 -o root -g wheel "$BACKUP_ROOT"
BACKUP_PATH="${BACKUP_ROOT}/mihomo.bak-$(date +%Y%m%d_%H%M%S)"

WAS_RUNNING=0
if service mihomo status >/dev/null 2>&1; then
  WAS_RUNNING=1
  echo ">> 正在停止当前 mihomo 服务..."
  service mihomo stop >/dev/null 2>&1 || true
  sleep 1
fi

echo ">> 备份当前旧版本至: $BACKUP_PATH"
cp -pf "$BIN_PATH" "$BACKUP_PATH"
chmod 700 "$BACKUP_PATH"

echo ">> 安装新版本二进制..."
install -m 755 -o root -g wheel "$WORK_DIR/mihomo" "$BIN_PATH"

# 恢复服务并进行端口连通性健康核验
if [ "$WAS_RUNNING" -eq 1 ]; then
  echo ">> 正在重启 mihomo 并验证端口监听..."
  if service mihomo start && sleep 1 \
     && service mihomo status >/dev/null 2>&1 \
     && sockstat -4l | grep -q '127\.0\.0\.1:18921'; then
    echo ">> mihomo 升级成功，端口监听正常！"
  else
    echo "警告：新版本启动或监听异常！正在自动回滚..." >&2
    service mihomo stop >/dev/null 2>&1 || true
    install -m 755 -o root -g wheel "$BACKUP_PATH" "$BIN_PATH"
    service mihomo start >/dev/null 2>&1 || true
    echo "已成功恢复旧版本运行" >&2
    exit 1
  fi
fi

# 自动轮转：仅保留最新 2 份历史备份
OLD_BAKS="$(ls -1t "${BACKUP_ROOT}"/mihomo.bak-* 2>/dev/null || true)"
OLD_COUNT="$(printf '%s\n' "$OLD_BAKS" | grep -v '^[[:space:]]*$' | wc -l | tr -d ' ')"
if [ "$OLD_COUNT" -gt 2 ]; then
  printf '%s\n' "$OLD_BAKS" | tail -n +3 | while IFS= read -r old_file; do
    [ -f "$old_file" ] && rm -f "$old_file" && echo ">> 清理过期备份: $old_file"
  done
fi

echo "=================================================="
echo " [完成] 升级成功！当前版本："
"$BIN_PATH" -v
echo " 历史备份保存在: $BACKUP_PATH"
echo "=================================================="
```

```bash
sudo chmod 755 03-upgrade-mihomo.sh
```

---

## 11. 日常排查命令

```bash
# 1. 查看防火墙规则及匹配计数
sudo pfctl -v -sr

# 2. 查看当前被 scan_blacklist 封禁的 IP
sudo pfctl -t scan_blacklist -T show

# 3. 手动解封被误判的 IP
sudo pfctl -t scan_blacklist -T delete 198.51.100.50

# 4. 查看当前网络监听端口
sudo sockstat -4l | grep -E '(18921|80|443|28622)'

# 5. 测试证书与伪装站响应
curl --resolve "proxy.example.com:443:127.0.0.1" -Iv "https://proxy.example.com/"

# 6. 实时跟踪代理运行日志
sudo tail -f /var/log/messages | grep mihomo
```

