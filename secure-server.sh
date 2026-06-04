#!/bin/bash
# ============================================================================
# UNIVERSAL SECURITY HARDENING - Works on any Nginx server
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NGINX_CONF_DIR='/etc/nginx'
NGINX_CONF_GLOBAL="$NGINX_CONF_DIR/conf.d/00-security-global.conf"
SECURITY_INCLUDE="$NGINX_CONF_DIR/conf.d/01-block-attacks.include"
BLACKLIST_CONF="$NGINX_CONF_DIR/blacklist.conf"

log() {
    local message="$1"
    local color="${2:-$NC}"
    echo -e "${color}${message}${NC}"
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root. Use sudo." >&2
        exit 1
    fi
}

detect_environment() {
    log "🔍 Detecting environment..." "$YELLOW"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="$NAME"
        VER="$VERSION_ID"
        log "✓ OS detected: $OS $VER"
    else
        log "⚠️  Unable to detect OS release file" "$YELLOW"
    fi

    if command -v nginx >/dev/null 2>&1; then
        NGINX_VERSION=$(nginx -v 2>&1 | cut -d'/' -f2)
        log "✓ Nginx version: $NGINX_VERSION"
    else
        if command -v apt-get >/dev/null 2>&1; then
            log "❌ Nginx not installed. Installing..." "$YELLOW"
            apt-get update -qq
            apt-get install -y -qq nginx
        else
            log "❌ Unsupported package manager. Nginx install failed." "$RED"
            exit 1
        fi
    fi

    if ! command -v nginx >/dev/null 2>&1; then
        log "❌ Nginx installation failed." "$RED"
        exit 1
    fi

    SITE_COUNT=$(find /etc/nginx/sites-available /etc/nginx/conf.d -maxdepth 1 -type f -name '*.conf' 2>/dev/null | wc -l)
    log "✓ Found $SITE_COUNT Nginx configuration file(s)"

    if command -v docker >/dev/null 2>&1; then
        DOCKER_COUNT=$(docker ps -q 2>/dev/null | wc -l)
        log "✓ Docker detected ($DOCKER_COUNT container(s))"
    fi
}

write_global_config() {
    log "📝 Writing global Nginx security config..." "$YELLOW"
    mkdir -p "$NGINX_CONF_DIR/conf.d"

    cat > "$NGINX_CONF_GLOBAL" <<'GLOBAL'
# Global security hardening for Nginx
server_tokens off;
sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 15;
client_body_timeout 10;
client_header_timeout 10;
reset_timedout_connection on;
large_client_header_buffers 4 16k;

limit_req_zone $binary_remote_addr zone=attack_scan:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=env_scan:10m rate=5r/m;

geo $block_ip {
    default 0;
    include /etc/nginx/blacklist.conf;
}

map $request_uri $block_attack {
    default 0;
    ~* /\.(env|git|htaccess|htpasswd|svn|idea|vscode|aws) 1;
    ~* /(shell|cmd|backdoor|webshell|asd67|rithin|wolv2|bless)\.php 1;
    ~* /(wp-admin|wp-includes|wp-content|wp-login|xmlrpc|wlwmanifest) 1;
    ~* /(actuator/env|debug/view|config\.php|wp-config\.php) 1;
}

map $http_user_agent $block_ua {
    default 0;
    ~*(bot|crawler|scanner|nikto|sqlmap|nmap|zgrab|curl|wget|python-requests) 1;
    ~*(CMS-Checker|ClaudeBot|Go-http-client) 1;
    "" 1;
}

add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header X-Download-Options "noopen" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
GLOBAL
}

write_include_file() {
    log "🛡️ Creating Nginx attack protection include..." "$YELLOW"

    cat > "$SECURITY_INCLUDE" <<'BLOCK'
# Block blacklisted IPs
if ($block_ip) {
    return 444;
}

# Block known attack patterns
if ($block_attack) {
    limit_req zone=attack_scan burst=5 nodelay;
    access_log off;
    return 444;
}

# Block suspicious user agents
if ($block_ua) {
    access_log off;
    return 444;
}

# Protect .env files
location ~* /\.env {
    limit_req zone=env_scan burst=1 nodelay;
    return 444;
}

# Prevent execution of PHP files where not expected
location ~* \.php$ {
    return 444;
}
BLOCK
}

write_inject_script() {
    log "🔧 Creating automatic site injector..." "$YELLOW"

    cat > /usr/local/bin/inject-security.sh <<'INJECT'
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SITES_DIR="/etc/nginx/sites-available"
if [ ! -d "$SITES_DIR" ]; then
    SITES_DIR="/etc/nginx/conf.d"
fi
INCLUDE_LINE="include /etc/nginx/conf.d/01-block-attacks.include;"
BACKUP_DIR="/etc/nginx/security-backup-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"

for config in "$SITES_DIR"/*.conf; do
    [ -f "$config" ] || continue
    cp "$config" "$BACKUP_DIR/"

    if ! grep -qF "$INCLUDE_LINE" "$config"; then
        awk -v include="$INCLUDE_LINE" '
            /server_name[[:space:]]/ && !found {
                print
                print "    " include
                found=1
                next
            }
            { print }
            END {
                if (!found) {
                    print "    " include
                }
            }' "$config" > "$config.tmp" && mv "$config.tmp" "$config"
        echo "✓ Secured: $(basename "$config")"
    fi
done

nginx -t && systemctl reload nginx
INJECT

    chmod +x /usr/local/bin/inject-security.sh
}

write_blacklist_script() {
    log "🚫 Creating blacklist updater..." "$YELLOW"
    touch "$BLACKLIST_CONF"

    cat > /usr/local/bin/update-blacklist.sh <<'BLACK'
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

ACCESS_LOG="/var/log/nginx/access.log"
BLACKLIST_CONF="/etc/nginx/blacklist.conf"
TMPFILE="/tmp/blacklist.tmp"

if [ ! -f "$ACCESS_LOG" ]; then
    exit 0
fi

grep " 444 " "$ACCESS_LOG" 2>/dev/null | awk '{print $1}' | sort | uniq -c | awk '$1 > 5 {print $2}' > "$TMPFILE"

echo "# Blocked IPs - $(date)" > "$BLACKLIST_CONF"
while read -r ip; do
    [ -z "$ip" ] && continue
    echo "$ip 1;" >> "$BLACKLIST_CONF"
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
    fi
done < "$TMPFILE"

nginx -t && nginx -s reload
BLACK

    chmod +x /usr/local/bin/update-blacklist.sh
}

install_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            log "📦 Installing fail2ban..." "$YELLOW"
            apt-get install -y fail2ban -qq
        fi
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        log "🔐 Configuring Fail2Ban for Nginx..." "$YELLOW"

        cat > /etc/fail2ban/jail.d/nginx-security.conf <<'FAIL'
[nginx-444]
enabled = true
port = http,https
filter = nginx-444
logpath = /var/log/nginx/access.log
maxretry = 3
bantime = 86400
FAIL

        cat > /etc/fail2ban/filter.d/nginx-444.conf <<'FILTER'
[Definition]
failregex = ^<HOST> .* "[A-Z]+ .*" 444
ignoreregex =
FILTER

        systemctl restart fail2ban 2>/dev/null || true
        systemctl enable fail2ban 2>/dev/null || true
    fi
}

write_status_script() {
    log "📊 Creating security status dashboard..." "$YELLOW"

    cat > /usr/local/bin/security-status.sh <<'DASH'
#!/bin/bash
clear
printf "╔════════════════════════════════════════════════════════════════╗\n"
printf "║              SECURITY DASHBOARD - %s                  ║\n" "$(hostname)"
printf "╠════════════════════════════════════════════════════════════════╣\n"
printf "║ %s                                      ║\n" "$(date)"
printf "╚════════════════════════════════════════════════════════════════╝\n"
printf "\n"
printf "🌍 Protected sites: %s\n" "$(find /etc/nginx/sites-available /etc/nginx/conf.d -maxdepth 1 -type f -name '*.conf' 2>/dev/null | wc -l)"
printf "🔥 Blocked IPs: %s\n" "$(iptables -L INPUT -n 2>/dev/null | grep -c DROP || true)"
printf "📊 Attacks blocked (24h): %s\n" "$(grep ' 444 ' /var/log/nginx/access.log 2>/dev/null | wc -l)"
printf "\n"
printf "✅ STATUS: ACTIVE\n"
DASH

    chmod +x /usr/local/bin/security-status.sh
}

install_cron_job() {
    log "⏱️  Installing cron job for blacklist updates..." "$YELLOW"
    local cron_entry="*/5 * * * * /usr/local/bin/update-blacklist.sh >/dev/null 2>&1"
    if ! crontab -l 2>/dev/null | grep -Fxq "$cron_entry"; then
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
    fi
}

apply_security() {
    log "🚀 Applying security to all sites..." "$YELLOW"
    /usr/local/bin/inject-security.sh
}

install_security() {
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    log "     UNIVERSAL SECURITY HARDENING v2.0                          " "$BLUE"
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    echo ""

    require_root
    detect_environment
    write_global_config
    write_include_file
    write_inject_script
    write_blacklist_script
    install_fail2ban
    apply_security
    write_status_script
    install_cron_job

    log "════════════════════════════════════════════════════════════════" "$BLUE"
    log "              INSTALLATION COMPLETE                             " "$BLUE"
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    echo ""
    log "✅ This server is now SECURED" "$GREEN"
    echo ""
    log "Commands:" "$YELLOW"
    echo "  • View status:    sudo /usr/local/bin/security-status.sh"
    echo "  • Test blocking:  curl -I http://localhost/.env"
    echo "  • Live attacks:   sudo tail -f /var/log/nginx/access.log | grep ' 444 '"
}

install_security
