#!/bin/bash
# ============================================================================
# UNIVERSAL SECURITY HARDENING - Works on any Nginx server
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Détection automatique
detect_environment() {
    log "🔍 Detecting environment..." "$YELLOW"
    
    # Détection OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        log "✓ OS: $OS $VER"
    fi
    
    # Détection Nginx
    if command -v nginx &> /dev/null; then
        NGINX_VERSION=$(nginx -v 2>&1 | cut -d'/' -f2)
        log "✓ Nginx version: $NGINX_VERSION"
    else
        log "❌ Nginx not found! Installing..." "$YELLOW"
        apt-get update -qq && apt-get install nginx -y -qq
    fi
    
    # Détection des sites
    if [ -d /etc/nginx/sites-available ]; then
        SITE_COUNT=$(ls -1 /etc/nginx/sites-available/*.conf 2>/dev/null | wc -l)
        log "✓ Found $SITE_COUNT site configurations"
    fi
    
    # Détection Docker
    if command -v docker &> /dev/null; then
        DOCKER_COUNT=$(docker ps -q 2>/dev/null | wc -l)
        log "✓ Docker detected ($DOCKER_COUNT containers)"
    fi
}

# Installation principale
install_security() {
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    log "     UNIVERSAL SECURITY HARDENING v2.0                          " "$BLUE"
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    echo ""
    
    detect_environment
    
    # 1. Créer configuration globale
    log "📝 Creating global security config..." "$YELLOW"
    
    cat > /etc/nginx/conf.d/00-security-global.conf << 'GLOBAL'
# Rate limiting
limit_req_zone $binary_remote_addr zone=attack_scan:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=env_scan:10m rate=5r/m;

# Blacklist
geo $block_ip {
    default 0;
    include /etc/nginx/blacklist.conf;
}

# Attack patterns
map $request_uri $block_attack {
    default 0;
    ~* /\.(env|git|htaccess|htpasswd|svn|idea|vscode|aws) 1;
    ~* /(shell|cmd|backdoor|webshell|asd67|rithin|wolv2|bless)\.php 1;
    ~* /(wp-admin|wp-includes|wp-content|wp-login|xmlrpc|wlwmanifest) 1;
    ~* /(actuator/env|debug/view|config\.php|wp-config\.php) 1;
}

# Malicious user agents
map $http_user_agent $block_ua {
    default 0;
    ~*(bot|crawler|scanner|nikto|sqlmap|nmap|zgrab|curl|wget|python-requests) 1;
    ~*(CMS-Checker|ClaudeBot|Go-http-client) 1;
    "" 1;
}

# Security headers (will be added automatically)
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
GLOBAL

    # 2. Créer include file
    cat > /etc/nginx/conf.d/01-block-attacks.include << 'BLOCK'
# Block IP
if ($block_ip) {
    return 444;
}

# Block attack patterns
if ($block_attack) {
    limit_req zone=attack_scan burst=5 nodelay;
    access_log off;
    return 444;
}

# Block malicious user agents
if ($block_ua) {
    access_log off;
    return 444;
}

# Block .env files
location ~* /\.env {
    limit_req zone=env_scan burst=1 nodelay;
    return 444;
}

# Block PHP files
location ~* \.php$ {
    return 444;
}
BLOCK

    # 3. Script d'injection automatique
    cat > /usr/local/bin/inject-security.sh << 'INJECT'
#!/bin/bash
SITES_DIR="/etc/nginx/sites-available"
INCLUDE="/etc/nginx/conf.d/01-block-attacks.include"
BACKUP="/etc/nginx/security-backup-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP"

for config in $SITES_DIR/*.conf; do
    [ -f "$config" ] || continue
    cp "$config" "$BACKUP/"
    
    if ! grep -q "01-block-attacks.include" "$config"; then
        sed -i "/server_name/a \    include $INCLUDE;" "$config"
        echo "✓ Secured: $(basename $config)"
    fi
done

nginx -t && systemctl reload nginx
INJECT

    chmod +x /usr/local/bin/inject-security.sh

    # 4. Blacklist dynamique
    touch /etc/nginx/blacklist.conf
    
    cat > /usr/local/bin/update-blacklist.sh << 'BLACK'
#!/bin/bash
tail -n 10000 /var/log/nginx/access.log 2>/dev/null | \
    grep " 444 " | awk '{print $1}' | sort | uniq -c | \
    awk '$1 > 5 {print $2}' > /tmp/blacklist.tmp

echo "# Blocked IPs - $(date)" > /etc/nginx/blacklist.conf
while read ip; do
    [ -n "$ip" ] && echo "$ip 1;" >> /etc/nginx/blacklist.conf
    iptables -A INPUT -s "$ip" -j DROP 2>/dev/null
done < /tmp/blacklist.tmp

nginx -s reload 2>/dev/null
BLACK

    chmod +x /usr/local/bin/update-blacklist.sh

    # 5. Installation Fail2ban (optionnel)
    if command -v fail2ban-client &> /dev/null || apt-get install -y fail2ban 2>/dev/null; then
        cat > /etc/fail2ban/jail.d/nginx-security.conf << 'FAIL'
[nginx-444]
enabled = true
port = http,https
filter = nginx-444
logpath = /var/log/nginx/access.log
maxretry = 3
bantime = 86400
FAIL

        cat > /etc/fail2ban/filter.d/nginx-444.conf << 'FILTER'
[Definition]
failregex = ^<HOST> .* "GET .*" 444
FILTER

        systemctl restart fail2ban 2>/dev/null
        systemctl enable fail2ban 2>/dev/null
    fi

    # 6. Appliquer à tous les sites
    log "🚀 Applying security to all sites..." "$YELLOW"
    /usr/local/bin/inject-security.sh

    # 7. Créer dashboard
    cat > /usr/local/bin/security-status.sh << 'DASH'
#!/bin/bash
clear
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              SECURITY DASHBOARD - $(hostname)                  ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║ $(date)                                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "🌍 Protected sites: $(ls -1 /etc/nginx/sites-available/*.conf 2>/dev/null | wc -l)"
echo "🔥 Blocked IPs: $(iptables -L INPUT -n 2>/dev/null | grep DROP | wc -l)"
echo "📊 Attacks blocked (24h): $(grep " 444 " /var/log/nginx/access.log 2>/dev/null | wc -l)"
echo ""
echo "✅ STATUS: ACTIVE"
DASH

    chmod +x /usr/local/bin/security-status.sh

    # 8. Cron jobs
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/update-blacklist.sh") | crontab -

    # 9. Final
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

# Run installation
install_security