#!/bin/bash
# ============================================================================
# AUTO-SECURE - Automatic Nginx Security Hardening Script
# ============================================================================
# Author: InDepth Security Team
# Version: 2.0.0
# Description: Automatically secures all Nginx sites against bots and attacks
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    echo -e "${2:-$GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

# Backup before making changes
backup_configs() {
    BACKUP_DIR="/etc/nginx/backup-$(date +%Y%m%d-%H%M%S)"
    log "📦 Creating backup in $BACKUP_DIR..." "$YELLOW"
    mkdir -p "$BACKUP_DIR"
    cp -r /etc/nginx/sites-available "$BACKUP_DIR/"
    cp -r /etc/nginx/sites-enabled "$BACKUP_DIR/" 2>/dev/null
    cp -r /etc/nginx/conf.d "$BACKUP_DIR/" 2>/dev/null
    cp /etc/nginx/nginx.conf "$BACKUP_DIR/" 2>/dev/null
    tar -czf "$BACKUP_DIR/full-backup.tar.gz" -C /etc/nginx . 2>/dev/null
    log "✅ Backup created: $BACKUP_DIR" "$GREEN"
    echo "$BACKUP_DIR" > /tmp/nginx-backup-path
}

# Create security configuration files
create_security_files() {
    log "🔒 Creating security configuration files..." "$YELLOW"
    
    # Global security config
    cat > /etc/nginx/conf.d/00-security-global.conf << 'GLOBAL'
# ============================================
# GLOBAL SECURITY RULES
# ============================================

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=attack_scan:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=env_scan:10m rate=5r/m;

# Dynamic blacklist
geo $block_ip {
    default 0;
    include /etc/nginx/blacklist.conf;
}

# Block attack patterns
map $request_uri $block_attack {
    default 0;
    ~* /\.(env|git|htaccess|htpasswd|svn|idea|vscode|aws) 1;
    ~* /(shell|cmd|backdoor|webshell|asd67|rithin|wolv2|bless|chosen|t00l|wp-.*\.php)\.php 1;
    ~* /(wp-admin|wp-includes|wp-content|wp-login|xmlrpc|wlwmanifest) 1;
    ~* /(actuator/env|debug/view|config\.php|wp-config\.php|robots\.txt) 1;
}

# Block malicious user agents
map $http_user_agent $block_ua {
    default 0;
    ~*(bot|crawler|scanner|nikto|sqlmap|nmap|zgrab|curl|wget|python-requests|Go-http-client) 1;
    ~*(CMS-Checker|ClaudeBot|PetalBot|Applebot) 1;
    "" 1;
}

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
GLOBAL

    # Attack blocking include file
    cat > /etc/nginx/conf.d/01-block-attacks.include << 'BLOCK'
# ============================================
# ATTACK BLOCKING RULES
# ============================================

# Block by IP
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
    access_log off;
    return 444;
}

# Block all PHP files
location ~* \.php$ {
    return 444;
}
BLOCK

    touch /etc/nginx/blacklist.conf
    log "✅ Security files created" "$GREEN"
}

# Inject security into all configurations
inject_security() {
    log "💉 Injecting security rules into all sites..." "$YELLOW"
    
    for config in /etc/nginx/sites-available/*.conf; do
        if [ -f "$config" ] && ! grep -q "01-block-attacks.include" "$config"; then
            sed -i "/server_name/a \    include /etc/nginx/conf.d/01-block-attacks.include;" "$config"
            log "   ✓ $(basename $config)" "$GREEN"
        fi
    done
}

# Create monitoring scripts
create_monitoring_scripts() {
    log "📊 Creating monitoring scripts..." "$YELLOW"
    
    # Security dashboard
    cat > /usr/local/bin/security-status.sh << 'DASH'
#!/bin/bash
clear
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              SECURITY DASHBOARD - $(hostname)                  ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║ $(date)                                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "🌍 Protected sites: $(grep -l "01-block-attacks.include" /etc/nginx/sites-available/*.conf 2>/dev/null | wc -l)"
echo "🔥 Attacks blocked (24h): $(grep ' 444 ' /var/log/nginx/access.log 2>/dev/null | wc -l)"
echo "🛡️ Blacklisted IPs: $(wc -l < /etc/nginx/blacklist.conf 2>/dev/null)"
echo ""
echo "✅ STATUS: ACTIVE"
DASH

    # Dynamic blacklist updater
    cat > /usr/local/bin/update-blacklist.sh << 'BLACK'
#!/bin/bash
# Auto-block IPs that attack the server

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

    # Log cleaner
    cat > /usr/local/bin/clean-logs.sh << 'CLEAN'
#!/bin/bash
# Remove attack entries from logs for cleaner monitoring

LOG_FILE="/var/log/nginx/access.log"
if [ -f "$LOG_FILE" ]; then
    grep -v " 444 " "$LOG_FILE" > /tmp/access.log.clean
    mv /tmp/access.log.clean "$LOG_FILE"
    systemctl reload nginx 2>/dev/null
fi
CLEAN

    chmod +x /usr/local/bin/security-status.sh
    chmod +x /usr/local/bin/update-blacklist.sh
    chmod +x /usr/local/bin/clean-logs.sh
    
    log "✅ Monitoring scripts created" "$GREEN"
}

# Configure Fail2ban
setup_fail2ban() {
    if command -v fail2ban-client &> /dev/null || apt-get install -y fail2ban 2>/dev/null; then
        log "🛡️ Configuring Fail2ban..." "$YELLOW"
        
        cat > /etc/fail2ban/jail.d/nginx-security.conf << 'FAIL'
[nginx-444]
enabled = true
port = http,https
filter = nginx-444
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 86400
FAIL

        cat > /etc/fail2ban/filter.d/nginx-444.conf << 'FILTER'
[Definition]
failregex = ^<HOST> .* "GET .*" 444
FILTER

        systemctl restart fail2ban 2>/dev/null
        systemctl enable fail2ban 2>/dev/null
        log "✅ Fail2ban configured" "$GREEN"
    fi
}

# Setup cron jobs
setup_cron() {
    log "⏰ Setting up automated tasks..." "$YELLOW"
    
    (crontab -l 2>/dev/null | grep -v "update-blacklist\|clean-logs"; \
     echo "*/5 * * * * /usr/local/bin/update-blacklist.sh"; \
     echo "0 * * * * /usr/local/bin/clean-logs.sh") | crontab -
    
    log "✅ Scheduled tasks configured" "$GREEN"
}

# Main installation function
main() {
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    log "         AUTO-SECURE - Automatic Security Installation          " "$BLUE"
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    echo ""
    
    backup_configs
    create_security_files
    inject_security
    create_monitoring_scripts
    setup_fail2ban
    setup_cron
    
    # Test and reload
    log "🚀 Applying configurations..." "$YELLOW"
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        log "✅ Nginx reloaded successfully" "$GREEN"
    else
        log "❌ Nginx configuration error! Restoring backup..." "$RED"
        BACKUP_DIR=$(cat /tmp/nginx-backup-path)
        cp -r "$BACKUP_DIR/sites-available/"* /etc/nginx/sites-available/ 2>/dev/null
        cp -r "$BACKUP_DIR/conf.d/"* /etc/nginx/conf.d/ 2>/dev/null
        systemctl reload nginx
        log "✅ Backup restored successfully" "$GREEN"
        exit 1
    fi
    
    # Final summary
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    log "                    INSTALLATION SUCCESSFUL !                    " "$BLUE"
    log "════════════════════════════════════════════════════════════════" "$BLUE"
    echo ""
    log "📊 View dashboard:     sudo /usr/local/bin/security-status.sh" "$YELLOW"
    log "🧪 Test blocking:      curl -I https://your-domain.com/.env" "$YELLOW"
    log "📝 Monitor attacks:    sudo tail -f /var/log/nginx/access.log | grep ' 444 '" "$YELLOW"
    log "💾 Backup location:    $(cat /tmp/nginx-backup-path)" "$YELLOW"
    echo ""
}
