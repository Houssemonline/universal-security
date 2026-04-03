#!/bin/bash
# ============================================================================
# secure-server.sh - Automatic Nginx Security Hardening (WORKING VERSION)
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${2:-$GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

# Backup
backup_configs() {
    BACKUP_DIR="/etc/nginx/backup-$(date +%Y%m%d-%H%M%S)"
    log "Creating backup in $BACKUP_DIR..." "$YELLOW"
    mkdir -p "$BACKUP_DIR"
    cp -r /etc/nginx/sites-available "$BACKUP_DIR/" 2>/dev/null
    cp /etc/nginx/nginx.conf "$BACKUP_DIR/" 2>/dev/null
    log "Backup created: $BACKUP_DIR" "$GREEN"
    echo "$BACKUP_DIR" > /tmp/nginx-backup-path
}

# Create security files
create_security_files() {
    log "Creating security configuration files..." "$YELLOW"
    
    # Create conf.d directory if it doesn't exist
    sudo mkdir -p /etc/nginx/conf.d
    
    # Main security configuration
    sudo tee /etc/nginx/conf.d/security.conf > /dev/null << 'SECURITY'
# Rate limiting
limit_req_zone $binary_remote_addr zone=attack_scan:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=env_scan:10m rate=5r/m;

# Blacklist
geo $block_ip {
    default 0;
    include /etc/nginx/blacklist.conf;
}

# Block attack patterns
map $request_uri $block_attack {
    default 0;
    ~* /\.(env|git|htaccess|htpasswd|svn|idea|vscode|aws) 1;
    ~* /(shell|cmd|backdoor|webshell|asd67|rithin|wolv2|bless|chosen|t00l)\.php 1;
    ~* /(wp-admin|wp-includes|wp-content|wp-login|xmlrpc|wlwmanifest) 1;
    ~* /(actuator/env|debug/view|config\.php|wp-config\.php|robots\.txt) 1;
}

# Block bad user agents
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
SECURITY

    # Blocking rules that will be included in each server block
    sudo tee /etc/nginx/conf.d/block-rules.conf > /dev/null << 'RULES'
if ($block_ip) {
    return 444;
}
if ($block_attack) {
    return 444;
}
if ($block_ua) {
    return 444;
}
location ~* /\.env {
    return 444;
}
location ~* \.php$ {
    return 444;
}
RULES

    sudo touch /etc/nginx/blacklist.conf
    log "Security files created" "$GREEN"
}

# Inject security into all site configs
inject_security() {
    log "Injecting security rules into all sites..." "$YELLOW"
    
    for config in /etc/nginx/sites-available/*.conf; do
        if [ -f "$config" ] && ! grep -q "block-rules.conf" "$config"; then
            # Add include after server_name line
            sudo sed -i "/server_name/a \    include /etc/nginx/conf.d/block-rules.conf;" "$config"
            log "Secured: $(basename $config)" "$GREEN"
        fi
    done
}

# Create monitoring scripts
create_monitoring_scripts() {
    log "Creating monitoring scripts..." "$YELLOW"
    
    sudo tee /usr/local/bin/security-status.sh > /dev/null << 'DASH'
#!/bin/bash
clear
echo "========================================="
echo "SECURITY DASHBOARD - $(hostname)"
echo "========================================="
echo "Time: $(date)"
echo ""
echo "Protected sites: $(grep -l "block-rules.conf" /etc/nginx/sites-available/*.conf 2>/dev/null | wc -l)"
echo "Attacks blocked: $(grep ' 444 ' /var/log/nginx/access.log 2>/dev/null | wc -l)"
echo "STATUS: ACTIVE"
DASH
    
    sudo chmod +x /usr/local/bin/security-status.sh
    log "Monitoring scripts created" "$GREEN"
}

# Main installation
main() {
    log "=========================================" "$BLUE"
    log "Secure Server - Automatic Installation" "$BLUE"
    log "=========================================" "$BLUE"
    
    backup_configs
    create_security_files
    inject_security
    create_monitoring_scripts
    
    # Test and reload
    log "Testing and applying configuration..." "$YELLOW"
    if sudo nginx -t 2>/dev/null; then
        sudo systemctl reload nginx
        log "Nginx reloaded successfully!" "$GREEN"
    else
        log "ERROR in configuration! Rolling back..." "$RED"
        BACKUP_DIR=$(cat /tmp/nginx-backup-path)
        sudo cp -r "$BACKUP_DIR/sites-available/"* /etc/nginx/sites-available/ 2>/dev/null
        sudo systemctl reload nginx
        exit 1
    fi
    
    log "=========================================" "$BLUE"
    log "INSTALLATION COMPLETE!" "$GREEN"
    log "=========================================" "$BLUE"
    log "Test with: curl -I https://your-domain.com/.env" "$YELLOW"
    log "Dashboard: sudo /usr/local/bin/security-status.sh" "$YELLOW"
}

main
