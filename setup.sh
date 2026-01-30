#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/ncae_setup.log"

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "$(date): $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "$(date): WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "$(date): ERROR: $1" >> "$LOG_FILE"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root"
    fi
}

update_system() {
    log "Updating package lists..."
    apt-get update -y
}

# --- Service Functions ---

setup_http() {
    log "Setting up HTTP (Nginx)..."
    apt-get install -y nginx

    # Create index.html with "Hello World!"
    echo "Hello World!" > /var/www/html/index.html

    # Ensure permissions are correct
    chown www-data:www-data /var/www/html/index.html
    chmod 644 /var/www/html/index.html

    log "HTTP setup complete."
}

setup_ftp() {
    log "Setting up FTP (vsftpd)..."
    apt-get install -y vsftpd

    # Backup original config
    if [ ! -f /etc/vsftpd.conf.bak ]; then
        mv /etc/vsftpd.conf /etc/vsftpd.conf.bak
    fi

    # Copy new config
    if [ -f "configs/vsftpd.conf" ]; then
        cp configs/vsftpd.conf /etc/vsftpd.conf
    else
        warn "configs/vsftpd.conf not found! Using default."
    fi

    # Setup anonymous directory and file
    mkdir -p /srv/ftp
    echo "iloveftp" > /srv/ftp/iloveftp.txt
    chown ftp:ftp /srv/ftp/iloveftp.txt
    chmod 644 /srv/ftp/iloveftp.txt

    systemctl restart vsftpd
    log "FTP setup complete."
}

setup_dns() {
    log "Setting up DNS (Bind9)..."
    apt-get install -y bind9 bind9utils bind9-doc

    # Copy configs
    if [ -f "configs/named.conf.options" ]; then
        cp configs/named.conf.options /etc/bind/named.conf.options
    else
        warn "configs/named.conf.options not found! Using default."
    fi

    if [ -f "configs/named.conf.local" ]; then
        cp configs/named.conf.local /etc/bind/named.conf.local
    fi

    if [ -f "configs/db.test.local" ]; then
        cp configs/db.test.local /etc/bind/db.test.local
    fi

    systemctl restart bind9
    log "DNS setup complete."
}

setup_sql() {
    log "Setting up SQL (MariaDB)..."
    apt-get install -y mariadb-server

    # Configure to listen on all interfaces
    # We create a custom config file to override the default bind-address.
    # This is safer than using sed to edit default files which might change location.
    echo "[mysqld]" > /etc/mysql/mariadb.conf.d/99-ncae.cnf
    echo "bind-address = 0.0.0.0" >> /etc/mysql/mariadb.conf.d/99-ncae.cnf

    systemctl restart mariadb

    # Run init script
    if [ -f "configs/init.sql" ]; then
        log "Running SQL init script..."
        mysql < configs/init.sql
    else
        warn "configs/init.sql not found! Database not initialized."
    fi

    log "SQL setup complete."
}

setup_ssh() {
    log "Setting up SSH..."
    apt-get install -y openssh-server

    # Create ssh-user if it doesn't exist
    if ! id "ssh-user" &>/dev/null; then
        useradd -m -s /bin/bash ssh-user
        log "Created user: ssh-user"
    fi

    # Set up authorized keys
    mkdir -p /home/ssh-user/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxm2qvXKjqVOqytO3r8MzlAoGVUP8AS31PaCkkpi7piFNhvRTQARDXoGdg5CRjT/tWvKzpufao9glVzTyKzOacS+UHJanbUIC1zqSaWeH4aITLcmqnpb+BmvtU/eGhx/pQJHPVraxv/Tls4Cmt4ptHBJXUx0S+ldFp6YCqFxMpKIe6Mx+DKFGyL0Eisn9PbDqQK10CyMcL6PIftdp42Q8Zm3J2F4KoQGlR6Ba02SnJN8c1H9o+dDJh3pjR5m5SJpRL1/Lk+DBnk/B/xC2CYFLtT4EBVVWD3u5bonuWcrTXICXYPPoHcl/PSEnYpnLv8QuYVrq8yIW9oCp+RfbtCv0DrO9gSFXa6/mWzs1jMXVYpxizOeJgIzBQxMC52oiyFeZIBdsfrcVvRdh4WrRWKm8N04wftfkukwTfuLvuos729ydBO+81xtJ9vk3cnc+uOmy/0kFRJ0ad2eJY464eFTss03dAm4kqm6Q91CsKTJdlkBxXM6za+zRn6MnTDqMuLJU= root@debian12" > /home/ssh-user/.ssh/authorized_keys
    
    chown -R ssh-user:ssh-user /home/ssh-user/.ssh
    chmod 700 /home/ssh-user/.ssh
    chmod 600 /home/ssh-user/.ssh/authorized_keys

    # Harden SSH Config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    systemctl restart ssh
    log "SSH setup complete."
}

setup_security() {
    log "Hardening System (Firewall & Permissions)..."
    
    # 1. Reset potential Red Team configurations
    # Flush existing iptables rules (clears malicious open ports)
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Disable conflicting firewall services
    systemctl stop firewalld 2>/dev/null || true
    systemctl disable firewalld 2>/dev/null || true

    # 2. Install & Configure UFW
    apt-get install -y ufw

    # Default policies from scratch
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow services
    ufw allow 22/tcp   # SSH
    ufw allow 80/tcp   # HTTP
    ufw allow 21/tcp   # FTP
    ufw allow 53       # DNS (TCP/UDP)
    ufw allow 3306/tcp # MySQL

    # 3. Anti-Persistence & User Security
    log "Clearing all user crontabs..."
    # Warning: This deletes ALL scheduled tasks.
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -r -u "$user" 2>/dev/null || true
    done

    log "Checking for unauthorized UID 0 (root) users..."
    # Lists anyone with UID 0 who isn't 'root'
    # If found, these are likely backdoors.
    awk -F: '($3 == 0 && $1 != "root") {
        print "\033[0;31m[!] WARNING: User " $1 " has UID 0! This is likely a backdoor.\033[0m";
        print "    Run this command to remove them: userdel -f " $1;
    }' /etc/passwd

    log "Audit: Listing all 'human' users (UID >= 1000) with login shells..."
    # We look for users with UID >= 1000 and a shell that isn't /bin/false or /usr/sbin/nologin
    awk -F: '($3 >= 1000 && $7 !~ /(nologin|false)/) {print "    User: " $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd
    echo "    (Verify that only 'user' and 'ssh-user' are in this list!)"

    log "Securing file permissions..."
    chmod 600 /etc/shadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group

    # 4. Enable firewall (non-interactive)
    ufw --force enable

    log "Firewall enabled, rules flushed, and basics hardened."
    
    echo ""
    warn "ACTION REQUIRED: Change passwords for 'root' and 'user' immediately!"
    echo "    Run: passwd root"
    echo "    Run: passwd user"
}

# --- Main Execution ---

main() {
    check_root
    
    log "Starting setup..."

    update_system
    
    setup_http
    setup_ftp
    setup_dns
    setup_sql
    setup_ssh
    setup_security

    log "Setup complete!"
}

main
