#!/bin/bash

set -e

# --- Configuration ---
LOG_FILE="/var/log/ncae_setup.log"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "$(date): $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "$(date): WARNING: $1" >> "$LOG_FILE"
}

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

log "Starting setup... Detailed logs at $LOG_FILE"
echo "$(date): Starting Setup" > "$LOG_FILE"

# FIX: Ensure system binaries (iptables, ufw, useradd) are in PATH
export PATH=$PATH:/usr/sbin:/sbin

# --- 1. System Update ---
log "Updating package lists..."
apt update -y >> "$LOG_FILE" 2>&1

# --- 2. Services ---

# 2.1 HTTP (Nginx)
log "Setting up HTTP (Nginx)..."
apt install -y nginx >> "$LOG_FILE" 2>&1
echo "Hello World!" > /var/www/html/index.html
# Nginx permissions: defaults usually work, but this ensures www-data can read it.
chown www-data:www-data /var/www/html/index.html
systemctl restart nginx >> "$LOG_FILE" 2>&1

# 2.2 FTP (vsftpd)
log "Setting up FTP (vsftpd)..."
apt install -y vsftpd >> "$LOG_FILE" 2>&1
# Backup default
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak 2>/dev/null || true
# Inline Config Modification (Safer than replacing)
sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf 2>/dev/null || true
# Ensure anon_root is set (append if missing)
if ! grep -q "anon_root" /etc/vsftpd.conf; then
    echo "anon_root=/srv/ftp" >> /etc/vsftpd.conf
fi
# Configure Passive Mode Ports (Must match Firewall!)
if ! grep -q "pasv_min_port" /etc/vsftpd.conf; then
    echo "pasv_min_port=40000" >> /etc/vsftpd.conf
    echo "pasv_max_port=50000" >> /etc/vsftpd.conf
fi

# Setup content
mkdir -p /srv/ftp
echo "iloveftp" > /srv/ftp/iloveftp.txt
# CRITICAL: vsftpd SECURITY CHECK requires root ownership of the chroot root.
# If this is owned by ftp/user, vsftpd will REFUSE to start.
chown root:root /srv/ftp
chmod 755 /srv/ftp
chown ftp:ftp /srv/ftp/iloveftp.txt
systemctl restart vsftpd >> "$LOG_FILE" 2>&1

# 2.3 DNS (Bind9)
log "Setting up DNS (Bind9)..."
apt install -y bind9 bind9utils bind9-doc >> "$LOG_FILE" 2>&1
# Define Zone
if ! grep -q "test.local" /etc/bind/named.conf.local; then
    cat <<EOF >> /etc/bind/named.conf.local
zone "test.local" {
    type master;
    file "/etc/bind/db.test.local";
};
EOF
fi
# Create Zone File
cat <<EOF > /etc/bind/db.test.local
; BIND data file for test.local
\$TTL    604800
@       IN      SOA     test.local. root.test.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.test.local.
@       IN      A       10.10.10.10
ns      IN      A       10.10.10.10
EOF
systemctl restart bind9 >> "$LOG_FILE" 2>&1

# 2.4 SQL (MariaDB)
log "Setting up SQL (MariaDB)..."
apt install -y mariadb-server >> "$LOG_FILE" 2>&1
systemctl start mariadb >> "$LOG_FILE" 2>&1
# Init Database, Table, and User
mysql -e "CREATE DATABASE IF NOT EXISTS cyberforce;"
mysql -e "CREATE TABLE IF NOT EXISTS cyberforce.supersecret (id INT AUTO_INCREMENT PRIMARY KEY, data INT);"
mysql -e "INSERT INTO cyberforce.supersecret (data) VALUES (7);"
mysql -e "CREATE USER IF NOT EXISTS 'scoring-sql'@'%' IDENTIFIED BY 'password';"
mysql -e "GRANT ALL PRIVILEGES ON cyberforce.* TO 'scoring-sql'@'%';"
mysql -e "FLUSH PRIVILEGES;"
# Configure Remote Access (Override)
echo "[mysqld]" > /etc/mysql/mariadb.conf.d/99-ncae.cnf
echo "bind-address = 0.0.0.0" >> /etc/mysql/mariadb.conf.d/99-ncae.cnf
systemctl restart mariadb >> "$LOG_FILE" 2>&1

# 2.5 SSH
log "Setting up SSH..."
apt install -y openssh-server >> "$LOG_FILE" 2>&1
if ! id "ssh-user" &>/dev/null; then
    /usr/sbin/useradd -m -s /bin/bash ssh-user
fi
# Auth Key
mkdir -p /home/ssh-user/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxm2qvXKjqVOqytO3r8MzlAoGVUP8AS31PaCkkpi7piFNhvRTQARDXoGdg5CRjT/tWvKzpufao9glVzTyKzOacS+UHJanbUIC1zqSaWeH4aITLcmqnpb+BmvtU/eGhx/pQJHPVraxv/Tls4Cmt4ptHBJXUx0S+ldFp6YCqFxMpKIe6Mx+DKFGyL0Eisn9PbDqQK10CyMcL6PIftdp42Q8Zm3J2F4KoQGlR6Ba02SnJN8c1H9o+dDJh3pjR5m5SJpRL1/Lk+DBnk/B/xC2CYFLtT4EBVVWD3u5bonuWcrTXICXYPPoHcl/PSEnYpnLv8QuYVrq8yIW9oCp+RfbtCv0DrO9gSFXa6/mWzs1jMXVYpxizOeJgIzBQxMC52oiyFeZIBdsfrcVvRdh4WrRWKm8N04wftfkukwTfuLvuos729ydBO+81xtJ9vk3cnc+uOmy/0kFRJ0ad2eJY464eFTss03dAm4kqm6Q91CsKTJdlkBxXM6za+zRn6MnTDqMuLJU= root@debian12" > /home/ssh-user/.ssh/authorized_keys
chown -R ssh-user:ssh-user /home/ssh-user/.ssh
chmod 700 /home/ssh-user/.ssh
chmod 600 /home/ssh-user/.ssh/authorized_keys
# Config Hardening
# WARNING: Disabling password auth is best practice for security competitions,
# but we will leave it enabled for now so you can log in easily.
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh >> "$LOG_FILE" 2>&1

# --- 3. Security Hardening ---
log "Applying Security Hardening..."

# 3.1 Firewall
log "  - Resetting Firewall..."
apt install -y iptables >> "$LOG_FILE" 2>&1
# Preventive: Set default policies to ACCEPT before flushing to avoid locking out SSH
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F >> "$LOG_FILE" 2>&1 || true
iptables -X >> "$LOG_FILE" 2>&1 || true
systemctl stop firewalld >> "$LOG_FILE" 2>&1 || true
systemctl disable firewalld >> "$LOG_FILE" 2>&1 || true

log "  - Installing UFW..."
# Un-silenced to debug installation issues
apt install -y ufw >> "$LOG_FILE" 2>&1

if ! command -v ufw &> /dev/null; then
    warn "UFW failed to install! Checking path or package manager..."
    # Try to find it in common locations
    if [ -f /usr/sbin/ufw ]; then
        log "Found UFW at /usr/sbin/ufw. Fixing PATH or using absolute path."
        alias ufw='/usr/sbin/ufw'
    else
        warn "UFW binary not found. Firewall setup might fail."
    fi
fi

ufw --force reset >> "$LOG_FILE" 2>&1
ufw default deny incoming
ufw default allow outgoing

# Allow Critical Services
ufw allow 22/tcp comment 'SSH' >> "$LOG_FILE" 2>&1
ufw allow 80/tcp comment 'HTTP' >> "$LOG_FILE" 2>&1
ufw allow 21/tcp comment 'FTP' >> "$LOG_FILE" 2>&1
ufw allow 53/tcp comment 'DNS TCP' >> "$LOG_FILE" 2>&1
ufw allow 53/udp comment 'DNS UDP' >> "$LOG_FILE" 2>&1
ufw allow 3306/tcp comment 'SQL' >> "$LOG_FILE" 2>&1

# Required for FTP Passive Mode (if client requests it) - High ports
ufw allow 40000:50000/tcp comment 'FTP Passive' >> "$LOG_FILE" 2>&1

ufw --force enable >> "$LOG_FILE" 2>&1
log "Firewall Rules Applied:"
# Show all active rules so you can verify SSH, HTTP, DNS, SQL, and FTP are ALL open.
ufw status

# 3.2 Anti-Persistence
log "  - Clearing Crontabs..."
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -r -u "$user" 2>/dev/null || true
done

log "Setup Complete!"
echo ""
echo "REMINDER: Run ./hunt.sh to audit users and find backdoors!"
echo "REMINDER: Change passwords for 'root' and 'user' now!"
echo "  Run: passwd root"
echo "  Run: passwd user"
