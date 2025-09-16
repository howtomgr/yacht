# Yacht Installation Guide

Yacht is a free and open-source Container Management. A web-based UI for managing Docker containers

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 8000 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 8000 (default yacht port)
  - Firewall rules configured
- **Dependencies**:
  - docker, docker-compose
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install yacht
sudo dnf install -y yacht docker, docker-compose

# Enable and start service
sudo systemctl enable --now yacht

# Configure firewall
sudo firewall-cmd --permanent --add-service=yacht || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
yacht --version || systemctl status yacht
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install yacht
sudo apt install -y yacht docker, docker-compose

# Enable and start service
sudo systemctl enable --now yacht

# Configure firewall
sudo ufw allow 8000

# Verify installation
yacht --version || systemctl status yacht
```

### Arch Linux

```bash
# Install yacht
sudo pacman -S yacht

# Enable and start service
sudo systemctl enable --now yacht

# Verify installation
yacht --version || systemctl status yacht
```

### Alpine Linux

```bash
# Install yacht
apk add --no-cache yacht

# Enable and start service
rc-update add yacht default
rc-service yacht start

# Verify installation
yacht --version || rc-service yacht status
```

### openSUSE/SLES

```bash
# Install yacht
sudo zypper install -y yacht docker, docker-compose

# Enable and start service
sudo systemctl enable --now yacht

# Configure firewall
sudo firewall-cmd --permanent --add-service=yacht || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
yacht --version || systemctl status yacht
```

### macOS

```bash
# Using Homebrew
brew install yacht

# Start service
brew services start yacht

# Verify installation
yacht --version
```

### FreeBSD

```bash
# Using pkg
pkg install yacht

# Enable in rc.conf
echo 'yacht_enable="YES"' >> /etc/rc.conf

# Start service
service yacht start

# Verify installation
yacht --version || service yacht status
```

### Windows

```powershell
# Using Chocolatey
choco install yacht

# Or using Scoop
scoop install yacht

# Verify installation
yacht --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /config

# Set up basic configuration
sudo tee /config/yacht.conf << 'EOF'
# Yacht Configuration
WORKERS=4
EOF

# Set appropriate permissions
sudo chown -R yacht:yacht /config || \
  sudo chown -R $(whoami):$(whoami) /config

# Test configuration
sudo yacht --test || sudo yacht configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false yacht || true

# Secure configuration files
sudo chmod 750 /config
sudo chmod 640 /config/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable yacht

# Start service
sudo systemctl start yacht

# Stop service
sudo systemctl stop yacht

# Restart service
sudo systemctl restart yacht

# Reload configuration
sudo systemctl reload yacht

# Check status
sudo systemctl status yacht

# View logs
sudo journalctl -u yacht -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add yacht default

# Start service
rc-service yacht start

# Stop service
rc-service yacht stop

# Restart service
rc-service yacht restart

# Check status
rc-service yacht status

# View logs
tail -f /config/logs/yacht.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'yacht_enable="YES"' >> /etc/rc.conf

# Start service
service yacht start

# Stop service
service yacht stop

# Restart service
service yacht restart

# Check status
service yacht status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start yacht
brew services stop yacht
brew services restart yacht

# Check status
brew services list | grep yacht

# View logs
tail -f $(brew --prefix)/var/log/yacht.log
```

### Windows Service Manager

```powershell
# Start service
net start yacht

# Stop service
net stop yacht

# Using PowerShell
Start-Service yacht
Stop-Service yacht
Restart-Service yacht

# Check status
Get-Service yacht

# Set to automatic startup
Set-Service yacht -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /config/yacht.conf << 'EOF'
# Performance tuning
WORKERS=4
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart yacht
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream yacht_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name yacht.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yacht.example.com;

    ssl_certificate /etc/ssl/certs/yacht.crt;
    ssl_certificate_key /etc/ssl/private/yacht.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://yacht_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName yacht.example.com
    Redirect permanent / https://yacht.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName yacht.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/yacht.crt
    SSLCertificateKeyFile /etc/ssl/private/yacht.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:8000/
        ProxyPassReverse http://127.0.0.1:8000/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:8000/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend yacht_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/yacht.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend yacht_backend

backend yacht_backend
    balance roundrobin
    option httpchk GET /health
    server yacht1 127.0.0.1:8000 check
```

### Caddy Configuration

```caddy
yacht.example.com {
    reverse_proxy 127.0.0.1:8000 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /config yacht || true

# Set ownership
sudo chown -R yacht:yacht /config
sudo chown -R yacht:yacht /config/logs

# Set permissions
sudo chmod 750 /config
sudo chmod 640 /config/*
sudo chmod 750 /config/logs

# Configure firewall (UFW)
sudo ufw allow from any to any port 8000 proto tcp comment "Yacht"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=yacht
sudo firewall-cmd --permanent --service=yacht --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=yacht
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 8000 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/yacht.key \
    -out /etc/ssl/certs/yacht.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=yacht.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/yacht.key
sudo chmod 644 /etc/ssl/certs/yacht.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d yacht.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/yacht.conf
[yacht]
enabled = true
port = 8000
filter = yacht
logpath = /config/logs/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/yacht.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE yacht_db;
CREATE USER yacht_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE yacht_db TO yacht_user;
\q
EOF

# Configure connection in Yacht
echo "DATABASE_URL=postgresql://yacht_user:secure_password_here@localhost/yacht_db" | \
  sudo tee -a /config/yacht.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE yacht_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'yacht_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON yacht_db.* TO 'yacht_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://yacht_user:secure_password_here@localhost/yacht_db" | \
  sudo tee -a /config/yacht.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/yacht
sudo chown yacht:yacht /var/lib/yacht

# Initialize database
sudo -u yacht yacht init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
yacht soft nofile 65535
yacht hard nofile 65535
yacht soft nproc 32768
yacht hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /config/performance.conf
# Performance configuration
WORKERS=4

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart yacht
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'yacht'
    static_configs:
      - targets: ['localhost:8000/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/yacht-health

# Check if service is running
if ! systemctl is-active --quiet yacht; then
    echo "CRITICAL: Yacht service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 8000 2>/dev/null; then
    echo "CRITICAL: Yacht is not listening on port 8000"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:8000/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: Yacht is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/yacht
/config/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 yacht yacht
    postrotate
        systemctl reload yacht > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/yacht
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/yacht-backup

BACKUP_DIR="/backup/yacht"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/yacht_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping Yacht service..."
systemctl stop yacht

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /config \
    /var/lib/yacht \
    /config/logs

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump yacht_db | gzip > "$BACKUP_DIR/yacht_db_$DATE.sql.gz"
fi

# Start service
echo "Starting Yacht service..."
systemctl start yacht

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/yacht-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping Yacht service..."
systemctl stop yacht

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql yacht_db
fi

# Fix permissions
chown -R yacht:yacht /config
chown -R yacht:yacht /var/lib/yacht

# Start service
echo "Starting Yacht service..."
systemctl start yacht

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status yacht
sudo journalctl -u yacht -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 8000
sudo lsof -i :8000

# Verify configuration
sudo yacht --test || sudo yacht configtest

# Check permissions
ls -la /config
ls -la /config/logs
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep yacht
curl -I http://localhost:8000

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 8000

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep yacht
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep python)
htop -p $(pgrep python)

# Check for memory leaks
ps aux | grep python
cat /proc/$(pgrep python)/status | grep -i vm

# Analyze logs for errors
grep -i error /config/logs/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U yacht_user -d yacht_db -c "SELECT 1;"
mysql -u yacht_user -p yacht_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /config/yacht.conf

# Restart with debug mode
sudo systemctl stop yacht
sudo -u yacht yacht --debug

# Watch debug logs
tail -f /config/logs/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep python) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/yacht.pcap port 8000
sudo tcpdump -r /tmp/yacht.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep python)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  yacht:
    image: yacht:yacht
    container_name: yacht
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/config
      - ./data:/var/lib/yacht
      - ./logs:/config/logs
    networks:
      - yacht_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  yacht_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# yacht-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: yacht
  labels:
    app: yacht
spec:
  replicas: 1
  selector:
    matchLabels:
      app: yacht
  template:
    metadata:
      labels:
        app: yacht
    spec:
      containers:
      - name: yacht
        image: yacht:yacht
        ports:
        - containerPort: 8000
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /config
        - name: data
          mountPath: /var/lib/yacht
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: yacht-config
      - name: data
        persistentVolumeClaim:
          claimName: yacht-data
---
apiVersion: v1
kind: Service
metadata:
  name: yacht
spec:
  selector:
    app: yacht
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: yacht-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# yacht-playbook.yml
- name: Install and configure Yacht
  hosts: all
  become: yes
  vars:
    yacht_version: latest
    yacht_port: 8000
    yacht_config_dir: /config
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - docker, docker-compose
        state: present
    
    - name: Install Yacht
      package:
        name: yacht
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ yacht_config_dir }}"
        state: directory
        owner: yacht
        group: yacht
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: yacht.conf.j2
        dest: "{{ yacht_config_dir }}/yacht.conf"
        owner: yacht
        group: yacht
        mode: '0640'
      notify: restart yacht
    
    - name: Start and enable service
      systemd:
        name: yacht
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ yacht_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart yacht
      systemd:
        name: yacht
        state: restarted
```

### Terraform Configuration

```hcl
# yacht.tf
resource "aws_instance" "yacht_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.yacht.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install Yacht
    apt-get update
    apt-get install -y yacht docker, docker-compose
    
    # Configure Yacht
    systemctl enable yacht
    systemctl start yacht
  EOF
  
  tags = {
    Name = "Yacht Server"
    Application = "Yacht"
  }
}

resource "aws_security_group" "yacht" {
  name        = "yacht-sg"
  description = "Security group for Yacht"
  
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Yacht Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update yacht
sudo dnf update yacht

# Debian/Ubuntu
sudo apt update
sudo apt upgrade yacht

# Arch Linux
sudo pacman -Syu yacht

# Alpine Linux
apk update
apk upgrade yacht

# openSUSE
sudo zypper ref
sudo zypper update yacht

# FreeBSD
pkg update
pkg upgrade yacht

# Always backup before updates
/usr/local/bin/yacht-backup

# Restart after updates
sudo systemctl restart yacht
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /config/logs -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze yacht_db

# Check disk usage
df -h | grep -E "(/$|yacht)"
du -sh /var/lib/yacht

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u yacht | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.yacht.org/
- GitHub Repository: https://github.com/yacht/yacht
- Community Forum: https://forum.yacht.org/
- Wiki: https://wiki.yacht.org/
- Docker Hub: https://hub.docker.com/r/yacht/yacht
- Security Advisories: https://security.yacht.org/
- Best Practices: https://docs.yacht.org/best-practices
- API Documentation: https://api.yacht.org/
- Comparison with Portainer, Rancher, Docker Swarm UI, Shipyard: https://docs.yacht.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
