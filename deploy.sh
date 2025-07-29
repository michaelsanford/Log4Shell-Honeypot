#!/bin/bash

set -e

echo "=== Log4Shell Honeypot Deployment Script ==="

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root for fail2ban configuration"
    exit 1
fi

echo "1. Generating SSL certificates..."
./generate-ssl.sh

echo "2. Setting up fail2ban configuration..."
cat > /etc/fail2ban/filter.d/log4shell-honeypot.conf << 'EOF'
[Definition]
failregex = .*"source_ip": "(<HOST>)".*"event_type": "log4shell_attempt".*
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/log4shell-honeypot.conf << 'EOF'
[log4shell-honeypot]
enabled = true
port = http,https,8080,8443
filter = log4shell-honeypot
logpath = /var/log/log4shell-honeypot.log
maxretry = 3
bantime = 3600
findtime = 600
action = iptables-multiport[name=log4shell, port="http,https,8080,8443"]
EOF

echo "3. Restarting fail2ban..."
systemctl restart fail2ban

echo "4. Creating log directory..."
mkdir -p /var/log
chmod 755 /var/log

echo "5. Starting honeypot with docker-compose..."
docker-compose down 2>/dev/null || true
docker-compose up -d

echo "6. Waiting for services to start..."
sleep 10

echo "7. Testing health endpoint..."
if curl -f http://localhost/health > /dev/null 2>&1; then
    echo "✓ Honeypot is healthy"
else
    echo "✗ Honeypot health check failed"
    docker-compose logs
    exit 1
fi

echo ""
echo "=== Deployment Complete ==="
echo "Honeypot is running on:"
echo "  HTTP: http://localhost"
echo "  HTTPS: https://localhost"
echo "  Alt HTTPS: https://localhost:8443"
echo ""
echo "Monitoring commands:"
echo "  docker-compose logs -f"
echo "  ./monitor.py --tail"
echo "  ./monitor.py --hours 1"
echo ""
echo "fail2ban status:"
echo "  fail2ban-client status log4shell-honeypot"
