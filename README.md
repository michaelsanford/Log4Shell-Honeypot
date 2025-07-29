# Log4Shell Honeypot

Enhanced dockerized honeypot for [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) with comprehensive security features, monitoring, and alerting capabilities.

[![Snyk Container](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/snyk-container-analysis.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/snyk-container-analysis.yml)
[![CodeQL](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/codeql-analysis.yml)
[![Pylint](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/pylint.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/pylint.yml)

## Features

### Enhanced Detection
- **Comprehensive Pattern Matching**: Detects 20+ Log4Shell exploit patterns including JNDI, LDAP, RMI, DNS, and environment variable lookups
- **Multi-Source Detection**: Monitors HTTP headers, form data, and query parameters
- **Real-time Logging**: Structured JSON logging with detailed attack information

### Security & Performance
- **Rate Limiting**: Configurable per-IP rate limiting to prevent abuse
- **Reverse Proxy**: Nginx configuration with security headers and SSL termination
- **Container Security**: Non-root user, read-only filesystem, dropped capabilities
- **fail2ban Integration**: Automatic IP blocking after repeated attempts

### Monitoring & Alerting
- **Health Checks**: Built-in health endpoint for container orchestration
- **Metrics Endpoint**: Real-time statistics on requests and attacks
- **Log Analysis**: Python script for analyzing attack patterns and trends
- **Real-time Monitoring**: Tail logs with formatted output

### Operational Features
- **Log Rotation**: Automatic log rotation with configurable size limits
- **Graceful Shutdown**: Proper signal handling for clean container stops
- **Configuration**: Environment-based configuration for all settings
- **SSL Support**: Self-signed certificate generation for HTTPS

## Quick Start

### Simple Deployment
```bash
# Generate SSL certificates
./generate-ssl.sh

# Start with docker-compose
docker-compose up -d

# Monitor logs
./monitor.py --tail
```

### Full Deployment (with fail2ban)
```bash
# Run as root for fail2ban setup
sudo ./deploy.sh
```

### Manual Docker Run
```bash
# x86_64
docker run -d -p 8080:8080 \
  -e HONEYPOT_NAME="log4shell-honeypot" \
  -e LOG_FORMAT="json" \
  -e RATE_LIMIT_REQUESTS="100" \
  --name="log4shell-honeypot" \
  msanford/log4shell-honeypot:latest

# ARM (e.g., Raspberry Pi)
docker run -d -p 8080:8080 \
  -e HONEYPOT_NAME="log4shell-honeypot" \
  --name="log4shell-honeypot" \
  msanford/log4shell-honeypot:arm-latest
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_NAME` | `log4shell-honeypot` | Name identifier for the honeypot |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LOG_FORMAT` | `json` | Log format (json or text) |
| `MAX_LOG_SIZE` | `10485760` | Maximum log file size in bytes (10MB) |
| `LOG_BACKUP_COUNT` | `5` | Number of backup log files to keep |
| `RATE_LIMIT_REQUESTS` | `100` | Maximum requests per IP per window |
| `RATE_LIMIT_WINDOW` | `3600` | Rate limit window in seconds (1 hour) |

### Using Configuration File
```bash
# Load from config file
docker-compose --env-file config.env up -d
```

## Detection Patterns

The honeypot detects the following Log4Shell patterns:

- `${jndi:` - JNDI lookups (primary attack vector)
- `${ldap:` - LDAP directory lookups
- `${rmi:` - RMI remote method invocation
- `${dns:` - DNS lookups
- `${env:` - Environment variable access
- `${sys:` - System property access
- `${java:` - Java runtime information
- And 15+ additional patterns

## Monitoring

### Real-time Monitoring
```bash
# Tail logs with formatted output
./monitor.py --tail

# Analyze last 24 hours
./monitor.py --hours 24

# Analyze last hour
./monitor.py --hours 1
```

### Health Check
```bash
curl http://localhost/health
```

### Metrics
```bash
curl http://localhost/metrics
```

### fail2ban Status
```bash
sudo fail2ban-client status log4shell-honeypot
```

## Log Format

Enhanced JSON log format includes:

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "honeypot": "log4shell-honeypot",
  "event_type": "log4shell_attempt",
  "source_ip": "192.168.1.100",
  "real_ip": "10.0.0.5",
  "method": "POST",
  "url": "http://honeypot.local/",
  "user_agent": "Mozilla/5.0...",
  "detected_patterns": ["${jndi:", "${env:"],
  "detection_source": "form_field:username",
  "headers": {...},
  "form_data": {...},
  "query_params": {...},
  "content_length": 45
}
```

## Security Features

### Container Security
- Non-root user execution
- Read-only root filesystem
- Dropped Linux capabilities
- No new privileges
- Temporary filesystem for /tmp

### Network Security
- Nginx reverse proxy with security headers
- Rate limiting at multiple levels
- SSL/TLS termination
- fail2ban integration for IP blocking

### Logging Security
- Structured logging for SIEM integration
- Log rotation to prevent disk exhaustion
- Separate log volumes
- Error handling for logging failures

## Integration

### SIEM Integration
The structured JSON logs can be easily ingested by:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- Graylog
- Fluentd/Fluent Bit

### Alerting
Set up alerts based on:
- Attack frequency thresholds
- New attack patterns
- Geographic anomalies
- User agent patterns

## Build from Source

```bash
# Build container
docker build -t log4shell-honeypot:latest .

# Build with specific tag
docker build -t log4shell-honeypot:v2.0 .
```

## Troubleshooting

### Check Container Status
```bash
docker-compose ps
docker-compose logs log4shell-honeypot
```

### Verify Health
```bash
curl -f http://localhost/health || echo "Health check failed"
```

### Check fail2ban
```bash
sudo fail2ban-client status
sudo tail -f /var/log/fail2ban.log
```

### Log Analysis
```bash
# Check for recent attacks
./monitor.py --hours 1

# View raw logs
tail -f /var/log/log4shell-honeypot.log
```

## Performance Tuning

### High Traffic Environments
- Increase `RATE_LIMIT_REQUESTS` for legitimate high traffic
- Adjust `MAX_LOG_SIZE` and `LOG_BACKUP_COUNT` for log retention
- Use external log aggregation to reduce local storage

### Resource Limits
```yaml
# In docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 256M
    reservations:
      cpus: '0.1'
      memory: 128M
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Considerations

- Deploy behind a firewall with restricted access
- Monitor logs regularly for attack patterns
- Keep container images updated
- Use strong SSL certificates in production
- Implement network segmentation
- Regular security audits of the deployment

## Acknowledgements

This is an enhanced fork of [BinaryDefense/log4shell-honeypot-flask](https://github.com/BinaryDefense/log4shell-honeypot-flask) with significant security and operational improvements.
