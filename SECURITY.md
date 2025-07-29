# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities by creating a GitHub issue or contacting the maintainer directly.

## Security Features

### Container Security
- Non-root user execution (UID/GID 1000)
- Read-only root filesystem
- Dropped all Linux capabilities except essential ones
- No new privileges flag set
- Temporary filesystem for /tmp
- Minimal Alpine Linux base image

### Network Security
- Nginx reverse proxy with security headers
- Rate limiting at application and proxy level
- SSL/TLS termination with modern cipher suites
- fail2ban integration for automated IP blocking
- Restricted access to metrics endpoint

### Application Security
- Input validation and sanitization
- Structured logging to prevent log injection
- Graceful error handling
- Rate limiting per IP address
- Comprehensive pattern detection

### Operational Security
- Log rotation to prevent disk exhaustion
- Health checks for monitoring
- Configurable logging levels
- Separate log volumes
- Signal handling for graceful shutdown

## Deployment Security Checklist

- [ ] Deploy behind a firewall
- [ ] Use strong SSL certificates in production
- [ ] Configure fail2ban for IP blocking
- [ ] Set up log monitoring and alerting
- [ ] Implement network segmentation
- [ ] Regular security updates
- [ ] Monitor resource usage
- [ ] Backup log data regularly
- [ ] Review access logs periodically
- [ ] Test disaster recovery procedures

## Known Security Considerations

1. This is a honeypot designed to attract attackers
2. Deploy in an isolated network segment
3. Monitor for lateral movement attempts
4. Regularly update container images
5. Use dedicated logging infrastructure
6. Implement proper access controls
