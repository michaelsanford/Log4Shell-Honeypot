# Log4Shell Honeypot

Dockerized honeypot for [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) based on Alpine, written in Python/Flask.

[![Snyk Container](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/snyk-container-analysis.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/snyk-container-analysis.yml)
[![CodeQL](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/codeql-analysis.yml)
[![Pylint](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/pylint.yml/badge.svg)](https://github.com/michaelsanford/Log4Shell-Honeypot/actions/workflows/pylint.yml)

## Detection Rule

The container responds with a plain login form.

Any request will be inspected for `${` (headers and body).

This triggers a critical-level log with the entire request as a JSON payload.

## Event log

The event log will look like this (but as a single line):

```yaml
CRITICAL:<HONEYPOT_NAME>:{
  'honeypot': '<HONEYPOT_NAME>', 
  'source': '172.17.0.1',
  'headers': EnvironHeaders([
    ('Host', 'localhost:8080'),
    ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0'),
    ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'),
    ('Accept-Language', 'en-CA,fr-CA;q=0.5'),
    ('Accept-Encoding', 'gzip, deflate'),
    ('Content-Type', 'application/x-www-form-urlencoded'),
    ('Content-Length', '45'), 
    ('Origin', 'http://localhost:8080'),
    ('Connection', 'keep-alive'), 
    ('Referer', 'http://localhost:8080/'), 
    ('Upgrade-Insecure-Requests', '1'), 
    ('Sec-Fetch-Dest', 'document'), 
    ('Sec-Fetch-Mode', 'navigate'), 
    ('Sec-Fetch-Site', 'same-origin'), 
    ('Sec-Fetch-User', '?1')
  ]),
  'body': [
    ('username', '${'), 
    ('password', ''), 
    ('submit', 'Submit Query')
  ]}
```

## Docker Quickstart

```shell
# x86_64
docker run -d -p 8080:8080 -e HONEYPOT_NAME="log4shell-honeypot" --name="log4shell-honeypot" msanford/log4shell-honeypot:latest

# ARM (e.g., Raspberry Pi)
docker run -d -p 8080:8080 -e HONEYPOT_NAME="log4shell-honeypot" --name="log4shell-honeypot" msanford/log4shell-honeypot:arm-latest
```

A `docker-compose.yml` fragment is also provided.

### Build

```shell
docker build -t log4shell-honeypot:latest .
```


# Acknowledgements

This is a modified fork of [BinaryDefense/log4shell-honeypot-flask](https://github.com/BinaryDefense/log4shell-honeypot-flask) 👏🏼.