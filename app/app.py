# pylint: disable=C0116,C0301,C0114,C0103
import json
import logging
import logging.handlers
import os
import re
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from waitress import serve

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "log4shell-honeypot").strip()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json")
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", "10485760"))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))

LOG4SHELL_PATTERNS = [
    r'\$\{jndi:',
    r'\$\{ldap:',
    r'\$\{rmi:',
    r'\$\{dns:',
    r'\$\{nis:',
    r'\$\{nds:',
    r'\$\{corba:',
    r'\$\{iiop:',
    r'\$\{env:',
    r'\$\{sys:',
    r'\$\{java:',
    r'\$\{lower:',
    r'\$\{upper:',
    r'\$\{date:',
    r'\$\{ctx:',
    r'\$\{main:',
    r'\$\{bundle:',
    r'\$\{marker:',
    r'\$\{event:',
    r'\$\{log4j:',
    r'\$\{map:',
    r'\$\{sd:',
    r'\$\{',
]

COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in LOG4SHELL_PATTERNS]

request_counts = defaultdict(list)

def setup_logging():
    logger = logging.getLogger(HONEYPOT_NAME)
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    handler = logging.handlers.RotatingFileHandler(
        f'/var/log/{HONEYPOT_NAME}.log',
        maxBytes=MAX_LOG_SIZE,
        backupCount=LOG_BACKUP_COUNT
    )
    
    if LOG_FORMAT.lower() == "json":
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

log = setup_logging()

app = Flask(__name__)

def is_rate_limited(client_ip):
    now = datetime.now()
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    
    request_counts[client_ip] = [
        timestamp for timestamp in request_counts[client_ip] 
        if timestamp > cutoff
    ]
    
    if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
        return True
    
    request_counts[client_ip].append(now)
    return False

def detect_log4shell(text):
    if not text:
        return False, []
    
    detected_patterns = []
    text_str = str(text).lower()
    
    for i, pattern in enumerate(COMPILED_PATTERNS):
        if pattern.search(text_str):
            detected_patterns.append(LOG4SHELL_PATTERNS[i])
    
    return len(detected_patterns) > 0, detected_patterns

def report_hit(r, detected_patterns, detection_source):
    try:
        client_ip = r.headers.get('X-Forwarded-For', r.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        msg_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "honeypot": HONEYPOT_NAME,
            "event_type": "log4shell_attempt",
            "source_ip": client_ip,
            "real_ip": r.remote_addr,
            "method": r.method,
            "url": r.url,
            "user_agent": r.headers.get('User-Agent', ''),
            "detected_patterns": detected_patterns,
            "detection_source": detection_source,
            "headers": dict(r.headers),
            "form_data": dict(request.form.items()) if request.form else {},
            "query_params": dict(request.args.items()) if request.args else {},
            "content_length": r.content_length or 0
        }
        
        if LOG_FORMAT.lower() == "json":
            log.critical(json.dumps(msg_data))
        else:
            log.critical(f"Log4Shell attempt detected: {msg_data}")
            
    except Exception as e:
        log.error(f"Error logging attack attempt: {e}")

def graceful_shutdown(signum, frame):
    log.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

LOGIN_FORM = """<html>
<head><title>Secure Area Login</title></head>
<body>
<h1>Log in to Secure Area</h1>
<form method='post' action='/'>
  <b>Username:</b> <input name='username' type='text'/><br/>
  <b>Password:</b> <input name='password' type='password'/><br/>
  <input type='submit' name='submit'/>
</form>
</body></html>"""

@app.route("/health", methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "honeypot": HONEYPOT_NAME,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200

@app.route("/metrics", methods=['GET'])
def metrics():
    total_requests = sum(len(timestamps) for timestamps in request_counts.values())
    active_ips = len([ip for ip, timestamps in request_counts.items() if timestamps])
    
    return jsonify({
        "total_requests": total_requests,
        "active_ips": active_ips,
        "rate_limit_window": RATE_LIMIT_WINDOW,
        "rate_limit_requests": RATE_LIMIT_REQUESTS,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200

@app.route("/", methods=['POST', 'GET', 'PUT', 'DELETE'])
def homepage():
    try:
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        if is_rate_limited(client_ip):
            log.warning(f"Rate limit exceeded for IP: {client_ip}")
            return "Too Many Requests", 429
        
        detected = False
        all_patterns = []
        
        for header_name, header_value in request.headers:
            is_detected, patterns = detect_log4shell(header_value)
            if is_detected:
                detected = True
                all_patterns.extend(patterns)
                report_hit(request, patterns, f"header:{header_name}")
        
        for param_name, param_value in request.args.items():
            is_detected, patterns = detect_log4shell(param_value)
            if is_detected:
                detected = True
                all_patterns.extend(patterns)
                report_hit(request, patterns, f"query_param:{param_name}")
        
        if request.method == 'POST':
            for field_name, field_value in request.form.items():
                is_detected, patterns = detect_log4shell(field_value)
                if is_detected:
                    detected = True
                    all_patterns.extend(patterns)
                    report_hit(request, patterns, f"form_field:{field_name}")
            
            return "<html><head><title>Login Failed</title></head><body><h1>Login Failed</h1><br/></body></html>"
        
        return LOGIN_FORM
        
    except Exception as e:
        log.error(f"Error processing request: {e}")
        return "Internal Server Error", 500

if __name__ == '__main__':
    log.info(f"Starting {HONEYPOT_NAME} honeypot...")
    log.info(f"Log level: {LOG_LEVEL}, Log format: {LOG_FORMAT}")
    log.info(f"Rate limiting: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds")
    serve(app, host='0.0.0.0', port=8080)
