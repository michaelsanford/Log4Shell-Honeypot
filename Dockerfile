FROM python:3.13.5-alpine

RUN apk add --no-cache \
    dumb-init \
    && addgroup --gid 1000 --system honeypot \
    && adduser --uid 1000 --system --home /usr/src/app --ingroup honeypot honeypot \
    && mkdir -p /var/log \
    && chown honeypot:honeypot /var/log

USER honeypot

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir --user -r requirements.txt

COPY app/*.py .

ENV FLASK_ENV=production
ENV FLASK_APP=app.py
ENV FLASK_DEBUG=0
ENV LOG_LEVEL=INFO
ENV LOG_FORMAT=json
ENV MAX_LOG_SIZE=10485760
ENV LOG_BACKUP_COUNT=5
ENV RATE_LIMIT_REQUESTS=100
ENV RATE_LIMIT_WINDOW=3600

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["python", "./app.py"]
