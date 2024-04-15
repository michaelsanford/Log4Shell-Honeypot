FROM python:3.12.3-alpine

RUN addgroup --gid 1000 --system honeypot && \
    adduser --uid 1000 --system --home /usr/src/app --ingroup honeypot honeypot

USER honeypot

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/*.py .

ENV FLASK_ENV production
ENV FLASK_APP app.py
ENV FLASK_DEBUG 0

EXPOSE 8080

CMD [ "python", "./app.py" ]