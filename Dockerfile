FROM python:3-alpine
RUN apk --update --no-cache add curl

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/app.py .

HEALTHCHECK --interval=90s --timeout=1s --start-period=5s \
    CMD curl --fail http://127.0.0.1:8080/healthcheck

ENV FLASK_ENV production
ENV FLASK_APP app.py
ENV FLASK_DEBUG 0

EXPOSE 8080

CMD [ "python", "./app.py" ]