# pylint: disable=C0116,C0301,C0114,C0103
import logging
import os

from flask import Flask, request
from waitress import serve

HONEYPOT_NAME = "log4shell-honeypot"
if "HONEYPOT_NAME" in os.environ and os.environ["HONEYPOT_NAME"].strip() != "":
    HONEYPOT_NAME = os.environ["HONEYPOT_NAME"]

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(HONEYPOT_NAME)

app = Flask(__name__)


def report_hit(r):
    msg = {
        "honeypot": HONEYPOT_NAME,
        "source": r.remote_addr,
        "headers": r.headers,
        "body": list(request.form.items())
    }

    log.critical(msg)


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


@app.route("/", methods=['POST', 'GET', 'PUT', 'DELETE'])
def homepage():
    for header in request.headers:
        if "${" in header:
            report_hit(request)

    if request.method == 'POST':
        for _, value in request.form.items():
            if "${" in value:
                report_hit(request)
        return "<html><head><title>Login Failed</title></head><body><h1>Login Failed</h1><br/></body></html>"

    return LOGIN_FORM


if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=8080)
