from flask import Flask, request
import hmac
import hashlib
import git
from environs import Env
import json
import subprocess


app = Flask(__name__)

env = Env()
env.read_env()

@app.route("/")
def hello_world():
    #subprocess.run(["print('cheese')"])
    #subprocess.run(["print('hello')", ""])
    #process = subprocess.Popen(["mkdir", "cheese2"])
    #process = subprocess.Popen(["sudo", "systemctl", "restart", "gunicorn"])
    #stdout, stderr = process.communicate()
    return "<p>Hello world</p>"


def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if signature_header:
        hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
        expected_signature = "sha256=" + hash_object.hexdigest()
        return hmac.compare_digest(expected_signature, signature_header)


@app.route("/ghook_cms", methods=['POST', 'GET'])
def deploy_cms():
    if request.method == 'POST':
        if verify_signature(request.get_data(), env("GH_SECRET"), request.headers.get('x-hub-signature-256')):
            local_dir = '/home/jamal/headlessDjangoSite/headlessDjango'
            repo = git.Repo(local_dir)
            current = repo.head.commit
            repo.remotes.origin.pull()
            if current == repo.head.commit:
                return "Repo not changed", 200
            else:
                # Do the other things directly as Linux commands
                #p_pip = subprocess.Popen(["pip", "install", "-r", "requirements.txt"])          # Install dependencies
                #p_restart = subprocess.Popen(["python", "manage.py", "migrate"])      # Run db migrations
                p_restart_g = subprocess.Popen(["sudo", "systemctl", "restart", "gunicorn"])      # Restart Django
                p_restart_ng = subprocess.Popen(["sudo", "systemctl", "restart", "nginx"])         # Restart web server
                return "App updated", 200
        return 'Forbidden', 403
    return 'Not allowed', 405