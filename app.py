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

def verify_signature(payload_body, secret_token, signature_header):
    """ Verify that the payload was sent from GitHub by validating SHA256.
    """
    if signature_header:
        hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
        expected_signature = "sha256=" + hash_object.hexdigest()
        return hmac.compare_digest(expected_signature, signature_header)

@app.route("/ghook_cms", methods=['POST', 'GET'])
def deploy_cms():
    """ If the request is valid:
        1. Pull the new code that's just been pushed (uses python git library)
        2. Restart Gunicorn/Django, etc (directly runs Linux commands)
    """
    if request.method == 'POST':
        if verify_signature(request.get_data(), env("GH_SECRET"), request.headers.get('x-hub-signature-256')):
            local_dir = '/home/jamal/headlessDjangoSite/headlessDjango'
            repo = git.Repo(local_dir)
            current = repo.head.commit
            repo.remotes.origin.pull()
            if current == repo.head.commit:
                return "Repo not changed", 200
            else:
                subprocess.Popen([env["VENV_PYTHON_PATH"], "manage.py", "migrate"])                     # Run db migrations
                subprocess.Popen([env["VENV_PYTHON_PATH"], "pip", "install", "-r", "requirements.txt"]) # Install dependencies
                subprocess.Popen(["sudo", "systemctl", "restart", "gunicorn"])                          # Restart Django
                subprocess.Popen(["sudo", "systemctl", "restart", "nginx"])                             # Restart web server
                return "App updated", 200
        return 'Forbidden', 403
    return 'Not allowed', 405