from flask import Flask, request
from hmac import HMAC, compare_digest
from hashlib import sha256
import git
from environs import Env

app = Flask(__name__)

env = Env()
env.read_env()

@app.route("/")
def hello_world():
    return "<p>Hello world</p>"

def verify_signature(req):
     received_sign = req.headers.get('X-Hub-Signature-256').split('sha256=')[-1].strip()
     secret = env("GH_SECRET").encode()
     expected_sign = HMAC(key=secret, msg=req.data, digestmod=sha256).hexdigest()
     return compare_digest(received_sign, expected_sign)

@app.route("/ghook_cms", methods=['POST', 'GET'])
def deploy_cms():
    if request.method == 'POST':
        if verify_signature(request):
            # LOCAL:
            #local_dir = '/home/user/bk/headlessDjango'
            # LIVE:
            local_dir = '/home/jamal/headlessDjangoSite/headlessDjango'
            repo = git.Repo(local_dir)
            current = repo.head.commit
            repo.remotes.origin.pull()
            if current == repo.head.commit:
                return "Repo not changed. Sleep mode activated.", 200
            else:
                return "Repo changed! Activated.", 200
        return 'Forbidden', 403
    return 'Not allowed', 405