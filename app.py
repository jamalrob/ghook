from flask import Flask, request
import hmac
from hashlib import sha256
import git
from environs import Env

app = Flask(__name__)

env = Env()
env.read_env()

@app.route("/")
def hello_world():
    return "<p>Hello world</p>"

def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signatures didn't match!")

#def verify_signature(req):
#     received_sign = req.headers.get('X-Hub-Signature-256').split('sha256=')[-1].strip()
#     secret = env("GH_SECRET").encode()
#     expected_sign = HMAC(key=secret, msg=req.data, digestmod=sha256).hexdigest()
#     return compare_digest(received_sign, expected_sign)

@app.route("/ghook_cms", methods=['POST', 'GET'])
def deploy_cms():
    if request.method == 'POST':
        if verify_signature(request.body(), env("GH_SECRET"), request.headers.get('x-hub-signature-256')):
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