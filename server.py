from flask import Flask, request, jsonify
import os, base64, json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)
user_keys = {}

@app.route("/enroll", methods=["POST"])
def enroll():
    data = request.json
    username = data["username"]
    pub_key_pem = data["public_key_pem"].encode()
    user_keys[username] = serialization.load_pem_public_key(pub_key_pem)
    return jsonify({"status": "enrolled"})

@app.route("/challenge", methods=["GET"])
def challenge():
    challenge = base64.urlsafe_b64encode(os.urandom(16)).decode()
    return jsonify({"challenge": challenge})

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    username = data["username"]
    signature = base64.b64decode(data["signature"])
    message = json.dumps(data["assertion"]).encode()
    pub_key = user_keys[username]
    try:
        pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return jsonify({"status": "success"})
    except:
        return jsonify({"status": "failed"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
