import json
import base64
import hashlib
import requests
import os

from datetime import datetime, timedelta

from flask import Flask, request, render_template, redirect, jsonify

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------- CONFIG ----------------

AES_KEY = b"busiabusiabusia1"

# GitHub Gist configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GIST_ID = "666dd6bbb0519a21fdde99436d1fc9ed"
GIST_FILE = "users.json"
GITHUB_API_BASE = "https://api.github.com"

# ---------------- STORAGE (Gist) ----------------

def generate_password(uuid: str, expire_date: str) -> str:
    # expire_date must be YYYY-MM-DD
    formatted = expire_date.replace("-", ".")  # YYYY.MM.DD
    raw = f"{uuid}{formatted}"

    b64 = base64.b64encode(raw.encode())
    sha = hashlib.sha256(b64).hexdigest()

    return sha

def load_users():
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        resp = requests.get(f"{GITHUB_API_BASE}/gists/{GIST_ID}", headers=headers)
        if resp.status_code == 200:
            gist = resp.json()
            if GIST_FILE in gist["files"]:
                content = gist["files"][GIST_FILE]["content"]
                return json.loads(content)
            else:
                print("Gist file not found.")
                return {"users": {}}
        else:
            print(f"Failed to load Gist: {resp.status_code}")
            return {"users": {}}
    except Exception as e:
        print(f"Error loading users: {e}")
        return {"users": {}}

# ---------------- AES ----------------

def generate_token(user):
    data_string = "|".join([
        user.get("uuid", ""),
        user.get("expire_date", ""),
        user.get("name", ""),
        user.get("surname", ""),
        user.get("birthdate", ""),
        user.get("pesel", ""),
        user.get("photo_url", ""),
        user.get("password", "")
    ])
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data_string.encode(), AES.block_size))
    # URL-safe base64
    return base64.urlsafe_b64encode(iv + encrypted).decode()


def decrypt_token(token):
    try:
        raw = base64.urlsafe_b64decode(token)
        iv = raw[:16]
        encrypted = raw[16:]
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        parts = decrypted.decode().split("|")
        return {
            "uuid": parts[0],
            "expire_date": parts[1],
            "name": parts[2],
            "surname": parts[3],
            "birthdate": parts[4],
            "pesel": parts[5],
            "photo_url": parts[6],
            "password": parts[7]
        }
    except Exception as e:
        print("Decrypt error:", e)
        return None

# ---------------- FLASK ----------------

app = Flask(__name__)
app.secret_key = "devsecret"

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    req_data = request.json
    uuid = req_data.get("device_id")
    entered_password = req_data.get("password")
    
    if not uuid or not entered_password:
        return jsonify({"message": "Missing device_id or password"}), 400

    data = load_users()
    user = data["users"].get(uuid)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check expiration
    if datetime.strptime(user["expire_date"], "%Y-%m-%d") < datetime.now():
        return jsonify({"message": "Access expired"}), 403
    expected_password = generate_password(uuid, user["expire_date"])
    print("Entered:", entered_password)
    print("Expected:", expected_password)
   
    if entered_password != expected_password:
        print("Password mismatch")
        return redirect("/")
    
    token = generate_token({
        "uuid": uuid,
        "expire_date": user["expire_date"],
        "name": user["name"],
        "surname": user["surname"],
        "birthdate": user["birthdate"],
        "pesel": user["pesel"],
        "photo_url": user.get("photo_url", ""),
        "password": expected_password
    })

    # set cookie and return redirect
    resp = jsonify({"success": True, "redirect": f"/1.html?token={token}"})
    resp.set_cookie("device_id", uuid, path="/")
    return resp

@app.route("/1.html")
def protected():
    token = request.args.get("token")
    device_uuid = request.cookies.get("device_id")

    if not token or not device_uuid:
        return redirect("/")

    decrypted = decrypt_token(token)
    if not decrypted:
        print("Token invalid")
        return redirect("/")

    # 1️⃣ Device check
    if decrypted["uuid"] != device_uuid:
        print("Device UUID mismatch")
        return redirect("/")

    # 2️⃣ Load user
    data = load_users()
    user = data["users"].get(decrypted["uuid"])
    if not user:
        print("UUID not found in users.json")
        return redirect("/")

    # 3️⃣ Expiration check
    if datetime.strptime(user["expire_date"], "%Y-%m-%d") < datetime.now():
        print("Token expired")
        return redirect("/")

    # 4️⃣ Validate password (from token after decryption)
    expected_password = generate_password(user["uuid"], user["expire_date"])
    print(decrypted["password"])
    print(expected_password)
    if decrypted["password"] != expected_password:
        print("Password mismatch after decryption")
        return redirect("/")

    return render_template("1.html", data=decrypted)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)