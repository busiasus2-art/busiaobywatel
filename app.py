import os
import json
import base64
import hashlib
import asyncio
import threading
from datetime import datetime, timedelta

from flask import Flask, request, render_template, session, redirect, jsonify

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import quote
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# ---------------- CONFIG ----------------

BOT_TOKEN = '5371778560:AAHOKeESqlyJaHWyAWgzJ3RSOpIcjJSeXUo'  # NEVER hardcode
ADMIN_ID = 1542340573
AES_KEY = b"busiabusiabusia1"
DATA_FILE = "users.json"

# ---------------- STORAGE ----------------

def generate_password(uuid: str, expire_date: str) -> str:
    # expire_date must be YYYY-MM-DD
    formatted = expire_date.replace("-", ".")  # YYYY.MM.DD
    raw = f"{uuid}{formatted}"

    b64 = base64.b64encode(raw.encode())
    sha = hashlib.sha256(b64).hexdigest()

    return sha

def load_users():
    if not os.path.exists(DATA_FILE):
        return {"users": {}}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ---------------- AES ----------------

def generate_token(user):
    data_string = "|".join([
        user.get("uuid", ""),
        user.get("expire_date", ""),
        user.get("password", ""),
        user.get("name", ""),
        user.get("surname", ""),
        user.get("birthdate", ""),
        user.get("pesel", ""),
        user.get("photo_url", "")
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
            "password": parts[2],
            "name": parts[3],
            "surname": parts[4],
            "birthdate": parts[5],
            "pesel": parts[6],
            "photo_url": parts[7]
        }
    except Exception as e:
        print("Decrypt error:", e)
        return None

# ---------------- TELEGRAM BOT ----------------

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    args = context.args
    if len(args) < 7:
        await update.message.reply_text(
            "Usage:\n/add <uuid> <days> <name> <surname> <birthdate> <pesel> <photo_url>"
        )
        return

    uuid, days, name, surname, birthdate, pesel, photo_url = args
    days = int(days)

    expire_date = "9999-12-31" if days == 0 else \
        (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    data = load_users()
    data["users"][uuid] = {
        "uuid": uuid,
        "expire_date": expire_date,
        "name": name,
        "surname": surname,
        "birthdate": birthdate,
        "pesel": pesel,
        "photo_url": photo_url
    }

    save_users(data)

    token = generate_password(uuid, expire_date)

    await update.message.reply_text(
        f"User added.\nExpire: {expire_date}\nPASSWORD:\n{token}"
    )


async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /remove <uuid>")
        return

    uuid = context.args[0]
    data = load_users()

    if uuid in data["users"]:
        del data["users"][uuid]
        save_users(data)
        await update.message.reply_text(f"Removed user {uuid}")
    else:
        await update.message.reply_text("UUID not found")

# /view <uuid> — detailed info
async def view_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /view <uuid>")
        return

    uuid = context.args[0]
    data = load_users()
    user = data["users"].get(uuid)

    if not user:
        await update.message.reply_text("UUID not found")
        return

    msg = f"UUID: {uuid}\nExpire: {user['expire_date']}\nName: {user['name']}\nSurname: {user['surname']}\nBirthdate: {user['birthdate']}\nPESEL: {user['pesel']}\nPhoto URL: {user.get('photo_url', '')}"
    await update.message.reply_text(msg)

# /viewall — list all UUIDs in JSON
async def viewall(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    data = load_users()
    uuids = list(data["users"].keys())
    await update.message.reply_text(json.dumps(uuids, indent=2))

# ---------------- FLASK ----------------

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devsecret")

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    uuid = request.json.get("device_id")
    if not uuid:
        return jsonify({"message": "Missing device_id"}), 400

    data = load_users()
    user = data["users"].get(uuid)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # generate password on the server
    password = generate_password(uuid, user["expire_date"])

    # generate AES token for page
    token = generate_token({
        "uuid": uuid,
        "expire_date": user["expire_date"],
        "password": password,
        "name": user["name"],
        "surname": user["surname"],
        "birthdate": user["birthdate"],
        "pesel": user["pesel"],
        "photo_url": user.get("photo_url", "")
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

    # 4️⃣ Validate password
    expected_password = generate_password(user["uuid"], user["expire_date"])
    if decrypted["password"] != expected_password:
        print("Password mismatch")
        return redirect("/")

    return render_template("1.html", data=decrypted)

# ---------------- RUN BOTH ----------------

def run_flask():
    app.run(host="0.0.0.0", port=10000, use_reloader=False)


if __name__ == "__main__":
    from threading import Thread

    # Start Flask in background thread
    flask_thread = Thread(target=run_flask)
    flask_thread.start()

    # Start Telegram bot (this blocks main thread)
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("add", add_user))
    application.add_handler(CommandHandler("remove", remove_user))
    application.add_handler(CommandHandler("view", view_user))
    application.add_handler(CommandHandler("viewall", viewall))

    application.run_polling(drop_pending_updates=True)