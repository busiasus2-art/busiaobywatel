from flask import jsonify, Flask, request, render_template, session, redirect

import sqlite3
import json
import hashlib
import base64
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devsecret")
DB = "database.db"


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    device_id TEXT PRIMARY KEY,
                    password TEXT,
                    expire_date TEXT,
                    who TEXT,
                    png_path TEXT,
                    data TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

def generate_encrypted_password(device_id: str, expire_date: str) -> str:
    """Создаёт пароль uuid+expire_date и шифрует Base64 -> SHA256"""
    raw = f"{device_id}{expire_date}"
    b64 = base64.b64encode(raw.encode())
    sha256_hash = hashlib.sha256(b64).hexdigest()
    return sha256_hash
    
@app.route("/1.html")
def protected_page():
    try:
        print("static_folder =", app.static_folder)   # ← Add this
        print("templates_folder =", app.template_folder)
        
        if not session.get("logged_in"):
            return render_template("login.html")

        device_id = session.get("device_id")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT data FROM users WHERE device_id = ?", (device_id,))
        user = c.fetchone()
        conn.close()

        if not user:
            session.clear()
            return render_template("login.html")

        user_data = json.loads(user[0])
        return render_template("1.html", data=user_data)
    except Exception as e:
        print(f"TEMPLATE ERROR: {e}")  # Will show in console
        return f"Template failed: {e}", 500


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    device_id = data.get("device_id")
    password = data.get("password")  # это пароль который ввёл пользователь

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT password, expire_date FROM users WHERE device_id = ?", (device_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"message": "Пользователь не найден"}), 404

    stored_hash, expire_date = user
    input_hash = generate_encrypted_password(device_id, expire_date)

    if input_hash != stored_hash:
        return jsonify({"message": "Неверный пароль"}), 403

    # проверка срока действия
    if datetime.strptime(expire_date, "%Y-%m-%d") < datetime.now():
        return jsonify({"message": "Срок действия истёк"}), 403

    # создаём сессию
    session["logged_in"] = True
    session["device_id"] = device_id
    return jsonify({"success": True})


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/1.html")

@app.route("/c.html", methods=["GET"])
def c_page():
    if not session.get("logged_in"):
        return redirect("/1.html")  # если нет сессии → login
    return render_template("c.html")


@app.route("/submit_c", methods=["POST"])
def submit_c():
    if not session.get("logged_in"):
        return {"message": "Not logged in"}, 403

    device_id = session.get("device_id")
    data = request.json  # ожидаем JSON: {name, surname, birthdate, pesel, url}

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # получаем старый JSON
    c.execute("SELECT data FROM users WHERE device_id = ?", (device_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        return {"message": "User not found"}, 404

    user_data = json.loads(user[0])
    if "birthdate" in user_data and user_data["birthdate"]:
        parts = user_data["birthdate"].split("-")  # формат YYYY-MM-DD
        if len(parts) == 3:
            user_data["birthdate"] = f"{parts[2]}.{parts[1]}.{parts[0]}"
    user_data.update(data)

    # сохраняем обратно
    c.execute("UPDATE users SET data = ? WHERE device_id = ?", (json.dumps(user_data), device_id))
    conn.commit()
    conn.close()

    return {"success": True}
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)