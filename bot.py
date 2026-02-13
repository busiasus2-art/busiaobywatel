import sqlite3
import json
from datetime import datetime, timedelta
import base64
import hashlib
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

ADMIN_ID = 1542340573
DB = "database.db"
TOKEN = "5371778560:AAHOKeESqlyJaHWyAWgzJ3RSOpIcjJSeXUo"

def connect():
    return sqlite3.connect(DB)

def init_db():
    conn = connect()
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

# Password generator
def generate_encrypted_password(device_id: str, expire_date: str) -> str:
    raw = f"{device_id}{expire_date}"
    b64 = base64.b64encode(raw.encode())
    sha256_hash = hashlib.sha256(b64).hexdigest()
    return sha256_hash

# /add command
async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /add <uuid> <days> [who]")
        return

    device_id = args[0]
    days = int(args[1])
    who = args[2] if len(args) > 2 else ""

    if days == 0:
        expire_date = "9999-12-31"
    else:
        expire_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    password_encrypted = generate_encrypted_password(device_id, expire_date)
    user_data = {}

    conn = connect()
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO users
        (device_id, password, expire_date, who, png_path, data)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (device_id, password_encrypted, expire_date, who, "default.png", json.dumps(user_data)))
    conn.commit()
    conn.close()

    # Показываем зашифрованный пароль
    await update.message.reply_text(f"User {device_id} added.\nExpire: {expire_date}\nPassword: {password_encrypted}")

# /remove command
async def remove(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /remove <uuid>")
        return

    device_id = context.args[0]
    conn = connect()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE device_id = ?", (device_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    await update.message.reply_text(f"Removed {device_id} ({'Success' if deleted else 'Not found'})")

# /view command
async def view(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    conn = connect()
    c = conn.cursor()
    c.execute("SELECT device_id, password, expire_date, who FROM users")
    rows = c.fetchall()
    conn.close()

    if not rows:
        await update.message.reply_text("No users in database")
        return

    msg = "All users:\n"
    for r in rows:
        msg += f"{r[0]} | {r[1]} | {r[2]} | {r[3]}\n"

    await update.message.reply_text(msg)

# /viewid command
async def viewid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != ADMIN_ID:
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /viewid <uuid>")
        return

    device_id = context.args[0]
    conn = connect()
    c = conn.cursor()
    c.execute("SELECT device_id, password, expire_date, who, png_path, data FROM users WHERE device_id = ?", (device_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        await update.message.reply_text("User not found")
        return

    user_data = json.loads(user[5]) if user[5] else {}
    msg = f"""Device: {user[0]}
Password: {user[1]}
Expire: {user[2]}
Who: {user[3]}
PNG path: {user[4]}
Data:"""
    for k, v in user_data.items():
        msg += f"\n  {k}: {v}"

    await update.message.reply_text(msg)

# Run bot
if __name__ == "__main__":
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("add", add_user))
    app.add_handler(CommandHandler("remove", remove))
    app.add_handler(CommandHandler("view", view))
    app.add_handler(CommandHandler("viewid", viewid))
    app.run_polling(drop_pending_updates=True)
