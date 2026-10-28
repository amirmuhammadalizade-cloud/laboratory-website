from flask import Flask, render_template, request
import sqlite3
from pathlib import Path

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"


def create_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL
            )
        """)


create_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register")
def register():
    return render_template("register.html")




@app.route("/login", methods=["POST"])
def login():
    phone = request.form.get("phone", "").strip()
    name = request.form.get("name", "").strip()

    if len(phone) != 11 or not phone.startswith("09") or not phone.isdigit():
        return "شماره تلفن معتبر نیست.", 400

    with sqlite3.connect(DB_PATH) as conn:
        user = conn.execute(
            "SELECT id, name FROM users WHERE phone = ?",
            (phone,)
        ).fetchone()

        if user:
            return f"این شماره قبلاً ثبت‌نام کرده است. سلام {user[1]}!"

        if not name:
            return "لطفاً نام خود را وارد کنید.", 400

        conn.execute(
            "INSERT INTO users (phone, name) VALUES (?, ?)",
            (phone, name)
        )

    return f"ثبت‌نام {name} با موفقیت انجام شد."


if __name__ == "__main__":
    app.run(debug=True)
