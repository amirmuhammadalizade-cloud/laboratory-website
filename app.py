
from flask import Flask, render_template, request, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import time
from pathlib import Path

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-later"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"

OTP_VALIDITY = 300
MAX_ATTEMPTS = 5

# کدهای تأیید موقتاً در حافظه سرور نگهداری می‌شوند.
otp_storage = {}


# ---------- Database ----------

def create_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT
            )
        """)

        # سازگاری با دیتابیس نسخه قبلی
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "password_hash" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN password_hash TEXT"
            )


create_database()


# ---------- Helper functions ----------

def is_valid_phone(phone):
    return (
        len(phone) == 11
        and phone.startswith("09")
        and phone.isdigit()
    )


def json_response(message, status=200, **extra):
    return jsonify({
        "ok": 200 <= status < 300,
        "message": message,
        **extra
    }), status


# ---------- Home and registration page ----------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    phone = request.form.get("phone", "").strip()

    if not is_valid_phone(phone):
        return json_response(
            "شماره تلفن معتبر نیست.",
            400
        )

    with sqlite3.connect(DB_PATH) as conn:
        user = conn.execute(
            "SELECT password_hash FROM users WHERE phone = ?",
            (phone,)
        ).fetchone()

    session.clear()
    session["phone"] = phone

    # شماره قبلاً ثبت شده است.
    if user:
        session["registration_step"] = "login"

        if not user[0]:
            return json_response(
                "این حساب مربوط به نسخه قبلی سایت است و رمز عبور ندارد. "
                "بازیابی این حساب باید جداگانه پیاده‌سازی شود.",
                409,
                next="login"
            )

        return json_response(
            "این شماره قبلاً ثبت‌نام کرده است. رمز عبور خود را وارد کنید.",
            next="login"
        )

    # شماره جدید است؛ تولید کد تأیید
    code = f"{secrets.randbelow(900000) + 100000}"

    otp_storage[phone] = {
        "code": code,
        "expires_at": time.time() + OTP_VALIDITY,
        "attempts": 0
    }

    session["registration_step"] = "verify"

    # فقط برای آزمایش؛ در نسخه واقعی حذف شود.
    print(f"Verification code for {phone}: {code}")

    return json_response(
        "کد تأیید تولید شد. کد آزمایشی را در ترمینال ببینید.",
        next="verify"
    )


# ---------- Existing user login ----------

@app.route("/login", methods=["POST"])
def login():
    phone = session.get("phone")

    if (
        not phone
        or session.get("registration_step") != "login"
    ):
        return json_response(
            "درخواست معتبر نیست. دوباره شماره تلفن را وارد کنید.",
            400
        )

    password = request.form.get("password", "")

    with sqlite3.connect(DB_PATH) as conn:
        user = conn.execute(
            "SELECT name, password_hash FROM users WHERE phone = ?",
            (phone,)
        ).fetchone()

    if not user:
        session.clear()
        return json_response(
            "حساب کاربری پیدا نشد. دوباره شماره را وارد کنید.",
            404
        )

    name, password_hash = user

    if not password_hash:
        return json_response(
            "این حساب رمز عبور ندارد و نیاز به بازیابی دارد.",
            409
        )

    if not check_password_hash(password_hash, password):
        return json_response(
            "رمز عبور اشتباه است.",
            401
        )

    session.clear()

    return json_response(
        f"ورود موفق بود. سلام {name}!",
        next="done"
    )


# ---------- Verify phone number ----------

@app.route("/verify", methods=["POST"])
def verify():
    phone = session.get("phone")

    if (
        not phone
        or session.get("registration_step") != "verify"
    ):
        return json_response(
            "ابتدا شماره تلفن خود را وارد کنید.",
            400
        )

    otp = otp_storage.get(phone)

    if not otp:
        session.clear()
        return json_response(
            "کد تأیید موجود نیست. دوباره ثبت‌نام کنید.",
            400
        )

    if time.time() >= otp["expires_at"]:
        otp_storage.pop(phone, None)
        session.clear()

        return json_response(
            "کد تأیید منقضی شده است. دوباره ثبت‌نام کنید.",
            400
        )

    entered_code = request.form.get("code", "").strip()

    if (
        not entered_code.isdigit()
        or len(entered_code) != 6
        or entered_code != otp["code"]
    ):
        otp["attempts"] += 1

        if otp["attempts"] >= MAX_ATTEMPTS:
            otp_storage.pop(phone, None)
            session.clear()

            return json_response(
                "تعداد تلاش‌های مجاز تمام شد. دوباره ثبت‌نام کنید.",
                429
            )

        remaining = MAX_ATTEMPTS - otp["attempts"]

        return json_response(
            f"کد تأیید اشتباه است. {remaining} تلاش باقی مانده است.",
            400
        )

    # کد صحیح است.
    otp_storage.pop(phone, None)
    session["registration_step"] = "complete"
    session["phone_verified"] = True

    return json_response(
        "شماره تلفن تأیید شد. نام و رمز عبور خود را وارد کنید.",
        next="complete"
    )


# ---------- Complete new registration ----------

@app.route("/complete-registration", methods=["POST"])
def complete_registration():
    phone = session.get("phone")

    if (
        not phone
        or session.get("registration_step") != "complete"
        or not session.get("phone_verified")
    ):
        return json_response(
            "ابتدا شماره تلفن خود را تأیید کنید.",
            400
        )

    name = request.form.get("name", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not name:
        return json_response(
            "لطفاً نام خود را وارد کنید.",
            400
        )

    if len(name) > 100:
        return json_response(
            "نام نباید بیشتر از ۱۰۰ کاراکتر باشد.",
            400
        )

    if not 4 <= len(password) <= 8:
        return json_response(
            "رمز عبور باید بین ۴ تا ۸ کاراکتر باشد.",
            400
        )

    if password != confirm_password:
        return json_response(
            "رمز عبور و تکرار آن یکسان نیستند.",
            400
        )

    password_hash = generate_password_hash(password)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO users (phone, name, password_hash)
                VALUES (?, ?, ?)
                """,
                (phone, name, password_hash)
            )

    except sqlite3.IntegrityError:
        return json_response(
            "این شماره قبلاً ثبت شده است.",
            409
        )

    session.clear()

    return json_response(
        f"ثبت‌نام {name} با موفقیت انجام شد.",
        next="done"
    )


if __name__ == "__main__":
    app.run(debug=True)
