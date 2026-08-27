"""
Bait Al Gahwa — application intake + admin dashboard.

A small, dependency-light Flask app:
  - GET  /                        the public application form (public/index.html)
  - POST /api/applications        applicants submit here (multipart form + files)
  - GET  /admin/login             admin sign-in
  - GET  /admin                   dashboard: list of applications (auth required)
  - GET  /admin/applications/<id> single application detail (auth required)
  - GET  /admin/export.csv        CSV export (auth required)
  - GET  /admin/files/<name>      serves an uploaded photo/CV/video (auth required)

Configuration is via environment variables — see .env.example.
"""

import csv
import hmac
import html
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, session, jsonify, send_from_directory,
    send_file, abort, g,
)
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "gahwa.db"
DATA_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # required — see warning below
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

if not ADMIN_PASSWORD:
    print(
        "\n[gahwa-journey] WARNING: ADMIN_PASSWORD is not set. "
        "Set it as an environment variable before deploying — without it, "
        "admin login will always fail.\n"
    )

app = Flask(__name__, static_folder=None)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # 30MB per request

PUBLIC_DIR = BASE_DIR / "public"

FIELDS = [
    "national", "dob", "name", "gender", "phone", "email", "location",
    "travel", "availability", "hours", "transport", "experience", "training",
    "languages", "education", "status", "motivation", "referral",
]


# ---------------------------------------------------------------- database --
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            status_review TEXT NOT NULL DEFAULT 'new',
            {', '.join(f + ' TEXT' for f in FIELDS)},
            cv_path TEXT,
            photo_path TEXT,
            video_path TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


# ------------------------------------------------------------- rate limits --
_rate_buckets = {}


def rate_limited(key, limit, window_seconds):
    now = time.time()
    bucket = [t for t in _rate_buckets.get(key, []) if now - t < window_seconds]
    bucket.append(now)
    _rate_buckets[key] = bucket
    return len(bucket) > limit


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


# ------------------------------------------------------------------- auth --
def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            if request.path.startswith("/admin/api/"):
                return jsonify({"error": "not_authenticated"}), 401
            return redirect("/admin/login")
        return fn(*args, **kwargs)
    return wrapper


def safe_equal(a, b):
    return hmac.compare_digest(str(a or ""), str(b or ""))


def make_reference():
    year = datetime.now(timezone.utc).year
    return f"BAG-{year}-{secrets.token_hex(3).upper()}"


# --------------------------------------------------------------- frontend --
@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")


# --------------------------------------------------------- applicant API --
@app.route("/api/check-duplicate", methods=["POST"])
def check_duplicate():
    """Lets the frontend flag a returning applicant as soon as they type their
    email or phone, instead of only at final submission."""
    ip = client_ip()
    if rate_limited(f"dupe-check:{ip}", limit=60, window_seconds=3600):
        return jsonify({"error": "rate_limited"}), 429

    payload = request.get_json(silent=True) or {}
    field = payload.get("field")
    value = (payload.get("value") or "").strip()
    if not value or field not in ("email", "phone"):
        return jsonify({"duplicate": False})

    db = get_db()
    if field == "email":
        row = db.execute(
            "SELECT id FROM applications WHERE LOWER(TRIM(email)) = ?",
            (value.lower(),),
        ).fetchone()
        return jsonify({"duplicate": bool(row)})

    # phone: compare the last 9 digits so +9715XXXXXXXX / 05XXXXXXXX / 5XXXXXXXX
    # typed for the same number are all recognised as the same person
    digits = re.sub(r"\D", "", value)
    if not digits:
        return jsonify({"duplicate": False})
    suffix = digits[-9:]
    for row in db.execute("SELECT phone FROM applications").fetchall():
        existing_digits = re.sub(r"\D", "", row["phone"] or "")
        if existing_digits and existing_digits[-9:] == suffix:
            return jsonify({"duplicate": True})
    return jsonify({"duplicate": False})


@app.route("/api/applications", methods=["POST"])
def submit_application():
    ip = client_ip()
    if rate_limited(f"submit:{ip}", limit=8, window_seconds=3600):
        return jsonify({
            "error": "rate_limited",
            "message": "Too many submissions from this connection. Please try again later.",
        }), 429

    form = request.form
    files = request.files

    # honeypot — real applicants never populate this
    if form.get("company_website"):
        return jsonify({"ok": True, "reference": make_reference()})

    if not form.get("name") or not form.get("email") or not form.get("dob") or not form.get("national"):
        return jsonify({"error": "missing_fields", "message": "Required fields are missing."}), 400

    email_value = (form.get("email") or "").strip()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", email_value) or ".." in email_value:
        return jsonify({"error": "invalid_email", "message": "Enter a valid email address."}), 400

    phone_value = (form.get("phone") or "").strip()
    phone_digits = re.sub(r"\D", "", phone_value)
    if not re.match(r"^\+?[0-9\s\-()]+$", phone_value) or not (7 <= len(phone_digits) <= 15):
        return jsonify({"error": "invalid_phone", "message": "Enter a valid mobile number."}), 400

    # -------------------------------------------------- duplicate applicant --
    # Block a second application from the same person. We match on email
    # (case/whitespace-insensitive) and on the last 9 digits of the phone
    # number, since the same UAE number can be typed as +9715XXXXXXXX,
    # 05XXXXXXXX, or 5XXXXXXXX and should still be recognised as one person.
    db = get_db()
    existing_email = db.execute(
        "SELECT id FROM applications WHERE LOWER(TRIM(email)) = ?",
        (email_value.lower(),),
    ).fetchone()
    if existing_email:
        return jsonify({
            "error": "duplicate_email",
            "message": "You've already applied with this email address. Only one application is allowed per person.",
        }), 409

    if phone_digits:
        phone_suffix = phone_digits[-9:]
        for row in db.execute("SELECT phone FROM applications").fetchall():
            existing_digits = re.sub(r"\D", "", row["phone"] or "")
            if existing_digits and existing_digits[-9:] == phone_suffix:
                return jsonify({
                    "error": "duplicate_phone",
                    "message": "You've already applied with this mobile number. Only one application is allowed per person.",
                }), 409

    photo = files.get("photo")
    if not photo or not photo.filename:
        return jsonify({"error": "missing_photo", "message": "A recent photo is required."}), 400

    def save_upload(file_storage):
        if not file_storage or not file_storage.filename:
            return None
        ext = Path(secure_filename(file_storage.filename)).suffix[:10]
        fname = f"{int(time.time()*1000)}-{secrets.token_hex(6)}{ext}"
        file_storage.save(UPLOADS_DIR / fname)
        return fname

    try:
        cv_path = save_upload(files.get("cv"))
        photo_path = save_upload(photo)
        video_path = save_upload(files.get("video"))
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("upload failed")
        return jsonify({"error": "upload_failed", "message": "Could not save your files. Please try again."}), 500

    reference = make_reference()
    values = {f: (form.get(f) or "") for f in FIELDS}

    db = get_db()
    db.execute(
        f"""
        INSERT INTO applications
            (reference, created_at, status_review, {', '.join(FIELDS)}, cv_path, photo_path, video_path)
        VALUES
            (?, ?, 'new', {', '.join('?' for _ in FIELDS)}, ?, ?, ?)
        """,
        [reference, datetime.now(timezone.utc).isoformat()] + [values[f] for f in FIELDS] + [cv_path, photo_path, video_path],
    )
    db.commit()

    return jsonify({"ok": True, "reference": reference})


# --------------------------------------------------------------- admin ui --
@app.route("/admin/login", methods=["GET"])
def admin_login_page():
    if session.get("is_admin"):
        return redirect("/admin")
    return login_page(bool(request.args.get("error")))


@app.route("/admin/login", methods=["POST"])
def admin_login_submit():
    ip = client_ip()
    if rate_limited(f"login:{ip}", limit=20, window_seconds=900):
        return "Too many attempts. Please wait a while and try again.", 429

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user_ok = safe_equal(username, ADMIN_USERNAME)
    pass_ok = safe_equal(password, ADMIN_PASSWORD) if ADMIN_PASSWORD else False
    if user_ok and pass_ok:
        session["is_admin"] = True
        session.permanent = True
        return redirect("/admin")
    return redirect("/admin/login?error=1")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect("/admin/login")


@app.route("/admin")
@require_admin
def admin_dashboard():
    rows = get_db().execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
    return dashboard_page(rows)


@app.route("/admin/applications/<int:app_id>")
@require_admin
def admin_detail(app_id):
    row = get_db().execute("SELECT * FROM applications WHERE id = ?", (app_id,)).fetchone()
    if not row:
        abort(404)
    return detail_page(row)


@app.route("/admin/applications/<int:app_id>/status", methods=["POST"])
@require_admin
def admin_update_status(app_id):
    status = request.form.get("status_review", "")
    if status not in ("new", "shortlisted", "rejected", "hired"):
        abort(400)
    db = get_db()
    db.execute("UPDATE applications SET status_review = ? WHERE id = ?", (status, app_id))
    db.commit()
    return redirect(f"/admin/applications/{app_id}")


@app.route("/admin/export.csv")
@require_admin
def admin_export_csv():
    rows = get_db().execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
    cols = ["id", "reference", "created_at", "status_review"] + FIELDS
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for r in rows:
        writer.writerow([r[c] for c in cols])
    output = buf.getvalue()
    return app.response_class(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=gahwa-applications.csv"},
    )


@app.route("/admin/files/<path:filename>")
@require_admin
def admin_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name or not (UPLOADS_DIR / safe_name).exists():
        abort(404)
    return send_file(UPLOADS_DIR / safe_name)


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "too_large", "message": "One of your files is too large."}), 413


# -------------------------------------------------------------- templates --
STYLE = """
:root{
  --ink:#150d09; --panel:#241811; --panel-hi:#2e2016; --panel-line:#3c2a1b;
  --brass:#c9974d; --brass-hi:#e0b06e; --brass-ink:#1c1108;
  --parchment:#ece0cb; --muted:#a2907a; --cardamom:#8fa176; --carnelian:#a34c3c;
}
*{box-sizing:border-box;}
body{margin:0;background:var(--ink);color:var(--parchment);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;border-bottom:1px solid var(--panel-line);}
header h1{font-size:1.1rem;margin:0;font-weight:600;}
a{color:var(--brass-hi);}
.wrap{max-width:1100px;margin:0 auto;padding:28px;}
table{width:100%;border-collapse:collapse;font-size:0.92rem;}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--panel-line);}
th{color:var(--muted);font-weight:600;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.04em;}
tr:hover td{background:var(--panel-hi);}
.btn{display:inline-flex;align-items:center;gap:6px;background:var(--brass);color:var(--brass-ink);
  border:none;padding:9px 16px;font-weight:600;cursor:pointer;text-decoration:none;font-size:0.88rem;border-radius:2px;}
.btn.secondary{background:transparent;color:var(--parchment);border:1px solid var(--panel-line);}
.pill{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.75rem;border:1px solid var(--panel-line);}
.pill.new{color:var(--brass-hi);border-color:var(--brass);}
.pill.shortlisted{color:var(--cardamom);border-color:var(--cardamom);}
.pill.rejected{color:var(--carnelian);border-color:var(--carnelian);}
.pill.hired{color:var(--parchment);background:var(--cardamom);border-color:var(--cardamom);}
.card{background:var(--panel);border:1px solid var(--panel-line);padding:24px;margin-bottom:18px;}
.row{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--panel-line);gap:20px;}
.row dt{color:var(--muted);}
.row dd{margin:0;text-align:right;max-width:60%;}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;gap:12px;flex-wrap:wrap;}
input[type=text],input[type=password]{background:var(--panel-hi);border:1px solid var(--panel-line);color:var(--parchment);padding:11px 12px;width:100%;font-size:0.95rem;}
.login-box{max-width:360px;margin:80px auto;background:var(--panel);border:1px solid var(--panel-line);padding:32px;}
.login-box h1{margin-top:0;}
.error{color:var(--carnelian);font-size:0.88rem;margin-bottom:14px;}
.empty{color:var(--muted);padding:40px 0;text-align:center;}
"""


def layout(title, body):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)} — Bait Al Gahwa Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<style>{STYLE}</style>
</head>
<body>{body}</body>
</html>"""


def login_page(has_error):
    err = '<p class="error">Incorrect username or password.</p>' if has_error else ""
    return layout(
        "Sign in",
        f"""<div class="login-box">
          <h1>Bait Al Gahwa</h1>
          <p style="color:var(--muted);margin-top:-10px;">Admin dashboard</p>
          {err}
          <form method="post" action="/admin/login">
            <div style="margin-bottom:14px;">
              <label style="display:block;margin-bottom:6px;font-size:0.85rem;color:var(--muted);">Username</label>
              <input type="text" name="username" autocomplete="username" required>
            </div>
            <div style="margin-bottom:20px;">
              <label style="display:block;margin-bottom:6px;font-size:0.85rem;color:var(--muted);">Password</label>
              <input type="password" name="password" autocomplete="current-password" required>
            </div>
            <button class="btn" type="submit" style="width:100%;justify-content:center;">Sign in</button>
          </form>
        </div>""",
    )


def dashboard_page(rows):
    if rows:
        body_rows = "".join(
            f"""<tr>
                <td>{html.escape(r['created_at'])}</td>
                <td>{html.escape(r['name'] or '')}</td>
                <td>{html.escape(r['location'] or '')}</td>
                <td><span class="pill {html.escape(r['status_review'])}">{html.escape(r['status_review'])}</span></td>
                <td>{html.escape(r['reference'])}</td>
                <td><a href="/admin/applications/{r['id']}">View →</a></td>
            </tr>"""
            for r in rows
        )
        body = f"""<table>
            <thead><tr><th>Received</th><th>Name</th><th>Location</th><th>Status</th><th>Reference</th><th></th></tr></thead>
            <tbody>{body_rows}</tbody>
        </table>"""
    else:
        body = '<div class="empty">No applications yet. Once someone submits the form, they\'ll show up here.</div>'

    return layout(
        "Applications",
        f"""<header>
          <h1>Bait Al Gahwa — Applications</h1>
          <form method="post" action="/admin/logout"><button class="btn secondary" type="submit">Sign out</button></form>
        </header>
        <div class="wrap">
          <div class="toolbar">
            <div style="color:var(--muted);">{len(rows)} application{'' if len(rows) == 1 else 's'}</div>
            <a class="btn secondary" href="/admin/export.csv">Export CSV</a>
          </div>
          {body}
        </div>""",
    )


def detail_page(r):
    languages = ", ".join(filter(None, (r["languages"] or "").split(",")))
    availability = ", ".join(filter(None, (r["availability"] or "").split(",")))
    fields = [
        ("Reference", r["reference"]), ("Received", r["created_at"]),
        ("UAE National", r["national"]), ("Date of birth", r["dob"]), ("Gender", r["gender"]),
        ("Mobile", r["phone"]), ("Email", r["email"]), ("Neighbourhood", r["location"]),
        ("Can travel", r["travel"]), ("Availability", availability), ("Hours per week", r["hours"]),
        ("Own transport", r["transport"]), ("Gahwa experience", r["experience"]),
        ("Hospitality training", r["training"]), ("Languages", languages),
        ("Education", r["education"]), ("Current status", r["status"]),
        ("Heard about us via", r["referral"]),
    ]
    rows_html = "".join(
        f'<div class="row"><dt>{html.escape(label)}</dt><dd>{html.escape(val or "")}</dd></div>'
        for label, val in fields
    )

    file_links = []
    if r["photo_path"]:
        file_links.append(f'<a class="btn secondary" href="/admin/files/{r["photo_path"]}" target="_blank">View photo</a>')
    if r["cv_path"]:
        file_links.append(f'<a class="btn secondary" href="/admin/files/{r["cv_path"]}" target="_blank">Download CV</a>')
    if r["video_path"]:
        file_links.append(f'<a class="btn secondary" href="/admin/files/{r["video_path"]}" target="_blank">View video</a>')
    files_html = " ".join(file_links) or '<span style="color:var(--muted);">None uploaded</span>'

    statuses = ["new", "shortlisted", "rejected", "hired"]
    status_buttons = "".join(
        f'<button class="btn {"" if s == r["status_review"] else "secondary"}" type="submit" '
        f'name="status_review" value="{s}" style="text-transform:capitalize;">{s}</button>'
        for s in statuses
    )

    return layout(
        r["name"] or "Applicant",
        f"""<header>
          <h1><a href="/admin" style="color:var(--parchment);text-decoration:none;">← Applications</a></h1>
          <form method="post" action="/admin/logout"><button class="btn secondary" type="submit">Sign out</button></form>
        </header>
        <div class="wrap">
          <h2 style="margin-top:0;">{html.escape(r['name'] or '')}</h2>
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="pill {html.escape(r['status_review'])}">{html.escape(r['status_review'])}</span>
              <form method="post" action="/admin/applications/{r['id']}/status" style="display:flex;gap:8px;">
                {status_buttons}
              </form>
            </div>
          </div>
          <div class="card">{rows_html}</div>
          <div class="card">
            <h3 style="margin-top:0;">Why they want to join</h3>
            <p style="white-space:pre-wrap;line-height:1.6;">{html.escape(r['motivation'] or '')}</p>
          </div>
          <div class="card">
            <h3 style="margin-top:0;">Supporting files</h3>
            {files_html}
          </div>
        </div>""",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)
