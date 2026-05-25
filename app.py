"""
WasteTrack Backend API
Flask + MySQL (XAMPP) REST API
"""

import os
import uuid
import re
import time
import base64
import traceback
from datetime import datetime, timezone
from email.mime.text import MIMEText
from functools import wraps
from urllib.parse import quote

import bcrypt
import pymysql
import pymysql.cursors
import requests as http_requests
import random
import string
from flask import Flask, request, jsonify, g, redirect
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app,
     resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
     expose_headers=["Authorization"])

# ── Email config ──────────────────────────────
# Uses smtplib directly (no Flask-Mail) to avoid IPv6 issues.
# Falls back to port 465 (SSL) if 587 (STARTTLS) fails.
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')

def send_email(to_address: str, subject: str, body: str) -> tuple:
    """
    Send email via Brevo (Sendinblue) HTTP API — works on Railway (port 443 only).
    Free tier: 300 emails/day. Set BREVO_API_KEY in Railway environment variables.
    Sign up free at https://app.brevo.com
    """
    if not BREVO_API_KEY:
        print("[EMAIL] BREVO_API_KEY not set — cannot send email")
        return False, "BREVO_API_KEY environment variable not set"

    try:
        resp = http_requests.post(
            "https://api.brevo.com/v3/smtp/email",
            json={
                "sender":      {"name": "WasteTrack", "email": MAIL_USERNAME or "noreply@wastetrack.app"},
                "to":          [{"email": to_address}],
                "subject":     subject,
                "textContent": body
            },
            headers={
                "api-key":      BREVO_API_KEY,
                "Content-Type": "application/json"
            },
            timeout=15
        )
        if resp.status_code in (200, 201, 202):
            return True, ""
        return False, f"Brevo API error: {resp.status_code} {resp.text}"
    except Exception as e:
        return False, str(e)

# Temporary store for verification codes {email: (code, expiry_timestamp)}
# WARNING: These are in-memory only — they are lost on server restart.
# For production, store them in the database or Redis.
pending_verifications = {}
verified_emails       = set()

# Rate-limit: track last send time per email to prevent spam {email: timestamp}
_last_code_sent = {}
RESEND_COOLDOWN_SECONDS = 60  # users must wait 60 s between sends

VERIFICATION_CODE_TTL = 600  # 10 minutes in seconds

# ─────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET", "wastetrack-dev-secret-change-in-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"]  = 86400      # 24 h
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 2592000    # 30 days

UPLOAD_FOLDER      = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "mp4", "mov"}
MAX_UPLOAD_MB      = 20
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

jwt = JWTManager(app)

# ─────────────────────────────────────────
# MySQL config
# ─────────────────────────────────────────
DB_CONFIG = {
    "host":        os.environ.get("DB_HOST",     "localhost"),
    "port":        int(os.environ.get("DB_PORT", 3306)),
    "user":        os.environ.get("DB_USER",     "root"),
    "password":    os.environ.get("DB_PASSWORD", ""),   # XAMPP default is empty
    "database":    os.environ.get("DB_NAME",     "wast"),  # ← fixed
    "charset":     "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit":  False
}

# ─────────────────────────────────────────
# Google OAuth config  ← paste your credentials here
# ─────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
# Update GOOGLE_REDIRECT_URI and FRONTEND_URL with your deployed URLs after deployment
GOOGLE_REDIRECT_URI  = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:5000/api/auth/google/callback")
FRONTEND_URL         = os.environ.get("FRONTEND_URL",        "http://localhost/wast/wm.html")
# ─────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = pymysql.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query(sql, params=(), one=False, commit=False):
    """Run a SELECT query and return dict rows."""
    db  = get_db()
    cur = db.cursor()
    try:
        cur.execute(sql, params)
        if commit:
            db.commit()
        if one:
            return cur.fetchone()
        return cur.fetchall()
    finally:
        cur.close()

def execute(sql, params=(), commit=True):
    """Run INSERT / UPDATE / DELETE."""
    db  = get_db()
    cur = db.cursor()
    try:
        cur.execute(sql, params)
        if commit:
            db.commit()
        return cur.lastrowid
    finally:
        cur.close()

# ─────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def now_dt():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def gen_ref():
    return f"REP-{datetime.now().year}-{str(uuid.uuid4())[:6].upper()}"

def validate_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None

# Admin guard decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        user = query("SELECT role, status FROM users WHERE id=%s", (identity,), one=True)
        if not user or user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        if user["status"] != "active":
            return jsonify({"error": "Account not active. Current status: " + user["status"]}), 403
        return fn(*args, **kwargs)
    return wrapper

# JWT blocklist check
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti   = jwt_payload["jti"]
    token = query("SELECT jti FROM revoked_tokens WHERE jti=%s", (jti,), one=True)
    return token is not None


# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data  = request.get_json(force=True, silent=True) or {}
    role  = data.get("role", "citizen")

    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"error": "name, email and password are required"}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if email not in verified_emails:
        return jsonify({"error": "Email not verified. Please verify your email first"}), 403
    verified_emails.discard(email)
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    if query("SELECT id FROM users WHERE email=%s", (email,), one=True):
        return jsonify({"error": "Email already registered"}), 409

    hashed          = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id         = str(uuid.uuid4())
    municipality    = None
    municipality_id = None
    phone           = None
    position        = None
    status          = "active"

    if role == "admin":
        municipality    = (data.get("municipality") or "").strip()
        municipality_id = (data.get("municipalityId") or "").strip()
        phone           = (data.get("phone") or "").strip() or None
        position        = (data.get("position") or "").strip() or None
        name            = (data.get("adminName") or name).strip()
        if not municipality or not municipality_id:
            return jsonify({"error": "municipality and municipalityId required for admin"}), 400
        status = "pending"

    execute(
        """INSERT INTO users
           (id, name, email, password, role, municipality, municipality_id, phone, position, status, provider, created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (user_id, name, email, hashed, role, municipality, municipality_id, phone, position, status, "email", now_dt())
    )

    # Create municipality record when admin registers
    if role == "admin":
        wilaya = (data.get("wilaya") or "").strip() or None
        existing = query("SELECT id FROM municipalities WHERE id=%s", (municipality_id,), one=True)
        if not existing:
            execute(
                """INSERT INTO municipalities
                   (id, name, wilaya, admin_id, admin_name, admin_email, admin_phone, admin_position, status, registered_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (municipality_id, municipality, wilaya, user_id, name, email, phone, position, "pending", now_dt())
            )
        else:
            # Update existing municipality with new admin info
            execute(
                """UPDATE municipalities SET admin_id=%s, admin_name=%s, admin_email=%s,
                   admin_phone=%s, admin_position=%s, status='pending' WHERE id=%s""",
                (user_id, name, email, phone, position, municipality_id)
            )

    access  = create_access_token(identity=user_id)
    refresh = create_refresh_token(identity=user_id)

    return jsonify({
        "message": "Account created",
        "user": {"id": user_id, "name": name, "email": email, "role": role, "status": status},
        "access_token":  access,
        "refresh_token": refresh
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(force=True, silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    user = query("SELECT * FROM users WHERE email=%s", (email,), one=True)

    # FIX: Google OAuth users have password=NULL — give a helpful error instead of
    #      crashing with AttributeError when bcrypt.checkpw receives None.encode()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not user["password"]:
        provider = user.get("provider", "google")
        return jsonify({"error": f"This account was created via {provider}. Please use '{provider.title()} Sign In'."}), 400
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401
    if user["status"] == "suspended":
        return jsonify({"error": "Account suspended"}), 403
    if user["status"] == "pending":
        return jsonify({"error": "Account pending approval. You will be notified once approved"}), 403

    execute("UPDATE users SET last_login=%s WHERE id=%s", (now_dt(), user["id"]))

    access  = create_access_token(identity=user["id"])
    refresh = create_refresh_token(identity=user["id"])

    return jsonify({
        "user": {
            "id":           user["id"],
            "name":         user["name"],
            "email":        user["email"],
            "role":         user["role"],
            "municipality": user["municipality"],
            "status":       user["status"]
        },
        "access_token":  access,
        "refresh_token": refresh
    })


@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity   = get_jwt_identity()
    new_access = create_access_token(identity=identity)
    return jsonify({"access_token": new_access})


@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    execute("INSERT IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (%s,%s)", (jti, now_dt()))
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def me():
    identity = get_jwt_identity()
    user = query(
        "SELECT id,name,email,role,municipality,status,created_at,last_login FROM users WHERE id=%s",
        (identity,), one=True
    )
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


# ─────────────────────────────────────────
# GOOGLE OAUTH ROUTES
# ─────────────────────────────────────────
@app.route("/api/auth/google")
def google_login():
    role = request.args.get("role", "citizen")
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid email profile"
        f"&state={role}"
    )
    return redirect(google_auth_url)


@app.route("/api/auth/google/callback")
def google_callback():
    code = request.args.get("code")
    role = request.args.get("state", "citizen")

    if not code:
        return jsonify({"error": "No code returned from Google"}), 400

    # Exchange code for access token
    token_res = http_requests.post("https://oauth2.googleapis.com/token", data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code"
    })
    token_data = token_res.json()

    if "access_token" not in token_data:
        return jsonify({"error": "Google token exchange failed", "detail": token_data}), 400

    # Get user info from Google
    user_info = http_requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {token_data['access_token']}"}
    ).json()

    email = user_info.get("email")
    name  = user_info.get("name", email)

    if not email:
        return jsonify({"error": "Could not get email from Google"}), 400

    # Check if user exists → login, else register
    existing = query("SELECT * FROM users WHERE email=%s", (email,), one=True)
    if existing:
        user_id = existing["id"]
        role    = existing["role"]  # keep original role
        execute("UPDATE users SET last_login=%s WHERE id=%s", (now_dt(), user_id))
    else:
        user_id = str(uuid.uuid4())
        execute(
            """INSERT INTO users
               (id, name, email, password, role, status, provider, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (user_id, name, email, None, role, "active", "google", now_dt())
        )

    access  = create_access_token(identity=user_id)
    refresh = create_refresh_token(identity=user_id)

    # FIX: Use URL hash fragment (#) instead of query string (?).
    # Hash fragments are never sent to the server and don't appear in server logs,
    # which prevents tokens from leaking via Referer headers or access logs.
    return redirect(
        f"{FRONTEND_URL}#{quote(name)}/{role}/{access}/{refresh}"
    )


# ─────────────────────────────────────────
# MARKERS ROUTES
# ─────────────────────────────────────────
@app.route("/api/markers", methods=["GET"])
def get_markers():
    # Public endpoint — no login required to view waste container locations
    type_filter = request.args.get("type")
    if type_filter and type_filter != "all":
        rows = query("SELECT * FROM markers WHERE type=%s ORDER BY created_at DESC", (type_filter,))
    else:
        rows = query("SELECT * FROM markers ORDER BY created_at DESC")
    # Convert Decimal lat/lng to float for JSON serialization
    for row in (rows or []):
        if row.get("lat") is not None:  row["lat"] = float(row["lat"])
        if row.get("lng") is not None:  row["lng"] = float(row["lng"])
    return jsonify(rows)


@app.route("/api/markers/<marker_id>", methods=["GET"])
@jwt_required()
def get_marker(marker_id):
    row = query("SELECT * FROM markers WHERE id=%s", (marker_id,), one=True)
    if not row:
        return jsonify({"error": "Marker not found"}), 404
    return jsonify(row)


@app.route("/api/markers", methods=["POST"])
@admin_required
def create_marker():
    data        = request.get_json(force=True, silent=True) or {}
    marker_type = data.get("type", "other")
    title       = (data.get("title") or "").strip()
    address     = (data.get("address") or "New Location").strip()
    description = (data.get("description") or "").strip()
    lat         = data.get("lat")
    lng         = data.get("lng")

    if not title or lat is None or lng is None:
        return jsonify({"error": "title, lat, lng are required"}), 400

    VALID_TYPES = {"garbage", "recycling", "toxic", "plastic", "glass", "paper", "organic", "other"}
    if marker_type not in VALID_TYPES:
        return jsonify({"error": f"type must be one of {VALID_TYPES}"}), 400

    marker_id  = str(uuid.uuid4())
    added_by   = get_jwt_identity()
    created_at = now_dt()

    execute(
        """INSERT INTO markers
           (id, type, title, address, description, lat, lng, added_by, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (marker_id, marker_type, title, address, description, lat, lng, added_by, created_at, created_at)
    )

    row = query("SELECT * FROM markers WHERE id=%s", (marker_id,), one=True)
    return jsonify(row), 201


@app.route("/api/markers/<marker_id>", methods=["PUT"])
@admin_required
def update_marker(marker_id):
    existing = query("SELECT * FROM markers WHERE id=%s", (marker_id,), one=True)
    if not existing:
        return jsonify({"error": "Marker not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    execute(
        """UPDATE markers
           SET type=%s, title=%s, address=%s, description=%s, lat=%s, lng=%s, updated_at=%s
           WHERE id=%s""",
        (
            data.get("type",        existing["type"]),
            data.get("title",       existing["title"]),
            data.get("address",     existing["address"]),
            data.get("description", existing["description"]),
            data.get("lat",         existing["lat"]),
            data.get("lng",         existing["lng"]),
            now_dt(), marker_id
        )
    )
    row = query("SELECT * FROM markers WHERE id=%s", (marker_id,), one=True)
    return jsonify(row)


@app.route("/api/markers/<marker_id>", methods=["DELETE"])
@admin_required
def delete_marker(marker_id):
    if not query("SELECT id FROM markers WHERE id=%s", (marker_id,), one=True):
        return jsonify({"error": "Marker not found"}), 404
    execute("DELETE FROM markers WHERE id=%s", (marker_id,))
    return jsonify({"message": "Marker deleted"})


# ─────────────────────────────────────────
# COMPLAINTS ROUTES
# ─────────────────────────────────────────
@app.route("/api/complaints", methods=["POST"])
@jwt_required()
def submit_complaint():
    is_multipart = request.content_type and "multipart" in request.content_type
    form = request.form if is_multipart else (request.get_json(force=True, silent=True) or {})

    issue_type     = (form.get("issueType") or form.get("issue_type") or "").strip()
    severity       = (form.get("severity") or "").strip()
    location       = (form.get("location") or "").strip()
    lat            = form.get("lat") or form.get("latitude") or None
    lng            = form.get("lng") or form.get("longitude") or None
    description    = (form.get("description") or "").strip()
    reporter_name  = (form.get("reporterName") or form.get("reporter_name") or "").strip()
    reporter_email = (form.get("reporterEmail") or form.get("reporter_email") or "").strip().lower()
    reporter_phone = (form.get("reporterPhone") or form.get("reporter_phone") or "").strip()
    want_follow_up = form.get("followUp", False)
    if isinstance(want_follow_up, str):
        want_follow_up = want_follow_up.lower() in ("true", "1", "yes", "on")

    # Convert lat/lng to float safely
    try: lat = float(lat) if lat else None
    except: lat = None
    try: lng = float(lng) if lng else None
    except: lng = None

    if not all([issue_type, severity, location, description, reporter_name, reporter_email]):
        return jsonify({"error": "issueType, severity, location, description, reporterName, reporterEmail required"}), 400
    if not validate_email(reporter_email):
        return jsonify({"error": "Invalid reporter email"}), 400

    VALID_TYPES      = {"overflow", "delay", "illegal", "damaged", "odor", "other"}
    VALID_SEVERITIES = {"low", "medium", "high"}
    if issue_type not in VALID_TYPES:
        return jsonify({"error": f"issueType must be one of {VALID_TYPES}"}), 400
    if severity not in VALID_SEVERITIES:
        return jsonify({"error": f"severity must be one of {VALID_SEVERITIES}"}), 400

    photo_path = None
    if "photo" in request.files:
        file = request.files["photo"]
        if file and file.filename and allowed_file(file.filename):
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            filename   = secure_filename(f"{uuid.uuid4()}_{file.filename}")
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            photo_path = f"/uploads/{filename}"

    complaint_id = str(uuid.uuid4())
    ref_number   = gen_ref()
    submitted_by = get_jwt_identity()
    created_at   = now_dt()

    execute(
        """INSERT INTO complaints
           (id, ref_number, issue_type, severity, location, lat, lng, description, photo_path,
            reporter_name, reporter_email, reporter_phone, want_follow_up,
            status, submitted_by, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (complaint_id, ref_number, issue_type, severity, location, lat, lng, description, photo_path,
         reporter_name, reporter_email, reporter_phone, int(want_follow_up),
         "open", submitted_by, created_at, created_at)
    )

    row = query("SELECT * FROM complaints WHERE id=%s", (complaint_id,), one=True)

    # 1. Send confirmation email to citizen
    if want_follow_up and reporter_email:
        citizen_body = (
            f"Hello {reporter_name},\n\n"
            f"Your complaint has been successfully submitted to WasteTrack.\n\n"
            f"Reference Number : {ref_number}\n"
            f"Issue Type       : {issue_type.replace('_', ' ').title()}\n"
            f"Severity         : {severity.title()}\n"
            f"Location         : {location}\n"
            f"Description      : {description}\n\n"
            f"Our team will review your report and take action as soon as possible.\n"
            f"You can use your reference number to follow up on this complaint.\n\n"
            f"Thank you for helping keep our community clean!\n\n"
            f"– The WasteTrack Team"
        )
        send_email(reporter_email, f"WasteTrack – Complaint Received ({ref_number})", citizen_body)

    # 2. Notify all active admins about the new complaint
    admin_emails = query(
        "SELECT email, name FROM users WHERE role='admin' AND status='active'", ()
    )
    if admin_emails:
        admin_body = (
            f"A new complaint has been submitted on WasteTrack.\n\n"
            f"Reference Number : {ref_number}\n"
            f"Issue Type       : {issue_type.replace('_', ' ').title()}\n"
            f"Severity         : {severity.upper()}\n"
            f"Location         : {location}\n"
            f"Reporter         : {reporter_name} ({reporter_email})\n"
            f"Description      : {description}\n\n"
            f"Please log in to the admin dashboard to review and respond.\n\n"
            f"– WasteTrack System"
        )
        for admin in admin_emails:
            send_email(admin["email"],
                       f"[WasteTrack] New {severity.upper()} Complaint – {ref_number}",
                       admin_body)

    return jsonify(row), 201


@app.route("/api/complaints", methods=["GET"])
@jwt_required()
def list_complaints():
    identity = get_jwt_identity()
    user     = query("SELECT role FROM users WHERE id=%s", (identity,), one=True)

    if user and user["role"] == "admin":
        status_filter = request.args.get("status")
        type_filter   = request.args.get("type")
        sql    = "SELECT * FROM complaints WHERE 1=1"
        params = []
        if status_filter:
            sql += " AND status=%s"; params.append(status_filter)
        else:
            # By default exclude resolved and closed — admins only see active reports
            sql += " AND status NOT IN ('resolved','closed')"
        if type_filter:
            sql += " AND issue_type=%s"; params.append(type_filter)
        sql += " ORDER BY created_at DESC"
        rows = query(sql, params)
    else:
        rows = query(
            "SELECT * FROM complaints WHERE submitted_by=%s ORDER BY created_at DESC",
            (identity,)
        )
    return jsonify(rows)


@app.route("/api/complaints/<complaint_id>", methods=["GET"])
@jwt_required()
def get_complaint(complaint_id):
    identity = get_jwt_identity()
    user     = query("SELECT role FROM users WHERE id=%s", (identity,), one=True)
    row      = query("SELECT * FROM complaints WHERE id=%s", (complaint_id,), one=True)

    if not row:
        return jsonify({"error": "Complaint not found"}), 404
    if user["role"] != "admin" and row["submitted_by"] != identity:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify(row)


@app.route("/api/complaints/<complaint_id>/status", methods=["PATCH"])
@admin_required
def update_complaint_status(complaint_id):
    data   = request.get_json(force=True, silent=True) or {}
    status = data.get("status", "").strip()
    VALID  = {"open", "in_progress", "resolved", "closed"}
    if status not in VALID:
        return jsonify({"error": f"status must be one of {VALID}"}), 400

    if not query("SELECT id FROM complaints WHERE id=%s", (complaint_id,), one=True):
        return jsonify({"error": "Complaint not found"}), 404

    execute("UPDATE complaints SET status=%s, updated_at=%s WHERE id=%s",
            (status, now_dt(), complaint_id))

    row = query("SELECT * FROM complaints WHERE id=%s", (complaint_id,), one=True)
    return jsonify(row)


# ─────────────────────────────────────────
# ADMIN – USER MANAGEMENT
# ─────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def list_users():
    rows = query(
        "SELECT id,name,email,role,municipality,municipality_id,phone,position,status,created_at,last_login FROM users ORDER BY created_at DESC"
    )
    return jsonify(rows)


@app.route("/api/admin/users/<user_id>/status", methods=["PATCH"])
@admin_required
def update_user_status(user_id):
    data   = request.get_json(force=True, silent=True) or {}
    status = data.get("status", "").strip()
    VALID  = {"active", "pending", "suspended"}
    if status not in VALID:
        return jsonify({"error": f"status must be one of {VALID}"}), 400

    user = query("SELECT id,name,email,role,municipality_id,municipality FROM users WHERE id=%s", (user_id,), one=True)
    if not user:
        return jsonify({"error": "User not found"}), 404

    execute("UPDATE users SET status=%s WHERE id=%s", (status, user_id))

    # Sync municipality status when approving/suspending an admin
    if user["role"] == "admin" and user.get("municipality_id"):
        if status == "active":
            execute(
                "UPDATE municipalities SET status='active', approved_at=%s WHERE id=%s",
                (now_dt(), user["municipality_id"])
            )
        else:
            execute(
                "UPDATE municipalities SET status=%s WHERE id=%s",
                (status, user["municipality_id"])
            )

    # Send email notification to the user about their status change
    if user.get("email"):
        if status == "active" and user["role"] == "admin":
            send_email(
                user["email"],
                "WasteTrack – Your Admin Account is Approved!",
                f"Hello {user['name']},\n\n"
                f"Great news! Your WasteTrack Municipality Admin account has been approved.\n\n"
                f"Municipality : {user.get('municipality', '')}\n\n"
                f"You can now log in and start managing waste containers and complaints for your municipality.\n\n"
                f"Login at: https://curious-churros-1c58e7.netlify.app/wm.html\n\n"
                f"– The WasteTrack Team"
            )
        elif status == "suspended":
            send_email(
                user["email"],
                "WasteTrack – Account Suspended",
                f"Hello {user['name']},\n\n"
                f"Your WasteTrack account has been suspended.\n"
                f"Please contact support for more information.\n\n"
                f"– The WasteTrack Team"
            )

    return jsonify({"message": f"User status updated to {status}"})


@app.route("/api/admin/municipalities", methods=["GET"])
@admin_required
def list_municipalities():
    rows = query("SELECT * FROM municipalities ORDER BY registered_at DESC")
    return jsonify(rows or [])


@app.route("/api/admin/municipalities/<muni_id>", methods=["GET"])
@admin_required
def get_municipality(muni_id):
    row = query("SELECT * FROM municipalities WHERE id=%s", (muni_id,), one=True)
    if not row:
        return jsonify({"error": "Municipality not found"}), 404
    return jsonify(row)


# ─────────────────────────────────────────
# Password Reset
# ─────────────────────────────────────────
_reset_codes = {}  # {email: (code, expiry)}

@app.route("/api/auth/forgot-password", methods=["POST", "OPTIONS"])
def forgot_password():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data  = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    user = query("SELECT id, name FROM users WHERE email=%s", (email,), one=True)
    if not user:
        # Don't reveal if email exists
        return jsonify({"message": "If this email is registered, a reset code has been sent"}), 200

    code   = ''.join(random.choices(string.digits, k=6))
    expiry = time.time() + 600  # 10 minutes
    _reset_codes[email] = (code, expiry)
    print(f"[WASTETRACK] Password reset code for {email}: {code}")

    send_email(
        email,
        "WasteTrack – Password Reset Code",
        f"Hello {user['name']},\n\n"
        f"Your password reset code is:\n\n"
        f"    {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you did not request this, ignore this email.\n\n"
        f"– The WasteTrack Team"
    )
    return jsonify({"message": "If this email is registered, a reset code has been sent"}), 200


@app.route("/api/auth/reset-password", methods=["POST", "OPTIONS"])
def reset_password():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data     = request.get_json(force=True, silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    code     = (data.get("code") or "").strip()
    password = data.get("new_password") or data.get("password", "")

    if not email or not code or not password:
        return jsonify({"error": "email, code and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    entry = _reset_codes.get(email)
    if not entry:
        return jsonify({"error": "No reset code found. Please request a new one"}), 400
    stored_code, expiry = entry
    if time.time() > expiry:
        del _reset_codes[email]
        return jsonify({"error": "Reset code has expired. Please request a new one"}), 400
    if code != stored_code:
        return jsonify({"error": "Invalid reset code"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    execute("UPDATE users SET password=%s WHERE email=%s", (hashed, email))
    del _reset_codes[email]
    return jsonify({"message": "Password reset successfully. You can now log in."}), 200



@app.route("/api/complaints/history", methods=["GET"])
@admin_required
def complaints_history():
    """Returns resolved and closed complaints for the history tab."""
    rows = query(
        "SELECT * FROM complaints WHERE status IN ('resolved','closed') ORDER BY updated_at DESC"
    )
    return jsonify(rows or [])


@app.route("/api/stats", methods=["GET"])
@admin_required
def get_stats():
    try:
        stats = {
            "total_users":            query("SELECT COUNT(*) AS n FROM users", one=True)["n"],
            "active_users":           query("SELECT COUNT(*) AS n FROM users WHERE status='active'", one=True)["n"],
            "pending_admins":         query("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND status='pending'", one=True)["n"],
            "total_markers":          query("SELECT COUNT(*) AS n FROM markers", one=True)["n"],
            "total_complaints":       query("SELECT COUNT(*) AS n FROM complaints", one=True)["n"],
            "open_complaints":        query("SELECT COUNT(*) AS n FROM complaints WHERE status='open'", one=True)["n"],
            "resolved_complaints":    query("SELECT COUNT(*) AS n FROM complaints WHERE status='resolved'", one=True)["n"],
            "complaints_by_type":     query("SELECT issue_type, COUNT(*) AS count FROM complaints GROUP BY issue_type"),
            "complaints_by_severity": query("SELECT severity, COUNT(*) AS count FROM complaints GROUP BY severity"),
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch stats: {str(e)}"}), 500


# ─────────────────────────────────────────
# Health check
# ─────────────────────────────────────────
@app.route("/uploads/<path:filename>", methods=["GET"])
def serve_upload(filename):
    from flask import send_from_directory
    return send_from_directory(UPLOAD_FOLDER, filename)



def health():
    return jsonify({"status": "ok", "service": "WasteTrack API", "version": "1.0.0"})


# ─────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Max {MAX_UPLOAD_MB}MB"}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.route("/api/auth/send-code", methods=["POST"])
def send_verification_code():
    data  = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or not validate_email(email):
        return jsonify({"error": "Valid email required"}), 400

    if query("SELECT id FROM users WHERE email=%s", (email,), one=True):
        return jsonify({"error": "Email already registered"}), 409

    # FIX: rate-limit repeated send requests to prevent abuse
    last_sent = _last_code_sent.get(email, 0)
    if time.time() - last_sent < RESEND_COOLDOWN_SECONDS:
        wait = int(RESEND_COOLDOWN_SECONDS - (time.time() - last_sent))
        return jsonify({"error": f"Please wait {wait}s before requesting a new code"}), 429

    code = ''.join(random.choices(string.digits, k=6))
    pending_verifications[email] = (code, time.time() + VERIFICATION_CODE_TTL)
    _last_code_sent[email] = time.time()

    # Always print the code to the Flask console so you can test without email
    print(f"[WASTETRACK] Verification code for {email}: {code}")

    body = (
        f"Hello!\n\n"
        f"Your WasteTrack verification code is:\n\n"
        f"    {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"Do not share it with anyone.\n\n"
        f"– The WasteTrack Team"
    )
    ok, err = send_email(email, "WasteTrack – Your Verification Code", body)
    if ok:
        print(f"[EMAIL] Code sent successfully to {email}")
        return jsonify({"message": "Code sent successfully"})
    else:
        traceback.print_exc()
        # dev_code lets the frontend still work even when SMTP is blocked.
        # REMOVE 'dev_code' before deploying to production.
        return jsonify({
            "error": "Failed to send email – check Flask console for the code",
            "detail": err,
            "dev_code": code
        }), 500


@app.route("/api/auth/verify-code", methods=["POST"])
def verify_code():
    data  = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code  = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"error": "email and code required"}), 400

    stored = pending_verifications.get(email)
    if not stored:
        return jsonify({"error": "No code found. Please request a new one"}), 400

    stored_code, expiry = stored
    if time.time() > expiry:
        del pending_verifications[email]
        return jsonify({"error": "Code expired. Please request a new one"}), 400
    if stored_code != code:
        return jsonify({"error": "Invalid code"}), 400

    del pending_verifications[email]
    verified_emails.add(email)
    return jsonify({"message": "Email verified", "verified": True})


@app.route("/api/auth/test-email", methods=["POST"])
def test_email():
    data  = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    ok, err = send_email(email, "WasteTrack – Email Test",
                         "If you received this, your email config is working correctly!")
    if ok:
        return jsonify({"message": f"Test email sent to {email}!"})
    else:
        traceback.print_exc()
        return jsonify({"error": "Email sending failed", "detail": err}), 500


# ─────────────────────────────────────────
# Auto-create tables on startup
# ─────────────────────────────────────────
def init_db():
    """Create all tables if they don't exist — safe to run multiple times."""
    try:
        conn = pymysql.connect(**DB_CONFIG)
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id              VARCHAR(36)  NOT NULL,
                name            VARCHAR(120) NOT NULL,
                email           VARCHAR(120) NOT NULL,
                password        VARCHAR(255) DEFAULT NULL,
                role            ENUM('citizen','admin') NOT NULL DEFAULT 'citizen',
                municipality    VARCHAR(120) DEFAULT NULL,
                municipality_id VARCHAR(60)  DEFAULT NULL,
                phone           VARCHAR(30)  DEFAULT NULL,
                position        VARCHAR(120) DEFAULT NULL,
                status          ENUM('active','pending','suspended') NOT NULL DEFAULT 'active',
                provider        ENUM('email','google') NOT NULL DEFAULT 'email',
                last_login      DATETIME     DEFAULT NULL,
                created_at      DATETIME     NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # Add phone/position columns if upgrading from old schema
        try:
            cur.execute("ALTER TABLE users ADD COLUMN phone VARCHAR(30) DEFAULT NULL")
        except: pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN position VARCHAR(120) DEFAULT NULL")
        except: pass
        cur.execute("""
            CREATE TABLE IF NOT EXISTS municipalities (
                id              VARCHAR(60)  NOT NULL,
                name            VARCHAR(120) NOT NULL,
                wilaya          VARCHAR(120) DEFAULT NULL,
                admin_id        VARCHAR(36)  DEFAULT NULL,
                admin_name      VARCHAR(120) DEFAULT NULL,
                admin_email     VARCHAR(120) DEFAULT NULL,
                admin_phone     VARCHAR(30)  DEFAULT NULL,
                admin_position  VARCHAR(120) DEFAULT NULL,
                status          ENUM('active','pending','suspended') NOT NULL DEFAULT 'pending',
                registered_at   DATETIME     NOT NULL,
                approved_at     DATETIME     DEFAULT NULL,
                PRIMARY KEY (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti        VARCHAR(64) NOT NULL,
                revoked_at DATETIME    NOT NULL,
                PRIMARY KEY (jti)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS markers (
                id          VARCHAR(36)    NOT NULL,
                type        VARCHAR(30)    NOT NULL,
                title       VARCHAR(120)   NOT NULL,
                address     VARCHAR(255)   DEFAULT NULL,
                description TEXT           DEFAULT NULL,
                lat         DECIMAL(10,7)  NOT NULL,
                lng         DECIMAL(10,7)  NOT NULL,
                added_by    VARCHAR(36)    DEFAULT NULL,
                created_at  DATETIME       NOT NULL,
                updated_at  DATETIME       NOT NULL,
                PRIMARY KEY (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                id             VARCHAR(36)  NOT NULL,
                ref_number     VARCHAR(30)  NOT NULL,
                issue_type     VARCHAR(30)  NOT NULL,
                severity       ENUM('low','medium','high') NOT NULL,
                location       VARCHAR(255) NOT NULL,
                lat            DECIMAL(10,7) DEFAULT NULL,
                lng            DECIMAL(10,7) DEFAULT NULL,
                description    TEXT         NOT NULL,
                photo_path     VARCHAR(255) DEFAULT NULL,
                reporter_name  VARCHAR(120) NOT NULL,
                reporter_email VARCHAR(120) NOT NULL,
                reporter_phone VARCHAR(30)  DEFAULT NULL,
                want_follow_up TINYINT(1)   NOT NULL DEFAULT 1,
                status         ENUM('open','in_progress','resolved','closed') NOT NULL DEFAULT 'open',
                submitted_by   VARCHAR(36)  DEFAULT NULL,
                created_at     DATETIME     NOT NULL,
                updated_at     DATETIME     NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY ref_number (ref_number)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # Add lat/lng columns if upgrading from old schema
        try:
            cur.execute("ALTER TABLE complaints ADD COLUMN lat DECIMAL(10,7) DEFAULT NULL")
        except: pass
        try:
            cur.execute("ALTER TABLE complaints ADD COLUMN lng DECIMAL(10,7) DEFAULT NULL")
        except: pass
        conn.commit()
        conn.close()
        print("✅ Database tables ready")
    except Exception as e:
        print(f"❌ Database init failed: {e}")

# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    print(f"🌿 WasteTrack API starting on port {port}")
    print(f"   DB  → {DB_CONFIG['host']}:{DB_CONFIG['port']} / {DB_CONFIG['database']}")
    app.run(host="0.0.0.0", port=port, debug=debug)
