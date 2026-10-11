import os, re, sqlite3, secrets, time
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),   # HTTPS only บนโฮสจริง
    MAX_CONTENT_LENGTH=64 * 1024)
DB = os.environ.get("DB_PATH", "app.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);"""
DUMMY = generate_password_hash("dummy-password")
fails = {}  # (ip, username) -> [count, locked_until]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
def q(sql, *a): return db().execute(sql, a)   # parameterized query เท่านั้น -> กัน SQL Injection
@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    with app.app_context():
        db().executescript(SCHEMA)
        u, p = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
        if u and p and not q("SELECT 1 FROM users WHERE username=?", u).fetchone():
            q("INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')", u, generate_password_hash(p))
        db().commit()

@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        g.user = q("SELECT * FROM users WHERE id=?", session["uid"]).fetchone()
        if not g.user: session.clear()
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":   # CSRF
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session["csrf"]): abort(400)
@app.context_processor
def inject(): return dict(csrf_token=session.get("csrf", ""), me=g.get("user"))
@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    r.headers["X-Frame-Options"] = "DENY"; r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"; r.headers["Cache-Control"] = "no-store"
    return r

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user: return redirect(url_for("login"))
        return f(*a, **k)
    return w
def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "admin": abort(403)   # เช็กบทบาทฝั่งเซิร์ฟเวอร์ทุกครั้ง
        return f(*a, **k)
    return w

@app.route("/")
def index(): return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", u): flash("ชื่อผู้ใช้ 3-30 ตัว (a-z, 0-9, _)")
        elif len(p) < 8 or len(p) > 128: flash("รหัสผ่านต้องยาว 8-128 ตัวอักษร")
        elif q("SELECT 1 FROM users WHERE username=?", u).fetchone(): flash("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
        else:
            # role fix เป็น user เสมอ ไม่รับจากฟอร์ม
            q("INSERT INTO users(username,password_hash,role) VALUES(?,?,'user')", u, generate_password_hash(p))
            db().commit(); flash("สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ"); return redirect(url_for("login"))
    return render_template("auth.html", title="สมัครสมาชิก")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        key = (request.remote_addr, u.lower()); f = fails.get(key, [0, 0])
        if f[1] > time.time(): flash("ลองผิดหลายครั้ง กรุณารอ 5 นาที"); return render_template("auth.html", title="เข้าสู่ระบบ")
        row = q("SELECT * FROM users WHERE username=?", u).fetchone()
        ok = check_password_hash(row["password_hash"] if row else DUMMY, p) and row
        if ok:
            fails.pop(key, None); session.clear(); session["uid"] = row["id"]; session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("notes"))
        f[0] += 1; f[1] = time.time() + 300 if f[0] >= 5 else 0; fails[key] = f
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")   # ข้อความเดียวกัน กัน user enumeration
    return render_template("auth.html", title="เข้าสู่ระบบ")

@app.post("/logout")
def logout(): session.clear(); return redirect(url_for("index"))

# ---------- CRUD: บันทึก (มีเจ้าของ) ----------
def valid_note():
    t, b = request.form.get("title", "").strip(), request.form.get("body", "").strip()
    if not t or len(t) > 100 or len(b) > 2000: flash("หัวข้อ 1-100 ตัวอักษร, เนื้อหาไม่เกิน 2000"); return None
    return t, b
def own_note(nid):
    n = q("SELECT * FROM notes WHERE id=?", nid).fetchone()
    if not n: abort(404)
    if n["user_id"] != g.user["id"]: abort(403)   # ตรวจความเป็นเจ้าของ
    return n

@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    if request.method == "POST":
        v = valid_note()
        if v: q("INSERT INTO notes(user_id,title,body) VALUES(?,?,?)", g.user["id"], *v); db().commit(); flash("บันทึกแล้ว")
        return redirect(url_for("notes"))
    rows = q("SELECT * FROM notes WHERE user_id=? ORDER BY id DESC", g.user["id"]).fetchall()
    return render_template("notes.html", notes=rows)

@app.route("/notes/<int:nid>/edit", methods=["GET", "POST"])
@login_required
def edit_note(nid):
    n = own_note(nid)
    if request.method == "POST":
        v = valid_note()
        if v: q("UPDATE notes SET title=?, body=? WHERE id=?", *v, nid); db().commit(); flash("แก้ไขแล้ว"); return redirect(url_for("notes"))
    return render_template("edit.html", n=n)

@app.post("/notes/<int:nid>/delete")
@login_required
def delete_note(nid):
    own_note(nid); q("DELETE FROM notes WHERE id=?", nid); db().commit(); flash("ลบแล้ว")
    return redirect(url_for("notes"))

# ---------- ฟอร์มที่ 2: ส่งข้อความถึงผู้ดูแล ----------
@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    if request.method == "POST":
        s, m = request.form.get("subject", "").strip(), request.form.get("message", "").strip()
        if not s or len(s) > 100 or not m or len(m) > 1000: flash("หัวข้อ 1-100, ข้อความ 1-1000 ตัวอักษร")
        else: q("INSERT INTO messages(user_id,subject,message) VALUES(?,?,?)", g.user["id"], s, m); db().commit(); flash("ส่งข้อความแล้ว")
        return redirect(url_for("contact"))
    rows = q("SELECT * FROM messages WHERE user_id=? ORDER BY id DESC", g.user["id"]).fetchall()
    return render_template("contact.html", msgs=rows)

# ---------- แอดมิน ----------
@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html",
        users=q("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall(),
        notes=q("SELECT n.*, u.username FROM notes n JOIN users u ON u.id=n.user_id ORDER BY n.id DESC").fetchall(),
        msgs=q("SELECT m.*, u.username FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC").fetchall())

@app.post("/admin/users/<int:uid>/role")
@admin_required
def set_role(uid):
    role = request.form.get("role")
    if role not in ("user", "admin") or uid == g.user["id"]: abort(400)
    q("UPDATE users SET role=? WHERE id=?", role, uid); db().commit(); return redirect(url_for("admin"))

@app.post("/admin/users/<int:uid>/delete")
@admin_required
def del_user(uid):
    if uid == g.user["id"]: abort(400)
    q("DELETE FROM users WHERE id=?", uid); db().commit(); return redirect(url_for("admin"))

@app.post("/admin/notes/<int:nid>/delete")
@admin_required
def admin_del_note(nid):
    q("DELETE FROM notes WHERE id=?", nid); db().commit(); return redirect(url_for("admin"))

init_db()
if __name__ == "__main__": app.run(debug=False)
