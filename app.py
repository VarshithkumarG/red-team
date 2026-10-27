"""SecureShop intentionally vulnerable training application.

Run only on localhost. Set LAB_MODE=secure to enable remediations.
"""
import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "secureshop.db"
MODE = os.environ.get("LAB_MODE", "vulnerable").lower()
if MODE not in {"vulnerable", "secure"}:
    raise RuntimeError("LAB_MODE must be vulnerable or secure")
if MODE == "secure" and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("Set SECRET_KEY to a random value before starting secure mode")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-lab-secret-change-me"),
    SESSION_COOKIE_HTTPONLY=(MODE == "secure"),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # HTTP localhost lab; use HTTPS before any deployment.
)


class QuietServerBannerHandler(WSGIRequestHandler):
    """Do not disclose the development server or runtime version in secure mode."""
    def version_string(self):
        return "SecureShop"


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer'
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
            description TEXT NOT NULL, price REAL NOT NULL, stock INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, item TEXT NOT NULL,
            total REAL NOT NULL, status TEXT NOT NULL
        );
        """)
        if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            enc = generate_password_hash
            pw = (lambda x: x) if MODE == "vulnerable" else enc
            conn.executemany("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)", [
                ("Alice Morgan", "alice@secureshop.test", pw("alice123"), "customer"),
                ("Jordan Lee", "jordan@secureshop.test", pw("jordan123"), "customer"),
                ("Store Admin", "admin@secureshop.test", pw("admin123"), "admin"),
            ])
            conn.executemany("INSERT INTO products(name,category,description,price,stock) VALUES(?,?,?,?,?)", [
                ("Studio Headphones", "Audio", "Balanced sound for work and travel.", 129.00, 18),
                ("Everyday Backpack", "Accessories", "Weather-resistant recycled fabric.", 74.50, 31),
                ("Mechanical Keyboard", "Workspace", "Compact tactile keyboard with hot-swap switches.", 99.00, 12),
                ("Desk Light", "Workspace", "Dimmable warm and cool lighting.", 48.00, 24),
            ])
            conn.executemany("INSERT INTO orders(user_id,item,total,status) VALUES(?,?,?,?)", [
                (1, "Studio Headphones", 129.00, "Shipped"),
                (2, "Everyday Backpack", 74.50, "Processing"),
            ])
        else:
            # Keep seeded demo users usable when switching profiles on an existing lab DB.
            for email, password in (("alice@secureshop.test", "alice123"),
                                    ("jordan@secureshop.test", "jordan123"),
                                    ("admin@secureshop.test", "admin123")):
                stored = generate_password_hash(password) if MODE == "secure" else password
                conn.execute("UPDATE users SET password=? WHERE email=?", (stored, email))


@app.before_request
def local_only_and_security_headers():
    # Fail closed if someone changes the bind address or proxies external traffic in.
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)
    if MODE == "secure":
        # Per-request token is kept in the signed session and checked on mutations.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.form.get("csrf_token", "")
            if not supplied or supplied != session.get("csrf_token"):
                abort(400, "Missing or invalid CSRF token")


@app.after_request
def response_headers(response):
    response.headers["X-Lab-Mode"] = MODE
    if MODE == "secure":
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'",
            "Cache-Control": "no-store",
        })
    else:
        response.headers["X-Powered-By"] = "SecureShop-Training/0.1"
    return response


@app.context_processor
def template_context():
    if MODE == "secure" and not session.get("csrf_token"):
        import secrets
        session["csrf_token"] = secrets.token_urlsafe(24)
    return {"lab_mode": MODE, "csrf_token": session.get("csrf_token", "")}


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    products = db().execute("SELECT * FROM products ORDER BY id LIMIT 3").fetchall()
    return render_template("home.html", products=products)


@app.route("/products")
def products():
    query = request.args.get("q", "").strip()
    if query and MODE == "vulnerable":
        # Deliberate SQL injection exercise. Only run against this local seeded DB.
        sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%' OR category LIKE '%" + query + "%' ORDER BY id"
        rows = db().execute(sql).fetchall()
    elif query:
        rows = db().execute("SELECT * FROM products WHERE name LIKE ? OR category LIKE ? ORDER BY id",
                            (f"%{query}%", f"%{query}%")).fetchall()
    else:
        rows = db().execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("products.html", products=rows, query=query)


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    product = db().execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        abort(404)
    return render_template("product.html", product=product)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, password = (request.form.get(k, "").strip() for k in ("name", "email", "password"))
        if not name or not email or len(password) < 6:
            flash("Enter a name, email, and password of at least 6 characters.", "error")
        else:
            stored = password if MODE == "vulnerable" else generate_password_hash(password)
            try:
                db().execute("INSERT INTO users(name,email,password) VALUES(?,?,?)", (name, email.lower(), stored))
                db().commit()
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        if MODE == "vulnerable":
            # Deliberate SQL injection and plaintext-password demonstration.
            row = db().execute("SELECT * FROM users WHERE email='" + email + "' AND password='" + password + "'").fetchone()
        else:
            row = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row and not check_password_hash(row["password"], password):
                row = None
        if row:
            session.clear()
            session.update(user_id=row["id"], name=row["name"], role=row["role"])
            if MODE == "secure":
                import secrets
                session["csrf_token"] = secrets.token_urlsafe(24)
            return redirect(request.args.get("next") or url_for("profile"))
        flash("Email or password was not recognized.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("home"))


@app.route("/profile")
@login_required
def profile():
    person_id = request.args.get("user_id", session["user_id"], type=int)
    if MODE == "secure" and person_id != session["user_id"] and session.get("role") != "admin":
        abort(403)
    person = db().execute("SELECT id,name,email,role FROM users WHERE id=?", (person_id,)).fetchone()
    if not person:
        abort(404)
    orders = db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (person_id,)).fetchall()
    return render_template("profile.html", person=person, orders=orders)


@app.route("/orders/<int:user_id>")
@login_required
def order_history(user_id):
    # Deliberate insecure direct object reference. Secure mode enforces ownership.
    if MODE == "secure" and user_id != session["user_id"] and session.get("role") != "admin":
        abort(403)
    person = db().execute("SELECT id,name FROM users WHERE id=?", (user_id,)).fetchone()
    if not person:
        abort(404)
    orders = db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    return render_template("orders.html", person=person, orders=orders)


@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    if request.method == "POST":
        product_id = request.form.get("product_id", type=int)
        product = db().execute("SELECT id,name,price FROM products WHERE id=?", (product_id,)).fetchone()
        if product:
            cart_items = session.get("cart", [])
            cart_items.append(dict(id=product["id"], name=product["name"], price=product["price"]))
            session["cart"] = cart_items
            flash("Added to your cart.", "success")
        return redirect(url_for("cart"))
    return render_template("cart.html", items=session.get("cart", []))


@app.route("/admin")
@login_required
@admin_required
def admin():
    users = db().execute("SELECT id,name,email,role FROM users ORDER BY id").fetchall()
    products = db().execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("admin.html", users=users, products=products)


@app.route("/admin/products", methods=["POST"])
@login_required
@admin_required
def add_product():
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "General").strip()
    try:
        price, stock = float(request.form.get("price", "0")), int(request.form.get("stock", "0"))
    except ValueError:
        abort(400)
    if not name or price < 0 or stock < 0:
        abort(400)
    db().execute("INSERT INTO products(name,category,description,price,stock) VALUES(?,?,?,?,?)",
                 (name, category, request.form.get("description", ""), price, stock))
    db().commit()
    flash("Product added.", "success")
    return redirect(url_for("admin"))


@app.route("/health")
def health():
    return {"status": "ok", "mode": MODE}


@app.errorhandler(500)
def internal_error(_error):
    if MODE == "vulnerable":
        return render_template("error.html", detail="A server error occurred. In this lab profile, verbose errors are enabled only in the server terminal."), 500
    return render_template("error.html", detail="The request could not be completed."), 500


init_db()

if __name__ == "__main__":
    # Loopback-only by design. Never change host to 0.0.0.0.
    run_options = {"request_handler": QuietServerBannerHandler} if MODE == "secure" else {}
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False, **run_options)
