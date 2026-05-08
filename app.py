import json
import logging
import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Paths & App ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

app = Flask(__name__)
app.config.update(
    if not app.config["SECRET_KEY"]:
    raise RuntimeError("Debes definir SECRET_KEY en variables de entorno")
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

# WARN if SECRET_KEY is not set via environment (would be random on every restart)
if not os.getenv("SECRET_KEY"):
    logger.warning(
        "SECRET_KEY not set via environment variable. "
        "Sessions will be invalidated on every server restart. "
        "Set a stable SECRET_KEY in production."
    )

# ── Rate-limit state (in-memory; works for single-worker deployments) ─────────
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_WINDOW_SECONDS = 900   # 15 min window
LOGIN_MAX_ATTEMPTS = 7

# ── Default seed data ─────────────────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "site_title": "👑 Red Elías Casino",
    "meta_description": "Red Elías Casino — Las mejores líneas de casino online. Bonos exclusivos, retiros rápidos y atención 24hs.",
    "phone": "5491125554455",
    "logo": "👑 Red Elías",
    "hero_badge": "🏆 Plataforma #1 en Argentina",
    "hero_title": "Las Mejores Líneas\nde Casino Online",
    "hero_sub": "Bonos exclusivos • Retiros rápidos • Atención 24hs",
    "hero_bonus": "🎁 Bono de Bienvenida hasta $50.000",
    "stat_platforms": "+6",
    "stat_support": "24hs",
    "stat_withdrawal": "$150K",
    "stat_bonus": "100%",
    "promo_tag": "🔥 Promo Especial",
    "promo_title": "Duplicá tu primera carga",
    "promo_amount": "$50.000",
    "promo_sub": "Empezá a jugar con ventaja desde el primer día",
    "promo_slot": "$150",
    "promo_withdraw_min": "$4.000",
    "promo_withdraw_max": "$150.000",
    "promo_cta": "👑 Activar Bono Ahora",
}

DEFAULT_CASINOS = [
    {"icon": "🌐", "name": "GanamosNet", "links": ["https://ganamosnet.fit", "https://ganamosnet.ink"]},
    {"icon": "🥇", "name": "OroPuro", "links": ["https://oropuro.bet"]},
    {"icon": "⚡", "name": "Bet30", "links": ["https://bet30.work"]},
    {"icon": "🏛️", "name": "Casino Zeus", "links": ["https://casinozeus.work"]},
    {"icon": "🎲", "name": "Azar Latino", "links": ["https://azarlatino.xyz"]},
    {"icon": "🎯", "name": "JugaBet", "links": ["https://jugabet.art"]},
]

DEFAULT_TESTIMONIALS = [
    {"name": "Martín G.", "info": "Buenos Aires • GanamosNet", "stars": 5, "text": "Cobré el retiro en menos de 2 horas. Atención impecable y el bono llegó tal cual prometieron. ¡Recomiendo al 100%!"},
    {"name": "Lucía R.", "info": "Córdoba • OroPuro", "stars": 5, "text": "Llevo 3 meses jugando y nunca tuve un problema. El soporte responde rápido y los retiros son confiables."},
    {"name": "Diego P.", "info": "Rosario • Bet30", "stars": 5, "text": "El bono de bienvenida me sorprendió. Fácil de activar, sin vueltas. Sigo jugando todos los días."},
    {"name": "Valeria M.", "info": "Mendoza • Casino Zeus", "stars": 5, "text": "Probé varias plataformas y Red Elías es la que más me convenció. Retiros rápidos y excelente atención."},
    {"name": "Rodrigo T.", "info": "La Plata • JugaBet", "stars": 5, "text": "Activé el bono con un solo mensaje de WhatsApp. Increíble la rapidez. Ya soy cliente fijo."},
    {"name": "Camila F.", "info": "Tucumán • Azar Latino", "stars": 5, "text": "Me explicaron todo desde cero. Muy buena onda el asesor. Los retiros siempre puntuales."},
]

DEFAULT_FAQS = [
    {"question": "¿Cómo activo el bono de bienvenida?", "answer": "Escribinos por WhatsApp, indicá en qué plataforma querés jugar y nuestro asesor te va a guiar para activar el bono en minutos."},
    {"question": "¿Cuánto tarda un retiro?", "answer": "Los retiros se procesan en un máximo de 24hs. En la mayoría de los casos el dinero llega en menos de 2 horas."},
    {"question": "¿Puedo jugar desde el celular?", "answer": "Sí, todas las plataformas están optimizadas para mobile. Podés jugar desde cualquier dispositivo sin necesidad de descargar nada."},
    {"question": "¿Es seguro depositar?", "answer": "Sí. Trabajamos solo con plataformas verificadas que utilizan protocolos de seguridad avanzados para proteger tus datos y fondos."},
    {"question": "¿Qué métodos de pago aceptan?", "answer": "Aceptamos transferencia bancaria, Mercado Pago y otros métodos según la plataforma. Consultá a tu asesor por las opciones disponibles."},
    {"question": "¿Tienen soporte los fines de semana?", "answer": "Sí, nuestro equipo de atención al cliente está disponible las 24 horas, los 7 días de la semana, incluyendo feriados."},
]


# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        # FIX BUG-10: enable FK enforcement (was disabled by default in sqlite3)
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS casinos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            position INTEGER NOT NULL,
            icon TEXT NOT NULL,
            name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS casino_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            casino_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            url TEXT NOT NULL,
            FOREIGN KEY(casino_id) REFERENCES casinos(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS faqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            position INTEGER NOT NULL,
            question TEXT NOT NULL,
            answer TEXT NOT NULL
        );
        """
    )
    db.commit()
    ensure_defaults(db)
    ensure_admin(db)


def ensure_defaults(db: sqlite3.Connection) -> None:
    if db.execute("SELECT COUNT(*) AS c FROM settings").fetchone()["c"] == 0:
        db.executemany(
            "INSERT INTO settings(key, value) VALUES(?, ?)",
            list(DEFAULT_SETTINGS.items()),
        )

    if db.execute("SELECT COUNT(*) AS c FROM casinos").fetchone()["c"] == 0:
        for idx, casino in enumerate(DEFAULT_CASINOS, start=1):
            cur = db.execute(
                "INSERT INTO casinos(position, icon, name) VALUES(?, ?, ?)",
                (idx, casino["icon"], casino["name"]),
            )
            for link_idx, link in enumerate(casino["links"], start=1):
                db.execute(
                    "INSERT INTO casino_links(casino_id, position, url) VALUES(?, ?, ?)",
                    (cur.lastrowid, link_idx, link),
                )

    if db.execute("SELECT COUNT(*) AS c FROM faqs").fetchone()["c"] == 0:
        for idx, faq in enumerate(DEFAULT_FAQS, start=1):
            db.execute(
                "INSERT INTO faqs(position, question, answer) VALUES(?, ?, ?)",
                (idx, faq["question"], faq["answer"]),
            )

    db.commit()


def ensure_admin(db: sqlite3.Connection) -> None:
    if db.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"] > 0:
        return
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    db.execute(
        "INSERT INTO admins(username, password_hash) VALUES(?, ?)",
        (username, generate_password_hash(password)),
    )
    db.commit()
    # FIX BUG-3: use logger instead of print so the password doesn't
    # appear in plain stdout in production server logs.
    logger.info("=== ADMIN INICIAL CREADO ===")
    logger.info("Usuario: %s", username)
    logger.info("Contraseña: %s", password)
    logger.info("Guarda estas credenciales y cámbialas después de entrar.")


def get_site_data() -> tuple:
    db = get_db()
    settings = {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM settings").fetchall()}

    casinos = []
    for row in db.execute("SELECT id, icon, name FROM casinos ORDER BY position ASC, id ASC").fetchall():
        links = db.execute(
            "SELECT url FROM casino_links WHERE casino_id = ? ORDER BY position ASC, id ASC",
            (row["id"],),
        ).fetchall()
        casinos.append({"id": row["id"], "icon": row["icon"], "name": row["name"], "links": [l["url"] for l in links]})

    faqs = [
        {"id": row["id"], "question": row["question"], "answer": row["answer"]}
        for row in db.execute("SELECT id, question, answer FROM faqs ORDER BY position ASC, id ASC").fetchall()
    ]

    # Build wa_url fresh every time (never stored in DB to avoid stale values)
    settings["wa_url"] = f"https://wa.me/{settings.get('phone', DEFAULT_SETTINGS['phone'])}"
    return settings, casinos, faqs, DEFAULT_TESTIMONIALS


# ── Validation helpers ────────────────────────────────────────────────────────
def validate_text(value, max_length: int = 300, allow_empty: bool = False) -> str:
    value = (value or "").strip()
    if not value and not allow_empty:
        raise ValueError("Hay campos obligatorios vacíos.")
    if len(value) > max_length:
        raise ValueError(f"Un campo supera el máximo permitido de {max_length} caracteres.")
    return value


def normalize_phone(value) -> str:
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if len(digits) < 10 or len(digits) > 20:
        raise ValueError("El número de WhatsApp no es válido (mínimo 10 dígitos).")
    return digits


def validate_url(value) -> str:
    value = (value or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Todos los enlaces deben usar https:// y tener un dominio válido.")
    if len(value) > 500:
        raise ValueError("Uno de los enlaces es demasiado largo.")
    return value


# ── CSRF ──────────────────────────────────────────────────────────────────────
def generate_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not form_token or not secrets.compare_digest(form_token, session_token):
        abort(400, description="Token CSRF inválido.")


# ── Auth & rate-limit ─────────────────────────────────────────────────────────
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


def get_client_ip() -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    recent = [ts for ts in LOGIN_ATTEMPTS.get(ip, []) if now - ts < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = recent
    return len(recent) >= LOGIN_MAX_ATTEMPTS


def register_login_failure(ip: str) -> None:
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def clear_login_failures(ip: str) -> None:
    LOGIN_ATTEMPTS.pop(ip, None)


# ── Template context & security headers ──────────────────────────────────────
@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token()}


@app.after_request
def add_security_headers(response):
    csp = "; ".join([
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        "script-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests",
    ])
    response.headers["Content-Security-Policy"] = csp
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response


# ── Public routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    settings, casinos, faqs, testimonials = get_site_data()
    return render_template(
        "index.html",
        settings=settings,
        casinos=casinos,
        faqs=faqs,
        testimonials=testimonials,
    )


# ── Admin routes ──────────────────────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()

        if is_rate_limited(ip):
            flash("Demasiados intentos fallidos. Esperá unos minutos e intentalo de nuevo.", "error")
            return render_template("admin_login.html")

        # FIX BUG-1 & BUG-5: wrap validate_text in try/except so an empty
        # username field returns a flash message instead of an unhandled 500.
        try:
            username = validate_text(request.form.get("username"), max_length=80)
        except ValueError:
            register_login_failure(ip)
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("admin_login.html")

        password = request.form.get("password", "")

        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if not admin or not check_password_hash(admin["password_hash"], password):
            register_login_failure(ip)
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("admin_login.html")

        clear_login_failures(ip)
        session.clear()
        session["admin_id"] = admin["id"]
        session["admin_username"] = admin["username"]
        session["csrf_token"] = secrets.token_hex(32)
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    validate_csrf()
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    settings, casinos, faqs, _testimonials = get_site_data()
    return render_template(
        "admin_dashboard.html",
        settings=settings,
        casinos=casinos,
        faqs=faqs,
        admin_username=session.get("admin_username"),
    )


@app.route("/admin/save-content", methods=["POST"])
@login_required
def admin_save_content():
    validate_csrf()
    db = get_db()
    try:
        payload = {
            "site_title":        validate_text(request.form.get("site_title"), 120),
            "meta_description":  validate_text(request.form.get("meta_description"), 220),
            "phone":             normalize_phone(request.form.get("phone")),
            "logo":              validate_text(request.form.get("logo"), 80),
            "hero_badge":        validate_text(request.form.get("hero_badge"), 120),
            "hero_title":        validate_text(request.form.get("hero_title"), 160),
            "hero_sub":          validate_text(request.form.get("hero_sub"), 180),
            "hero_bonus":        validate_text(request.form.get("hero_bonus"), 160),
            "stat_platforms":    validate_text(request.form.get("stat_platforms"), 20),
            "stat_support":      validate_text(request.form.get("stat_support"), 20),
            "stat_withdrawal":   validate_text(request.form.get("stat_withdrawal"), 30),
            "stat_bonus":        validate_text(request.form.get("stat_bonus"), 20),
            "promo_tag":         validate_text(request.form.get("promo_tag"), 80),
            "promo_title":       validate_text(request.form.get("promo_title"), 120),
            "promo_amount":      validate_text(request.form.get("promo_amount"), 30),
            "promo_sub":         validate_text(request.form.get("promo_sub"), 180),
            "promo_slot":        validate_text(request.form.get("promo_slot"), 30),
            "promo_withdraw_min":validate_text(request.form.get("promo_withdraw_min"), 30),
            "promo_withdraw_max":validate_text(request.form.get("promo_withdraw_max"), 30),
            "promo_cta":         validate_text(request.form.get("promo_cta"), 80),
        }

        casino_icons  = request.form.getlist("casino_icon[]")
        casino_names  = request.form.getlist("casino_name[]")
        casino_links  = request.form.getlist("casino_links[]")

        if not casino_names:
            raise ValueError("Debe existir al menos una plataforma.")
        if not (len(casino_icons) == len(casino_names) == len(casino_links)):
            raise ValueError("Los datos de plataformas están incompletos.")

        casinos = []
        for idx, (icon, name, links_blob) in enumerate(zip(casino_icons, casino_names, casino_links), start=1):
            icon  = validate_text(icon, 10)
            name  = validate_text(name, 80)
            links = [validate_url(line) for line in links_blob.splitlines() if line.strip()]
            if not links:
                raise ValueError("Cada plataforma debe tener al menos un enlace válido.")
            casinos.append({"position": idx, "icon": icon, "name": name, "links": links})

        faq_questions = request.form.getlist("faq_question[]")
        faq_answers   = request.form.getlist("faq_answer[]")
        if not faq_questions:
            raise ValueError("Debe existir al menos una pregunta frecuente.")
        if len(faq_questions) != len(faq_answers):
            raise ValueError("Las preguntas frecuentes están incompletas.")

        faqs = [
            {
                "position": idx,
                "question": validate_text(q, 180),
                "answer":   validate_text(a, 700),
            }
            for idx, (q, a) in enumerate(zip(faq_questions, faq_answers), start=1)
        ]

        with db:
            for key, value in payload.items():
                db.execute("REPLACE INTO settings(key, value) VALUES(?, ?)", (key, value))

            # FIX BUG-10 note: FK enforcement is ON so order matters —
            # casino_links must be deleted before casinos (already correct).
            db.execute("DELETE FROM casino_links")
            db.execute("DELETE FROM casinos")
            for casino in casinos:
                cur = db.execute(
                    "INSERT INTO casinos(position, icon, name) VALUES(?, ?, ?)",
                    (casino["position"], casino["icon"], casino["name"]),
                )
                for link_idx, link in enumerate(casino["links"], start=1):
                    db.execute(
                        "INSERT INTO casino_links(casino_id, position, url) VALUES(?, ?, ?)",
                        (cur.lastrowid, link_idx, link),
                    )

            db.execute("DELETE FROM faqs")
            for faq in faqs:
                db.execute(
                    "INSERT INTO faqs(position, question, answer) VALUES(?, ?, ?)",
                    (faq["position"], faq["question"], faq["answer"]),
                )

        flash("Contenido actualizado correctamente.", "success")

    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/change-credentials", methods=["POST"])
@login_required
def admin_change_credentials():
    validate_csrf()
    db = get_db()
    try:
        current_password = request.form.get("current_password", "")
        new_username     = validate_text(request.form.get("new_username"), 80)
        new_password     = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        admin = db.execute("SELECT * FROM admins WHERE id = ?", (session["admin_id"],)).fetchone()
        if not admin or not check_password_hash(admin["password_hash"], current_password):
            raise ValueError("La contraseña actual no es correcta.")
        if len(new_password) < 12:
            raise ValueError("La nueva contraseña debe tener al menos 12 caracteres.")
        if new_password != confirm_password:
            raise ValueError("La nueva contraseña y la confirmación no coinciden.")

        existing = db.execute(
            "SELECT id FROM admins WHERE username = ? AND id != ?",
            (new_username, session["admin_id"]),
        ).fetchone()
        if existing:
            raise ValueError("Ese nombre de usuario ya está en uso.")

        with db:
            db.execute(
                "UPDATE admins SET username = ?, password_hash = ? WHERE id = ?",
                (new_username, generate_password_hash(new_password), session["admin_id"]),
            )
        session["admin_username"] = new_username
        flash("Credenciales actualizadas correctamente.", "success")

    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(url_for("admin_dashboard"))


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Solicitud inválida.")), 400


@app.errorhandler(413)
def request_too_large(_error):
    return render_template("error.html", code=413, message="La solicitud es demasiado grande."), 413


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="La página que buscas no existe."), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", code=500, message="Ha ocurrido un error interno."), 500


# ── Bootstrap ─────────────────────────────────────────────────────────────────
with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
