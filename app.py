import jsonpoken"] = token
    return token


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not form_token or not secrets.compare_digest(form_token, session_token):
        abort(400, description="Token CSRF inválido.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


def get_client_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown")


def is_rate_limited(ip):
    now = time.time()
    attempts = [ts for ts in LOGIN_ATTEMPTS.get(ip, []) if now - ts < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def register_login_failure(ip):
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def clear_login_failures(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token()}


@app.after_request
def add_security_headers(response):
    csp = "; ".join(
        [
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
        ]
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response


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


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()
        if is_rate_limited(ip):
            flash("Demasiados intentos fallidos. Espera unos minutos e inténtalo otra vez.", "error")
            return render_template("admin_login.html")

        username = validate_text(request.form.get("username"), max_length=80)
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
            "site_title": validate_text(request.form.get("site_title"), 120),
            "meta_description": validate_text(request.form.get("meta_description"), 220),
            "phone": normalize_phone(request.form.get("phone")),
            "logo": validate_text(request.form.get("logo"), 80),
            "hero_badge": validate_text(request.form.get("hero_badge"), 120),
            "hero_title": validate_text(request.form.get("hero_title"), 160),
            "hero_sub": validate_text(request.form.get("hero_sub"), 180),
            "hero_bonus": validate_text(request.form.get("hero_bonus"), 160),
            "stat_platforms": validate_text(request.form.get("stat_platforms"), 20),
            "stat_support": validate_text(request.form.get("stat_support"), 20),
            "stat_withdrawal": validate_text(request.form.get("stat_withdrawal"), 30),
            "stat_bonus": validate_text(request.form.get("stat_bonus"), 20),
            "promo_tag": validate_text(request.form.get("promo_tag"), 80),
            "promo_title": validate_text(request.form.get("promo_title"), 120),
            "promo_amount": validate_text(request.form.get("promo_amount"), 30),
            "promo_sub": validate_text(request.form.get("promo_sub"), 180),
            "promo_slot": validate_text(request.form.get("promo_slot"), 30),
            "promo_withdraw_min": validate_text(request.form.get("promo_withdraw_min"), 30),
            "promo_withdraw_max": validate_text(request.form.get("promo_withdraw_max"), 30),
            "promo_cta": validate_text(request.form.get("promo_cta"), 80),
        }

        casino_icons = request.form.getlist("casino_icon[]")
        casino_names = request.form.getlist("casino_name[]")
        casino_links = request.form.getlist("casino_links[]")
        if not casino_names:
            raise ValueError("Debe existir al menos una plataforma.")
        if not (len(casino_icons) == len(casino_names) == len(casino_links)):
            raise ValueError("Los datos de plataformas están incompletos.")

        casinos = []
        for idx, (icon, name, links_blob) in enumerate(zip(casino_icons, casino_names, casino_links), start=1):
            icon = validate_text(icon, 10)
            name = validate_text(name, 80)
            links = [validate_url(line) for line in links_blob.splitlines() if line.strip()]
            if not links:
                raise ValueError("Cada plataforma debe tener al menos un enlace válido.")
            casinos.append({"position": idx, "icon": icon, "name": name, "links": links})

        faq_questions = request.form.getlist("faq_question[]")
        faq_answers = request.form.getlist("faq_answer[]")
        if not faq_questions:
            raise ValueError("Debe existir al menos una pregunta frecuente.")
        if len(faq_questions) != len(faq_answers):
            raise ValueError("Las preguntas frecuentes están incompletas.")

        faqs = []
        for idx, (question, answer) in enumerate(zip(faq_questions, faq_answers), start=1):
            faqs.append(
                {
                    "position": idx,
                    "question": validate_text(question, 180),
                    "answer": validate_text(answer, 700),
                }
            )

        with db:
            for key, value in payload.items():
                db.execute("REPLACE INTO settings(key, value) VALUES(?, ?)", (key, value))

            db.execute("DELETE FROM casino_links")
            db.execute("DELETE FROM casinos")
            for casino in casinos:
                cur = db.execute(
                    "INSERT INTO casinos(position, icon, name) VALUES(?, ?, ?)",
                    (casino["position"], casino["icon"], casino["name"]),
                )
                casino_id = cur.lastrowid
                for link_idx, link in enumerate(casino["links"], start=1):
                    db.execute(
                        "INSERT INTO casino_links(casino_id, position, url) VALUES(?, ?, ?)",
                        (casino_id, link_idx, link),
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
        new_username = validate_text(request.form.get("new_username"), 80)
        new_password = request.form.get("new_password", "")
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


with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
