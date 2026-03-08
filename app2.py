"""
app2.py
Flask application factory – konfigurace, inicializace a bootstrapping.
Všechny routes jsou v routes/ package.
Sdílené konstanty (VAPID, ACHIEVEMENTS, emaily) jsou v config.py.
"""
from __future__ import annotations
import base64
import os
from datetime import datetime, timedelta
from typing import Optional

from flask import Flask, Response, jsonify, redirect, url_for
from sqlalchemy.exc import OperationalError, IntegrityError

from config import (
    OWNER_ADMIN_EMAIL,
    SECRET_USER_EMAIL,
    VAPID_PRIVATE_KEY,
    VAPID_PUBLIC_KEY,
    VAPID_CLAIMS,
    ACHIEVEMENTS,
)
from extensions import db, login_manager, csrf
from models import (
    User, Sport, Round, Team, TeamAlias, Match, Tip,
    RoundUserScore, ImportSession, ExtraQuestion, ExtraAnswer,
    Achievement, UndoStack, PushSubscription, NotificationPreferences,
    AuditLog, APISource, APIImportLog, MatchAPIMapping,
)
from routes import register_all_routes


# =========================================================
# PWA FALLBACK ROUTES
# =========================================================

_TRANSPARENT_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO0H2p0AAAAASUVORK5CYII="
)


def ensure_pwa_routes(app: Flask) -> None:
    """Zajistí že /service-worker.js, /manifest.json a /pwa-icon/<size>
    vždy existují – zabrání 404 na Android/PWA i po refaktoringu routes."""
    endpoints = set(app.view_functions.keys())

    if "service_worker" not in endpoints:
        def _service_worker_fallback():
            sw = (
                "self.addEventListener('install',e=>self.skipWaiting());"
                "self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));"
                "self.addEventListener('fetch',()=>{});"
            )
            return Response(sw, mimetype="application/javascript")
        app.add_url_rule("/service-worker.js", endpoint="service_worker",
                         view_func=_service_worker_fallback)

    if "pwa_manifest" not in endpoints:
        def _manifest_fallback():
            return jsonify({
                "name": "Tipovačka", "short_name": "Tipovačka",
                "start_url": "/", "display": "standalone",
                "background_color": "#0b1020", "theme_color": "#0b1020",
                "icons": [
                    {"src": "/pwa-icon/192", "sizes": "192x192", "type": "image/png"},
                    {"src": "/pwa-icon/512", "sizes": "512x512", "type": "image/png"},
                ],
            })
        app.add_url_rule("/manifest.json", endpoint="pwa_manifest",
                         view_func=_manifest_fallback)

    if "pwa_icon" not in endpoints:
        def _pwa_icon_fallback(size: int):
            return Response(_TRANSPARENT_PNG, mimetype="image/png")
        app.add_url_rule("/pwa-icon/<int:size>", endpoint="pwa_icon",
                         view_func=_pwa_icon_fallback)


# =========================================================
# ROUTE ALIASES (trailing slash / legacy deep-links)
# =========================================================

def _install_route_aliases(app: Flask) -> None:
    """Přidá bezpečné redirect aliasy aby mobile/PWA deep-linky nedostaly 404."""

    def _redir(endpoint: str):
        return redirect(url_for(endpoint))

    existing_rules = {r.rule for r in app.url_map.iter_rules()}
    vf = app.view_functions

    if "notification_settings" in vf and "/notification-settings/" not in existing_rules:
        app.add_url_rule("/notification-settings/", endpoint="notification_settings_slash",
                         view_func=lambda: _redir("notification_settings"))

    if "leaderboard" in vf and "/leaderboard/" not in existing_rules:
        app.add_url_rule("/leaderboard/", endpoint="leaderboard_slash",
                         view_func=lambda: _redir("leaderboard"))

    if "home" in vf and "/home/" not in existing_rules:
        app.add_url_rule("/home/", endpoint="home_slash",
                         view_func=lambda: _redir("home"))

    if "home" in vf and "/" not in existing_rules:
        app.add_url_rule("/", endpoint="root",
                         view_func=lambda: _redir("home"))


# =========================================================
# DB SEEDING
# =========================================================

def seed_defaults_if_empty() -> None:
    """Vytvoří výchozí data (Sport + admin user) pokud je DB prázdná."""
    if Sport.query.count() == 0:
        db.session.add(Sport(name="Fotbal"))
        db.session.add(Sport(name="Hokej"))
        db.session.commit()

    if User.query.count() == 0:
        admin = User(
            email=OWNER_ADMIN_EMAIL,
            username="admin",
            is_admin=True,
            role="admin",
            email_verified=True,
        )
        admin.set_password("admin")  # ← po prvním přihlášení ZMĚNIT!
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Vytvořen výchozí admin účet: {OWNER_ADMIN_EMAIL}")

    # Zajisti že admin/owner mají ověřený email
    try:
        admin_users = User.query.filter(
            User.is_admin == True,
            User.email == (OWNER_ADMIN_EMAIL or "").lower()
        ).all()
        for u in admin_users:
            if not u.email_verified:
                u.email_verified = True
        if admin_users:
            db.session.commit()
    except Exception:
        db.session.rollback()


def ensure_sqlite_schema() -> None:
    """Přidá případně chybějící sloupce (SQLite nepodporuje ALTER TABLE IF NOT EXISTS)."""
    from sqlalchemy import text
    migrations = [
        ("users",   "verification_token",       "TEXT"),
        ("users",   "verification_token_expiry", "DATETIME"),
        ("users",   "email_verified",            "BOOLEAN DEFAULT 1"),
        ("users",   "reset_token",               "TEXT"),
        ("users",   "reset_token_expiry",        "DATETIME"),
        ("users",   "role",                      "TEXT DEFAULT 'user'"),
        ("users",   "first_name",                "TEXT"),
        ("users",   "last_name",                 "TEXT"),
        ("users",   "theme",                     "TEXT DEFAULT 'dark'"),
        ("users",   "language",                  "TEXT DEFAULT 'cs'"),
        ("teams",   "is_deleted",                "BOOLEAN DEFAULT 0"),
        ("teams",   "group",                     "TEXT"),
        ("teams",   "country_code",              "TEXT"),
        ("matches", "is_deleted",                "BOOLEAN DEFAULT 0"),
        ("matches", "start_time",                "DATETIME"),
        ("rounds",  "tips_locked",               "BOOLEAN DEFAULT 0"),
        ("rounds",  "extras_locked",             "BOOLEAN DEFAULT 0"),
        ("rounds",  "tips_deadline",             "DATETIME"),
        ("rounds",  "extras_deadline",           "DATETIME"),
        ("rounds",  "is_active",                 "BOOLEAN DEFAULT 1"),
        ("rounds",  "points_exact",              "INTEGER DEFAULT 3"),
        ("rounds",  "points_winner",             "INTEGER DEFAULT 1"),
    ]
    with db.engine.connect() as conn:
        for table, col, col_type in migrations:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                conn.commit()
            except Exception:
                pass  # Sloupec už existuje – OK


# =========================================================
# DB INIT (bezpečné pro více gunicorn workers)
# =========================================================

def _init_db_once(app: Flask) -> None:
    """Inicializuje DB schéma právě jednou. Brání race condition mezi workery."""
    instance_path = app.instance_path
    os.makedirs(instance_path, exist_ok=True)
    done_path = os.path.join(instance_path, ".db_init_done")
    lock_path = os.path.join(instance_path, ".db_init_lock")

    if os.path.exists(done_path):
        return

    # Odstraň zastaralý zámek (starší než 10 minut)
    try:
        if os.path.exists(lock_path):
            if (datetime.utcnow().timestamp() - os.path.getmtime(lock_path)) > 600:
                os.remove(lock_path)
    except Exception:
        pass

    # Atomicky získej zámek
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return  # Jiný worker inicializuje
    except Exception:
        fd = None

    try:
        with app.app_context():
            try:
                db.create_all()
            except OperationalError as e:
                if "already exists" not in str(e).lower():
                    raise

            try:
                ensure_sqlite_schema()
            except Exception:
                pass

            try:
                seed_defaults_if_empty()
            except IntegrityError:
                db.session.rollback()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass

        try:
            with open(done_path, "w", encoding="utf-8") as f:
                f.write(datetime.utcnow().isoformat() + "Z")
        except Exception:
            pass
    finally:
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass
        try:
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception:
            pass


# =========================================================
# LOGIN LOADER
# =========================================================

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        uid = int(user_id)
    except Exception:
        return None
    return db.session.get(User, uid)


# =========================================================
# APP FACTORY
# =========================================================

def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    # Bezpečnost
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(app.instance_path, "tipovacka.db")
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Session
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS na Koyeb
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)

    # CSRF
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_TIME_LIMIT"] = None
    app.config["WTF_CSRF_SSL_STRICT"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = True

    # Inicializace rozšíření
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    csrf.init_app(app)

    # Routes
    register_all_routes(app)

    # PWA fallbacky + aliasy
    ensure_pwa_routes(app)
    _install_route_aliases(app)

    # DB init (jednou po startu)
    _init_db_once(app)

    return app


# =========================================================
# WSGI entry point (Gunicorn: gunicorn app2:app)
# =========================================================

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
