# app_tipovacka3_all_1_8.py
from __future__ import annotations
import base64

import io
import json
import os
import re
from datetime import datetime, timedelta

# OCR support (optional - install with: pip install pytesseract pillow)
try:
    from PIL import Image
    import pytesseract
    import io
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    print("⚠️ Tesseract OCR not available - install with: pip install pytesseract pillow")
from typing import Optional
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy.exc import OperationalError, IntegrityError
from routes import register_all_routes

# BODY 1–8 (v jedné verzi)
# 1) Login/registrace + admin role
# 2) Přepínač soutěže (globální dropdown)
# 3) Správa soutěží (sport, aktivace, uzávěrky tipů/extra)
# 4) Týmy per soutěž + tabulka/standing
# 5) Zápasy (admin CRUD) + tipování + bodování
# 6) Extra otázky + odpovědi + uzávěrka
# 7) Exporty CSV (žebříček, zápasy, týmy, extra)
# 8) Hromadný import CSV (týmy, zápasy s round/round_id, extra) + audit log

# KONFIG (uprav si jen tyhle dvě položky)
OWNER_ADMIN_EMAIL = "3049@email.cz"          # owner (jen ty) – vidí tajného usera, má plná práva
SECRET_USER_EMAIL = "kubamartinec97@gmail.com"          # tajný user (skrytý v admin přehledu pro
# PWA ROUTES GUARARD (avoid 404 on Android / PWA)

# 1x1 transparent PNG
_TRANSPARENT_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO0H2p0AAAAASUVORK5CYII="
)

def ensure_pwa_routes(app: Flask) -> None:
    """Ensure critical PWA endpoints exist even if some route blocks were refactored.
    Prevents Android push from failing due to missing /service-worker.js or /manifest.json.
    """
    from flask import Response, jsonify, redirect

    endpoints = set(app.view_functions.keys())

    if "service_worker" not in endpoints:
        def _service_worker_fallback():
            sw_code = """// Minimal SW fallback (Tipovacka)
self.addEventListener('install', (event) => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', (event) => { /* network-first */ });
"""
            return Response(sw_code, mimetype="application/javascript")
        app.add_url_rule("/service-worker.js", endpoint="service_worker", view_func=_service_worker_fallback)

    if "pwa_manifest" not in endpoints:
        def _manifest_fallback():
            return jsonify({
                "name": "Tipovačka",
                "short_name": "Tipovačka",
                "start_url": "/",
                "display": "standalone",
                "background_color": "#0b1020",
                "theme_color": "#0b1020",
                "icons": [
                    {"src": "/pwa-icon/192", "sizes": "192x192", "type": "image/png"},
                    {"src": "/pwa-icon/512", "sizes": "512x512", "type": "image/png"}
                ]
            })
        app.add_url_rule("/manifest.json", endpoint="pwa_manifest", view_func=_manifest_fallback)

    if "pwa_icon" not in endpoints:
        def _pwa_icon_fallback(size: int):
            # Return tiny placeholder; browser will still accept manifest.
            return Response(_TRANSPARENT_PNG, mimetype="image/png")
        app.add_url_rule("/pwa-icon/<int:size>", endpoint="pwa_icon", view_func=_pwa_icon_fallback)

# APP + EXTENSIONS
from extensions import db, login_manager, csrf
from app_utils import (
    validate_password, get_email_config,
    send_email, send_email_with_attachment,
    send_verification_email, send_password_reset_email,
    send_welcome_email_for_imported_user, send_welcome_with_reset_link,
    now_utc, parse_naive_datetime, dt_to_input_value,
    admin_required, moderator_required, owner_required, can_see_user_in_admin,
    audit, create_undo_point, perform_undo,
    send_push_notification, send_push_to_all, get_notification_preferences,
    send_results_notification, send_deadline_reminder,
    send_achievement_notification, send_leaderboard_change_notification,
    send_new_round_notification,
    get_selected_round_id, set_selected_round_id,
    get_rounds_for_switch, ensure_selected_round,
    is_tips_locked, is_extras_locked,
    check_and_award_achievements, get_user_achievements,
    calc_points_for_tip, recompute_round_user_score,
    recompute_round_scores, get_cached_round_score,
    csv_response, binary_response,
)
from api_parsers import (
    fetch_nhl_games, fetch_football_games,
    fetch_thesportsdb_games, fetch_uefa_ucl_all_fixtures,
    fetch_api_games, import_matches_from_api, import_results_from_api,
)

def _init_db_once(app: Flask) -> None:
    """
    Initialize DB schema exactly once per deploy/start.
    This prevents concurrent gunicorn workers from racing on db.create_all()/seeding.
    Uses an atomic lock file in instance_path.
    """
    instance_path = app.instance_path
    os.makedirs(instance_path, exist_ok=True)

    done_path = os.path.join(instance_path, ".db_init_done")
    lock_path = os.path.join(instance_path, ".db_init_lock")

    # If already initialized, do nothing
    if os.path.exists(done_path):
        return

    # If lock exists and is stale (older than 10 minutes), remove it
    try:
        if os.path.exists(lock_path):
            mtime = os.path.getmtime(lock_path)
            if (datetime.utcnow().timestamp() - mtime) > 600:
                try:
                    os.remove(lock_path)
                except Exception:
                    pass
    except Exception:
        pass

    # Try to acquire lock atomically
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        # Another worker is initializing; skip
        return
    except Exception:
        # If we cannot lock for any reason, fall back to best-effort init (guarded)
        fd = None

    try:
        with app.app_context():
            try:
                db.create_all()
            except OperationalError as e:
                # Common when two processes race or table already exists.
                msg = str(e).lower()
                if "already exists" not in msg:
                    raise

            # Keep existing idempotent init steps
            try:
                ensure_sqlite_schema()
            except Exception:
                # keep app booting; schema helper should be idempotent
                pass

            try:
                seed_defaults_if_empty()
            except IntegrityError:
                # In case of race on first seed, ignore unique constraint conflicts
                db.session.rollback()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass

        # Mark done
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

# ROUTE ALIASES (prevents 404 on trailing slashes / renamed endpoints)

def _install_route_aliases(app: Flask) -> None:
    """Install a few safe redirect aliases so mobile/PWA deep-links don't 404."""

    def _redir(to_endpoint: str):
        return redirect(url_for(to_endpoint))

    # Notification settings sometimes linked with trailing slash
    if 'notification_settings' in app.view_functions and '/notification-settings/' not in {r.rule for r in app.url_map.iter_rules()}:
        app.add_url_rule('/notification-settings/', endpoint='notification_settings_slash', view_func=lambda: _redir('notification_settings'))

    # Leaderboard with trailing slash
    if 'leaderboard' in app.view_functions and '/leaderboard/' not in {r.rule for r in app.url_map.iter_rules()}:
        app.add_url_rule('/leaderboard/', endpoint='leaderboard_slash', view_func=lambda: _redir('leaderboard'))

    # Home with trailing slash
    if 'home' in app.view_functions and '/home/' not in {r.rule for r in app.url_map.iter_rules()}:
        app.add_url_rule('/home/', endpoint='home_slash', view_func=lambda: _redir('home'))

    # Root index sometimes expected
    if 'home' in app.view_functions and '/' not in {r.rule for r in app.url_map.iter_rules()}:
        app.add_url_rule('/', endpoint='root', view_func=lambda: _redir('home'))

def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    os.makedirs(app.instance_path, exist_ok=True)
    
    # Security Configuration
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "tipovacka.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Session Security
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS na produkci (Koyeb)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
    
    # CSRF Configuration
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_TIME_LIMIT"] = None  # Token nevyprší
    app.config["WTF_CSRF_SSL_STRICT"] = False  # Pro reverse proxy
    app.config["WTF_CSRF_CHECK_DEFAULT"] = True

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    csrf.init_app(app)

    register_all_routes(app)

    ensure_pwa_routes(app)
    # --- Route aliases for mobile/deeplinks (trailing slash / legacy paths) ---
    _install_route_aliases(app)

    _init_db_once(app)

    return app

# MODELY
from models import (
    User, Sport, Round, Team, TeamAlias, Match, Tip,
    RoundUserScore, ImportSession, ExtraQuestion, ExtraAnswer,
    Achievement, UndoStack, PushSubscription, NotificationPreferences,
    AuditLog, APISource, APIImportLog, MatchAPIMapping
)
# LOGIN LOADER
# PASSWORD VALIDATION

# EMAIL SYSTEM

# USER LOADER
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        uid = int(user_id)
    except Exception:
        return None
    return db.session.get(User, uid)

# HELPERS

# UNDO/REDO SYSTEM
import json

# PUSH NOTIFICATIONS

# VAPID klíče (vygenerované jednou pro aplikaci)
# V produkci dej do environment variables!
VAPID_PRIVATE_KEY = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzhjWVNJc2R4aDhXenMrSWgKd0N5THoyTk9ZQk1oK3BBbFhKNy9SWE0yYmZxaFJBTkNBQVR4M2NORjZ0Q215KzloVEtzekQ2bUxCK3RtREhlTwp1YTZBRHF5SFhYRnB4enk3bkJzNFk5dHFEUnVGN1Z0c3orKzFQdFRaanl0WnpkZlRodk1TWGNUZQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg"
VAPID_PUBLIC_KEY = "BPHdw0Xq0KbL72FMqzMPqYsH62YMd465roAOrIddcWnHPLucGzhj22oNG4XtW2zP77U-1NmPK1nN19OG8xJdxN4"
VAPID_CLAIMS = {"sub": "mailto:admin@tipovacka.cz"}

# ACHIEVEMENTY / ODZNAKY

ACHIEVEMENTS = {
    'first_tip': {
        'name': 'První krev',
        'icon': '🎯',
        'description': 'Zadal jsi svůj první tip',
        'color': '#6ea8fe'
    },
    'hattrick': {
        'name': 'Hattrick',
        'icon': '🔥',
        'description': '3 přesné tipy po sobě',
        'color': '#ff6b6b'
    },
    'perfect_5': {
        'name': 'Pětka',
        'icon': '⭐',
        'description': '5 přesných tipů po sobě',
        'color': '#ffc107'
    },
    'sniper': {
        'name': 'Sniper',
        'icon': '🎯',
        'description': '10 přesných tipů po sobě',
        'color': '#ff4d6d'
    },
    'perfect_round': {
        'name': 'Perfekcionista',
        'icon': '💎',
        'description': 'Všechny tipy v kole přesné',
        'color': '#33d17a'
    },
    'top_tipper': {
        'name': 'Stratég',
        'icon': '👑',
        'description': 'Nejlepší tipér v kole',
        'color': '#ffd700'
    },
    'full_attendance': {
        'name': 'Věrný fanoušek',
        'icon': '💯',
        'description': '100% účast - tipoval jsi všechny zápasy',
        'color': '#33d17a'
    },
    'comeback_king': {
        'name': 'Comeback',
        'icon': '📈',
        'description': 'Posun o 3+ místa nahoru v žebříčku',
        'color': '#26a269'
    },
    'century': {
        'name': 'Stovka',
        'icon': '💯',
        'description': 'Získal jsi 100 bodů',
        'color': '#ffc107'
    },
    'half_century': {
        'name': 'Padesátka',
        'icon': '5️⃣0️⃣',
        'description': 'Získal jsi 50 bodů',
        'color': '#6ea8fe'
    },
    'nostradamus': {
        'name': 'Nostradamus',
        'icon': '🔮',
        'description': 'Tipoval jsi překvapení jako první (velký outsider)',
        'color': '#a78bfa'
    },
    'warrior': {
        'name': 'Warrior',
        'icon': '⚔️',
        'description': 'Účast ve 3+ soutěžích',
        'color': '#f97316'
    },
    'lucky_strike': {
        'name': 'Štěstí přeje připraveným',
        'icon': '🍀',
        'description': 'Správný tip na zápas s kurzem 5:1+',
        'color': '#10b981'
    },
    'underdog': {
        'name': 'Underdog',
        'icon': '🐕',
        'description': 'Top 3 s méně než 50% tipnutých zápasů',
        'color': '#8b5cf6'
    }
}

def _award_achievement(user_id: int, achievement_type: str, round_id: int = None):
    """Uděl achievement (pokud ho už nemá)"""
    existing = Achievement.query.filter_by(
        user_id=user_id,
        achievement_type=achievement_type,
        round_id=round_id
    ).first()
    
    if not existing:
        achievement = Achievement(
            user_id=user_id,
            achievement_type=achievement_type,
            round_id=round_id
        )
        db.session.add(achievement)
        db.session.commit()

# ACHIEVEMENTY / ODZNAKY

# UI (JEDEN BASE + inline stránky)

def _parse_uefa_day_header(line: str, default_year: int) -> Optional[datetime]:
    """
    Parses lines like:
      "Wednesday 25 February"
      "Wednesday 28 January 2026"
    Returns a date (datetime at 00:00) or None.
    """
    s = (line or "").strip()
    if not s:
        return None

    m = re.match(r"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s+(\d{1,2})\s+([A-Za-z]+)(?:\s+(\d{4}))?$", s)
    if not m:
        return None

    day = int(m.group(2))
    month_name = (m.group(3) or "").lower()
    year = int(m.group(4)) if m.group(4) else default_year
    month = _UEFA_MONTHS.get(month_name)
    if not month:
        return None
    try:
        return datetime(year, month, day)
    except Exception:
        return None

def _normalize_team_name(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip())

if __name__ == "__main__":
    # Production: Gunicorn starts the app via Procfile
    # Development: python app2.py
    # app.run(debug=True, host='0.0.0.0', port=5000)
    pass

if __name__ == "__main__":
    # Production: Gunicorn starts the app via Procfile
    # Development: python app2.py
    pass
