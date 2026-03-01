# app_tipovacka3_all_1_8.py
from __future__ import annotations
import base64

import csv
import io
import json
import os
import re
import hashlib
import secrets
import smtplib
import tempfile
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

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
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, IntegrityError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash

# =========================================================
# BODY 1–8 (v jedné verzi)
# 1) Login/registrace + admin role
# 2) Přepínač soutěže (globální dropdown)
# 3) Správa soutěží (sport, aktivace, uzávěrky tipů/extra)
# 4) Týmy per soutěž + tabulka/standing
# 5) Zápasy (admin CRUD) + tipování + bodování
# 6) Extra otázky + odpovědi + uzávěrka
# 7) Exporty CSV (žebříček, zápasy, týmy, extra)
# 8) Hromadný import CSV (týmy, zápasy s round/round_id, extra) + audit log
# =========================================================

# =========================================================
# KONFIG (uprav si jen tyhle dvě položky)
# =========================================================
OWNER_ADMIN_EMAIL = "3049@email.cz"          # owner (jen ty) – vidí tajného usera, má plná práva
SECRET_USER_EMAIL = "kubamartinec97@gmail.com"          # tajný user (skrytý v admin přehledu pro
# =========================================================
# PWA ROUTES GUARARD (avoid 404 on Android / PWA)
# =========================================================

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


# =========================================================
# APP + EXTENSIONS
# =========================================================
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
csrf = CSRFProtect()


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



# =========================================================
# ROUTE ALIASES (prevents 404 on trailing slashes / renamed endpoints)
# =========================================================

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
    csrf.init_app(app)

    register_routes(app)

    ensure_pwa_routes(app)
    # --- Route aliases for mobile/deeplinks (trailing slash / legacy paths) ---
    _install_route_aliases(app)

    _init_db_once(app)

    return app


# =========================================================
# MODELY
# =========================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(190), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Nová pole pro osobní údaje
    first_name = db.Column(db.String(100), nullable=True)  # Jméno
    last_name = db.Column(db.String(100), nullable=True)   # Příjmení
    nickname = db.Column(db.String(80), nullable=True)     # Nick pro zobrazení v žebříčku

    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    role = db.Column(db.String(20), nullable=False, default='user')  # user|viewer|moderator|admin
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Email verifikace
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(100), nullable=True, index=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)
    
    # Password reset
    reset_token = db.Column(db.String(100), nullable=True, index=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def display_name(self) -> str:
        """Jméno pro zobrazení v žebříčku a UI"""
        if self.nickname:
            return self.nickname
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        return self.username

    @property
    def full_name(self) -> str:
        """Celé jméno (jméno + příjmení)"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        if self.last_name:
            return self.last_name
        return self.username

    @property
    def effective_role(self) -> str:
        # backwards compatible: if is_admin column is True, treat as admin
        if getattr(self, "is_admin", False):
            return "admin"
        return (getattr(self, "role", "user") or "user")

    @property
    def is_admin_effective(self) -> bool:
        return self.effective_role == "admin"

    @property
    def is_moderator_effective(self) -> bool:
        return self.effective_role in ("admin", "moderator")

    @property
    def can_tip(self) -> bool:
        return self.effective_role in ("user", "moderator", "admin")

    @property
    def is_owner(self) -> bool:
        return (self.email or "").lower() == (OWNER_ADMIN_EMAIL or "").lower()



class Sport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)


class Round(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False, index=True)

    sport_id = db.Column(db.Integer, db.ForeignKey("sport.id"), nullable=False)
    sport = db.relationship("Sport", lazy=True)

    tips_close_time = db.Column(db.DateTime, nullable=True)
    extra_close_time = db.Column(db.DateTime, nullable=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_archived = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)

    name = db.Column(db.String(140), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("round_id", "name", name="uq_team_round_name"),)


class TeamAlias(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)

    alias = db.Column(db.String(140), nullable=False, index=True)
    canonical_name = db.Column(db.String(140), nullable=False, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("round_id", "alias", name="uq_team_alias_round_alias"),)



class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)

    home_team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False, index=True)
    away_team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False, index=True)
    home_team = db.relationship("Team", foreign_keys=[home_team_id], lazy=True)
    away_team = db.relationship("Team", foreign_keys=[away_team_id], lazy=True)

    start_time = db.Column(db.DateTime, nullable=True)

    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Tip(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)

    match_id = db.Column(db.Integer, db.ForeignKey("match.id"), nullable=False, index=True)
    match = db.relationship("Match", lazy=True)

    tip_home = db.Column(db.Integer, nullable=False)
    tip_away = db.Column(db.Integer, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("user_id", "match_id", name="uq_tip_user_match"),)



class RoundUserScore(db.Model):
    __tablename__ = "round_user_score"
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    points = db.Column(db.Integer, default=0, nullable=False)
    exact_count = db.Column(db.Integer, default=0, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("round_id", "user_id", name="uq_round_user_score"),)


class ImportSession(db.Model):
    __tablename__ = "import_session"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    kind = db.Column(db.String(50), default="smart_import_matches", nullable=False)
    payload_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)


class ExtraQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)

    question = db.Column(db.String(255), nullable=False)
    deadline = db.Column(db.DateTime, nullable=True)  # Datum do kdy můžou users odpovídat
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ExtraAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("extra_question.id"), nullable=False, index=True)
    question = db.relationship("ExtraQuestion", lazy=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)

    answer_text = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("question_id", "user_id", name="uq_extra_q_user"),)


class Achievement(db.Model):
    """Achievementy/Odznaky uživatelů"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    
    achievement_type = db.Column(db.String(50), nullable=False)  # např. "hattrick", "perfect_round"
    earned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=True)  # Volitelné - ke které soutěži
    
    __table_args__ = (db.UniqueConstraint("user_id", "achievement_type", "round_id", name="uq_user_achievement"),)


class UndoStack(db.Model):
    """Stack pro undo/redo operace - možnost vrátit změny"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    
    action_type = db.Column(db.String(50), nullable=False)  # 'update_score', 'delete_match', atd.
    entity_type = db.Column(db.String(50), nullable=False)  # 'Match', 'Round', 'Team'
    entity_id = db.Column(db.Integer, nullable=True)
    
    # JSON snapshot stavu před změnou
    before_state = db.Column(db.Text, nullable=True)
    
    description = db.Column(db.String(255), nullable=True)  # Popis pro UI
    
    is_undone = db.Column(db.Boolean, default=False)  # Už bylo vráceno?
    undone_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class PushSubscription(db.Model):
    """Push notification subscriptions pro Web Push API"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    
    # Push subscription data (JSON)
    endpoint = db.Column(db.Text, nullable=False)  # Push service endpoint
    p256dh = db.Column(db.Text, nullable=False)    # Encryption key
    auth = db.Column(db.Text, nullable=False)      # Auth secret
    
    # Metadata
    user_agent = db.Column(db.String(255), nullable=True)  # Browser info
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    
    # Preferences
    enabled = db.Column(db.Boolean, default=True)  # User can disable
    
    __table_args__ = (
        db.UniqueConstraint("user_id", "endpoint", name="uq_user_endpoint"),
    )


class NotificationPreferences(db.Model):
    """Nastavení notifikací pro uživatele - co chce dostávat"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True, unique=True)
    user = db.relationship("User", lazy=True)
    
    # Typy notifikací (TRUE = chce dostávat)
    notify_results = db.Column(db.Boolean, default=True)        # Výsledky zadány
    notify_deadline = db.Column(db.Boolean, default=True)       # Deadline za 1h
    notify_new_round = db.Column(db.Boolean, default=True)      # Nová soutěž
    notify_achievement = db.Column(db.Boolean, default=True)    # Achievement získán
    notify_leaderboard = db.Column(db.Boolean, default=False)   # Změna v žebříčku (OFF default)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    actor = db.relationship("User", lazy=True)

    action = db.Column(db.String(80), nullable=False)
    entity = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)

    details = db.Column(db.Text, nullable=True)


# =========================================================
# API IMPORT MODELS
# =========================================================
class APISource(db.Model):
    """Konfigurace API zdroje pro automatický import"""
    __tablename__ = 'api_source'
    
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)
    
    # Typ API
    api_type = db.Column(db.String(50), nullable=False)  # 'nhl', 'api-football', 'manual'
    
    # Konfigurace
    api_url = db.Column(db.String(500), nullable=True)  # Base URL nebo endpoint
    api_key = db.Column(db.String(200), nullable=True)  # API klíč (pokud třeba)
    league_id = db.Column(db.String(100), nullable=True)  # ID ligy v API (např. NHL season ID)
    
    # Nastavení
    auto_import_matches = db.Column(db.Boolean, default=False)  # Automaticky importovat zápasy?
    auto_import_results = db.Column(db.Boolean, default=False)  # Automaticky importovat výsledky?
    require_admin_approval = db.Column(db.Boolean, default=True)  # Vyžadovat potvrzení adminem?
    
    # Kontrola overtime/shootouts
    exclude_overtime = db.Column(db.Boolean, default=True)  # Ignorovat prodloužení/nájezdy?
    
    # Metadata
    is_active = db.Column(db.Boolean, default=True)
    last_import_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_by = db.relationship("User", lazy=True)


class APIImportLog(db.Model):
    """Log importů z API"""
    __tablename__ = 'api_import_log'
    
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("api_source.id"), nullable=False, index=True)
    source = db.relationship("APISource", lazy=True)
    
    # Typ importu
    import_type = db.Column(db.String(50), nullable=False)  # 'matches', 'results'
    
    # Status
    status = db.Column(db.String(50), nullable=False)  # 'pending', 'approved', 'rejected', 'completed', 'failed'
    
    # Data
    imported_count = db.Column(db.Integer, default=0)  # Kolik záznamů bylo importováno
    skipped_count = db.Column(db.Integer, default=0)  # Kolik bylo přeskočeno
    error_count = db.Column(db.Integer, default=0)  # Kolik chyb
    
    # Preview data (JSON)
    preview_data = db.Column(db.Text, nullable=True)  # JSON s daty k importu (před potvrzením)
    error_details = db.Column(db.Text, nullable=True)  # Detaily chyb
    
    # Admin akce
    approved_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    approved_by = db.relationship("User", foreign_keys=[approved_by_id], lazy=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)


class MatchAPIMapping(db.Model):
    """Mapování mezi našimi zápasy a API ID"""
    __tablename__ = 'match_api_mapping'
    
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey("match.id"), nullable=False, unique=True)
    match = db.relationship("Match", lazy=True)
    
    source_id = db.Column(db.Integer, db.ForeignKey("api_source.id"), nullable=False)
    source = db.relationship("APISource", lazy=True)
    
    # API identifikátory
    api_match_id = db.Column(db.String(100), nullable=False)  # ID zápasu v API
    api_home_team_id = db.Column(db.String(100), nullable=True)  # ID domácího týmu v API
    api_away_team_id = db.Column(db.String(100), nullable=True)  # ID hostujícího týmu v API
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint("source_id", "api_match_id", name="uq_source_api_match"),
    )


# =========================================================
# LOGIN LOADER
# =========================================================
# =========================================================
# PASSWORD VALIDATION
# =========================================================
def validate_password(password: str) -> Tuple[bool, str]:
    """
    Ověří sílu hesla podle bezpečnostní policy.
    
    Požadavky:
    - Minimálně 8 znaků
    - Alespoň jedno malé písmeno (a-z)
    - Alespoň jedno velké písmeno (A-Z)
    - Alespoň jedna číslice (0-9)
    
    Returns:
        (is_valid, error_message)
        Pokud je heslo v pořádku: (True, "OK")
        Pokud ne: (False, "důvod proč ne")
    """
    if len(password) < 8:
        return False, "Heslo musí mít alespoň 8 znaků"
    
    if not re.search(r"[a-z]", password):
        return False, "Heslo musí obsahovat alespoň jedno malé písmeno (a-z)"
    
    if not re.search(r"[A-Z]", password):
        return False, "Heslo musí obsahovat alespoň jedno velké písmeno (A-Z)"
    
    if not re.search(r"[0-9]", password):
        return False, "Heslo musí obsahovat alespoň jednu číslici (0-9)"
    
    return True, "OK"


# =========================================================
# EMAIL SYSTEM
# =========================================================

def get_email_config():
    """
    Vrátí konfiguraci pro email.
    Podporuje obě konvence názvů: MAIL_* (Flask-Mail) a SMTP_* (custom).
    """
    return {
        'SMTP_SERVER': os.environ.get('MAIL_SERVER') or os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
        'SMTP_PORT': int(os.environ.get('MAIL_PORT') or os.environ.get('SMTP_PORT', '587')),
        'SMTP_USERNAME': os.environ.get('MAIL_USERNAME') or os.environ.get('SMTP_USERNAME', ''),
        'SMTP_PASSWORD': os.environ.get('MAIL_PASSWORD') or os.environ.get('SMTP_PASSWORD', ''),
        'FROM_EMAIL': os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('FROM_EMAIL', 'noreply@tipovacka.cz'),
        'FROM_NAME': os.environ.get('FROM_NAME', 'Tipovačka'),
        'USE_TLS': os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
        'SEND_REAL_EMAILS': os.environ.get('SEND_REAL_EMAILS', 'false').lower() == 'true',
        'REQUIRE_EMAIL_VERIFICATION': os.environ.get('REQUIRE_EMAIL_VERIFICATION', 'true').lower() == 'true'
    }


def send_email(to_email: str, subject: str, html_body: str, text_body: str = None) -> bool:
    """
    Pošle email.
    
    Args:
        to_email: Příjemce
        subject: Předmět
        html_body: HTML verze emailu
        text_body: Plain text verze (volitelné)
    
    Returns:
        True pokud email odeslán, False pokud chyba
    """
    config = get_email_config()
    
    # Development mode - jen vypíše do console
    if not config['SEND_REAL_EMAILS']:
        print(f"\n{'='*60}")
        print(f"📧 EMAIL (Development Mode - neposílá se)")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"{'='*60}")
        print(html_body)
        print(f"{'='*60}\n")
        return True
    
    # Production mode - skutečně pošle email
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{config['FROM_NAME']} <{config['FROM_EMAIL']}>"
        msg['To'] = to_email
        
        # Text verze (fallback)
        if text_body:
            part1 = MIMEText(text_body, 'plain', 'utf-8')
            msg.attach(part1)
        
        # HTML verze
        part2 = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(part2)
        
        # Pošli email
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            if config.get('USE_TLS', True):  # Default True pro Gmail
                server.starttls()
            if config['SMTP_USERNAME'] and config['SMTP_PASSWORD']:
                server.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    
    except Exception as e:
        print(f"❌ Chyba při posílání emailu: {e}")
        return False


def send_email_with_attachment(to_email: str, subject: str, html_body: str, text_body: str,
                                 attachment_data: bytes, attachment_name: str) -> bool:
    """Pošle email s přílohou (např. backup databáze)"""
    
    config = get_email_config()
    
    # Development mode - jen vypsat do logu
    if not config['SEND_REAL_EMAILS']:
        print("\n" + "="*60)
        print("📧 EMAIL S PŘÍLOHOU (Development Mode - neposílá se)")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"Attachment: {attachment_name} ({len(attachment_data)} bytes = {len(attachment_data)/(1024*1024):.2f} MB)")
        print("="*60)
        print(html_body[:500] + "..." if len(html_body) > 500 else html_body)
        print("="*60 + "\n")
        return True
    
    # Production mode - poslat skutečně
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders
        
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = f"{config['FROM_NAME']} <{config['FROM_EMAIL']}>"
        msg['To'] = to_email
        
        # Text část
        if text_body:
            msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        
        # HTML část
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Příloha
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment_data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')
        msg.attach(part)
        
        # Odešli
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            if config.get('USE_TLS', True):  # Default True pro Gmail
                server.starttls()
            if config['SMTP_USERNAME'] and config['SMTP_PASSWORD']:
                server.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    
    except Exception as e:
        print(f"❌ Chyba při posílání emailu s přílohou: {e}")
        return False


def send_verification_email(user: User, base_url: str) -> bool:
    """Pošle potvrzovací email po registraci"""
    
    verification_url = f"{base_url}/verify-email/{user.verification_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Tipovačka</h1>
            </div>
            <div class="content">
                <h2>Vítej v Tipovačce!</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Děkujeme za registraci! Zbývá už jen potvrdit tvůj email.</p>
                <p style="text-align: center;">
                    <a href="{verification_url}" class="button">
                        ✅ Potvrdit email
                    </a>
                </p>
                <p>Nebo zkopíruj tento odkaz do prohlížeče:</p>
                <p style="font-size: 12px; word-break: break-all;">{verification_url}</p>
                <p><strong>Platnost:</strong> 24 hodin</p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože někdo zaregistroval účet s tvým emailem.</p>
                <p>Pokud to nebyl ty, můžeš tento email ignorovat.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Děkujeme za registraci! Zbývá už jen potvrdit tvůj email.
    
    Klikni na tento odkaz pro potvrzení:
    {verification_url}
    
    Platnost: 24 hodin
    
    Pokud tento email jsi nedostal ty, můžeš ho ignorovat.
    """
    
    return send_email(
        to_email=user.email,
        subject="Potvrď svůj email - Tipovačka",
        html_body=html,
        text_body=text
    )


def send_password_reset_email(user: User, base_url: str) -> bool:
    """Pošle email s odkazem na reset hesla"""
    
    reset_url = f"{base_url}/reset-password/{user.reset_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .warning {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Tipovačka</h1>
            </div>
            <div class="content">
                <h2>Reset hesla</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Dostal jsi tento email protože někdo požádal o reset hesla pro tvůj účet.</p>
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">
                        🔑 Nastavit nové heslo
                    </a>
                </p>
                <p>Nebo zkopíruj tento odkaz do prohlížeče:</p>
                <p style="font-size: 12px; word-break: break-all;">{reset_url}</p>
                <div class="warning">
                    <strong>⚠️ Důležité:</strong>
                    <ul>
                        <li>Odkaz je platný <strong>1 hodinu</strong></li>
                        <li>Pokud jsi o reset nepožádal, ignoruj tento email</li>
                        <li>Tvé heslo zůstane nezměněné dokud neklikneš na odkaz</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>Pokud jsi o reset hesla nepožádal, někdo možná zadal tvůj email omylem.</p>
                <p>Tvé heslo je v bezpečí - změní se pouze pokud klikneš na odkaz výše.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Reset hesla - Tipovačka
    
    Ahoj {user.display_name},
    
    Dostal jsi tento email protože někdo požádal o reset hesla pro tvůj účet.
    
    Klikni na tento odkaz pro nastavení nového hesla:
    {reset_url}
    
    ⚠️ DŮLEŽITÉ:
    - Odkaz je platný 1 hodinu
    - Pokud jsi o reset nepožádal, ignoruj tento email
    - Tvé heslo zůstane nezměněné dokud neklikneš na odkaz
    
    Pokud jsi o reset hesla nepožádal, někdo možná zadal tvůj email omylem.
    Tvé heslo je v bezpečí - změní se pouze pokud klikneš na odkaz výše.
    """
    
    return send_email(
        to_email=user.email,
        subject="Reset hesla - Tipovačka",
        html_body=html,
        text_body=text
    )


def send_welcome_email_for_imported_user(user: User, password: str, base_url: str) -> bool:
    """Pošle welcome email importovanému uživateli s přihlašovacími údaji"""
    
    change_password_url = f"{base_url}/change-password"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .credentials {{ 
                background: white; 
                padding: 20px; 
                border-left: 4px solid #6ea8fe;
                margin: 20px 0;
                font-family: monospace;
            }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .warning {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Vítej v Tipovačce!</h1>
            </div>
            <div class="content">
                <h2>Tvůj účet byl vytvořen</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Byl jsi přidán do tipovací soutěže! Tady jsou tvoje přihlašovací údaje:</p>
                
                <div class="credentials">
                    <strong>🔐 Přihlašovací údaje:</strong><br><br>
                    <strong>Email:</strong> {user.email}<br>
                    <strong>Username:</strong> {user.username}<br>
                    <strong>Heslo:</strong> {password}
                </div>
                
                <div class="warning">
                    <strong>⚠️ DOPORUČUJEME:</strong><br>
                    Po prvním přihlášení si <strong>změň heslo</strong> na vlastní!
                </div>
                
                <p style="text-align: center;">
                    <a href="{base_url}" class="button">
                        🎯 Přihlásit se
                    </a>
                </p>
                
                <p>Po přihlášení můžeš jít na <strong>Profil → Změnit heslo</strong> nebo klikni sem:</p>
                <p style="font-size: 12px; word-break: break-all;">{change_password_url}</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                
                <p style="font-size: 14px; color: #666;">
                    <strong>Jak začít:</strong><br>
                    1. Přihlaš se pomocí údajů výše<br>
                    2. Změň si heslo (doporučeno)<br>
                    3. Začni tipovat!
                </p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože tě admin přidal do tipovací soutěže.</p>
                <p>Pokud máš dotazy, kontaktuj admina.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Byl jsi přidán do tipovací soutěže! Tady jsou tvoje přihlašovací údaje:
    
    🔐 PŘIHLAŠOVACÍ ÚDAJE:
    Email: {user.email}
    Username: {user.username}
    Heslo: {password}
    
    ⚠️ DOPORUČUJEME:
    Po prvním přihlášení si změň heslo na vlastní!
    
    Přihlásit se: {base_url}
    Změnit heslo: {change_password_url}
    
    JAK ZAČÍT:
    1. Přihlaš se pomocí údajů výše
    2. Změň si heslo (doporučeno)
    3. Začni tipovat!
    
    Tento email jsi dostal protože tě admin přidal do tipovací soutěže.
    Pokud máš dotazy, kontaktuj admina.
    """
    
    return send_email(
        to_email=user.email,
        subject="Vítej v Tipovačce - Přihlašovací údaje",
        html_body=html,
        text_body=text
    )


def send_welcome_with_reset_link(user: User, base_url: str) -> bool:
    """
    Pošle welcome email s reset linkem pro nastavení hesla.
    
    Používá se po importu uživatelů - user dostane email
    s odkazem pro nastavení vlastního hesla (bez hesla v emailu).
    """
    # Vygeneruj reset token
    user.reset_token = secrets.token_urlsafe(32)
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=24)  # 24h platnost
    db.session.commit()
    
    reset_url = f"{base_url}/reset-password/{user.reset_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .credentials {{ 
                background: white; 
                padding: 20px; 
                border-left: 4px solid #6ea8fe;
                margin: 20px 0;
                font-family: monospace;
            }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .info {{ background: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Vítej v Tipovačce!</h1>
            </div>
            <div class="content">
                <h2>Byl jsi přidán do soutěže</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Byl jsi přidán do tipovací soutěže! Pro dokončení registrace si nastav vlastní heslo.</p>
                
                <div class="credentials">
                    <strong>🔐 Tvoje přihlašovací údaje:</strong><br><br>
                    <strong>Email:</strong> {user.email}<br>
                    <strong>Username:</strong> {user.username}<br>
                    <strong>Heslo:</strong> <em>Nastavíš si sám (viz níže)</em>
                </div>
                
                <div class="info">
                    <strong>🔑 KROK 1: Nastav si heslo</strong><br>
                    Klikni na tlačítko níže a nastav si vlastní heslo:
                </div>
                
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">
                        🔑 Nastavit heslo
                    </a>
                </p>
                
                <p style="font-size: 12px; word-break: break-all;">Nebo zkopíruj tento odkaz: {reset_url}</p>
                
                <div class="info">
                    <strong>⏰ Platnost:</strong> 24 hodin<br>
                    Po nastavení hesla se můžeš přihlásit a začít tipovat!
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                
                <p style="font-size: 14px; color: #666;">
                    <strong>Jak začít:</strong><br>
                    1. Klikni na "Nastavit heslo"<br>
                    2. Zadej si vlastní heslo (min. 8 znaků)<br>
                    3. Přihlaš se pomocí email/username a nového hesla<br>
                    4. Začni tipovat!
                </p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože tě admin přidal do tipovací soutěže.</p>
                <p>Pokud máš dotazy, kontaktuj admina.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Byl jsi přidán do tipovací soutěže!
    
    🔐 TVOJE PŘIHLAŠOVACÍ ÚDAJE:
    Email: {user.email}
    Username: {user.username}
    Heslo: Nastavíš si sám (viz níže)
    
    🔑 KROK 1: NASTAV SI HESLO
    Klikni na tento odkaz a nastav si vlastní heslo:
    {reset_url}
    
    ⏰ Platnost: 24 hodin
    
    JAK ZAČÍT:
    1. Klikni na odkaz výše
    2. Zadej si vlastní heslo (min. 8 znaků)
    3. Přihlaš se pomocí email/username a nového hesla
    4. Začni tipovat!
    
    Tento email jsi dostal protože tě admin přidal do tipovací soutěže.
    Pokud máš dotazy, kontaktuj admina.
    """
    
    return send_email(
        to_email=user.email,
        subject="Vítej v Tipovačce - Nastav si heslo",
        html_body=html,
        text_body=text
    )


# =========================================================
# USER LOADER
# =========================================================
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        uid = int(user_id)
    except Exception:
        return None
    return db.session.get(User, uid)


# =========================================================
# HELPERS
# =========================================================
def now_utc() -> datetime:
    """Returns current Czech local time (Europe/Prague) as naive datetime.

    The app stores match times as naive Czech time. Servers (Heroku/Koyeb) usually run in UTC,
    so using datetime.now() would incorrectly lock tips ~1h early/late depending on DST.
    """
    try:
        from zoneinfo import ZoneInfo
        cz = ZoneInfo("Europe/Prague")
        return datetime.now(cz).replace(tzinfo=None)
    except Exception:
        # Fallback: best-effort local time
        return datetime.now()


def parse_naive_datetime(s: str) -> Optional[datetime]:
    """Parse datetime from form input (Czech time)"""
    s = (s or "").strip()
    if not s:
        return None
    s = s.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            # Uložit přímo jako český čas (naive datetime)
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def dt_to_input_value(dt: Optional[datetime]) -> str:
    """Convert datetime to form display (Czech time)"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M")


def admin_required() -> None:
    if not current_user.is_authenticated or not getattr(current_user, 'is_admin_effective', False):
        abort(403)


def moderator_required() -> None:
    if not current_user.is_authenticated or not getattr(current_user, 'is_moderator_effective', False):
        abort(403)


def owner_required() -> None:
    if not current_user.is_authenticated or not current_user.is_owner:
        abort(403)


def can_see_user_in_admin(user: User) -> bool:
    if (user.email or "").lower() != (SECRET_USER_EMAIL or "").lower():
        return True
    return bool(current_user.is_authenticated and current_user.is_owner)


def audit(action: str, entity: str, entity_id: Optional[int] = None, **details: Any) -> None:
    try:
        payload = {k: v for k, v in details.items() if v is not None}
        db.session.add(
            AuditLog(
                actor_user_id=(current_user.id if current_user.is_authenticated else None),
                action=action,
                entity=entity,
                entity_id=entity_id,
                details=(str(payload)[:4000] if payload else None),
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()


# =========================================================
# UNDO/REDO SYSTEM
# =========================================================
import json

def create_undo_point(action_type: str, entity_type: str, entity_id: int, before_state: dict, description: str = None):
    """
    Vytvoř undo point pro možnost vrácení změny
    """
    if not current_user.is_authenticated:
        return
    
    try:
        undo = UndoStack(
            user_id=current_user.id,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            before_state=json.dumps(before_state) if before_state else None,
            description=description
        )
        db.session.add(undo)
        db.session.commit()
        return undo.id
    except Exception:
        db.session.rollback()
        return None


def perform_undo(undo_id: int) -> dict:
    """
    Vrať změnu zpět
    """
    undo = db.session.get(UndoStack, undo_id)
    
    if not undo:
        return {'success': False, 'message': 'Undo záznam nenalezen'}
    
    if undo.is_undone:
        return {'success': False, 'message': 'Tato akce už byla vrácena'}
    
    try:
        before = json.loads(undo.before_state) if undo.before_state else {}
        
        # Restore podle typu entity
        if undo.entity_type == 'Match':
            match = db.session.get(Match, undo.entity_id)
            if match:
                if 'home_score' in before:
                    match.home_score = before['home_score']
                if 'away_score' in before:
                    match.away_score = before['away_score']
        
        # Označ jako undone
        undo.is_undone = True
        undo.undone_at = datetime.utcnow()
        
        db.session.commit()
        
        audit("undo.perform", "UndoStack", undo.id, description=undo.description)
        
        return {
            'success': True,
            'message': f'✅ Změna vrácena: {undo.description or ""}',
            'entity_type': undo.entity_type,
            'entity_id': undo.entity_id
        }
    
    except Exception as e:
        db.session.rollback()
        return {
            'success': False,
            'message': f'Chyba při vracení: {str(e)}'
        }


# =========================================================
# PUSH NOTIFICATIONS
# =========================================================

# VAPID klíče (vygenerované jednou pro aplikaci)
# V produkci dej do environment variables!
VAPID_PRIVATE_KEY = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzhjWVNJc2R4aDhXenMrSWgKd0N5THoyTk9ZQk1oK3BBbFhKNy9SWE0yYmZxaFJBTkNBQVR4M2NORjZ0Q215KzloVEtzekQ2bUxCK3RtREhlTwp1YTZBRHF5SFhYRnB4enk3bkJzNFk5dHFEUnVGN1Z0c3orKzFQdFRaanl0WnpkZlRodk1TWGNUZQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg"
VAPID_PUBLIC_KEY = "BPHdw0Xq0KbL72FMqzMPqYsH62YMd465roAOrIddcWnHPLucGzhj22oNG4XtW2zP77U-1NmPK1nN19OG8xJdxN4"
VAPID_CLAIMS = {"sub": "mailto:admin@tipovacka.cz"}

def send_push_notification(user_id: int, title: str, body: str, data: dict = None, icon: str = "/static/icon-192.png"):
    """
    Pošle push notifikaci uživateli
    
    Args:
        user_id: ID uživatele
        title: Nadpis notifikace
        body: Text notifikace
        data: Extra data (URL kam otevřít, atd.)
        icon: Ikona notifikace
    """
    try:
        # Import pywebpush (lazy import aby nerozbil app pokud není nainstalováno)
        try:
            from pywebpush import webpush, WebPushException
        except ImportError:
            print("⚠️ pywebpush není nainstalováno - notifikace se nepošle")
            return False
        
        # Najdi všechny aktivní subscriptions pro uživatele
        subscriptions = PushSubscription.query.filter_by(
            user_id=user_id,
            enabled=True
        ).all()
        
        if not subscriptions:
            return False
        
        # Připrav payload
        payload = {
            "title": title,
            "body": body,
            "icon": icon,
            "badge": "/static/badge-96.png",
            "data": data or {}
        }
        
        sent_count = 0
        failed_subs = []
        
        # Pošli na všechny zařízení uživatele
        for sub in subscriptions:
            try:
                subscription_info = {
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": sub.p256dh,
                        "auth": sub.auth
                    }
                }
                
                webpush(
                    subscription_info=subscription_info,
                    data=json.dumps(payload),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims=VAPID_CLAIMS
                )
                
                # Update last_used_at
                sub.last_used_at = datetime.utcnow()
                sent_count += 1
                
            except WebPushException as e:
                print(f"Push failed for sub {sub.id}: {e}")
                # Pokud je subscription invalid (410), smaž ji
                if e.response and e.response.status_code == 410:
                    failed_subs.append(sub)
        
        # Smaž failed subscriptions
        for sub in failed_subs:
            db.session.delete(sub)
        
        db.session.commit()
        
        return sent_count > 0
        
    except Exception as e:
        print(f"Error sending push: {e}")
        return False


def send_push_to_all(title: str, body: str, data: dict = None):
    """
    Pošle notifikaci VŠEM uživatelům
    """
    users = User.query.all()
    sent = 0
    for user in users:
        if send_push_notification(user.id, title, body, data):
            sent += 1
    return sent


def get_notification_preferences(user_id: int):
    """
    Získá nastavení notifikací pro uživatele
    Pokud neexistuje, vytvoř s výchozími hodnotami
    """
    prefs = NotificationPreferences.query.filter_by(user_id=user_id).first()
    
    if not prefs:
        # Vytvoř výchozí nastavení
        prefs = NotificationPreferences(
            user_id=user_id,
            notify_results=True,
            notify_deadline=True,
            notify_new_round=True,
            notify_achievement=True,
            notify_leaderboard=False
        )
        db.session.add(prefs)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            # Vrať výchozí hodnoty i když se neuložilo
            class DefaultPrefs:
                notify_results = True
                notify_deadline = True
                notify_new_round = True
                notify_achievement = True
                notify_leaderboard = False
            return DefaultPrefs()
    
    return prefs


def send_results_notification(round_id: int):
    """
    Pošle notifikaci o zadaných výsledcích
    Personalizované - každý uživatel dostane svoje body
    """
    r = db.session.get(Round, round_id)
    if not r:
        return
    
    # Pro každého uživatele spočítej body
    users = User.query.all()
    
    for user in users:
        # Zkontroluj jestli uživatel chce tyto notifikace
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_results:
            continue  # User nechce notifikace o výsledcích
        
        # Spočítej body v této soutěži
        tips = Tip.query.join(Match).filter(
            Match.round_id == round_id,
            Tip.user_id == user.id
        ).all()
        
        if not tips:
            continue  # Uživatel netipoval
        
        total_points = 0
        exact_count = 0
        
        for tip in tips:
            match = tip.match
            if match.home_score is not None and match.away_score is not None:
                pts = calc_points_for_tip(match, tip)
                total_points += pts
                if pts == 3:
                    exact_count += 1
        
        # Vytvoř personalizovaný text
        if exact_count > 0:
            body = f"Máš {exact_count} přesných tipů! Celkem {total_points} bodů 🎯"
        elif total_points > 0:
            body = f"Získal jsi {total_points} bodů!"
        else:
            body = f"Bohužel žádný bod tentokrát..."
        
        send_push_notification(
            user.id,
            f"⚽ Výsledky - {r.name}",
            body,
            {"url": "/leaderboard"}
        )


def send_deadline_reminder(round_id: int):
    """
    Pošle připomínku o deadline
    Pouze uživatelům kteří ještě netipovali
    """
    r = db.session.get(Round, round_id)
    if not r:
        return
    
    # Najdi zápasy bez tipu
    users = User.query.all()
    
    for user in users:
        # Zkontroluj preferences
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_deadline:
            continue  # User nechce deadline reminders
        
        # Kolik zápasů je v soutěži
        total_matches = Match.query.filter_by(
            round_id=round_id,
            is_deleted=False
        ).count()
        
        # Kolik uživatel natipoval
        tipped_count = Tip.query.join(Match).filter(
            Match.round_id == round_id,
            Tip.user_id == user.id
        ).count()
        
        if tipped_count < total_matches:
            missing = total_matches - tipped_count
            send_push_notification(
                user.id,
                f"⏰ Deadline za 1 hodinu!",
                f"Ještě nemáš {missing} tipů v {r.name}",
                {"url": "/my-tips"}
            )


def send_achievement_notification(user_id: int, achievement_type: str):
    """
    Pošle notifikaci o získaném achievementu
    """
    # Zkontroluj preferences
    prefs = get_notification_preferences(user_id)
    if not prefs.notify_achievement:
        return  # User nechce achievement notifikace
    
    achievement_names = {
        "first_tip": "První krok! 🎯",
        "hattrick": "Hat-trick! ⚽⚽⚽",
        "perfect_round": "Perfektní kolo! 💯",
        "comeback": "Návrat z popela! 🔥",
        "striker": "Střelec! 🎯",
        "lucky_seven": "Šťastná 7! 🍀"
    }
    
    name = achievement_names.get(achievement_type, "Nový achievement!")
    
    send_push_notification(
        user_id,
        f"🏅 {name}",
        "Získal jsi nový achievement!",
        {"url": "/profile"}
    )


def send_leaderboard_change_notification(user_id: int, old_position: int, new_position: int, round_id: int):
    """
    Pošle notifikaci o změně pozice v žebříčku
    """
    # Zkontroluj preferences
    prefs = get_notification_preferences(user_id)
    if not prefs.notify_leaderboard:
        return  # User nechce leaderboard notifikace
    
    r = db.session.get(Round, round_id)
    
    if new_position < old_position:
        # Posun nahoru
        icon_emoji = "📈"
        text = f"Posunul ses na {new_position}. místo!"
    else:
        # Posun dolů
        icon_emoji = "📉"
        text = f"Klesnul jsi na {new_position}. místo"
    
    send_push_notification(
        user_id,
        f"{icon_emoji} Změna v žebříčku!",
        text,
        {"url": "/leaderboard"}
    )


def send_new_round_notification(round_name: str):
    """
    Pošle notifikaci o nové soutěži
    """
    users = User.query.all()
    
    for user in users:
        # Zkontroluj preferences
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_new_round:
            continue  # User nechce notifikace o nových soutěžích
        
        send_push_notification(
            user.id,
            "🆕 Nová soutěž!",
            f"{round_name} - Tipuj teď!",
            {"url": "/matches"}
        )


def get_selected_round_id() -> Optional[int]:
    rid = session.get("selected_round_id")
    if rid is None:
        return None
    try:
        return int(rid)
    except Exception:
        return None


def set_selected_round_id(round_id: int) -> None:
    session["selected_round_id"] = int(round_id)


def get_rounds_for_switch():
    if not current_user.is_authenticated:
        return []
    return Round.query.order_by(Round.is_active.desc(), Round.id.desc()).all()


def ensure_selected_round() -> Optional[int]:
    rounds = get_rounds_for_switch()
    if not rounds:
        return None
    selected = get_selected_round_id()
    if selected is None or not any(r.id == selected for r in rounds):
        active = next((r for r in rounds if r.is_active), None)
        selected = active.id if active else rounds[0].id
        set_selected_round_id(selected)
    return selected


def is_tips_locked(r: Round, m: Optional[Match] = None) -> bool:
    # lock by round deadline
    if r.tips_close_time and now_utc() >= r.tips_close_time:
        return True
    # lock by match start
    if m and m.start_time and now_utc() >= m.start_time:
        return True
    return False


def is_extras_locked(r: Round) -> bool:
    return bool(r.extra_close_time and now_utc() >= r.extra_close_time)


# =========================================================
# ACHIEVEMENTY / ODZNAKY
# =========================================================

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


def check_and_award_achievements(user_id: int, round_id: int):
    """Zkontroluj a uděl achievementy pro uživatele v dané soutěži"""
    from flask import current_app
    
    user = db.session.get(User, user_id)
    r = db.session.get(Round, round_id)
    if not user or not r:
        return
    
    # Načti tipy uživatele
    my_tips = Tip.query.join(Match).filter(
        Tip.user_id == user_id,
        Match.round_id == round_id,
        Match.is_deleted == False
    ).all()
    
    if not my_tips:
        return
    
    # === FIRST TIP ===
    if len(my_tips) == 1:
        _award_achievement(user_id, 'first_tip', round_id)
    
    # Pro další achievementy potřebujeme vyhodnocené zápasy
    evaluated_tips = [t for t in my_tips if t.match.home_score is not None and t.match.away_score is not None]
    
    if not evaluated_tips:
        return
    
    # === HATTRICK & PERFECT 5 ===
    # Seřaď tipy podle data zápasu
    sorted_tips = sorted(evaluated_tips, key=lambda t: t.match.start_time or datetime.min)
    
    current_streak = 0
    max_streak = 0
    
    for tip in sorted_tips:
        points = calc_points_for_tip(tip.match, tip)
        if points == 3:  # Přesný tip
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 0
    
    if max_streak >= 3:
        _award_achievement(user_id, 'hattrick', round_id)
    if max_streak >= 5:
        _award_achievement(user_id, 'perfect_5', round_id)
    if max_streak >= 10:
        _award_achievement(user_id, 'sniper', round_id)  # NOVÉ: 10 přesných po sobě!
    
    # === PERFECT ROUND ===
    # Zkontroluj jestli všechny tipy jsou přesné
    all_exact = all(calc_points_for_tip(t.match, t) == 3 for t in evaluated_tips)
    if all_exact and len(evaluated_tips) >= 3:  # Min 3 zápasy
        _award_achievement(user_id, 'perfect_round', round_id)
    
    # === FULL ATTENDANCE ===
    # Zkontroluj jestli tipoval všechny zápasy
    all_matches = Match.query.filter_by(round_id=round_id, is_deleted=False).all()
    tipped_match_ids = {t.match_id for t in my_tips}
    all_match_ids = {m.id for m in all_matches}
    
    if tipped_match_ids == all_match_ids and len(all_matches) >= 5:  # Min 5 zápasů
        _award_achievement(user_id, 'full_attendance', round_id)
    
    # === CENTURY & HALF CENTURY ===
    total_points = sum(calc_points_for_tip(t.match, t) for t in evaluated_tips)
    
    if total_points >= 50:
        _award_achievement(user_id, 'half_century', round_id)
    if total_points >= 100:
        _award_achievement(user_id, 'century', round_id)
    
    # === TOP TIPPER ===
    # Zkontroluj jestli má nejvíc bodů v soutěži
    all_users = User.query.all()
    user_scores = []
    
    for u in all_users:
        u_tips = Tip.query.join(Match).filter(
            Tip.user_id == u.id,
            Match.round_id == round_id,
            Match.is_deleted == False,
            Match.home_score != None,
            Match.away_score != None
        ).all()
        
        u_total = sum(calc_points_for_tip(t.match, t) for t in u_tips)
        user_scores.append({'user_id': u.id, 'total': u_total})
    
    user_scores.sort(key=lambda x: -x['total'])
    
    # Pokud je první (a má alespoň nějaké body)
    if user_scores and user_scores[0]['user_id'] == user_id and user_scores[0]['total'] > 0:
        # Zkontroluj že nemá stejný počet bodů s někým jiným
        top_score = user_scores[0]['total']
        top_count = sum(1 for x in user_scores if x['total'] == top_score)
        if top_count == 1:  # Jen on má nejvíc
            _award_achievement(user_id, 'top_tipper', round_id)
    
    # === WARRIOR ===
    # Účast ve 3+ soutěžích (global achievement)
    rounds_participated = db.session.query(Round.id).join(Match).join(Tip).filter(
        Tip.user_id == user_id,
        Match.is_deleted == False
    ).distinct().count()
    
    if rounds_participated >= 3:
        _award_achievement(user_id, 'warrior', None)  # Global, ne per-round
    
    # === UNDERDOG ===
    # Top 3 s méně než 50% tipnutých zápasů
    if len(user_scores) >= 3:
        top_3_users = [x['user_id'] for x in user_scores[:3]]
        if user_id in top_3_users:
            # Počet tipnutých vs všech zápasů
            total_matches_count = len(all_matches)
            tipped_count = len(my_tips)
            if total_matches_count > 0 and tipped_count / total_matches_count < 0.5:
                _award_achievement(user_id, 'underdog', round_id)


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


def get_user_achievements(user_id: int, round_id: int = None):
    """Získej achievementy uživatele (volitelně filtrováno podle soutěže)"""
    query = Achievement.query.filter_by(user_id=user_id)
    
    if round_id is not None:
        query = query.filter_by(round_id=round_id)
    
    achievements = query.all()
    
    # Vrať seznam s detaily
    result = []
    for ach in achievements:
        if ach.achievement_type in ACHIEVEMENTS:
            info = ACHIEVEMENTS[ach.achievement_type].copy()
            info['earned_at'] = ach.earned_at
            info['type'] = ach.achievement_type
            result.append(info)
    
    return result


def calc_points_for_tip(match: Match, tip: Tip) -> int:
    if match.home_score is None or match.away_score is None:
        return 0
    if tip.tip_home == match.home_score and tip.tip_away == match.away_score:
        return 3
    m_diff = match.home_score - match.away_score
    t_diff = tip.tip_home - tip.tip_away
    if (m_diff == 0 and t_diff == 0) or (m_diff > 0 and t_diff > 0) or (m_diff < 0 and t_diff < 0):
        return 1
    return 0


# =========================================================
# ACHIEVEMENTY / ODZNAKY
# =========================================================


def recompute_round_user_score(round_id: int, user_id: int) -> RoundUserScore:
    """Přepočítá a uloží cache bodů pro (round, user)."""
    tips = (
        Tip.query.join(Match)
        .filter(Match.round_id == round_id, Tip.user_id == user_id, Match.is_deleted == False)
        .all()
    )

    total_points = 0
    exact_count = 0

    for tip in tips:
        match = tip.match
        if not match:
            continue
        if match.home_score is None or match.away_score is None:
            continue
        pts = calc_points_for_tip(match, tip)
        total_points += pts
        if pts == 3:
            exact_count += 1

    row = RoundUserScore.query.filter_by(round_id=round_id, user_id=user_id).first()
    if not row:
        row = RoundUserScore(round_id=round_id, user_id=user_id)

    row.points = int(total_points)
    row.exact_count = int(exact_count)
    row.updated_at = datetime.utcnow()
    db.session.add(row)
    db.session.commit()
    return row


def recompute_round_scores(round_id: int) -> None:
    """Přepočítá cache bodů pro celé kolo."""
    users = User.query.all()
    for u in users:
        try:
            recompute_round_user_score(round_id, u.id)
        except Exception:
            db.session.rollback()
            continue


def get_cached_round_score(round_id: int, user_id: int) -> Optional[RoundUserScore]:
    row = RoundUserScore.query.filter_by(round_id=round_id, user_id=user_id).first()
    return row



def csv_response(filename_ascii: str, content: str) -> Response:
    resp = Response(content, mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename_ascii}"'
    return resp


def binary_response(filename_ascii: str, content: bytes, mimetype: str) -> Response:
    resp = Response(content, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename_ascii}"'
    return resp


# =========================================================
# UI (JEDEN BASE + inline stránky)
# =========================================================
BASE_HTML = r"""
<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes">
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <title>Tipovačka</title>
  
  <!-- PWA Meta Tags -->
  <meta name="description" content="Tipovací aplikace pro sázení na sportovní výsledky">
  <meta name="theme-color" content="#0b1020">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Tipovačka">
  
  <!-- PWA Manifest -->
  <link rel="manifest" href="{{ url_for('pwa_manifest') }}">
  
  <!-- Icons -->
  <link rel="icon" type="image/png" sizes="192x192" href="{{ url_for('pwa_icon', size=192) }}">
  <link rel="icon" type="image/png" sizes="512x512" href="{{ url_for('pwa_icon', size=512) }}">
  <link rel="apple-touch-icon" href="{{ url_for('pwa_icon', size=192) }}">

  <style>
    /* ========================================
       COLOR THEMES - Default: Dark Blue
       ======================================== */
    
    :root{
      --bg:#0b1020; --card:#111a33; --text:#e9eefc; --muted:#a7b2d6;
      --line:rgba(255,255,255,.12); --accent:#6ea8fe;
      --ok:#33d17a; --warn:#f9c74f; --bad:#a7b2d6; --danger:#ff4d6d;
    }
    
    /* Light Theme */
    [data-theme="light"] {
      --bg:#f5f7fa; --card:#ffffff; --text:#1a1f2e; --muted:#6b7280;
      --line:rgba(0,0,0,.08); --accent:#3b82f6;
      --ok:#10b981; --warn:#f59e0b; --bad:#9ca3af; --danger:#ef4444;
    }
    
    [data-theme="light"] body {
      background: linear-gradient(180deg, #e5e7eb, #f5f7fa 35%, #f5f7fa);
    }
    
    [data-theme="light"] .card {
      background: #ffffff;
      box-shadow: 0 4px 20px rgba(0,0,0,.08);
    }
    
    [data-theme="light"] input, 
    [data-theme="light"] select, 
    [data-theme="light"] textarea {
      background: rgba(0,0,0,.03);
    }
    
    /* Green Theme */
    [data-theme="green"] {
      --bg:#0a1410; --card:#0f1f19; --text:#e8f5e9; --muted:#a5d6a7;
      --line:rgba(76,175,80,.15); --accent:#66bb6a;
      --ok:#81c784; --warn:#ffa726; --bad:#a5d6a7; --danger:#ef5350;
    }
    
    [data-theme="green"] body {
      background: linear-gradient(180deg, #051008, #0a1410 35%, #0a1410);
    }
    
    /* Purple Theme */
    [data-theme="purple"] {
      --bg:#1a0f1f; --card:#2a1a33; --text:#f3e5f5; --muted:#ce93d8;
      --line:rgba(186,104,200,.15); --accent:#ba68c8;
      --ok:#66bb6a; --warn:#ffb74d; --bad:#ce93d8; --danger:#ef5350;
    }
    
    [data-theme="purple"] body {
      background: linear-gradient(180deg, #0f0514, #1a0f1f 35%, #1a0f1f);
    }
    
    /* Ocean Theme */
    [data-theme="ocean"] {
      --bg:#051419; --card:#0a2533; --text:#e0f2f7; --muted:#80deea;
      --line:rgba(0,188,212,.15); --accent:#26c6da;
      --ok:#66bb6a; --warn:#ffca28; --bad:#80deea; --danger:#ff5252;
    }
    
    [data-theme="ocean"] body {
      background: linear-gradient(180deg, #020a0f, #051419 35%, #051419);
    }
    
    /* Sunset Theme */
    [data-theme="sunset"] {
      --bg:#1f0f0a; --card:#331a14; --text:#ffe8e0; --muted:#ffab91;
      --line:rgba(255,138,101,.15); --accent:#ff8a65;
      --ok:#66bb6a; --warn:#ffa726; --bad:#ffab91; --danger:#ef5350;
    }
    
    [data-theme="sunset"] body {
      background: linear-gradient(180deg, #140a05, #1f0f0a 35%, #1f0f0a);
    }
    
    /* Theme transition */
    body, .card, input, select, textarea {
      transition: background 0.3s ease, color 0.3s ease, border-color 0.3s ease;
    }
    
    /* ======================================== 
       VIZUÁLNÍ VYLEPŠENÍ & ANIMACE
       ======================================== */
    
    /* Smooth animations */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
      from { opacity: 0; transform: translateX(-20px); }
      to { opacity: 1; transform: translateX(0); }
    }
    
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    
    /* Card animations */
    .card {
      animation: fadeIn 0.4s ease;
    }
    
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 16px 40px rgba(0,0,0,.35);
      transition: transform 0.2s ease, box-shadow 0.3s ease;
    }
    
    /* Button effects */
    .btn {
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
    }
    
    .btn::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 0;
      height: 0;
      border-radius: 50%;
      background: rgba(255,255,255,.2);
      transform: translate(-50%, -50%);
      transition: width 0.4s, height 0.4s;
    }
    
    .btn:active::before {
      width: 300px;
      height: 300px;
    }
    
    .btn-primary {
      box-shadow: 0 4px 12px rgba(110,168,254,.25);
    }
    
    .btn-primary:hover {
      box-shadow: 0 6px 16px rgba(110,168,254,.35);
      transform: translateY(-1px);
    }
    
    /* Input focus effects */
    input:focus, select:focus, textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(110,168,254,.1);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    
    /* Link hover effects */
    a {
      position: relative;
      transition: color 0.2s ease;
    }
    
    .nav a {
      position: relative;
      transition: all 0.2s ease;
    }
    
    .nav a::after {
      content: '';
      position: absolute;
      bottom: -2px;
      left: 0;
      width: 0;
      height: 2px;
      background: var(--accent);
      transition: width 0.3s ease;
    }
    
    .nav a:hover::after {
      width: 100%;
    }
    
    /* Tag animations */
    .tag {
      transition: all 0.2s ease;
    }
    
    .tag:hover {
      transform: scale(1.05);
    }
    
    /* Progress bar animation */
    @keyframes progressFill {
      from { width: 0; }
    }
    
    .progress-bar {
      animation: progressFill 1s ease-out;
    }
    
    /* Achievement card effects */
    .achievement-card {
      transition: all 0.3s ease;
    }
    
    .achievement-card:hover {
      transform: translateY(-4px) scale(1.02);
    }
    
    /* Stats card pulse on hover */
    .stat-card:hover {
      animation: pulse 0.6s ease;
    }
    
    /* Smooth scrolling */
    html {
      scroll-behavior: smooth;
    }
    
    /* Selection color */
    ::selection {
      background: var(--accent);
      color: #fff;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 10px;
      height: 10px;
    }
    
    ::-webkit-scrollbar-track {
      background: var(--card);
      border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
      background: var(--accent);
      border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
      background: var(--accent);
      opacity: 0.8;
    }
    
    /* Loading animation */
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    
    .loading {
      animation: spin 1s linear infinite;
    }
    
    /* Notification badge pulse */
    .badge-pulse {
      animation: pulse 2s ease-in-out infinite;
    }
    
    /* Glassmorphism effect for cards */
    .card-glass {
      background: rgba(17,26,51,.65);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    
    /* Gradient text */
    .gradient-text {
      background: linear-gradient(135deg, var(--accent), var(--ok));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    /* Shine effect on hover */
    @keyframes shine {
      to { background-position: 200% center; }
    }
    
    .shine:hover {
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.1), transparent);
      background-size: 200% 100%;
      animation: shine 1.5s ease-in-out;
    }
    
    /* ======================================== */
    
    *{ box-sizing:border-box; }
    body{ margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
          background:linear-gradient(180deg,#060a14,#0b1020 35%,#0b1020); color:var(--text); }
    a{ color:var(--accent); text-decoration:none; }
    a:hover{ text-decoration:underline; }

    .container{ max-width:1200px; margin:24px auto; padding:0 16px; }
    .topbar{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; flex-wrap:wrap; }
    .brand{ font-weight:900; letter-spacing:.2px; }
    .nav a{ margin-left:10px; }
    
    /* Topbar actions container */
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    
    /* Round selector */
    .round-selector {
      margin: 0;
    }
    
    .round-selector select {
      max-width: 200px;
    }

    .card{
      background:rgba(17,26,51,.85);
      border:1px solid var(--line);
      border-radius:14px;
      padding:14px;
      box-shadow:0 12px 30px rgba(0,0,0,.25);
    }
    .btn{
      display:inline-flex; align-items:center; justify-content:center;
      padding:9px 12px; border-radius:10px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.06);
      color:var(--text);
      cursor:pointer;
    }
    .btn:hover{ background:rgba(255,255,255,.10); }
    .btn-primary{ background:rgba(110,168,254,.18); border-color:rgba(110,168,254,.5); }

    input, select, textarea{
      padding:9px 10px; border-radius:10px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.05);
      color:var(--text);
      outline:none;
    }
    textarea{ min-height:160px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
    select option{ color:#111; background:#fff; }

    .row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .sep{ border:none; border-top:1px solid var(--line); margin:14px 0; }

    .muted{ color:var(--muted); }
    .tag{ padding:2px 8px; border-radius:999px; border:1px solid var(--line); background:rgba(255,255,255,.05); font-size:12px; }
    .pill-ok{ color:var(--ok); border-color:rgba(51,209,122,.35); background:rgba(51,209,122,.10); }
    .pill-warn{ color:var(--warn); border-color:rgba(249,199,79,.35); background:rgba(249,199,79,.10); }
    .pill-bad{ color:var(--bad); border-color:rgba(167,178,214,.35); background:rgba(167,178,214,.07); }
    .score-final{ color:var(--danger); font-weight:900; }

    .grid2{ display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    @media (max-width: 700px){ .grid2{ grid-template-columns:1fr; } }

    /* Mobilní vylepšení */
    @media (max-width: 768px) {
      .container { padding: 0 12px; margin: 12px auto; }
      .card { padding: 12px; }
      .lb-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      .topbar { gap: 8px; flex-wrap: nowrap; }
      .topbar-actions { gap: 8px; }
      .round-selector select { max-width: 140px; font-size: 13px; padding: 6px 8px; }
      .theme-btn { padding: 6px 8px !important; font-size: 18px; }
      .nav a { margin-left: 6px; font-size: 14px; }
      .btn { padding: 8px 10px; font-size: 14px; }
      .btn-sm { padding: 6px 8px; font-size: 12px; }
      h2 { font-size: 20px; }
      h3 { font-size: 18px; }

      /* Zalamování řádku se zápasem na mobilu */
      .card .row[style*="flex-wrap:nowrap"] {
        flex-wrap: wrap !important;
      }
    }

    /* Touch-friendly vylepšení */
    @media (max-width: 768px) {
      /* Větší touch targety - minimálně 44x44px (Apple guidelines) */
      .btn, button, a.btn { 
        min-height: 44px;
        min-width: 44px;
        padding: 12px 20px; /* Větší padding pro pohodlné klikání */
      }
      
      /* Větší inputy pro snazší klikání */
      input, select, textarea {
        font-size: 16px; /* Zabrání auto-zoom na iOS */
        min-height: 44px;
        padding: 10px 12px;
      }
      
      /* Checkboxy a radio buttony větší */
      input[type="checkbox"],
      input[type="radio"] {
        min-width: 20px;
        min-height: 20px;
        width: 20px;
        height: 20px;
      }
      
      /* Horizontal scroll pro široké tabulky */
      /* DŮLEŽITÉ: Vynecháváme .lb (žebříček) protože má vlastní sticky columns! */
      .card {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch; /* Smooth scroll na iOS */
      }
      
      /* Tabulky - horizontal scroll pokud jsou moc široké */
      /* VYLOUČENO: table.lb (žebříček má sticky columns a nesmí mít display:block) */
      table:not(.lb) {
        display: block;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        white-space: nowrap; /* Zabrání zalomení textu */
      }
      
      /* Datatable wrapper - ale NE žebříček! */
      .datatable:not(.lb) {
        display: block;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }
      
      /* Card padding menší na mobilu */
      .card {
        padding: 16px;
        margin-bottom: 16px;
      }
      
      /* Větší řádkování pro lepší čitelnost */
      body {
        line-height: 1.6;
      }
      
      /* Tlačítka v řádku na mobilu - plná šířka nebo stack */
      .row {
        flex-direction: column;
        gap: 12px;
      }
      
      .row .btn {
        width: 100%; /* Plná šířka na mobilu */
      }
    }
    
    /* ═══════════════════════════════════════════════════
       DESKTOP NAVIGATION (default = 769px+)
       ═══════════════════════════════════════════════════ */
    /* Desktop nav visible by default */
    .desktop-nav {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    
    .desktop-nav > a, .desktop-nav .nav-dropdown > a {
      padding: 8px 14px;
      border-radius: 8px;
      transition: background 0.2s;
      white-space: nowrap;
    }
    
    .desktop-nav > a:hover, .desktop-nav .nav-dropdown > a:hover {
      background: rgba(255,255,255,.08);
    }
    
    .desktop-nav .nav-dropdown {
      position: relative;
    }
    
    /* Dropdown hidden by default, shows on hover */
    .desktop-nav .nav-dropdown-menu {
      display: none;
      position: absolute;
      top: 100%;
      left: 0;
      min-width: 200px;
      background: rgba(11,16,32,0.98);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 6px;
      margin-top: 4px;
      box-shadow: 0 8px 24px rgba(0,0,0,.5);
      z-index: 1000;
    }
    
    .desktop-nav .nav-dropdown:hover .nav-dropdown-menu {
      display: block;
    }
    
    .desktop-nav .nav-dropdown-menu a {
      display: block;
      padding: 10px 14px;
      border-radius: 6px;
      transition: background 0.15s;
      white-space: nowrap;
    }
    
    .desktop-nav .nav-dropdown-menu a:hover {
      background: rgba(110,168,254,.15);
    }
    
    /* Mobile nav and hamburger hidden by default (desktop) */
    .mobile-nav {
      display: none;
    }
    
    .mobile-menu-btn {
      display: none;
    }
    
    /* ═══════════════════════════════════════════════════
       MOBILE NAVIGATION (max-width: 768px)
       ═══════════════════════════════════════════════════ */
    @media (max-width: 768px) {
        /* Hide desktop nav on mobile */
        .desktop-nav {
          display: none !important;
        }
        
        /* Show hamburger button */
        .mobile-menu-btn {
          display: block;
          background: rgba(255,255,255,.06);
          border: 1px solid var(--line);
          padding: 10px;
          border-radius: 10px;
          cursor: pointer;
          width: 44px;
          height: 44px;
        }
        
        .mobile-menu-btn span {
          display: block;
          width: 24px;
          height: 2px;
          background: var(--text);
          margin: 5px 0;
          transition: 0.3s;
        }
        
        /* Mobile nav - fullscreen overlay (hidden until toggled) */
        .mobile-nav {
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100vh;
          background: rgba(11,16,32,0.98);
          z-index: 2000;
          flex-direction: column;
          justify-content: flex-start;
          padding-top: 80px;
          overflow-y: auto;
        }
        
        .mobile-nav.mobile-open {
          display: flex !important;
        }
        
        .mobile-nav > a, .mobile-nav .nav-dropdown > a {
          font-size: 18px;
          padding: 14px 20px;
          display: block;
          width: 85%;
          margin: 0 auto 8px auto;
          text-align: left;
          background: rgba(255,255,255,.05);
          border-radius: 10px;
        }
        
        .mobile-nav .nav-dropdown {
          width: 85%;
          margin: 0 auto 8px auto;
        }
        
        .mobile-nav .nav-dropdown > a {
          width: 100%;
          margin: 0;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .dropdown-arrow {
          font-size: 12px;
          transition: transform 0.2s;
        }
        
        .mobile-nav .nav-dropdown.open .dropdown-arrow {
          transform: rotate(180deg);
        }
        
        /* Mobile dropdown menu */
        .mobile-nav .nav-dropdown-menu {
          display: none;
          flex-direction: column;
          gap: 6px;
          padding: 8px 0 0 0;
        }
        
        .mobile-nav .nav-dropdown.open .nav-dropdown-menu {
          display: flex;
        }
        
        .mobile-nav .nav-dropdown-menu a {
          font-size: 16px !important;
          padding: 12px 20px !important;
          background: rgba(255,255,255,.03) !important;
          border-left: 3px solid rgba(110,168,254,.5);
          margin-left: 16px !important;
          width: calc(100% - 16px) !important;
        }
        
        /* Close button */
        .mobile-close-btn {
          position: fixed;
          top: 20px;
          right: 20px;
          font-size: 36px;
          background: rgba(255,255,255,.1);
          border: 1px solid var(--line);
          border-radius: 50%;
          color: var(--text);
          cursor: pointer;
          width: 50px;
          height: 50px;
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 2001;
        }
      }

    /* Datatable mobilní */
    @media (max-width: 768px) {
      .datatable { font-size: 13px; }
      .datatable th, .datatable td { padding: 8px 6px; }
    }
    
    /* PWA Install Banner */
    .pwa-install-banner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: linear-gradient(135deg, #6ea8fe, #5a8fd9);
      color: white;
      padding: 16px;
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      z-index: 999;
      box-shadow: 0 -4px 20px rgba(0,0,0,.3);
    }
    
    .pwa-install-banner.show {
      display: flex;
    }
    
    .pwa-install-banner .btn {
      background: white;
      color: #0b1020;
      border: none;
      font-weight: 900;
    }
    
    .pwa-dismiss {
      background: transparent;
      border: 1px solid rgba(255,255,255,.5);
      color: white;
    }
    
    /* Theme Switcher */
    .theme-switcher {
      position: relative;
      display: inline-block;
    }
    
    .theme-btn {
      background: rgba(255,255,255,.06);
      border: 1px solid var(--line);
      padding: 8px 12px;
      border-radius: 10px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 14px;
      transition: background 0.2s;
    }
    
    .theme-btn:hover {
      background: rgba(255,255,255,.10);
    }
    
    .theme-dropdown {
      position: absolute;
      top: calc(100% + 8px);
      right: 0;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px;
      min-width: 200px;
      box-shadow: 0 12px 30px rgba(0,0,0,.3);
      display: none;
      z-index: 100;
    }
    
    .theme-dropdown.show {
      display: block;
    }
    
    .theme-option {
      padding: 10px 12px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 10px;
      transition: background 0.2s;
      margin-bottom: 4px;
    }
    
    .theme-option:hover {
      background: rgba(255,255,255,.08);
    }
    
    .theme-option.active {
      background: rgba(110,168,254,.18);
      border: 1px solid rgba(110,168,254,.5);
    }
    
    .theme-preview {
      width: 24px;
      height: 24px;
      border-radius: 6px;
      border: 1px solid var(--line);
    }
    
    .theme-preview.dark { background: linear-gradient(135deg, #0b1020, #6ea8fe); }
    .theme-preview.light { background: linear-gradient(135deg, #f5f7fa, #3b82f6); }
    .theme-preview.green { background: linear-gradient(135deg, #0a1410, #66bb6a); }
    .theme-preview.purple { background: linear-gradient(135deg, #1a0f1f, #ba68c8); }
    .theme-preview.ocean { background: linear-gradient(135deg, #051419, #26c6da); }
    .theme-preview.sunset { background: linear-gradient(135deg, #1f0f0a, #ff8a65); }
    
    @media (max-width: 768px) {
      .theme-switcher {
        position: static;
      }
      
      .theme-dropdown {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        right: auto;
      }
    }
    
    /* ========================================
       MOBILNÍ OPTIMALIZACE
       ======================================== */
    
    /* Větší touch targets pro mobil */
    @media (max-width: 768px) {
      /* Větší tlačítka */
      .btn {
        min-height: 44px;
        padding: 12px 20px;
        font-size: 16px;
      }
      
      .btn-sm {
        min-height: 40px;
        padding: 10px 16px;
        font-size: 14px;
      }
      
      /* Větší input fields */
      input[type="text"],
      input[type="email"],
      input[type="password"],
      input[type="number"],
      select,
      textarea {
        min-height: 44px;
        padding: 12px;
        font-size: 16px; /* Prevence auto-zoom na iOS */
      }
      
      /* Větší checkboxy */
      input[type="checkbox"] {
        width: 24px;
        height: 24px;
        min-width: 24px;
        min-height: 24px;
      }
      
      /* Responsive admin dashboard */
      .admin-dashboard {
        grid-template-columns: 1fr;
        gap: 12px;
      }
      
      .stat-card {
        padding: 16px;
      }
      
      .stat-value {
        font-size: 28px;
      }
      
      /* Bulk Edit table na mobilu */
      .bulk-table {
        font-size: 14px;
      }
      
      .bulk-table th,
      .bulk-table td {
        padding: 8px 4px;
      }
      
      .bulk-table input[type="number"] {
        width: 50px;
        min-height: 40px;
        font-size: 16px;
      }
      
      /* Undo tabulka */
      .datatable {
        font-size: 14px;
      }
      
      .datatable th,
      .datatable td {
        padding: 10px 8px;
      }
      
      /* Match preview (Smart Import) */
      .match-preview {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }
      
      .match-checkbox {
        width: 24px;
        height: 24px;
      }
      
      /* Cards stack na mobilu */
      .row {
        flex-direction: column;
        gap: 12px;
      }
      
      .card {
        padding: 16px;
      }
      
      /* Zmenši navigaci */
      .topbar {
        padding: 12px 16px;
      }
      
      .brand {
        font-size: 18px;
      }
      
      /* Mobilní menu */
      .nav a {
        padding: 12px 16px;
        font-size: 16px;
      }
      
      /* Container */
      .container {
        padding: 12px;
      }
      
      /* Skryj méně důležité sloupce v tabulkách */
      .datatable th:nth-child(2),
      .datatable td:nth-child(2) {
        display: none;
      }
    }
    
    /* Extra malé obrazovky (< 480px) */
    @media (max-width: 480px) {
      .container {
        padding: 8px;
      }
      
      .card {
        padding: 12px;
        border-radius: 8px;
      }
      
      h1 { font-size: 24px; }
      h2 { font-size: 20px; }
      h3 { font-size: 18px; }
      
      /* Bulk Edit - scrollable horizontálně */
      .bulk-table-wrapper {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }
      
      .bulk-table {
        min-width: 600px; /* Force scroll pokud je třeba */
      }
      
      /* Stack admin controls vertikálně */
      .admin-controls {
        flex-direction: column !important;
        align-items: stretch !important;
      }
      
      .admin-controls .btn {
        width: 100%;
      }
    }
    
    /* Touch-friendly hover effects */
    @media (hover: none) and (pointer: coarse) {
      /* Disable hover effects na touch zařízeních */
      .card:hover,
      .stat-card:hover,
      .match-row:hover {
        transform: none;
      }
      
      /* Ale přidej active state */
      .btn:active {
        transform: scale(0.97);
        opacity: 0.9;
      }
      
      .card:active {
        background: rgba(255,255,255,.05);
      }
    }
    
    /* Landscape orientation optimalizace */
    @media (max-width: 768px) and (orientation: landscape) {
      .container {
        padding: 8px 16px;
      }
      
      .stat-card {
        padding: 12px;
      }
      
      .stat-value {
        font-size: 24px;
      }
    }
    
    /* Bottom Navigation (pouze mobil) */
    .bottom-nav {
      display: none;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: var(--card);
      border-top: 1px solid var(--line);
      padding: 8px 0;
      z-index: 1000;
      box-shadow: 0 -2px 10px rgba(0,0,0,.1);
    }
    
    @media (max-width: 768px) {
      .bottom-nav {
        display: flex;
        justify-content: space-around;
        align-items: center;
      }
      
      /* Přidej padding na konci stránky kvůli bottom nav */
      .container {
        padding-bottom: 80px;
      }
    }
    
    .bottom-nav-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-decoration: none;
      color: var(--muted);
      font-size: 11px;
      padding: 8px 12px;
      border-radius: 8px;
      transition: all 0.2s ease;
      min-width: 60px;
    }
    
    .bottom-nav-item:hover,
    .bottom-nav-item.active {
      color: var(--accent);
      background: rgba(110,168,254,.1);
    }
    
    .bottom-nav-item .nav-icon {
      font-size: 24px;
      margin-bottom: 4px;
    }
    
    /* iOS Safe Area */
    @supports (padding: max(0px)) {
      body {
        padding-left: max(0px, env(safe-area-inset-left));
        padding-right: max(0px, env(safe-area-inset-right));
      }
      
      .topbar {
        padding-top: max(12px, env(safe-area-inset-top));
      }
      
      .bottom-nav {
        padding-bottom: max(8px, env(safe-area-inset-bottom));
      }
    }
    
    /* Swipe gestures hint */
    @media (max-width: 768px) {
      .swipeable {
        touch-action: pan-y;
        position: relative;
      }
      
      .swipeable::after {
        content: '';
        position: absolute;
        left: 0;
        top: 50%;
        transform: translateY(-50%);
        width: 4px;
        height: 40%;
        background: var(--accent);
        opacity: 0.3;
        border-radius: 0 4px 4px 0;
      }
    }
  

    /* ========================================
       TABLE LAYOUT IMPROVEMENTS (Smart Import Preview + Admin tables)
       ======================================== */
    table.preview-table{ width:100%; border-collapse:separate; border-spacing:0; table-layout:fixed; }
    table.preview-table thead th{ position:sticky; top:0; z-index:2; background:var(--card); }
    table.preview-table th, table.preview-table td{ padding:10px 8px; vertical-align:middle; }
    table.preview-table td:first-child, table.preview-table th:first-child{ text-align:center; }
    table.preview-table input[type="text"]{ width:100%; min-width:120px; }
    table.preview-table input.home-score, 
    table.preview-table input.away-score, 
    table.preview-table input[type="number"].home-score,
    table.preview-table input[type="number"].away-score{ width:70px; text-align:center; }
    table.preview-table input.start-time{ width:180px; max-width:100%; }
    @media (max-width: 900px){
      table.preview-table{ table-layout:auto; }
      table.preview-table input.start-time{ width:160px; }
    }

</style>
</head>

<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">Tipovačka</div>

      <div class="topbar-actions">
        {% if current_user.is_authenticated %}
          {% if rounds_for_switch and selected_round_id_for_switch %}
            <form method="post" action="{{ url_for('set_round') }}" class="round-selector">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
              <input type="hidden" name="next" value="{{ request.full_path }}">
              <select name="round_id" onchange="this.form.submit()">
                {% for r in rounds_for_switch %}
                  <option value="{{ r.id }}" {% if r.id == selected_round_id_for_switch %}selected{% endif %}>
                    {% if r.is_active %}★ {% endif %}{{ r.name }}
                  </option>
                {% endfor %}
              </select>
            </form>
          {% endif %}

          <!-- Theme Switcher -->
          <div class="theme-switcher">
            <button class="theme-btn" onclick="toggleThemeDropdown()" aria-label="Změnit motiv">
              🎨
            </button>
            <div class="theme-dropdown" id="theme-dropdown">
              <div class="theme-option active" data-theme="dark" onclick="setTheme('dark')">
                <div class="theme-preview dark"></div>
                <span>Dark Blue (výchozí)</span>
              </div>
              <div class="theme-option" data-theme="light" onclick="setTheme('light')">
                <div class="theme-preview light"></div>
                <span>Light</span>
              </div>
              <div class="theme-option" data-theme="green" onclick="setTheme('green')">
                <div class="theme-preview green"></div>
                <span>Green Forest</span>
              </div>
              <div class="theme-option" data-theme="purple" onclick="setTheme('purple')">
                <div class="theme-preview purple"></div>
                <span>Purple Night</span>
              </div>
              <div class="theme-option" data-theme="ocean" onclick="setTheme('ocean')">
                <div class="theme-preview ocean"></div>
                <span>Ocean Blue</span>
              </div>
              <div class="theme-option" data-theme="sunset" onclick="setTheme('sunset')">
                <div class="theme-preview sunset"></div>
                <span>Sunset Orange</span>
              </div>
            </div>
          </div>

          <!-- Mobile menu button -->
          <button class="mobile-menu-btn" onclick="toggleMobileMenu()" aria-label="Menu">
            <span></span>
            <span></span>
            <span></span>
          </button>

          <!-- DESKTOP NAVIGATION -->
          <div class="nav desktop-nav">
            <a href="{{ url_for('home') }}">🏠 Home</a>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('leaderboard') }}">📊 Žebříček</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('leaderboard') }}">Hlavní žebříček</a>
                <a href="{{ url_for('mini_leaderboards') }}">Mini žebříčky</a>
                <a href="{{ url_for('compare') }}">Porovnat</a>
              </div>
            </div>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('matches') }}">⚽ Zápasy</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('matches') }}">Všechny zápasy</a>
                <a href="{{ url_for('teams') }}">Týmy</a>
              </div>
            </div>
            
            <a href="{{ url_for('extras') }}">🎯 Extra</a>
            <a href="{{ url_for('archive') }}">📦 Archiv</a>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('my_stats') }}">📈 Stats</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('my_stats') }}">Moje statistiky</a>
                <a href="{{ url_for('achievements') }}">Achievementy</a>
              </div>
            </div>
            
            {% if current_user.is_admin_effective %}
              <div class="nav-dropdown">
                <a href="{{ url_for('admin_dashboard') }}">⚙️ Admin</a>
                <div class="nav-dropdown-menu">
                  <a href="{{ url_for('admin_dashboard') }}">Dashboard</a>
                  <a href="{{ url_for('admin_rounds') }}">Soutěže</a>
                  <a href="{{ url_for('admin_import') }}">Import</a>
                  <a href="{{ url_for('admin_export_hub') }}">Export</a>
                  <a href="{{ url_for('admin_bulk_edit') }}">Bulk Edit</a>
                  <a href="{{ url_for('admin_undo') }}">Undo</a>
                  <a href="{{ url_for('admin_users') }}">Uživatelé</a>
                  <a href="{{ url_for('admin_api_sources') }}">🔌 API Zdroje</a>
                  <a href="{{ url_for('admin_team_aliases') }}">🔁 Aliasy týmů</a>
                  <a href="{{ url_for('admin_backup') }}">💾 Záloha</a>
                  <a href="{{ url_for('admin_audit') }}">Historie</a>
                </div>
              </div>
            {% endif %}
            
            <div class="nav-dropdown">
              <a href="#">👤 {{ current_user.display_name }}</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('change_password') }}">Změnit heslo</a>
                <a href="{{ url_for('logout') }}">Odhlásit</a>
              </div>
            </div>
          </div>
          
          <!-- MOBILE NAVIGATION -->
          <div class="nav mobile-nav" id="mobile-nav">
            <button class="mobile-close-btn" onclick="toggleMobileMenu()">×</button>
            
            <a href="{{ url_for('home') }}" onclick="closeMobileMenu()">🏠 Home</a>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                📊 Žebříček <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('leaderboard') }}" onclick="closeMobileMenu()">Hlavní žebříček</a>
                <a href="{{ url_for('mini_leaderboards') }}" onclick="closeMobileMenu()">Mini žebříčky</a>
                <a href="{{ url_for('compare') }}" onclick="closeMobileMenu()">Porovnat</a>
              </div>
            </div>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                ⚽ Zápasy <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('matches') }}" onclick="closeMobileMenu()">Všechny zápasy</a>
                <a href="{{ url_for('teams') }}" onclick="closeMobileMenu()">Týmy</a>
              </div>
            </div>
            
            <a href="{{ url_for('extras') }}" onclick="closeMobileMenu()">🎯 Extra</a>
            <a href="{{ url_for('archive') }}" onclick="closeMobileMenu()">📦 Archiv</a>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                📈 Stats <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('my_stats') }}" onclick="closeMobileMenu()">Moje statistiky</a>
                <a href="{{ url_for('achievements') }}" onclick="closeMobileMenu()">Achievementy</a>
              </div>
            </div>
            
            {% if current_user.is_admin_effective %}
              <div class="nav-dropdown">
                <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                  ⚙️ Admin <span class="dropdown-arrow">▼</span>
                </a>
                <div class="nav-dropdown-menu">
                  <a href="{{ url_for('admin_dashboard') }}" onclick="closeMobileMenu()">Dashboard</a>
                  <a href="{{ url_for('admin_rounds') }}" onclick="closeMobileMenu()">Soutěže</a>
                  <a href="{{ url_for('admin_import') }}" onclick="closeMobileMenu()">Import</a>
                  <a href="{{ url_for('admin_export_hub') }}" onclick="closeMobileMenu()">Export</a>
                  <a href="{{ url_for('admin_bulk_edit') }}" onclick="closeMobileMenu()">Bulk Edit</a>
                  <a href="{{ url_for('admin_undo') }}" onclick="closeMobileMenu()">Undo</a>
                  <a href="{{ url_for('admin_users') }}" onclick="closeMobileMenu()">Uživatelé</a>
                  <a href="{{ url_for('admin_api_sources') }}" onclick="closeMobileMenu()">🔌 API Zdroje</a>
                  <a href="{{ url_for('admin_backup') }}" onclick="closeMobileMenu()">💾 Záloha</a>
                  <a href="{{ url_for('admin_audit') }}" onclick="closeMobileMenu()">Historie</a>
                </div>
              </div>
            {% endif %}
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                👤 {{ current_user.display_name }} <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('change_password') }}" onclick="closeMobileMenu()">Změnit heslo</a>
                <a href="{{ url_for('logout') }}" onclick="closeMobileMenu()">Odhlásit</a>
              </div>
            </div>
          </div>
        {% else %}
          <div class="nav">
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Registrace</a>
          </div>
        {% endif %}
      </div>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="card" style="margin-bottom:14px;">
          {% for cat, msg in messages %}
            <div style="margin:6px 0;">
              <span class="tag">{{ cat }}</span>
              <span style="margin-left:8px;">{{ msg }}</span>
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {{ content|safe }}
  </div>
  
  <!-- PWA Install Banner -->
  <div class="pwa-install-banner" id="pwa-banner">
    <div>
      <strong>📱 Instaluj aplikaci</strong>
      <div style="font-size: 13px; opacity: 0.9; margin-top: 4px;">
        Přidej si Tipovačku na plochu!
      </div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="installPWA()">Instalovat</button>
      <button class="btn pwa-dismiss" onclick="dismissPWA()">Později</button>
    </div>
  </div>
  
  <script>
    // Mobile menu toggle
    function toggleMobileMenu() {
      const nav = document.getElementById('mobile-nav');
      nav.classList.toggle('mobile-open');
    }
    
    function closeMobileMenu() {
      const nav = document.getElementById('mobile-nav');
      nav.classList.remove('mobile-open');
      // Zavři všechny dropdowny
      document.querySelectorAll('.mobile-nav .nav-dropdown').forEach(d => d.classList.remove('open'));
    }
    
    // Mobile dropdown toggle
    function toggleDropdown(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const toggle = e.currentTarget;
      const dropdown = toggle.parentElement;
      const isOpen = dropdown.classList.contains('open');
      
      // Zavři ostatní dropdowny
      document.querySelectorAll('.mobile-nav .nav-dropdown').forEach(d => {
        if (d !== dropdown) d.classList.remove('open');
      });
      
      // Toggle aktuální
      dropdown.classList.toggle('open');
    }
    
    // PWA Install
    let deferredPrompt;
    
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
      
      // Zobraz banner pokud už nebyl dismissed
      if (!localStorage.getItem('pwa-dismissed')) {
        document.getElementById('pwa-banner').classList.add('show');
      }
    });
    
    function installPWA() {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then((choiceResult) => {
          if (choiceResult.outcome === 'accepted') {
            console.log('PWA installed');
          }
          deferredPrompt = null;
          document.getElementById('pwa-banner').classList.remove('show');
        });
      }
    }
    
    function dismissPWA() {
      document.getElementById('pwa-banner').classList.remove('show');
      localStorage.setItem('pwa-dismissed', 'true');
    }
    
    // Theme Switcher
    const themes = {
      'dark': 'Dark Blue',
      'light': 'Light',
      'green': 'Green Forest',
      'purple': 'Purple Night',
      'ocean': 'Ocean Blue',
      'sunset': 'Sunset Orange'
    };
    
    function toggleThemeDropdown() {
      const dropdown = document.getElementById('theme-dropdown');
      dropdown.classList.toggle('show');
      
      // Zavři při kliknutí mimo
      if (dropdown.classList.contains('show')) {
        setTimeout(() => {
          document.addEventListener('click', closeThemeOnClickOutside);
        }, 0);
      }
    }
    
    function closeThemeOnClickOutside(e) {
      const dropdown = document.getElementById('theme-dropdown');
      const themeSwitcher = dropdown.closest('.theme-switcher');
      
      if (!themeSwitcher.contains(e.target)) {
        dropdown.classList.remove('show');
        document.removeEventListener('click', closeThemeOnClickOutside);
      }
    }
    
    function setTheme(theme) {
      // Nastav data-theme na html element
      document.documentElement.setAttribute('data-theme', theme);
      
      // Ulož do localStorage
      localStorage.setItem('preferred-theme', theme);
      
      // Označ že je to manuální override (ne auto)
      localStorage.setItem('theme-manual-override', 'true');
      
      // Update UI
      updateThemeUI(theme);
      
      // Zavři dropdown
      document.getElementById('theme-dropdown').classList.remove('show');
      document.removeEventListener('click', closeThemeOnClickOutside);
    }
    
    function updateThemeUI(theme) {
      // Update button text
      document.getElementById('current-theme-name').textContent = themes[theme] || 'Dark';
      
      // Update active option
      document.querySelectorAll('.theme-option').forEach(option => {
        if (option.dataset.theme === theme) {
          option.classList.add('active');
        } else {
          option.classList.remove('active');
        }
      });
    }
    
    // Auto Dark/Light Theme Detection
    function detectAutoTheme() {
      // 1. Pokud má uživatel manuální override, použij to
      const manualTheme = localStorage.getItem('preferred-theme');
      const isManualOverride = localStorage.getItem('theme-manual-override') === 'true';
      
      if (isManualOverride && manualTheme) {
        return manualTheme;
      }
      
      // 2. Detekce system preference (Dark Mode v OS)
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
      }
      
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        return 'light';
      }
      
      // 3. Auto-switch podle času (18:00-6:00 = dark)
      const hour = new Date().getHours();
      if (hour >= 18 || hour < 6) {
        return 'dark'; // Večer/noc
      } else {
        return 'light'; // Den
      }
    }
    
    // Načti saved theme při startu
    window.addEventListener('DOMContentLoaded', () => {
      const autoTheme = detectAutoTheme();
      document.documentElement.setAttribute('data-theme', autoTheme);
      
      // Update UI pokud existuje
      const themeNameEl = document.getElementById('current-theme-name');
      if (themeNameEl) {
        updateThemeUI(autoTheme);
      }
      
      // Poslouchej system preference změny
      if (window.matchMedia) {
        const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
        darkModeQuery.addEventListener('change', (e) => {
          // Pokud není manual override, auto-přepni
          const isManual = localStorage.getItem('theme-manual-override') === 'true';
          if (!isManual) {
            const newTheme = e.matches ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            if (themeNameEl) {
              updateThemeUI(newTheme);
            }
          }
        });
      }
    });
    
    // Keyboard Shortcuts pro adminy
    {% if current_user.is_authenticated and current_user.is_admin_effective %}
    document.addEventListener('keydown', function(e) {
      // Ctrl/Cmd + Shift + D = Dashboard
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'D') {
        e.preventDefault();
        window.location.href = "{{ url_for('admin_dashboard') }}";
      }
      
      // Ctrl/Cmd + Shift + B = Bulk Edit
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        window.location.href = "{{ url_for('admin_bulk_edit') }}";
      }
    });
    {% endif %}
    
    // Service Worker registrace
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/service-worker.js')
          .then(reg => console.log('Service Worker registered'))
          .catch(err => console.log('Service Worker registration failed:', err));
      });
    }
  </script>
  
  {% if current_user.is_authenticated %}
  <!-- Bottom Navigation (mobil - pro všechny) -->
  <nav class="bottom-nav">
    {% if current_user.is_admin_effective %}
      <!-- Admin verze -->
      <a href="{{ url_for('admin_dashboard') }}" class="bottom-nav-item {% if request.endpoint == 'admin_dashboard' %}active{% endif %}">
        <div class="nav-icon">👨‍💼</div>
        <div>Dashboard</div>
      </a>
      <a href="{{ url_for('admin_bulk_edit') }}" class="bottom-nav-item {% if request.endpoint == 'admin_bulk_edit' %}active{% endif %}">
        <div class="nav-icon">✏️</div>
        <div>Bulk Edit</div>
      </a>
      <a href="{{ url_for('admin_undo') }}" class="bottom-nav-item {% if request.endpoint == 'admin_undo' %}active{% endif %}">
        <div class="nav-icon">🔄</div>
        <div>Undo</div>
      </a>
      <a href="{{ url_for('admin_import') }}" class="bottom-nav-item {% if request.endpoint == 'admin_import' %}active{% endif %}">
        <div class="nav-icon">📥</div>
        <div>Import</div>
      </a>
    {% else %}
      <!-- User verze -->
      <a href="{{ url_for('leaderboard') }}" class="bottom-nav-item {% if request.endpoint == 'leaderboard' %}active{% endif %}">
        <div class="nav-icon">🏆</div>
        <div>Žebříček</div>
      </a>
      <a href="{{ url_for('my_tips') }}" class="bottom-nav-item {% if request.endpoint == 'my_tips' %}active{% endif %}">
        <div class="nav-icon">🎯</div>
        <div>Tipy</div>
      </a>
      <a href="{{ url_for('profile') }}" class="bottom-nav-item {% if request.endpoint == 'profile' %}active{% endif %}">
        <div class="nav-icon">👤</div>
        <div>Profil</div>
      </a>
      <a href="{{ url_for('archive') }}" class="bottom-nav-item {% if request.endpoint == 'archive' %}active{% endif %}">
        <div class="nav-icon">📚</div>
        <div>Archiv</div>
      </a>
    {% endif %}
  </nav>
  {% endif %}
  
  <!-- Push Notification Button (floating) -->
  {% if current_user.is_authenticated %}
  <button id="push-notification-btn" class="push-notif-btn" draggable="true" style="display:none;" title="Notifikace (přesouvatelné)">
    <span id="push-icon">🔔</span>
  </button>
  {% endif %}
  
  <style>
    /* Floating Notification Button */
    .push-notif-btn {
      position: fixed !important;  /* Force fixed */
      top: 80px;
      right: 20px;
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border: none;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      cursor: move;  /* Změněno z pointer na move */
      z-index: 99999 !important;  /* Nad vším! */
      font-size: 24px;
      transition: transform 0.3s ease, box-shadow 0.3s ease;  /* Bez transition na top/left */
      display: flex;
      align-items: center;
      justify-content: center;
      user-select: none;
      touch-action: none;
    }
    
    .push-notif-btn:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 16px rgba(0,0,0,0.4);
    }
    
    .push-notif-btn:active {
      transform: scale(0.95);
    }
    
    .push-notif-btn.dragging {
      opacity: 0.8;
      transform: scale(1.15);
      cursor: grabbing;
    }
    
    .push-notif-btn.disabled {
      background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
      opacity: 0.6;
    }
    
    @media (max-width: 768px) {
      .push-notif-btn {
        top: 16px;        /* Výš aby nebyl zakrytý */
        right: 16px;
        width: 48px;      /* Trochu větší pro touch */
        height: 48px;
        font-size: 22px;
        z-index: 99999 !important;  /* Opakuji pro jistotu */
      }
    }
  </style>
  
  <script>
    // Push Notification Management
    {% if current_user.is_authenticated %}
    (function() {
      const btn = document.getElementById('push-notification-btn');
      const icon = document.getElementById('push-icon');
      
      if (!btn) return;
      
      // Check if push is supported
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        console.log('Push notifications not supported');
        return;
      }
      
      // Show button
      btn.style.display = 'flex';
      
      // Check current subscription status
      navigator.serviceWorker.ready.then(registration => {
        return registration.pushManager.getSubscription();
      }).then(subscription => {
        updateUI(!!subscription);
      });
      
      // Button click handler with long press for settings
      let pressTimer;
      
      btn.addEventListener('mousedown', () => {
        pressTimer = setTimeout(() => {
          // Long press - open settings
          window.location.href = '/notification-settings';
        }, 500);  // 500ms = long press
      });
      
      btn.addEventListener('mouseup', () => {
        clearTimeout(pressTimer);
      });
      
      btn.addEventListener('touchstart', () => {
        pressTimer = setTimeout(() => {
          // Long press - open settings
          window.location.href = '/notification-settings';
        }, 500);
      });
      
      btn.addEventListener('touchend', () => {
        clearTimeout(pressTimer);
      });
      
      btn.addEventListener('click', async () => {
        try {
          const registration = await navigator.serviceWorker.ready;
          const subscription = await registration.pushManager.getSubscription();
          
          if (subscription) {
            // Unsubscribe
            await unsubscribeUser(subscription);
          } else {
            // Subscribe
            await subscribeUser(registration);
          }
        } catch (error) {
          console.error('Push error:', error);
          alert('Chyba: ' + error.message);
        }
      });
      
      async function subscribeUser(registration) {
        try {
          // Request permission
          const permission = await Notification.requestPermission();
          
          if (permission !== 'granted') {
            alert('❌ Notifikace nejsou povolené v prohlížeči');
            return;
          }
          
          // Get public key
          const response = await fetch('/api/push/vapid-public-key');
          const data = await response.json();
          const publicKey = data.publicKey;
          
          // Subscribe
          const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey)
          });
          
          // Send to server
          const subResponse = await fetchWithCSRF('/api/push/subscribe', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(subscription.toJSON())
          });
          
          const result = await subResponse.json();
          
          if (result.success) {
            updateUI(true);
            showToast('✅ Notifikace povoleny!');
          } else {
            throw new Error(result.message);
          }
          
        } catch (error) {
          console.error('Subscribe error:', error);
          alert('Chyba při povolování notifikací: ' + error.message);
        }
      }
      
      async function unsubscribeUser(subscription) {
        try {
          // Unsubscribe from push service
          await subscription.unsubscribe();
          
          // Tell server
          await fetchWithCSRF('/api/push/unsubscribe', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(subscription.toJSON())
          });
          
          updateUI(false);
          showToast('🔕 Notifikace zakázány');
          
        } catch (error) {
          console.error('Unsubscribe error:', error);
          alert('Chyba při zakazování notifikací: ' + error.message);
        }
      }
      
      function updateUI(isSubscribed) {
        if (isSubscribed) {
          icon.textContent = '🔔';
          btn.classList.remove('disabled');
          btn.title = 'Zakázat notifikace';
        } else {
          icon.textContent = '🔕';
          btn.classList.add('disabled');
          btn.title = 'Povolit notifikace';
        }
      }
      
      function showToast(message) {
        // Simple toast notification
        const toast = document.createElement('div');
        toast.textContent = message;
        toast.style.cssText = `
          position: fixed;
          top: 140px;
          right: 20px;
          background: rgba(17,26,51,0.95);
          color: #e9eefc;
          padding: 12px 20px;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          z-index: 10000;
          font-size: 14px;
          animation: slideIn 0.3s ease;
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
          toast.style.animation = 'slideOut 0.3s ease';
          setTimeout(() => toast.remove(), 300);
        }, 3000);
      }
      
      function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
          .replace(/\-/g, '+')
          .replace(/_/g, '/');
        
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        
        for (let i = 0; i < rawData.length; ++i) {
          outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
      }
      
      // ========== DRAG & DROP FUNCTIONALITY ==========
      let isDragging = false;
      let dragStartX, dragStartY;
      let btnStartX, btnStartY;
      
      // Load saved position from localStorage
      function loadPosition() {
        const saved = localStorage.getItem('push-btn-position');
        if (saved) {
          try {
            const pos = JSON.parse(saved);
            btn.style.left = pos.x + 'px';
            btn.style.top = pos.y + 'px';
            btn.style.right = 'auto';  // Disable right positioning
          } catch (e) {
            console.error('Error loading button position:', e);
          }
        }
      }
      
      // Save position to localStorage
      function savePosition() {
        const rect = btn.getBoundingClientRect();
        localStorage.setItem('push-btn-position', JSON.stringify({
          x: rect.left,
          y: rect.top
        }));
      }
      
      // Mouse/Touch drag handlers
      function startDrag(e) {
        isDragging = true;
        btn.classList.add('dragging');
        
        const touch = e.type.includes('touch') ? e.touches[0] : e;
        dragStartX = touch.clientX;
        dragStartY = touch.clientY;
        
        const rect = btn.getBoundingClientRect();
        btnStartX = rect.left;
        btnStartY = rect.top;
        
        // Prevent default to avoid text selection
        e.preventDefault();
      }
      
      function doDrag(e) {
        if (!isDragging) return;
        
        const touch = e.type.includes('touch') ? e.touches[0] : e;
        const deltaX = touch.clientX - dragStartX;
        const deltaY = touch.clientY - dragStartY;
        
        const newX = btnStartX + deltaX;
        const newY = btnStartY + deltaY;
        
        // Keep button within viewport
        const maxX = window.innerWidth - btn.offsetWidth;
        const maxY = window.innerHeight - btn.offsetHeight;
        
        btn.style.left = Math.max(0, Math.min(newX, maxX)) + 'px';
        btn.style.top = Math.max(0, Math.min(newY, maxY)) + 'px';
        btn.style.right = 'auto';  // Disable right positioning
        
        e.preventDefault();
      }
      
      function endDrag(e) {
        if (!isDragging) return;
        
        isDragging = false;
        btn.classList.remove('dragging');
        savePosition();
        
        e.preventDefault();
        
        // Prevent click event if dragged more than 5px
        const touch = e.type.includes('touch') ? e.changedTouches[0] : e;
        const moved = Math.abs(touch.clientX - dragStartX) + Math.abs(touch.clientY - dragStartY);
        if (moved > 5) {
          e.stopPropagation();
        }
      }
      
      // Add event listeners for drag
      btn.addEventListener('mousedown', startDrag);
      document.addEventListener('mousemove', doDrag);
      document.addEventListener('mouseup', endDrag);
      
      // Touch events for mobile
      btn.addEventListener('touchstart', startDrag, { passive: false });
      document.addEventListener('touchmove', doDrag, { passive: false });
      document.addEventListener('touchend', endDrag, { passive: false });
      
      // Load saved position on page load
      loadPosition();
      // ========== END DRAG & DROP ==========
      
    })();
    {% endif %}
  </script>
  
  <script>
    // Globální helper pro CSRF token
    function getCSRFToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.content : '';
    }
    
    // Helper pro fetch s CSRF tokenem
    function fetchWithCSRF(url, options = {}) {
      const token = getCSRFToken();
      
      if (!options.headers) {
        options.headers = {};
      }
      
      // Přidej CSRF token pro POST/PUT/DELETE requesty
      if (options.method && options.method.toUpperCase() !== 'GET') {
        options.headers['X-CSRFToken'] = token;
      }
      
      return fetch(url, options);
    }
  </script>
  
</body>
</html>
"""


def render_page(content_html: str, **ctx):
    selected = None
    rounds = []
    if current_user.is_authenticated:
        rounds = get_rounds_for_switch()
        selected = ensure_selected_round()

    # Odstranit z ctx pokud tam náhodou jsou (zabránit konfliktu)
    ctx.pop('rounds_for_switch', None)
    ctx.pop('selected_round_id_for_switch', None)
    
    # Přidat CSRF token funkci do kontextu
    ctx['csrf_token'] = generate_csrf

    inner = render_template_string(content_html, rounds_for_switch=rounds, selected_round_id_for_switch=selected, **ctx)
    return render_template_string(
        BASE_HTML,
        content=inner,
        rounds_for_switch=rounds,
        selected_round_id_for_switch=selected,
        **ctx,
    )


# =========================================================
# API IMPORT HELPER FUNCTIONS
# =========================================================
def fetch_nhl_games(season: str = "20252026", team: str = None) -> List[Dict]:
    """
    Stáhne zápasy z NHL API
    
    Args:
        season: Sezóna ve formátu YYYYYYYY (např. "20252026")
        team: Zkratka týmu (např. "BOS", "TOR") - optional
    
    Returns:
        List zápasů
    """
    try:
        # NHL API endpoint - aktualizovaný na 2025
        if team:
            url = f"https://api-web.nhle.com/v1/club-schedule/{team}/month/now"
        else:
            # Pro celou sezónu použij schedule endpoint
            url = f"https://api-web.nhle.com/v1/schedule/now"
        
        print(f"🏒 NHL API: Stahuji z {url}")
        
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        print(f"🏒 NHL API: Response status {response.status_code}")
        
        games = []
        
        # Parse response - NHL API struktura
        # Může být gameWeek nebo games přímo
        game_list = []
        
        if 'gameWeek' in data:
            for week in data.get('gameWeek', []):
                game_list.extend(week.get('games', []))
        elif 'games' in data:
            game_list = data.get('games', [])
        else:
            print(f"⚠️ NHL API: Neočekávaná struktura dat: {list(data.keys())}")
            return []
        
        print(f"🏒 NHL API: Nalezeno {len(game_list)} zápasů")
        
        for game in game_list:
            # Kontrola stavu zápasu
            game_state = game.get('gameState', '')
            game_type = game.get('gameType', 2)  # 2 = regular season
            
            # Parse týmy - různé možné struktury
            home_team = ""
            away_team = ""
            
            if 'homeTeam' in game and 'awayTeam' in game:
                # Nová struktura
                home_data = game.get('homeTeam', {})
                away_data = game.get('awayTeam', {})
                
                # Zkus různé možnosti názvů
                home_team = (
                    home_data.get('placeName', {}).get('default', '') or
                    home_data.get('name', {}).get('default', '') or
                    home_data.get('commonName', {}).get('default', '') or
                    home_data.get('abbrev', '')
                )
                
                away_team = (
                    away_data.get('placeName', {}).get('default', '') or
                    away_data.get('name', {}).get('default', '') or
                    away_data.get('commonName', {}).get('default', '') or
                    away_data.get('abbrev', '')
                )
            
            if not home_team or not away_team:
                print(f"⚠️ Přeskakuji zápas - chybí týmy: {game.get('id')}")
                continue
            
            # Parse datum/čas
            start_time_utc = game.get('startTimeUTC', '') or game.get('gameDate', '')
            start_time = None
            if start_time_utc:
                try:
                    start_time = datetime.fromisoformat(start_time_utc.replace('Z', '+00:00'))
                except:
                    print(f"⚠️ Chyba parsování času: {start_time_utc}")
            
            # Parse výsledek (pokud je)
            home_score = None
            away_score = None
            overtime = False
            shootout = False
            
            if game_state in ['OFF', 'FINAL']:  # Zápas skončil
                home_score = game.get('homeTeam', {}).get('score')
                away_score = game.get('awayTeam', {}).get('score')
                
                # Kontrola overtime/shootout
                period_descriptor = game.get('periodDescriptor', {})
                period_type = period_descriptor.get('periodType', 'REG')
                
                if period_type == 'OT':
                    overtime = True
                elif period_type == 'SO':
                    shootout = True
            
            games.append({
                'api_id': str(game.get('id', '')),
                'home_team': home_team,
                'away_team': away_team,
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': overtime,
                'shootout': shootout
            })
        
        print(f"✅ NHL API: Zpracováno {len(games)} platných zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ NHL API: Timeout při stahování")
        return []
    except requests.exceptions.ConnectionError as e:
        print(f"❌ NHL API: Chyba připojení: {e}")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"❌ NHL API: HTTP chyba {e.response.status_code}: {e}")
        return []
    except Exception as e:
        print(f"❌ NHL API: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []


def fetch_football_games(league_id: int, api_key: str, season: int = None) -> List[Dict]:
    """
    Stáhne fotbalové zápasy z API-Football
    
    Args:
        league_id: ID ligy (např. 39 = Premier League)
        api_key: API klíč
        season: Rok sezóny (např. 2024)
    
    Returns:
        List zápasů
    """
    try:
        if season is None:
            # FREE plán má přístup jen k sezónám 2022-2024
            # Použij 2024 jako default (poslední dostupná na FREE)
            season = 2024
        
        print(f"⚽ API-Football: Stahuji ligu {league_id}, sezóna {season}")
        
        url = "https://v3.football.api-sports.io/fixtures"
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': 'v3.football.api-sports.io'
        }
        params = {
            'league': league_id,
            'season': season
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        print(f"⚽ API-Football: Response status {response.status_code}")
        
        response.raise_for_status()
        data = response.json()
        
        # Check for API errors
        if 'errors' in data and data['errors']:
            print(f"❌ API-Football errors: {data['errors']}")
            return []
        
        results_count = data.get('results', 0)
        print(f"⚽ API-Football: Nalezeno {results_count} zápasů")
        
        games = []
        
        for fixture in data.get('response', []):
            fixture_data = fixture.get('fixture', {})
            teams = fixture.get('teams', {})
            goals = fixture.get('goals', {})
            score = fixture.get('score', {})
            
            # Parse datum/čas
            date_str = fixture_data.get('date', '')
            start_time = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else None
            
            # Parse výsledek
            home_score = goals.get('home')
            away_score = goals.get('away')
            
            # Kontrola extra time (použijeme jen regulární čas)
            fulltime_score = score.get('fulltime', {})
            if fulltime_score and fulltime_score.get('home') is not None:
                home_score = fulltime_score.get('home')
                away_score = fulltime_score.get('away')
            
            # Detekce extra time
            extratime_score = score.get('extratime', {})
            overtime = extratime_score.get('home') is not None
            
            games.append({
                'api_id': str(fixture_data.get('id', '')),
                'home_team': teams.get('home', {}).get('name', ''),
                'away_team': teams.get('away', {}).get('name', ''),
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': overtime,
                'shootout': False  # Fotbal nemá nájezdy
            })
        
        print(f"✅ API-Football: Zpracováno {len(games)} zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ API-Football: Timeout při stahování")
        return []
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        print(f"❌ API-Football: HTTP chyba {status_code}")
        if status_code == 401:
            print("   → Špatný API klíč")
        elif status_code == 403:
            print("   → Přístup zakázán (zkontroluj API klíč a sezónu)")
        elif status_code == 429:
            print("   → Rate limit překročen (100 requestů/den)")
        return []
    except Exception as e:
        print(f"❌ API-Football: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []


def fetch_thesportsdb_games(league_id: int, season: str = None) -> List[Dict]:
    """
    Stáhne fotbalové zápasy z TheSportsDB (ZDARMA!)
    
    Args:
        league_id: ID ligy (např. 4631 = Chance Liga, 4480 = Champions League)
        season: Sezóna ve formátu "2024-2025" (volitelné, pokud None vrátí poslední 15 zápasů)
    
    Returns:
        List zápasů
    """
    try:
        # TheSportsDB používá API klíč "3" pro free tier (nebo "1")
        api_key = "3"
        
        if season:
            # Stáhni zápasy pro konkrétní sezónu
            url = f"https://www.thesportsdb.com/api/v1/json/{api_key}/eventsseason.php"
            params = {
                'id': league_id,
                's': season  # Formát: "2024-2025"
            }
            print(f"⚽ TheSportsDB: Stahuji ligu {league_id}, sezóna {season}")
        else:
            # Stáhni posledních 15 zápasů ligy
            url = f"https://www.thesportsdb.com/api/v1/json/{api_key}/eventspastleague.php"
            params = {'id': league_id}
            print(f"⚽ TheSportsDB: Stahuji posledních 15 zápasů ligy {league_id}")
        
        response = requests.get(url, params=params, timeout=15)
        
        print(f"⚽ TheSportsDB: Response status {response.status_code}")
        
        response.raise_for_status()
        data = response.json()
        
        events = data.get('events', [])
        
        if not events:
            print(f"⚽ TheSportsDB: Žádné zápasy nenalezeny")
            return []
        
        print(f"⚽ TheSportsDB: Nalezeno {len(events)} zápasů")
        
        games = []
        
        for event in events:
            # Parse datum/čas
            date_str = event.get('dateEvent', '')
            time_str = event.get('strTime', '') or event.get('strTimeLocal', '') or '00:00:00'
            
            # Zkombinuj datum a čas
            start_time = None
            if date_str:
                try:
                    # Formát: "2024-12-25" + "20:00:00"
                    datetime_str = f"{date_str} {time_str}"
                    start_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    print(f"⚠️ Chyba parsování času: {date_str} {time_str} - {e}")
                    try:
                        # Zkus jen datum
                        start_time = datetime.strptime(date_str, "%Y-%m-%d")
                    except:
                        pass
            
            # Parse výsledek
            home_score = event.get('intHomeScore')
            away_score = event.get('intAwayScore')
            
            # Převeď na int pokud jsou stringy
            if home_score is not None:
                try:
                    home_score = int(home_score)
                except:
                    home_score = None
            
            if away_score is not None:
                try:
                    away_score = int(away_score)
                except:
                    away_score = None
            
            games.append({
                'api_id': str(event.get('idEvent', '')),
                'home_team': event.get('strHomeTeam', ''),
                'away_team': event.get('strAwayTeam', ''),
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': False,  # TheSportsDB nerozlišuje prodloužení
                'shootout': False
            })
        
        print(f"✅ TheSportsDB: Zpracováno {len(games)} zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ TheSportsDB: Timeout při stahování")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"❌ TheSportsDB: HTTP chyba {e.response.status_code}")
        return []
    except Exception as e:
        print(f"❌ TheSportsDB: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []



# =========================================================
# UEFA UCL (All fixtures & results) - FREE scraper
# =========================================================

UEFA_UCL_ALL_FIXTURES_URL_DEFAULT = "https://www.uefa.com/uefachampionsleague/news/029c-1e9a2f63fe2d-ebf9ad643892-1000--2025-26-champions-league-all-the-fixtures-and-results/"


_UEFA_MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}


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


def fetch_uefa_ucl_all_fixtures(url: Optional[str] = None) -> List[Dict]:
    """
    Scrape UEFA UCL 'All the fixtures and results' article.

    Returns list of dicts compatible with existing API import pipeline:
      {
        'api_id': str,                 # deterministic hash
        'home_team': str,
        'away_team': str,
        'start_time': ISO string (naive CZ time) or None,
        'home_score': int|None,
        'away_score': int|None,
        'overtime': bool,
        'shootout': bool
      }

    Notes:
      - Article states: "Kick-offs 21:00 CET unless stated."
      - Sometimes individual match line includes explicit time "(18:45 CET)".
      - We treat times as local (CET/CEST) naive datetimes to match the rest of the app.
    """
    try:
        target = (url or "").strip() or UEFA_UCL_ALL_FIXTURES_URL_DEFAULT
        headers = {
            "User-Agent": "Mozilla/5.0 (TipovackaBot; +https://example.invalid)",
            "Accept-Language": "en,en-US;q=0.9",
        }
        resp = requests.get(target, headers=headers, timeout=20)
        resp.raise_for_status()
        html = resp.text or ""
    except Exception as e:
        print(f"❌ UEFA UCL: Nepodařilo se stáhnout stránku: {e}")
        return []

    # Extract the main article body as plain-ish text
    # We rely on the fact that UEFA page is fairly readable even after stripping tags.
    txt = re.sub(r"<br\s*/?>", "\n", html, flags=re.I)
    txt = re.sub(r"</p\s*>", "\n", txt, flags=re.I)
    txt = re.sub(r"<[^>]+>", "", txt)
    txt = txt.replace("\xa0", " ")
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in txt.splitlines()]
    lines = [ln for ln in lines if ln]

    # Default year heuristic: use current year; if we see an explicit year in any date header, we'll override as we go.
    default_year = datetime.now().year

    games: List[Dict] = []
    current_date: Optional[datetime] = None
    default_kickoff = "21:00"  # CET unless stated
    # We only start collecting after we hit "Knockout phase play-offs" or "League phase results" etc.
    in_relevant_section = False

    for ln in lines:
        # Section start
        if ln.lower().startswith("knockout phase") or ln.lower().startswith("league phase") or ln.lower().startswith("qualifying"):
            in_relevant_section = True

        if not in_relevant_section:
            continue

        # Date header?
        d = _parse_uefa_day_header(ln, default_year=default_year)
        if d:
            current_date = d
            # If line had year, update default_year
            m_year = re.search(r"\b(\d{4})\b$", ln)
            if m_year:
                try:
                    default_year = int(m_year.group(1))
                except Exception:
                    pass
            continue

        # Match lines are often like:
        # "Atalanta vs Borussia Dortmund (first leg: 0-2) (18:45 CET)"
        # "Juventus vs Galatasaray (first leg: 2-5)"
        # "Atlético de Madrid 4-1 Club Brugge (agg: 7-4)"
        if not current_date:
            continue

        # Grab explicit time if present
        time_match = re.search(r"\((\d{1,2}:\d{2})\s*CET\)", ln)
        kickoff_hm = time_match.group(1) if time_match else default_kickoff

        # Clean helper: remove bracketed notes (first leg / agg / etc.) but preserve score tokens
        ln_clean = re.sub(r"\([^)]*\)", "", ln).strip()
        ln_clean = re.sub(r"\s+", " ", ln_clean)

        home = away = None
        hs = as_ = None

        # Finished match with score: "Home 1-2 Away" (sometimes uses en dash)
        m_score = re.match(r"^(.+?)\s+(\d+)\s*[-–]\s*(\d+)\s+(.+?)$", ln_clean)
        if m_score:
            home = _normalize_team_name(m_score.group(1))
            hs = int(m_score.group(2))
            as_ = int(m_score.group(3))
            away = _normalize_team_name(m_score.group(4))
        else:
            # Upcoming match: "Home vs Away"
            m_vs = re.match(r"^(.+?)\s+vs\s+(.+?)$", ln_clean, flags=re.I)
            if m_vs:
                home = _normalize_team_name(m_vs.group(1))
                away = _normalize_team_name(m_vs.group(2))

        if not home or not away:
            continue

        # Compose start_time
        start_time = None
        try:
            hh, mm = kickoff_hm.split(":")
            start_time = datetime(current_date.year, current_date.month, current_date.day, int(hh), int(mm))
        except Exception:
            start_time = None

        # Deterministic ID – stable between match import and result import for the same tie/date
        base = f"uefa-ucl|{home.lower()}|{away.lower()}|{current_date.date().isoformat()}"
        api_id = hashlib.sha1(base.encode("utf-8")).hexdigest()

        games.append({
            "api_id": api_id,
            "home_team": home,
            "away_team": away,
            "start_time": start_time.isoformat() if start_time else None,
            "home_score": hs,
            "away_score": as_,
            "overtime": False,
            "shootout": False
        })

    print(f"🏆 UEFA UCL: Nalezeno {len(games)} zápasů (All fixtures)")
    return games


def fetch_api_games(api_source: APISource, import_type: Optional[str] = None) -> List[Dict]:
    """
    Univerzální funkce pro stažení zápasů podle typu API

    Supported:
      - nhl
      - api-football
      - thesportsdb
      - uefa-ucl (scrape UEFA "All fixtures and results")
    """
    api_type = (api_source.api_type or "").lower().strip()

    if api_type == 'nhl':
        season = api_source.league_id or "20252026"
        return fetch_nhl_games(season=season)

    if api_type == 'api-football':
        league_id = int(api_source.league_id) if api_source.league_id else 39
        api_key = api_source.api_key or ""
        return fetch_football_games(league_id=league_id, api_key=api_key)

    if api_type == 'thesportsdb':
        league_id = int(api_source.league_id) if api_source.league_id else 4631
        season = api_source.api_key if api_source.api_key else None
        return fetch_thesportsdb_games(league_id=league_id, season=season)

    if api_type == 'uefa-ucl':
        # We reuse league_id as optional URL override to avoid DB migration.
        url = api_source.league_id or None
        games = fetch_uefa_ucl_all_fixtures(url=url)

        # Filter depending on import type:
        # - matches: only upcoming (unplayed) fixtures
        # - results: only games that already have a score
        try:
            now_local = datetime.now(ZoneInfo("Europe/Prague")).replace(tzinfo=None)
        except Exception:
            now_local = datetime.now()

        if import_type == 'matches':
            filtered: List[Dict] = []
            for g in games:
                if g.get('home_score') is not None or g.get('away_score') is not None:
                    continue
                st = None
                try:
                    st = datetime.fromisoformat(g['start_time']) if g.get('start_time') else None
                except Exception:
                    st = None
                # keep only future fixtures (allow small negative drift)
                if st and st >= (now_local - timedelta(minutes=5)):
                    filtered.append(g)
            return filtered

        if import_type == 'results':
            return [g for g in games if g.get('home_score') is not None and g.get('away_score') is not None]

        return games

    print(f"❌ Neznámý typ API: {api_type}")
    return []


def import_matches_from_api(api_source: APISource, games: List[Dict], commit: bool = False) -> Tuple[int, int, List[str]]:
    """
    Importuje zápasy do databáze
    
    Args:
        api_source: API zdroj
        games: List zápasů z API
        commit: Zda commitnout změny (False = dry run)
    
    Returns:
        (imported_count, skipped_count, errors)
    """
    imported = 0
    skipped = 0
    errors = []
    
    for game in games:
        try:
            # Najdi nebo vytvoř týmy
            home_team = Team.query.filter_by(
                round_id=api_source.round_id,
                name=game['home_team']
            ).first()
            
            if not home_team:
                home_team = Team(
                    round_id=api_source.round_id,
                    name=game['home_team']
                )
                db.session.add(home_team)
                db.session.flush()
            
            away_team = Team.query.filter_by(
                round_id=api_source.round_id,
                name=game['away_team']
            ).first()
            
            if not away_team:
                away_team = Team(
                    round_id=api_source.round_id,
                    name=game['away_team']
                )
                db.session.add(away_team)
                db.session.flush()
            
            # Check jestli zápas už existuje (podle API ID)
            existing_mapping = MatchAPIMapping.query.filter_by(
                source_id=api_source.id,
                api_match_id=game['api_id']
            ).first()
            
            if existing_mapping:
                skipped += 1
                continue
            
            # Vytvoř zápas
            start_time = datetime.fromisoformat(game['start_time']) if game['start_time'] else None
            
            match = Match(
                round_id=api_source.round_id,
                home_team_id=home_team.id,
                away_team_id=away_team.id,
                start_time=start_time
            )
            db.session.add(match)
            db.session.flush()
            
            # Vytvoř mapping
            mapping = MatchAPIMapping(
                match_id=match.id,
                source_id=api_source.id,
                api_match_id=game['api_id']
            )
            db.session.add(mapping)
            
            imported += 1
        
        except Exception as e:
            errors.append(f"Chyba u zápasu {game.get('home_team')} vs {game.get('away_team')}: {str(e)}")
            skipped += 1
    
    if commit:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Chyba při commitu: {str(e)}")
            return 0, len(games), errors
    
    return imported, skipped, errors


def import_results_from_api(api_source: APISource, games: List[Dict], commit: bool = False) -> Tuple[int, int, List[str]]:
    """
    Importuje výsledky zápasů do databáze
    
    Args:
        api_source: API zdroj
        games: List zápasů s výsledky z API
        commit: Zda commitnout změny
    
    Returns:
        (updated_count, skipped_count, errors)
    """
    updated = 0
    skipped = 0
    errors = []
    
    for game in games:
        try:
            # Najdi zápas podle API ID
            mapping = MatchAPIMapping.query.filter_by(
                source_id=api_source.id,
                api_match_id=game['api_id']
            ).first()
            
            if not mapping:
                errors.append(f"Zápas {game['api_id']} nemá mapping")
                skipped += 1
                continue
            
            match = Match.query.get(mapping.match_id)
            if not match:
                errors.append(f"Zápas ID {mapping.match_id} neexistuje")
                skipped += 1
                continue
            
            # Kontrola výsledku
            home_score = game.get('home_score')
            away_score = game.get('away_score')
            
            if home_score is None or away_score is None:
                # Zápas ještě neskončil
                skipped += 1
                continue
            
            # Kontrola overtime/shootout (pokud je nastaveno exclude_overtime)
            if api_source.exclude_overtime:
                if game.get('overtime') or game.get('shootout'):
                    errors.append(f"Zápas {game['home_team']} vs {game['away_team']} šel do prodloužení/nájezdů - kontroluj manuálně")
                    skipped += 1
                    continue
            
            # Update výsledku
            if match.home_score is None or match.away_score is None:
                match.home_score = home_score
                match.away_score = away_score
                updated += 1
            else:
                # Výsledek už existuje - skip
                skipped += 1
        
        except Exception as e:
            errors.append(f"Chyba u zápasu {game.get('api_id')}: {str(e)}")
            skipped += 1
    
    if commit:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Chyba při commitu: {str(e)}")
            return 0, len(games), errors
    
    return updated, skipped, errors


# =========================================================
# ROUTES
# =========================================================
def register_routes(app: Flask) -> None:
    # =========================================================
    # SECURITY HEADERS
    # =========================================================
    @app.after_request
    def set_security_headers(response):
        """
        Přidá bezpečnostní hlavičky ke všem HTTP odpovědím.
        
        Headers:
        - X-Frame-Options: Ochrana proti clickjacking
        - X-Content-Type-Options: Ochrana proti MIME sniffing
        - X-XSS-Protection: XSS filter pro starší browsery
        - Strict-Transport-Security: Vynutí HTTPS
        - Content-Security-Policy: Kontroluje odkud se načítají skripty
        - Referrer-Policy: Omezuje jaké info se posílá v Referer headeru
        """
        # Ochrana proti clickjacking - stránka nemůže být v iframe
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Ochrana proti MIME-type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # XSS Protection pro starší browsery
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # HSTS - vynutí HTTPS na 1 rok (jen pokud už je HTTPS)
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        # Povolujeme inline scripts/styles kvůli render_template_string
        # V produkci by bylo lepší mít external files, ale pro jednoduchost používáme inline
        csp_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'"
        ]
        response.headers['Content-Security-Policy'] = '; '.join(csp_parts)
        
        # Referrer Policy - omezuje info v Referer headeru
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy (dříve Feature-Policy)
        # Zakazuje přístup k senzitivním API
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response
    
    # =========================================================
    # ROUTES
    # =========================================================
    @app.route("/old-index-redirect")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/set-round", methods=["POST"])
    @login_required
    def set_round():
        rid = int(request.form["round_id"])
        r = db.session.get(Round, rid)
        if not r:
            abort(404)
        set_selected_round_id(r.id)
        audit("round.switch", "Round", r.id)
        nxt = (request.form.get("next") or "").strip()
        if nxt.startswith("/"):
            return redirect(nxt)
        return redirect(url_for("matches"))

    # --- AUTH ---
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("matches"))

        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()
            first_name = (request.form.get("first_name") or "").strip()
            last_name = (request.form.get("last_name") or "").strip()
            nickname = (request.form.get("nickname") or "").strip()

            if not email or not username or not password:
                flash("Vyplň email, uživatelské jméno i heslo.", "error")
                return redirect(url_for("register"))
            
            # Validace síly hesla
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, "error")
                return redirect(url_for("register"))

            if User.query.filter_by(email=email).first():
                flash("Email už existuje.", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("Uživatelské jméno už existuje.", "error")
                return redirect(url_for("register"))

            # Zkontroluj jestli je vyžadována email verifikace
            email_config = get_email_config()
            require_verification = email_config.get('REQUIRE_EMAIL_VERIFICATION', True)
            
            u = User(
                email=email,
                username=username,
                first_name=first_name or None,
                last_name=last_name or None,
                nickname=nickname or None,
                is_admin=False,
                role="user",
                email_verified=not require_verification  # Pokud není vyžadována verifikace, email je automaticky ověřený
            )
            u.set_password(password)
            
            if require_verification:
                # Vygeneruj verification token (jen pokud je verifikace vyžadována)
                u.verification_token = secrets.token_urlsafe(32)
                u.verification_token_expires = datetime.utcnow() + timedelta(hours=24)
            
            db.session.add(u)
            db.session.commit()
            audit("user.register", "User", u.id, email=email)
            
            if require_verification:
                # Pošli potvrzovací email (jen pokud je verifikace vyžadována)
                base_url = request.url_root.rstrip('/')
                email_sent = send_verification_email(u, base_url)
                
                if email_sent:
                    flash("📧 Registrace OK! Zkontroluj email a potvrď registraci.", "ok")
                else:
                    flash("⚠️ Registrace OK, ale nepodařilo se poslat potvrzovací email. Kontaktuj admina.", "warning")
            else:
                # Email verifikace není vyžadována
                flash("✅ Registrace úspěšná! Můžeš se hned přihlásit.", "ok")
            
            return redirect(url_for("login"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Registrace</h2>
  <div class="muted">Vytvoř si účet pro účast v tipovací soutěži</div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Email *</label>
      <input name="email" type="email" placeholder="tvuj@email.cz" required>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Uživatelské jméno (login) *</label>
      <input name="username" placeholder="username" required>
      <div class="muted" style="font-size:12px; margin-top:4px;">Pro přihlášení do aplikace</div>
    </div>
    <div class="grid2">
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Jméno</label>
        <input name="first_name" placeholder="Jan">
      </div>
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Příjmení</label>
        <input name="last_name" placeholder="Novák">
      </div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Přezdívka (Nick)</label>
      <input name="nickname" placeholder="JN23">
      <div class="muted" style="font-size:12px; margin-top:4px;">Toto jméno uvidí ostatní v žebříčku. Pokud nevyplníš, použije se jméno a příjmení nebo username.</div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Heslo *</label>
      <input name="password" type="password" placeholder="Min. 8 znaků" required minlength="8">
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Požadavky:<br>
        • Alespoň 8 znaků<br>
        • Velké písmeno (A-Z)<br>
        • Malé písmeno (a-z)<br>
        • Číslice (0-9)
      </div>
    </div>
    <button class="btn btn-primary" type="submit">Registrovat</button>
  </form>
  <hr class="sep">
  <div class="muted">Už máš účet? <a href="{{ url_for('login') }}">Přihlásit se</a></div>
</div>
""")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("matches"))

        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = (request.form.get("password") or "").strip()

            u = User.query.filter_by(email=email).first()
            if not u or not u.check_password(password):
                flash("Špatný email nebo heslo.", "error")
                return redirect(url_for("login"))
            
            # Zkontroluj jestli je email ověřený (pouze pokud je to vyžadováno)
            email_config = get_email_config()
            if email_config.get('REQUIRE_EMAIL_VERIFICATION', True) and not u.email_verified:
                flash("⚠️ Nejdřív musíš potvrdit email. Zkontroluj svou emailovou schránku.", "error")
                return redirect(url_for("login"))

            login_user(u)
            ensure_selected_round()
            audit("user.login", "User", u.id)
            return redirect(url_for("matches"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Login</h2>
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input name="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Heslo" required>
    <button class="btn btn-primary" type="submit">Přihlásit</button>
  </form>
  <hr class="sep">
  <div class="muted">
    Nemáš účet? <a href="{{ url_for('register') }}">Registrace</a>
    <br>
    Zapomněl jsi heslo? <a href="{{ url_for('forgot_password') }}">Reset hesla</a>
  </div>
</div>
""")

    @app.route("/logout")
    @login_required
    def logout():
        audit("user.logout", "User", current_user.id)
        logout_user()
        return redirect(url_for("login"))
    
    # --- EMAIL VERIFIKACE ---
    @app.route("/verify-email/<token>")
    def verify_email(token: str):
        """Potvrzení emailu po registraci"""
        user = User.query.filter_by(verification_token=token).first()
        
        if not user:
            flash("❌ Neplatný ověřovací odkaz.", "error")
            return redirect(url_for("login"))
        
        # Zkontroluj expiraci
        if user.verification_token_expires and user.verification_token_expires < datetime.utcnow():
            flash("❌ Ověřovací odkaz expiroval. Požádej o nový.", "error")
            return redirect(url_for("login"))
        
        # Ověř email
        user.email_verified = True
        user.verification_token = None
        user.verification_token_expires = None
        db.session.commit()
        audit("user.email_verified", "User", user.id)
        
        flash("✅ Email ověřen! Teď se můžeš přihlásit.", "ok")
        return redirect(url_for("login"))
    
    # --- ZAPOMENUTÉ HESLO ---
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        """Formulář pro zadání emailu - pošle reset link"""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            
            if not email:
                flash("Zadej email.", "error")
                return redirect(url_for("forgot_password"))
            
            user = User.query.filter_by(email=email).first()
            
            # I když uživatel neexistuje, zobraz stejnou zprávu (bezpečnost)
            if user:
                # Vygeneruj reset token
                user.reset_token = secrets.token_urlsafe(32)
                user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                audit("user.password_reset_requested", "User", user.id)
                
                # Pošli reset email
                base_url = request.url_root.rstrip('/')
                send_password_reset_email(user, base_url)
            
            flash("📧 Pokud email existuje, poslali jsme ti odkaz na reset hesla. Zkontroluj schránku.", "ok")
            return redirect(url_for("login"))
        
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Zapomenuté heslo</h2>
  <div class="muted">Zadej svůj email a pošleme ti odkaz na reset hesla</div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Email</label>
      <input name="email" type="email" placeholder="tvuj@email.cz" required autofocus>
    </div>
    <div class="row" style="gap:10px;">
      <button class="btn btn-primary" type="submit">📧 Poslat reset link</button>
      <a class="btn" href="{{ url_for('login') }}">Zrušit</a>
    </div>
  </form>
  <hr class="sep">
  <div class="muted">
    Vzpomněl sis? <a href="{{ url_for('login') }}">Přihlásit se</a>
  </div>
</div>
""")
    
    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token: str):
        """Formulář pro nastavení nového hesla"""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user:
            flash("❌ Neplatný reset odkaz.", "error")
            return redirect(url_for("login"))
        
        # Zkontroluj expiraci
        if user.reset_token_expires and user.reset_token_expires < datetime.utcnow():
            flash("❌ Reset odkaz expiroval. Požádej o nový.", "error")
            return redirect(url_for("forgot_password"))
        
        if request.method == "POST":
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            
            if not new_password or not confirm_password:
                flash("Vyplň obě pole.", "error")
                return redirect(url_for("reset_password", token=token))
            
            if new_password != confirm_password:
                flash("Hesla se neshodují.", "error")
                return redirect(url_for("reset_password", token=token))
            
            # Validace síly hesla
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, "error")
                return redirect(url_for("reset_password", token=token))
            
            # Nastav nové heslo
            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expires = None
            db.session.commit()
            audit("user.password_reset_completed", "User", user.id)
            
            flash("✅ Heslo změněno! Teď se můžeš přihlásit.", "ok")
            return redirect(url_for("login"))
        
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Nové heslo</h2>
  <div class="muted">Zadej si nové silné heslo</div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Nové heslo *</label>
      <input name="new_password" type="password" placeholder="Min. 8 znaků" required minlength="8" autofocus>
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Požadavky: min. 8 znaků, velké/malé písmeno, číslo
      </div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Potvrď nové heslo *</label>
      <input name="confirm_password" type="password" placeholder="Zadej heslo znovu" required minlength="8">
    </div>
    <div class="row" style="gap:10px;">
      <button class="btn btn-primary" type="submit">🔑 Nastavit heslo</button>
      <a class="btn" href="{{ url_for('login') }}">Zrušit</a>
    </div>
  </form>
</div>
""", title="Reset hesla")

    # --- ZMĚNA HESLA (pro všechny přihlášené uživatele) ---
    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            old_password = request.form.get("old_password", "").strip()
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            
            # Validace
            if not old_password or not new_password or not confirm_password:
                flash("Všechna pole jsou povinná.", "error")
                return redirect(url_for("change_password"))
            
            # Kontrola starého hesla
            if not check_password_hash(current_user.password_hash, old_password):
                flash("Staré heslo je nesprávné.", "error")
                return redirect(url_for("change_password"))
            
            # Kontrola že nové hesla souhlasí
            if new_password != confirm_password:
                flash("Nová hesla se neshodují.", "error")
                return redirect(url_for("change_password"))
            
            # Validace síly nového hesla
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, "error")
                return redirect(url_for("change_password"))
            
            # Změna hesla
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            audit("user.change_password", "User", current_user.id)
            flash("Heslo bylo úspěšně změněno.", "ok")
            return redirect(url_for("dashboard"))
        
        # GET - zobraz formulář
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Změna hesla</h2>
  <div class="muted">Změňte si heslo pro svůj účet</div>
  <hr class="sep">
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="form-group">
      <label>Staré heslo</label>
      <input type="password" name="old_password" required autofocus>
    </div>
    <div class="form-group">
      <label>Nové heslo</label>
      <input type="password" name="new_password" required minlength="8">
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Požadavky: min. 8 znaků, velké/malé písmeno, číslo
      </div>
    </div>
    <div class="form-group">
      <label>Potvrďte nové heslo</label>
      <input type="password" name="confirm_password" required minlength="8">
    </div>
    <div class="form-actions">
      <button type="submit" class="btn btn-primary">Změnit heslo</button>
      <a href="{{ url_for('dashboard') }}" class="btn">Zrušit</a>
    </div>
  </form>
</div>
""", title="Změna hesla")

    # --- DASHBOARD (ÚVODNÍ STRÁNKA) ---
    @app.route("/")
    @app.route("/home")
    @login_required
    def home():
        """Nová moderní home page s iOS gridem"""
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("admin_rounds") if current_user.is_admin_effective else url_for("logout"))
        
        # Quick stats pro home
        my_tips_count = Tip.query.join(Match).filter(
            Match.round_id == r.id,
            Tip.user_id == current_user.id
        ).count()
        
        total_matches = Match.query.filter_by(round_id=r.id, is_deleted=False).count()
        
        # Počet notifikací (pokud máme notification systém)
        notification_count = 0  # Placeholder
        
        return render_page(r"""
<style>
/* iOS Grid Style */
.home-container {
  padding: 0;
  max-width: 100%;
}

.section-title {
  font-size: 14px;
  font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 24px 16px 12px 16px;
}

/* iOS Grid */
.ios-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  padding: 0 16px 24px 16px;
}

.grid-item {
  aspect-ratio: 1;
  background: linear-gradient(135deg, rgba(110,168,254,0.15) 0%, rgba(118,75,162,0.15) 100%);
  border-radius: 20px;
  border: 1px solid rgba(110,168,254,0.2);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  cursor: pointer;
  transition: all 0.2s;
  text-decoration: none;
  color: #e9eefc;
  position: relative;
  overflow: hidden;
}

.grid-item:hover {
  transform: translateY(-4px);
  background: linear-gradient(135deg, rgba(110,168,254,0.25) 0%, rgba(118,75,162,0.25) 100%);
  border-color: rgba(110,168,254,0.4);
  box-shadow: 0 8px 24px rgba(110,168,254,0.3);
}

.grid-item:active {
  transform: scale(0.95);
}

.grid-icon {
  font-size: 32px;
  line-height: 1;
}

.grid-label {
  font-size: 12px;
  font-weight: 600;
  text-align: center;
  line-height: 1.2;
}

.grid-badge {
  position: absolute;
  top: 8px;
  right: 8px;
  background: #ef4444;
  color: white;
  border-radius: 10px;
  padding: 2px 6px;
  font-size: 10px;
  font-weight: 900;
  min-width: 18px;
  text-align: center;
}

/* Material Cards (Admin) */
.admin-cards {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
  padding: 0 16px 24px 16px;
}

.admin-card {
  background: rgba(110,168,254,0.08);
  border: 1px solid rgba(110,168,254,0.2);
  border-radius: 16px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
  text-decoration: none;
  color: #e9eefc;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.admin-card:hover {
  background: rgba(110,168,254,0.15);
  border-color: rgba(110,168,254,0.3);
  transform: translateY(-2px);
  box-shadow: 0 4px 16px rgba(0,0,0,0.2);
}

.admin-card-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.admin-card-icon {
  font-size: 24px;
}

.admin-card-title {
  font-size: 15px;
  font-weight: 700;
}

.admin-card-desc {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.4;
}

/* Collapse Menu */
.collapse-section {
  margin: 0 16px 24px 16px;
  background: rgba(0,0,0,0.2);
  border-radius: 12px;
  overflow: hidden;
}

.collapse-header {
  padding: 16px;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
  user-select: none;
}

.collapse-header:hover {
  background: rgba(255,255,255,0.05);
}

.collapse-title {
  font-size: 14px;
  font-weight: 600;
  color: #94a3b8;
}

.collapse-arrow {
  transition: transform 0.2s;
}

.collapse-arrow.open {
  transform: rotate(180deg);
}

.collapse-content {
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.3s ease;
}

.collapse-content.open {
  max-height: 500px;
}

.collapse-item {
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  text-decoration: none;
  color: #e9eefc;
  border-top: 1px solid rgba(255,255,255,0.05);
  transition: background 0.2s;
}

.collapse-item:hover {
  background: rgba(255,255,255,0.05);
}

.collapse-item-icon {
  font-size: 20px;
  width: 24px;
  text-align: center;
}

.collapse-item-text {
  flex: 1;
  font-size: 14px;
}

.collapse-item-arrow {
  font-size: 12px;
  color: #94a3b8;
}

@media (max-width: 768px) {
  .ios-grid {
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }
  
  .grid-icon {
    font-size: 28px;
  }
  
  .grid-label {
    font-size: 11px;
  }
  
  .admin-cards {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 380px) {
  .ios-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>

<div class="home-container">
  
  <!-- Hlavní navigace (iOS Grid) -->
  <div class="section-title">Hlavní menu</div>
  <div class="ios-grid">
    
    <a href="{{ url_for('matches') }}" class="grid-item">
      <div class="grid-icon">⚽</div>
      <div class="grid-label">Zápasy</div>
      {% if total_matches - my_tips_count > 0 %}
      <div class="grid-badge">{{ total_matches - my_tips_count }}</div>
      {% endif %}
    </a>
    
    <a href="{{ url_for('leaderboard') }}" class="grid-item">
      <div class="grid-icon">📊</div>
      <div class="grid-label">Žebříček</div>
    </a>
    
    <a href="{{ url_for('mini_leaderboards') }}" class="grid-item">
      <div class="grid-icon">🏅</div>
      <div class="grid-label">Mini žebříčky</div>
    </a>
    
    <a href="{{ url_for('compare') }}" class="grid-item">
      <div class="grid-icon">🆚</div>
      <div class="grid-label">Porovnat</div>
    </a>
    
    <a href="{{ url_for('my_tips') }}" class="grid-item">
      <div class="grid-icon">🎯</div>
      <div class="grid-label">Moje tipy</div>
    </a>
    
    <a href="{{ url_for('my_stats') }}" class="grid-item">
      <div class="grid-icon">📈</div>
      <div class="grid-label">Statistiky</div>
    </a>
    
    <a href="{{ url_for('achievements') }}" class="grid-item">
      <div class="grid-icon">🏆</div>
      <div class="grid-label">Achievementy</div>
    </a>
    
    <a href="{{ url_for('extras') }}" class="grid-item">
      <div class="grid-icon">🎯</div>
      <div class="grid-label">Extra</div>
    </a>
    
    <a href="{{ url_for('archive') }}" class="grid-item">
      <div class="grid-icon">📚</div>
      <div class="grid-label">Archiv</div>
    </a>
    
    <a href="{{ url_for('dashboard') }}" class="grid-item">
      <div class="grid-icon">📊</div>
      <div class="grid-label">Dashboard</div>
    </a>
    
  </div>
  
  <!-- Admin sekce (Cards) -->
  {% if current_user.is_admin_effective %}
  <div class="section-title">Administrace</div>
  <div class="admin-cards">
    
    <a href="{{ url_for('admin_dashboard') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🏅</div>
        <div class="admin-card-title">Admin Dashboard</div>
      </div>
      <div class="admin-card-desc">Přehled a statistiky</div>
    </a>
    
    <a href="{{ url_for('admin_bulk_edit') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">✏️</div>
        <div class="admin-card-title">Bulk Edit</div>
      </div>
      <div class="admin-card-desc">Zadávání výsledků</div>
    </a>
    
    <a href="{{ url_for('admin_import') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">📥</div>
        <div class="admin-card-title">Import</div>
      </div>
      <div class="admin-card-desc">Importovat data</div>
    </a>
    
    <a href="{{ url_for('admin_export_hub') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">📤</div>
        <div class="admin-card-title">Export</div>
      </div>
      <div class="admin-card-desc">Exportovat data</div>
    </a>
    
    <a href="{{ url_for('admin_undo') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">⏪</div>
        <div class="admin-card-title">Undo</div>
      </div>
      <div class="admin-card-desc">Vrátit změny</div>
    </a>
    
    <a href="{{ url_for('admin_rounds') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🎮</div>
        <div class="admin-card-title">Soutěže</div>
      </div>
      <div class="admin-card-desc">Správa soutěží</div>
    </a>
    
    <a href="{{ url_for('admin_users') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">👥</div>
        <div class="admin-card-title">Uživatelé</div>
      </div>
      <div class="admin-card-desc">Správa userů</div>
    </a>
    
    <a href="{{ url_for('admin_api_sources') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🔌</div>
        <div class="admin-card-title">API Zdroje</div>
      </div>
      <div class="admin-card-desc">Fotbal & hokej API</div>
    </a>

    <a href="{{ url_for('admin_team_aliases') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🔁</div>
        <div class="admin-card-title">Aliasy týmů</div>
      </div>
      <div class="admin-card-desc">Mapování zkratek pro import</div>
    </a>

    <a href="{{ url_for('admin_smart_import') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🤖</div>
        <div class="admin-card-title">Smart Import</div>
      </div>
      <div class="admin-card-desc">AI parsování zápasů</div>
    </a>
    
  </div>
  {% endif %}
  
  <!-- Collapse menu (Ostatní) -->
  <div class="collapse-section">
    <div class="collapse-header" onclick="toggleCollapse(this)">
      <div class="collapse-title">Další možnosti</div>
      <div class="collapse-arrow">▼</div>
    </div>
    <div class="collapse-content">
      
      <a href="{{ url_for('notification_settings') }}" class="collapse-item">
        <div class="collapse-item-icon">🔔</div>
        <div class="collapse-item-text">Nastavení notifikací</div>
        <div class="collapse-item-arrow">›</div>
      </a>
      
      <a href="{{ url_for('archive_compare') }}" class="collapse-item">
        <div class="collapse-item-icon">🆚</div>
        <div class="collapse-item-text">Srovnat soutěže</div>
        <div class="collapse-item-arrow">›</div>
      </a>
      
      <a href="{{ url_for('archive_calendar') }}" class="collapse-item">
        <div class="collapse-item-icon">📅</div>
        <div class="collapse-item-text">Kalendář soutěží</div>
        <div class="collapse-item-arrow">›</div>
      </a>
      
      {% if current_user.is_admin_effective %}
      <a href="{{ url_for('admin_audit') }}" class="collapse-item">
        <div class="collapse-item-icon">📋</div>
        <div class="collapse-item-text">Audit log</div>
        <div class="collapse-item-arrow">›</div>
      </a>
      {% endif %}
      
      <a href="{{ url_for('logout') }}" class="collapse-item">
        <div class="collapse-item-icon">🚪</div>
        <div class="collapse-item-text">Odhlásit se</div>
        <div class="collapse-item-arrow">›</div>
      </a>
      
    </div>
  </div>
  
</div>

<script>
function toggleCollapse(header) {
  const content = header.nextElementSibling;
  const arrow = header.querySelector('.collapse-arrow');
  
  content.classList.toggle('open');
  arrow.classList.toggle('open');
}
</script>
""", r=r, my_tips_count=my_tips_count, total_matches=total_matches, notification_count=notification_count)


    @app.route("/dashboard")
    @login_required
    def dashboard():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("admin_rounds") if current_user.is_admin_effective else url_for("logout"))

        now = datetime.now()

        # Nadcházející zápasy (max 5)
        upcoming_matches = Match.query.filter_by(round_id=r.id, is_deleted=False).filter(
            db.or_(Match.start_time == None, Match.start_time > now)
        ).order_by(Match.start_time.asc().nullslast()).limit(5).all()

        # Moje tipy na nadcházející zápasy
        my_tips = {t.match_id: t for t in Tip.query.filter_by(user_id=current_user.id).all()}

        # Top 3 žebříček
        users = User.query.all()
        user_scores = []
        for u in users:
            # Skrýt tajného uživatele
            is_secret = (u.email or "").lower() == (SECRET_USER_EMAIL or "").lower()
            if is_secret and not current_user.is_owner and current_user.id != u.id:
                continue

            tips = Tip.query.join(Match).filter(
                Tip.user_id == u.id,
                Match.round_id == r.id,
                Match.is_deleted == False
            ).all()

            total = 0
            for tip in tips:
                if tip.match.home_score is not None and tip.match.away_score is not None:
                    total += calc_points_for_tip(tip.match, tip)

            user_scores.append({'user': u, 'total': total})

        user_scores.sort(key=lambda x: -x['total'])
        top3 = user_scores[:3]

        # Moje pozice
        my_position = None
        my_points = 0
        for idx, item in enumerate(user_scores, 1):
            if item['user'].id == current_user.id:
                my_position = idx
                my_points = item['total']
                break

        # Čas do uzávěrky
        time_to_close = None
        if r.tips_close_time and r.tips_close_time > now:
            delta = r.tips_close_time - now
            hours = int(delta.total_seconds() / 3600)
            minutes = int((delta.total_seconds() % 3600) / 60)
            time_to_close = f"{hours}h {minutes}m"

        # ===== NOVÉ STATISTIKY =====
        
        # Moje tipy s vyhodnocenými zápasy
        my_all_tips = Tip.query.join(Match).filter(
            Tip.user_id == current_user.id,
            Match.round_id == r.id,
            Match.is_deleted == False,
            Match.home_score != None,
            Match.away_score != None
        ).all()

        # % úspěšnosti
        total_tips = len(my_all_tips)
        exact_tips = 0
        partial_tips = 0
        
        for tip in my_all_tips:
            points = calc_points_for_tip(tip.match, tip)
            if points == 3:
                exact_tips += 1
            elif points == 1:
                partial_tips += 1
        
        success_rate = 0
        if total_tips > 0:
            success_rate = int((exact_tips + partial_tips) / total_tips * 100)
        
        exact_rate = 0
        if total_tips > 0:
            exact_rate = int(exact_tips / total_tips * 100)

        # Hot streak (nejdelší série správných tipů)
        current_streak = 0
        max_streak = 0
        
        # Seřadit tipy podle data zápasu
        sorted_tips = sorted(my_all_tips, key=lambda t: t.match.start_time or datetime.min)
        
        for tip in sorted_tips:
            points = calc_points_for_tip(tip.match, tip)
            if points > 0:  # Alespoň nějaké body
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 0

        # Nejlepší/nejhorší zápas
        best_match = None
        best_points = -1
        worst_match = None
        worst_points = 4  # Více než maximum (3)
        
        for tip in my_all_tips:
            points = calc_points_for_tip(tip.match, tip)
            
            if points > best_points:
                best_points = points
                best_match = tip.match
            
            if points < worst_points:
                worst_points = points
                worst_match = tip.match

        # Graf vývoje bodů (posledních 10 zápasů)
        graph_data = []
        cumulative_points = 0
        
        for tip in sorted_tips[-10:]:  # Posledních 10
            points = calc_points_for_tip(tip.match, tip)
            cumulative_points += points
            graph_data.append({
                'match': f"{tip.match.home_team.name[:3]}-{tip.match.away_team.name[:3]}",
                'points': points,
                'cumulative': cumulative_points
            })

        return render_page(r"""
<style>
  .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
  .stat-card { background: rgba(255,255,255,.03); border-radius: 14px; padding: 20px; border: 1px solid var(--line); }
  .stat-number { font-size: 36px; font-weight: 900; color: #33d17a; margin: 10px 0; }
  .stat-label { color: rgba(233,238,252,.65); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
  .quick-actions { display: flex; gap: 10px; flex-wrap: wrap; }
  
  /* Pokročilé statistiky */
  .stats-section { margin-bottom: 20px; }
  .progress-bar { background: rgba(255,255,255,.1); border-radius: 10px; height: 24px; overflow: hidden; position: relative; margin-top: 10px; }
  .progress-fill { background: linear-gradient(90deg, #33d17a, #26a269); height: 100%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 900; transition: width 0.5s; }
  .progress-fill.exact { background: linear-gradient(90deg, #ffc107, #ff9800); }
  
  /* Graf */
  .chart-container { margin-top: 20px; }
  .chart-bars { display: flex; align-items: flex-end; gap: 8px; height: 120px; }
  .chart-bar { flex: 1; background: linear-gradient(to top, #33d17a, #26a269); border-radius: 4px 4px 0 0; position: relative; min-height: 10px; transition: all 0.3s; }
  .chart-bar:hover { opacity: 0.8; }
  .chart-bar-label { position: absolute; top: -20px; left: 50%; transform: translateX(-50%); font-size: 11px; font-weight: 900; white-space: nowrap; }
  .chart-bar-match { text-align: center; font-size: 10px; color: rgba(233,238,252,.65); margin-top: 4px; }
  
  /* Hot streak */
  .streak-badge { display: inline-block; background: linear-gradient(135deg, #ff6b6b, #ff8e53); color: white; padding: 8px 16px; border-radius: 20px; font-weight: 900; font-size: 14px; }
  .streak-badge.cold { background: linear-gradient(135deg, #6c757d, #5a6268); }
  
  /* Best/worst match */
  .match-highlight { background: rgba(255,255,255,.05); border-radius: 10px; padding: 12px; margin-top: 10px; }
  .match-highlight.best { border-left: 4px solid #33d17a; }
  .match-highlight.worst { border-left: 4px solid #ff6b6b; }
  
  @media (max-width: 768px) {
    .dashboard-grid { grid-template-columns: 1fr; }
    .chart-bars { gap: 4px; }
  }
</style>

<div class="card">
  <h2 style="margin: 0 0 8px 0;">📊 Dashboard</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
</div>

<!-- Základní statistiky -->
<div class="stats-section">
  <h3 style="margin: 0 0 15px 0;">Tvoje statistiky</h3>
  <div class="dashboard-grid">
    <div class="stat-card">
      <div class="stat-label">Pozice v žebříčku</div>
      <div class="stat-number">{% if my_position %}#{{ my_position }}{% else %}—{% endif %}</div>
      <div class="muted">z {{ user_scores|length }} tipérů • {{ my_points }} bodů</div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Úspěšnost tipů</div>
      <div class="stat-number">{{ success_rate }}%</div>
      <div class="muted">{{ exact_tips + partial_tips }} správných z {{ total_tips }}</div>
      <div class="progress-bar">
        <div class="progress-fill" style="width: {{ success_rate }}%;">{{ success_rate }}%</div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Přesné tipy</div>
      <div class="stat-number" style="color: #ffc107;">{{ exact_rate }}%</div>
      <div class="muted">{{ exact_tips }} přesných z {{ total_tips }}</div>
      <div class="progress-bar">
        <div class="progress-fill exact" style="width: {{ exact_rate }}%;">{{ exact_rate }}%</div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Nenatipované zápasy</div>
      <div class="stat-number" style="color: {% if (upcoming_matches|length - (upcoming_matches|selectattr('id', 'in', my_tips.keys())|list|length)) > 0 %}#ff6b6b{% else %}#33d17a{% endif %};">
        {{ upcoming_matches|length - (upcoming_matches|selectattr('id', 'in', my_tips.keys())|list|length) }}
      </div>
      <div class="muted">z {{ upcoming_matches|length }} nadcházejících</div>
    </div>

    {% if time_to_close %}
    <div class="stat-card">
      <div class="stat-label">Do uzávěrky</div>
      <div class="stat-number" style="font-size: 28px; color: {% if 'h 0m' in time_to_close or time_to_close.startswith('0h') %}#ff6b6b{% else %}#33d17a{% endif %};">
        {{ time_to_close }}
      </div>
      <div class="muted">{{ r.tips_close_time.strftime('%d.%m. %H:%M') }}</div>
    </div>
    {% endif %}

    <div class="stat-card">
      <div class="stat-label">
        Hot Streak 🔥
        <span style="font-size: 11px; font-weight: 400; opacity: 0.7; margin-left: 6px;" title="Nejdelší série správných tipů po sobě">ⓘ</span>
      </div>
      <div class="stat-number" style="font-size: 32px;">{{ max_streak }}</div>
      <div class="muted">
        {% if max_streak >= 5 %}
          <span class="streak-badge">🔥 V ohni!</span>
        {% elif max_streak >= 3 %}
          <span class="streak-badge">💪 Dobrá forma</span>
        {% elif max_streak > 0 %}
          <span class="streak-badge cold">Začínáš</span>
        {% else %}
          <span class="muted">Zatím žádná série</span>
        {% endif %}
        <div style="font-size: 11px; margin-top: 8px; opacity: 0.7; line-height: 1.4;">
          Nejdelší série správných tipů po sobě
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Graf vývoje -->
{% if graph_data|length > 0 %}
<div class="card stats-section">
  <h3 style="margin: 0 0 15px 0;">📈 Vývoj bodů (posledních {{ graph_data|length }} zápasů)</h3>
  <div class="chart-container">
    <div class="chart-bars">
      {% for item in graph_data %}
        <div class="chart-bar" style="height: {% if item.points > 0 %}{{ (item.points / 3 * 100)|int }}%{% else %}8%{% endif %};">
          <div class="chart-bar-label">{{ item.points }}</div>
        </div>
      {% endfor %}
    </div>
    <div style="display: flex; gap: 8px; margin-top: 8px;">
      {% for item in graph_data %}
        <div class="chart-bar-match" style="flex: 1;">{{ item.match }}</div>
      {% endfor %}
    </div>
  </div>
  <div class="muted" style="margin-top: 15px; text-align: center;">
    Celkem: <b>{{ graph_data[-1].cumulative if graph_data else 0 }}</b> bodů z posledních {{ graph_data|length }} zápasů
  </div>
</div>
{% endif %}

<!-- Nejlepší/nejhorší zápas -->
{% if best_match or worst_match %}
<div class="card stats-section">
  <h3 style="margin: 0 0 15px 0;">🎯 Tvoje výkony</h3>
  
  {% if best_match %}
  <div class="match-highlight best">
    <div style="font-size: 12px; color: #33d17a; font-weight: 900; margin-bottom: 4px;">
      ✓ NEJLEPŠÍ ZÁPAS ({{ best_points }} {% if best_points == 1 %}bod{% elif best_points < 5 %}body{% else %}bodů{% endif %})
    </div>
    <div style="font-weight: 900;">
      {{ best_match.home_team.name }} {{ best_match.home_score }}:{{ best_match.away_score }} {{ best_match.away_team.name }}
    </div>
    {% set my_tip = my_tips.get(best_match.id) %}
    {% if my_tip %}
      <div class="muted" style="font-size: 12px;">
        Tvůj tip: {{ my_tip.tip_home }}:{{ my_tip.tip_away }}
        {% if best_points == 3 %}🎯 Přesný tip!{% elif best_points == 1 %}✓ Správný výsledek{% endif %}
      </div>
    {% endif %}
  </div>
  {% endif %}
  
  {% if worst_match and worst_points == 0 %}
  <div class="match-highlight worst">
    <div style="font-size: 12px; color: #ff6b6b; font-weight: 900; margin-bottom: 4px;">
      ✗ NEJHORŠÍ ZÁPAS (0 bodů)
    </div>
    <div style="font-weight: 900;">
      {{ worst_match.home_team.name }} {{ worst_match.home_score }}:{{ worst_match.away_score }} {{ worst_match.away_team.name }}
    </div>
    {% set my_tip = my_tips.get(worst_match.id) %}
    {% if my_tip %}
      <div class="muted" style="font-size: 12px;">
        Tvůj tip: {{ my_tip.tip_home }}:{{ my_tip.tip_away }} ✗ Netrefil
      </div>
    {% endif %}
  </div>
  {% endif %}
</div>
{% endif %}

<div class="card">
  <h3 style="margin: 0 0 15px 0;">🏆 Top 3</h3>
  {% for item in top3 %}
    <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
      <div>
        <span style="font-size: 20px; margin-right: 10px;">{% if loop.index == 1 %}🥇{% elif loop.index == 2 %}🥈{% else %}🥉{% endif %}</span>
        <strong>{{ item.user.username }}</strong>
      </div>
      <div style="font-weight: 900; font-size: 18px;">{{ item.total }}</div>
    </div>
  {% endfor %}
  <hr class="sep">
  <a class="btn" href="{{ url_for('leaderboard') }}">Celý žebříček →</a>
</div>

{% if upcoming_matches|length > 0 %}
<div class="card">
  <h3 style="margin: 0 0 15px 0;">⚽ Nadcházející zápasy</h3>
  {% for m in upcoming_matches %}
    <div class="row" style="justify-content: space-between; margin-bottom: 12px;">
      <div>
        <strong>{{ m.home_team.name }} - {{ m.away_team.name }}</strong>
        <div class="muted" style="font-size: 12px;">
          {% if m.start_time %}{{ m.start_time.strftime('%d.%m. %H:%M') }}{% else %}Čas bude upřesněn{% endif %}
        </div>
      </div>
      <div>
        {% if my_tips.get(m.id) %}
          <span class="tag pill-ok">✓ Tipoval</span>
        {% else %}
          <span class="tag pill-bad">Netipoval</span>
        {% endif %}
      </div>
    </div>
  {% endfor %}
  <hr class="sep">
  <a class="btn btn-primary" href="{{ url_for('matches') }}">Tipovat zápasy →</a>
</div>
{% endif %}

<div class="card">
  <h3 style="margin: 0 0 15px 0;">Rychlé odkazy</h3>
  <div class="quick-actions">
    <a class="btn btn-primary" href="{{ url_for('my_stats') }}">📊 Detailní statistiky</a>
    <a class="btn" href="{{ url_for('matches') }}">Zápasy</a>
    <a class="btn" href="{{ url_for('extras') }}">Extra otázky</a>
    <a class="btn" href="{{ url_for('leaderboard') }}">Žebříček</a>
    <a class="btn" href="{{ url_for('teams') }}">Týmy</a>
  </div>
</div>
""", r=r, upcoming_matches=upcoming_matches, my_tips=my_tips, top3=top3,
     my_position=my_position, my_points=my_points, time_to_close=time_to_close,
     user_scores=user_scores, total_tips=total_tips, exact_tips=exact_tips, 
     partial_tips=partial_tips, success_rate=success_rate, exact_rate=exact_rate,
     max_streak=max_streak, best_match=best_match, best_points=best_points,
     worst_match=worst_match, worst_points=worst_points, graph_data=graph_data)

    # --- MOJE STATISTIKY (detailní analýza) ---
    @app.route("/my-stats")
    @login_required
    def my_stats():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("dashboard"))

        # Načti všechny moje tipy s vyhodnocenými zápasy
        my_tips = Tip.query.join(Match).filter(
            Tip.user_id == current_user.id,
            Match.round_id == r.id,
            Match.is_deleted == False,
            Match.home_score != None,
            Match.away_score != None
        ).all()

        # Základní statistiky
        total_tips = len(my_tips)
        exact_tips = 0  # 3 body
        partial_tips = 0  # 1 bod
        failed_tips = 0  # 0 bodů
        total_points = 0

        for tip in my_tips:
            points = calc_points_for_tip(tip.match, tip)
            total_points += points
            if points == 3:
                exact_tips += 1
            elif points == 1:
                partial_tips += 1
            else:
                failed_tips += 1

        # Průměrné body na zápas
        avg_points = round(total_points / total_tips, 2) if total_tips > 0 else 0

        # Analýza typů tipů (výhra domácích / remíza / výhra hostů)
        home_wins = 0  # Tipoval výhru domácích
        draws = 0  # Tipoval remízu
        away_wins = 0  # Tipoval výhru hostů

        for tip in my_tips:
            if tip.tip_home > tip.tip_away:
                home_wins += 1
            elif tip.tip_home == tip.tip_away:
                draws += 1
            else:
                away_wins += 1

        # Nejčastější typ tipu
        most_common_type = "Výhra domácích"
        most_common_count = home_wins
        if draws > most_common_count:
            most_common_type = "Remíza"
            most_common_count = draws
        if away_wins > most_common_count:
            most_common_type = "Výhra hostů"
            most_common_count = away_wins

        # Oblíbené týmy (nejlepší úspěšnost)
        team_stats = {}  # {team_id: {'name': ..., 'tips': 0, 'points': 0}}

        for tip in my_tips:
            for team in [tip.match.home_team, tip.match.away_team]:
                if team.id not in team_stats:
                    team_stats[team.id] = {'name': team.name, 'tips': 0, 'points': 0}
                
                team_stats[team.id]['tips'] += 1
                team_stats[team.id]['points'] += calc_points_for_tip(tip.match, tip)

        # Spočítej průměr pro každý tým (min 2 tipy)
        team_averages = []
        for team_id, stats in team_stats.items():
            if stats['tips'] >= 2:  # Minimálně 2 tipy
                avg = round(stats['points'] / stats['tips'], 2)
                team_averages.append({
                    'name': stats['name'],
                    'tips': stats['tips'],
                    'points': stats['points'],
                    'avg': avg
                })

        # Seřaď podle průměru (nejlepší první)
        team_averages.sort(key=lambda x: (-x['avg'], -x['tips']))
        top_teams = team_averages[:5]  # Top 5 týmů
        worst_teams = team_averages[-5:] if len(team_averages) > 5 else []  # Worst 5

        # Srovnání s průměrem skupiny
        all_users = User.query.all()
        group_total_points = 0
        group_total_tips = 0

        for u in all_users:
            # Skrýt tajného uživatele
            is_secret = (u.email or "").lower() == (SECRET_USER_EMAIL or "").lower()
            if is_secret and not current_user.is_owner and current_user.id != u.id:
                continue

            u_tips = Tip.query.join(Match).filter(
                Tip.user_id == u.id,
                Match.round_id == r.id,
                Match.is_deleted == False,
                Match.home_score != None,
                Match.away_score != None
            ).all()

            for tip in u_tips:
                group_total_points += calc_points_for_tip(tip.match, tip)
                group_total_tips += 1

        group_avg = round(group_total_points / group_total_tips, 2) if group_total_tips > 0 else 0
        diff_from_avg = round(avg_points - group_avg, 2)

        return render_page(r"""
<style>
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-bottom: 20px; }
  .mini-stat { background: rgba(255,255,255,.03); border-radius: 10px; padding: 16px; border: 1px solid var(--line); }
  .mini-stat-label { font-size: 12px; color: rgba(233,238,252,.65); margin-bottom: 4px; }
  .mini-stat-value { font-size: 24px; font-weight: 900; color: #33d17a; }
  
  .pie-chart { width: 200px; height: 200px; margin: 20px auto; }
  .team-list { list-style: none; padding: 0; }
  .team-item { display: flex; justify-content: space-between; padding: 10px; background: rgba(255,255,255,.03); margin-bottom: 8px; border-radius: 8px; }
  .team-item.best { border-left: 3px solid #33d17a; }
  .team-item.worst { border-left: 3px solid #ff6b6b; }
  
  .comparison-card { text-align: center; padding: 20px; }
  .comparison-number { font-size: 48px; font-weight: 900; margin: 10px 0; }
  .comparison-number.better { color: #33d17a; }
  .comparison-number.worse { color: #ff6b6b; }
  .comparison-number.equal { color: #ffc107; }
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: center;">
    <div>
      <h2 style="margin: 0 0 8px 0;">📊 Moje statistiky</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b> • Vyhodnoceno: {{ total_tips }} zápasů</div>
    </div>
    <a class="btn" href="{{ url_for('dashboard') }}">← Dashboard</a>
  </div>
</div>

<!-- Základní metriky -->
<div class="card">
  <h3 style="margin: 0 0 15px 0;">Základní metriky</h3>
  <div class="stats-grid">
    <div class="mini-stat">
      <div class="mini-stat-label">Celkem bodů</div>
      <div class="mini-stat-value">{{ total_points }}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Průměr na zápas</div>
      <div class="mini-stat-value">{{ avg_points }}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Přesné tipy</div>
      <div class="mini-stat-value" style="color: #ffc107;">{{ exact_tips }}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Částečné tipy</div>
      <div class="mini-stat-value" style="color: #6ea8fe;">{{ partial_tips }}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Netrefené</div>
      <div class="mini-stat-value" style="color: #ff6b6b;">{{ failed_tips }}</div>
    </div>
  </div>
</div>

<!-- Srovnání s průměrem -->
<div class="card">
  <h3 style="margin: 0 0 15px 0;">📈 Srovnání s průměrem skupiny</h3>
  <div class="comparison-card">
    <div class="muted">Tvůj průměr vs skupinový průměr</div>
    <div class="comparison-number {% if diff_from_avg > 0 %}better{% elif diff_from_avg < 0 %}worse{% else %}equal{% endif %}">
      {% if diff_from_avg > 0 %}+{% endif %}{{ diff_from_avg }}
    </div>
    <div class="row" style="justify-content: center; gap: 40px; margin-top: 20px;">
      <div>
        <div class="muted" style="font-size: 12px;">Ty</div>
        <div style="font-size: 32px; font-weight: 900;">{{ avg_points }}</div>
      </div>
      <div>
        <div class="muted" style="font-size: 12px;">Průměr skupiny</div>
        <div style="font-size: 32px; font-weight: 900; color: rgba(233,238,252,.5);">{{ group_avg }}</div>
      </div>
    </div>
    {% if diff_from_avg > 0 %}
      <div style="margin-top: 15px; color: #33d17a;">✓ Jsi nad průměrem!</div>
    {% elif diff_from_avg < 0 %}
      <div style="margin-top: 15px; color: #ff6b6b;">Jsi pod průměrem, ale můžeš se zlepšit!</div>
    {% else %}
      <div style="margin-top: 15px; color: #ffc107;">Jsi přesně na průměru!</div>
    {% endif %}
  </div>
</div>

<!-- Rozdělení bodů -->
<div class="card">
  <h3 style="margin: 0 0 15px 0;">🎯 Rozdělení bodů</h3>
  <div style="display: flex; gap: 20px; flex-wrap: wrap; align-items: center; justify-content: space-around;">
    <div style="text-align: center;">
      <div style="font-size: 48px; font-weight: 900; color: #ffc107;">{{ exact_tips }}</div>
      <div class="muted">zápasů</div>
      <div style="font-weight: 900; margin-top: 4px;">Přesné tipy</div>
      <div class="muted" style="font-size: 12px;">{{ exact_tips * 3 }} bodů celkem</div>
      <div style="font-size: 12px; margin-top: 4px;">
        {% if total_tips > 0 %}{{ (exact_tips / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
    <div style="text-align: center;">
      <div style="font-size: 48px; font-weight: 900; color: #6ea8fe;">{{ partial_tips }}</div>
      <div class="muted">zápasů</div>
      <div style="font-weight: 900; margin-top: 4px;">Částečné tipy</div>
      <div class="muted" style="font-size: 12px;">{{ partial_tips * 1 }} bodů celkem</div>
      <div style="font-size: 12px; margin-top: 4px;">
        {% if total_tips > 0 %}{{ (partial_tips / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
    <div style="text-align: center;">
      <div style="font-size: 48px; font-weight: 900; color: #ff6b6b;">{{ failed_tips }}</div>
      <div class="muted">zápasů</div>
      <div style="font-weight: 900; margin-top: 4px;">Netrefené</div>
      <div class="muted" style="font-size: 12px;">{{ failed_tips * 0 }} bodů celkem</div>
      <div style="font-size: 12px; margin-top: 4px;">
        {% if total_tips > 0 %}{{ (failed_tips / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
  </div>
</div>

<!-- Analýza tendencí -->
<div class="card">
  <h3 style="margin: 0 0 15px 0;">🎲 Tvoje tipovací tendence</h3>
  <div class="stats-grid">
    <div class="mini-stat">
      <div class="mini-stat-label">Výhry domácích</div>
      <div class="mini-stat-value" style="font-size: 20px;">{{ home_wins }}</div>
      <div class="muted" style="font-size: 11px;">
        {% if total_tips > 0 %}{{ (home_wins / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Remízy</div>
      <div class="mini-stat-value" style="font-size: 20px;">{{ draws }}</div>
      <div class="muted" style="font-size: 11px;">
        {% if total_tips > 0 %}{{ (draws / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
    <div class="mini-stat">
      <div class="mini-stat-label">Výhry hostů</div>
      <div class="mini-stat-value" style="font-size: 20px;">{{ away_wins }}</div>
      <div class="muted" style="font-size: 11px;">
        {% if total_tips > 0 %}{{ (away_wins / total_tips * 100)|int }}%{% else %}0%{% endif %}
      </div>
    </div>
  </div>
  <div style="margin-top: 15px; text-align: center; padding: 10px; background: rgba(255,255,255,.03); border-radius: 8px;">
    <div class="muted" style="font-size: 12px;">Nejčastěji tipuješ</div>
    <div style="font-size: 18px; font-weight: 900; margin-top: 4px;">{{ most_common_type }}</div>
    <div class="muted" style="font-size: 11px;">{{ most_common_count }}× z {{ total_tips }}</div>
  </div>
</div>

<!-- Oblíbené týmy -->
{% if top_teams|length > 0 %}
<div class="card">
  <h3 style="margin: 0 0 15px 0;">⭐ Tvoje oblíbené týmy (nejlepší úspěšnost)</h3>
  <div class="muted" style="margin-bottom: 12px; font-size: 13px;">Týmy u kterých získáváš nejvíc bodů (min. 2 tipy)</div>
  <ul class="team-list">
    {% for team in top_teams %}
      <li class="team-item best">
        <div>
          <strong>{{ team.name }}</strong>
          <div class="muted" style="font-size: 12px;">{{ team.tips }} tipů • {{ team.points }} bodů</div>
        </div>
        <div style="font-size: 20px; font-weight: 900; color: #33d17a;">{{ team.avg }}</div>
      </li>
    {% endfor %}
  </ul>
</div>
{% endif %}

<!-- Problémové týmy -->
{% if worst_teams|length > 0 %}
<div class="card">
  <h3 style="margin: 0 0 15px 0;">⚠️ Problémové týmy (nejhorší úspěšnost)</h3>
  <div class="muted" style="margin-bottom: 12px; font-size: 13px;">Týmy u kterých získáváš nejméně bodů</div>
  <ul class="team-list">
    {% for team in worst_teams|reverse %}
      <li class="team-item worst">
        <div>
          <strong>{{ team.name }}</strong>
          <div class="muted" style="font-size: 12px;">{{ team.tips }} tipů • {{ team.points }} bodů</div>
        </div>
        <div style="font-size: 20px; font-weight: 900; color: #ff6b6b;">{{ team.avg }}</div>
      </li>
    {% endfor %}
  </ul>
</div>
{% endif %}

""", r=r, total_tips=total_tips, exact_tips=exact_tips, partial_tips=partial_tips,
     failed_tips=failed_tips, total_points=total_points, avg_points=avg_points,
     home_wins=home_wins, draws=draws, away_wins=away_wins, 
     most_common_type=most_common_type, most_common_count=most_common_count,
     top_teams=top_teams, worst_teams=worst_teams,
     group_avg=group_avg, diff_from_avg=diff_from_avg)

    # --- ACHIEVEMENTY / ODZNAKY ---
    @app.route("/achievements")
    @login_required
    def achievements():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("dashboard"))
        
        # Načti moje achievementy
        my_achievements = get_user_achievements(current_user.id, r.id)
        
        # Seřaď podle data získání (nejnovější první)
        my_achievements.sort(key=lambda x: x['earned_at'], reverse=True)
        
        # Spočítej kolik achievementů je k dispozici
        total_achievements = len(ACHIEVEMENTS)
        earned_count = len(my_achievements)
        
        # Seznam všech achievementů (abychom mohli zobrazit i ty co ještě nemáme)
        all_achievements_list = []
        for key, info in ACHIEVEMENTS.items():
            earned = any(a['type'] == key for a in my_achievements)
            earned_date = None
            if earned:
                for a in my_achievements:
                    if a['type'] == key:
                        earned_date = a['earned_at']
                        break
            
            all_achievements_list.append({
                'type': key,
                'name': info['name'],
                'icon': info['icon'],
                'description': info['description'],
                'color': info['color'],
                'earned': earned,
                'earned_at': earned_date
            })
        
        return render_page(r"""
<style>
  .achievements-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
  .achievement-card { 
    background: rgba(255,255,255,.03); 
    border-radius: 12px; 
    padding: 20px; 
    border: 2px solid var(--line); 
    text-align: center;
    transition: all 0.3s;
  }
  .achievement-card.earned { 
    border-color: var(--achievement-color); 
    background: linear-gradient(135deg, rgba(255,255,255,.05), rgba(var(--achievement-rgb), 0.1));
  }
  .achievement-card.locked { opacity: 0.5; filter: grayscale(100%); }
  .achievement-card:hover { transform: translateY(-4px); }
  .achievement-icon { font-size: 64px; margin-bottom: 10px; }
  .achievement-name { font-size: 18px; font-weight: 900; margin-bottom: 6px; }
  .achievement-desc { font-size: 13px; color: rgba(233,238,252,.65); margin-bottom: 10px; }
  .achievement-date { font-size: 11px; color: rgba(233,238,252,.5); }
  .achievement-badge { 
    display: inline-block; 
    padding: 4px 12px; 
    border-radius: 12px; 
    font-size: 11px; 
    font-weight: 900; 
    margin-top: 8px;
  }
  .badge-earned { background: linear-gradient(135deg, #33d17a, #26a269); color: white; }
  .badge-locked { background: rgba(255,255,255,.1); color: rgba(233,238,252,.5); }
  .progress-summary { 
    background: rgba(255,255,255,.05); 
    padding: 20px; 
    border-radius: 12px; 
    text-align: center; 
    margin-bottom: 24px;
  }
  .progress-bar-big { 
    background: rgba(255,255,255,.1); 
    height: 40px; 
    border-radius: 20px; 
    overflow: hidden; 
    margin-top: 12px;
  }
  .progress-fill-big { 
    background: linear-gradient(90deg, #33d17a, #26a269); 
    height: 100%; 
    display: flex; 
    align-items: center; 
    justify-content: center; 
    font-weight: 900; 
    transition: width 0.5s;
  }
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: center;">
    <div>
      <h2 style="margin: 0 0 8px 0;">🏆 Moje achievementy</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <a class="btn" href="{{ url_for('dashboard') }}">← Dashboard</a>
  </div>
</div>

<div class="progress-summary">
  <div style="font-size: 48px; font-weight: 900; color: #33d17a;">{{ earned_count }} / {{ total_achievements }}</div>
  <div class="muted">Odemčených achievementů</div>
  <div class="progress-bar-big">
    <div class="progress-fill-big" style="width: {% if total_achievements > 0 %}{{ (earned_count / total_achievements * 100)|int }}%{% else %}0%{% endif %};">
      {% if total_achievements > 0 %}{{ (earned_count / total_achievements * 100)|int }}%{% else %}0%{% endif %}
    </div>
  </div>
</div>

<div class="achievements-grid">
  {% for achievement in all_achievements_list %}
    <div class="achievement-card {% if achievement.earned %}earned{% else %}locked{% endif %}" 
         style="--achievement-color: {{ achievement.color }}; --achievement-rgb: {{ achievement.color|replace('#', '')|int(base=16) }};">
      <div class="achievement-icon">{{ achievement.icon }}</div>
      <div class="achievement-name" style="{% if achievement.earned %}color: {{ achievement.color }};{% endif %}">
        {{ achievement.name }}
      </div>
      <div class="achievement-desc">{{ achievement.description }}</div>
      {% if achievement.earned %}
        <div class="achievement-badge badge-earned">
          ✓ Odemčeno {{ achievement.earned_at.strftime('%d.%m.%Y') }}
        </div>
      {% else %}
        <div class="achievement-badge badge-locked">
          🔒 Zamčeno
        </div>
      {% endif %}
    </div>
  {% endfor %}
</div>

""", r=r, my_achievements=my_achievements, total_achievements=total_achievements,
     earned_count=earned_count, all_achievements_list=all_achievements_list)

    # --- MATCHES + TIPY ---
    @app.route("/matches", methods=["GET", "POST"])
    @login_required
    def matches():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž. Admin ji musí vytvořit.", "error")
            return redirect(url_for("admin_rounds") if current_user.is_admin_effective else url_for("logout"))

        # Kontrola, jestli uživatel může tipovat
        can_user_tip = current_user.can_tip

        if request.method == "POST":
            if not can_user_tip:
                flash("Nemáš oprávnění k tipování.", "error")
                return redirect(url_for("matches"))
            
            # Hromadné uložení (jako Bulk Edit)
            saved_count = 0
            for key in request.form:
                if key.startswith("tip_home_"):
                    match_id = int(key.replace("tip_home_", ""))
                    tip_home_key = f"tip_home_{match_id}"
                    tip_away_key = f"tip_away_{match_id}"

                    if tip_home_key in request.form and tip_away_key in request.form:
                        tip_home_val = request.form.get(tip_home_key, "").strip()
                        tip_away_val = request.form.get(tip_away_key, "").strip()

                        # Prázdný input = skip
                        if not tip_home_val and not tip_away_val:
                            continue

                        tip_home = int(tip_home_val) if tip_home_val else 0
                        tip_away = int(tip_away_val) if tip_away_val else 0

                        m = db.session.get(Match, match_id)
                        if not m or m.round_id != r.id:
                            continue

                        if is_tips_locked(r, m):
                            continue

                        existing = Tip.query.filter_by(user_id=current_user.id, match_id=m.id).first()
                        if existing:
                            existing.tip_home = tip_home
                            existing.tip_away = tip_away
                        else:
                            db.session.add(Tip(user_id=current_user.id, match_id=m.id, tip_home=tip_home, tip_away=tip_away))
                        saved_count += 1

            db.session.commit()
            
            # Cache bodů pro leaderboard
            try:
                recompute_round_user_score(r.id, current_user.id)
            except Exception:
                db.session.rollback()
            
            # Zkontroluj achievementy
            check_and_award_achievements(current_user.id, r.id)
            
            audit("tip.save_all", "Tip", None, count=saved_count)
            flash(f"💾 Uloženo {saved_count} tipů.", "ok")
            return redirect(url_for("matches"))

        # Načti zápasy k tipování (bez výsledku)
        now = now_utc()
        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).filter(
            db.or_(Match.start_time == None, Match.start_time > now),
            db.or_(Match.home_score == None, Match.away_score == None)
        ).order_by(Match.start_time.asc().nullslast(), Match.id.asc()).all()

        # Moje tipy
        tips = Tip.query.filter_by(user_id=current_user.id).all()
        tip_map = {t.match_id: t for t in tips}
        
        # Stats
        total = len(matches_q)
        with_tips = sum(1 for m in matches_q if m.id in tip_map)
        without_tips = total - with_tips

        return render_page(r"""
<style>
  .matches-table {
    width: 100%;
    border-collapse: collapse;
  }
  
  .matches-table th,
  .matches-table td {
    padding: 12px 8px;
    text-align: left;
    border-bottom: 1px solid var(--line);
  }
  
  .matches-table th {
    background: rgba(255,255,255,.03);
    font-weight: 900;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  
  .matches-table input[type="number"] {
    width: 60px;
    text-align: center;
    font-size: 18px;
    font-weight: 900;
    padding: 8px;
  }
  
  .match-row:hover {
    background: rgba(255,255,255,.03);
  }
  
  .match-row.has-tip {
    background: rgba(110,168,254,.08);
  }
  
  .match-row.locked {
    opacity: 0.6;
    background: rgba(255,255,255,.02);
  }
  
  /* Mobile optimalizace */
  @media (max-width: 768px) {
    .matches-table th,
    .matches-table td {
      padding: 8px 4px;
      font-size: 13px;
    }
    
    .matches-table input[type="number"] {
      width: 50px;
      font-size: 16px;
      padding: 6px;
    }
    
    .match-row .team-name {
      display: block;
      max-width: 120px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
  }
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: center; flex-wrap: wrap;">
    <div>
      <h2 style="margin: 0 0 8px 0;">⚽ Zápasy k tipování</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <div class="row" style="gap: 8px;">
      <div class="tag pill-ok">✅ {{ with_tips }}</div>
      <div class="tag pill-warn">⏳ {{ without_tips }}</div>
    </div>
  </div>
</div>

{% if not can_user_tip %}
  <div class="card" style="background:rgba(255,77,109,0.08); border-color:rgba(255,77,109,0.3);">
    <div style="text-align:center; padding:20px;">
      <div style="font-size:48px; margin-bottom:12px;">🚫</div>
      <h3 style="margin:0 0 8px 0;">Nemáš oprávnění k tipování</h3>
      <div class="muted">Kontaktuj administrátora pro změnu role.</div>
    </div>
  </div>
{% elif total == 0 %}
  <div class="card">
    <div style="text-align:center; padding:40px;">
      <div style="font-size:48px; margin-bottom:12px;">✅</div>
      <h3 style="margin:0 0 8px 0;">Všechny zápasy natipované!</h3>
      <div class="muted">Žádné další zápasy k tipování.</div>
    </div>
  </div>
{% else %}

<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

  <div class="card">
    <div class="row" style="justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap;">
      <h3 style="margin: 0;">📋 Zápasy ({{ total }})</h3>
      <div class="row" style="gap: 8px;">
        {% if current_user.is_admin_effective %}
          <a href="{{ url_for('admin_match_new') }}" class="btn" style="background: rgba(51,209,122,.15); color: #33d17a; border: 1px solid rgba(51,209,122,.3);">
            ➕ Přidat zápas
          </a>
        {% endif %}
        <button type="submit" class="btn btn-primary">💾 Uložit všechny tipy</button>
      </div>
    </div>
    
    <div class="muted" style="margin-bottom:12px; padding:10px; background:rgba(110,168,254,0.08); border-radius:8px; border:1px solid rgba(110,168,254,0.2);">
      💡 <strong>Tip:</strong> Zadej tipy do tabulky a klikni "Uložit všechny tipy" dole. Prázdné pole = 0.
    </div>
    
    <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
      <table class="matches-table">
        <thead>
          <tr>
            <th style="width: 40px;">#</th>
            <th>Domácí</th>
            <th style="width: 70px; text-align: center;">Tip</th>
            <th style="width: 30px; text-align: center;">:</th>
            <th style="width: 70px; text-align: center;">Tip</th>
            <th>Hosté</th>
            <th style="width: 120px;">Datum/Čas</th>
          </tr>
        </thead>
        <tbody>
          {% for m in matches %}
            {% set locked = tips_locked(r, m) %}
            {% set my_tip = tip_map.get(m.id) %}
            <tr class="match-row {% if my_tip %}has-tip{% endif %} {% if locked %}locked{% endif %}">
              <td>{{ loop.index }}</td>
              <td><strong class="team-name">{{ m.home_team.name if m.home_team else '?' }}</strong></td>
              <td style="text-align: center;">
                <input type="number" 
                       name="tip_home_{{ m.id }}" 
                       value="{{ my_tip.tip_home if my_tip else '' }}"
                       min="0" max="99"
                       {% if locked %}disabled{% endif %}
                       placeholder="0">
              </td>
              <td style="text-align: center; font-size: 20px; font-weight: 900; color: var(--muted);">:</td>
              <td style="text-align: center;">
                <input type="number" 
                       name="tip_away_{{ m.id }}" 
                       value="{{ my_tip.tip_away if my_tip else '' }}"
                       min="0" max="99"
                       {% if locked %}disabled{% endif %}
                       placeholder="0">
              </td>
              <td><strong class="team-name">{{ m.away_team.name if m.away_team else '?' }}</strong></td>
              <td class="muted">
                {% if m.start_time %}
                  {{ m.start_time.strftime("%d.%m. %H:%M") }}
                {% else %}
                  —
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    
    <div style="margin-top: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
      <div class="muted" style="font-size: 13px;">
        📊 Natipováno <b>{{ with_tips }}/{{ total }}</b> zápasů
        {% if without_tips > 0 %}
          • <span style="color: var(--warn);">Zbývá {{ without_tips }}</span>
        {% endif %}
      </div>
      <button type="submit" class="btn btn-primary">💾 Uložit všechny tipy</button>
    </div>
  </div>
</form>

<!-- Keyboard shortcuts hint -->
<div class="card" style="background:rgba(0,0,0,0.2); border: 1px dashed var(--line);">
  <div class="muted" style="font-size: 12px; text-align: center;">
    ⌨️ <strong>Klávesové zkratky:</strong> Tab = další pole • Enter v posledním poli = uložit
  </div>
</div>

<script>
// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
  // Ctrl+S nebo Cmd+S = Save
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    document.querySelector('form').submit();
  }
});

// Enter v posledním input = submit
const inputs = document.querySelectorAll('input[type="number"]');
inputs.forEach((input, index) => {
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (index === inputs.length - 1) {
        // Poslední input → submit
        document.querySelector('form').submit();
      } else {
        // Jinak → next input
        inputs[index + 1].focus();
      }
    }
  });
});
</script>

{% endif %}
""", r=r, matches=matches_q, tip_map=tip_map, tips_locked=is_tips_locked, 
    total=total, with_tips=with_tips, without_tips=without_tips, can_user_tip=can_user_tip)

    # --- TEAMS + TABULKA ---
    @app.route("/teams")
    @login_required
    def teams():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("matches"))

        teams_q = Team.query.filter_by(round_id=r.id, is_deleted=False).order_by(Team.name.asc()).all()
        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).all()

        @dataclass
        class Row:
            team: Team
            played: int = 0
            wins: int = 0
            draws: int = 0
            losses: int = 0
            gf: int = 0
            ga: int = 0
            pts: int = 0

        stats = {t.id: Row(team=t) for t in teams_q}
        for m in matches_q:
            if m.home_score is None or m.away_score is None:
                continue
            h = stats.get(m.home_team_id)
            a = stats.get(m.away_team_id)
            if not h or not a:
                continue
            h.played += 1; a.played += 1
            h.gf += m.home_score; h.ga += m.away_score
            a.gf += m.away_score; a.ga += m.home_score
            if m.home_score > m.away_score:
                h.wins += 1; a.losses += 1; h.pts += 3
            elif m.home_score < m.away_score:
                a.wins += 1; h.losses += 1; a.pts += 3
            else:
                h.draws += 1; a.draws += 1; h.pts += 1; a.pts += 1

        rows = list(stats.values())
        rows.sort(key=lambda x: (-x.pts, -(x.gf - x.ga), -x.gf, x.team.name.lower()))

        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Týmy</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <div class="row">
      {% if current_user.is_admin_effective %}
        <a class="btn btn-primary" href="{{ url_for('admin_team_new') }}">Přidat tým</a>
        <a class="btn" href="{{ url_for('export_teams_csv') }}">Export týmů</a>
      {% endif %}
    </div>
  </div>

  <hr class="sep">

  {% if rows|length == 0 %}
    <div class="muted">Zatím žádné týmy.</div>
  {% else %}
    <div class="card" style="background:rgba(255,255,255,.03);">
      <div class="row" style="justify-content:space-between; font-weight:900;">
        <div style="min-width:240px;">Tým</div>
        <div class="row" style="gap:14px;">
          <div class="muted">Z</div><div class="muted">V</div><div class="muted">R</div><div class="muted">P</div>
          <div class="muted">GF</div><div class="muted">GA</div><div class="muted">+/-</div>
          <div class="tag">Body</div>
        </div>
      </div>
      <hr class="sep">

      {% for row in rows %}
        <div class="row" style="justify-content:space-between;">
          <div style="min-width:240px;"><b>{{ row.team.name }}</b></div>
          <div class="row" style="gap:18px;">
            <div>{{ row.played }}</div><div>{{ row.wins }}</div><div>{{ row.draws }}</div><div>{{ row.losses }}</div>
            <div>{{ row.gf }}</div><div>{{ row.ga }}</div><div>{{ row.gf - row.ga }}</div>
            <div class="tag" style="font-weight:900;">{{ row.pts }}</div>
          </div>
        </div>
        {% if not loop.last %}<hr class="sep">{% endif %}
      {% endfor %}
    </div>
  {% endif %}
</div>
""", r=r, rows=rows)

    # --- LEADERBOARD ---
    @app.route("/leaderboard")
    @login_required
    def leaderboard():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("matches"))

        now = datetime.now()  # Pro kontrolu deadline

        def abbr(team: str) -> str:
            t = (team or "").strip()
            if not t:
                return "---"
            # vezmeme první 3 písmena (bez mezer), uppercase
            t2 = "".join(ch for ch in t if ch.isalnum())
            return (t2[:3] or t[:3]).upper()

        matches_q = (
            Match.query.filter_by(round_id=r.id, is_deleted=False)
            .order_by(Match.start_time.asc().nullslast(), Match.id.asc())
            .all()
        )

        # uživatelé pro řazení (tajný user se v žebříčku normálně ukazuje)
        users = User.query.order_by(User.username.asc()).all()

        # přednačti tipy pro tuto soutěž
        tips = (
            Tip.query.join(Match)
            .filter(Match.round_id == r.id)
            .all()
        )
        tips_by_user = {}
        for t in tips:
            tips_by_user.setdefault(t.user_id, {})[t.match_id] = t

        rows = []
        for u in users:
            # Skrýt tajného uživatele pro všechny kromě ownera a jeho samotného
            is_secret = (u.email or "").lower() == (SECRET_USER_EMAIL or "").lower()
            if is_secret and not current_user.is_owner and current_user.id != u.id:
                continue

            # Zobrazit jen uživatele, kteří mají alespoň jeden tip v této soutěži
            tmap = tips_by_user.get(u.id, {})
            if not tmap:
                continue  # Uživatel nemá žádný tip v této soutěži

            total = 0
            exact_count = 0
            winner_count = 0
            for m in matches_q:
                t = tmap.get(m.id)
                if t:
                    pts = calc_points_for_tip(m, t)
                    total += pts
                    if pts == 3:
                        exact_count += 1
                    elif pts == 1:
                        winner_count += 1
            rows.append({
                "user": u,
                "total": total,
                "tmap": tmap,
                "exact_count": exact_count,
                "winner_count": winner_count
            })

        rows.sort(key=lambda x: (-x["total"], x["user"].username.lower()))

        # Načíst extra otázky pro tuto soutěž
        extra_questions = ExtraQuestion.query.filter_by(
            round_id=r.id,
            is_deleted=False
        ).order_by(ExtraQuestion.id.asc()).all()

        # Načíst všechny odpovědi na extra otázky
        extra_answers = ExtraAnswer.query.join(ExtraQuestion).filter(
            ExtraQuestion.round_id == r.id,
            ExtraQuestion.is_deleted == False
        ).all()

        # Seskupit odpovědi podle user_id a question_id
        extra_map = {}
        for ans in extra_answers:
            if ans.user_id not in extra_map:
                extra_map[ans.user_id] = {}
            extra_map[ans.user_id][ans.question_id] = ans

        # Načíst achievementy pro každého uživatele
        achievements_map = {}
        for row in rows:
            user_achievements = get_user_achievements(row['user'].id, r.id)
            # Zobraz jen ikony (max 5 nejnovějších)
            achievements_map[row['user'].id] = sorted(user_achievements, key=lambda x: x['earned_at'], reverse=True)[:5]

        return render_page(r"""
<style>
  .lb-wrap{ overflow:auto; border-radius:14px; border:1px solid var(--line); }
  table.lb{ border-collapse:separate; border-spacing:0; min-width:max-content; width:max-content; background:rgba(17,26,51,.55); }
  table.lb th, table.lb td{ border-right:1px solid var(--line); border-bottom:1px solid var(--line); padding:6px 6px; font-size:13px; text-align:center; white-space:nowrap; }
  table.lb thead th{ background:rgba(17,26,51,.92); font-weight:800; }
  /* dva hlavičkové řádky sticky */
  table.lb thead tr:nth-child(1) th{ position:sticky; top:0; z-index:5; height:80px; }
  table.lb thead tr:nth-child(2) th{ position:sticky; top:80px; z-index:5; height:34px; }

  /* Sticky první dva sloupce VLEVO */
  .sticky-name{ 
    position:sticky; 
    left:0; 
    z-index:10;  /* Vyšší než header rows */
    background:rgba(17,26,51,.99) !important;  /* Téměř neprůhledné */
    text-align:left !important; 
  }
  
  .sticky-points{ 
    position:sticky; 
    left:110px; /* Vedle sticky-name */
    z-index:10;  /* Vyšší než header rows */
    background:rgba(17,26,51,.99) !important;  /* Téměř neprůhledné */
  }
  
  /* DŮLEŽITÉ: Header sticky sloupce musí mít NEJVYŠŠÍ z-index */
  table.lb thead th.sticky-name,
  table.lb thead th.sticky-points {
    z-index:20;  /* NAD VŠÍM! */
    background:rgba(17,26,51,1) !important;  /* 100% neprůhledné */
  }
  
  .col-user{ width:110px; max-width:110px; overflow:hidden; text-overflow:ellipsis; }
  .col-total{ width:60px; }
  .col-exact{ width:55px; }
  
  /* Mobilní optimalizace: Shadow efekty pro sticky */
  @media (max-width: 768px) {
    /* Tipér - sticky vlevo s shadow */
    .sticky-name {
      position: sticky !important;
      left: 0 !important;
      z-index: 10 !important;
      box-shadow: 4px 0 10px rgba(0,0,0,0.3);
      background: rgba(17,26,51,.99) !important;
    }
    
    /* Body - sticky vlevo vedle Tipéra s shadow */
    .sticky-points {
      position: sticky !important;
      left: 110px !important;
      z-index: 10 !important;
      box-shadow: 4px 0 10px rgba(0,0,0,0.3);
      background: rgba(17,26,51,.99) !important;
    }
    
    /* Header má nejvyšší z-index */
    table.lb thead th.sticky-name,
    table.lb thead th.sticky-points {
      z-index: 20 !important;
      background: rgba(17,26,51,1) !important;
    }
    
    /* Zvětšit touch targety */
    table.lb th, table.lb td {
      font-size: 12px;
      padding: 10px 6px;
      min-height: 44px;
    }
    
    /* Wrapper - smooth scrolling */
    .lb-wrap {
      -webkit-overflow-scrolling: touch;
    }
    
    /* Zápasy scrollují - mírně užší */
    .col-m {
      width: 50px;
      min-width: 50px;
      max-width: 50px;
    }
  }

  /* match cols */
  .col-m{ width:48px; min-width:48px; max-width:48px; }
  .col-extra{ width:120px; min-width:80px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .vertical-text{
    writing-mode: vertical-rl;
    text-orientation: mixed;
    transform: rotate(180deg);
    white-space: nowrap;
    padding: 8px 6px;
  }
  .cell-empty{ color:rgba(233,238,252,.35); }
  .cell-tipped{ color:rgba(51,209,122,.7); font-weight:900; }
  .cell-exact{ background:rgba(51,209,122,.14); color:#33d17a; font-weight:900; }
  .cell-one{ background:rgba(249,199,79,.12); color:#f9c74f; font-weight:900; }
  .cell-bad{ background:rgba(167,178,214,.07); color:rgba(233,238,252,.55); }
  .score{ color:#ff4d6d; font-weight:900; }
  
  /* ===== Mobile tweaks ===== */
  @media (max-width: 700px){
    .card{ padding:14px; }
    h2{ font-size:26px; }
    .row{ flex-wrap: wrap; }
    .row > form{ width:100%; }
    select{ width:100%; min-width:0 !important; }
    .btn{ width:100%; text-align:center; }
    .muted{ font-size:14px; }
    .lb-wrap{ overflow-x:auto; -webkit-overflow-scrolling:touch; border-radius:14px; }
    .col-user{ width:140px; min-width:140px; max-width:140px; }
    .col-total{ width:52px; min-width:52px; max-width:52px; }
    .col-m{ width:44px; min-width:44px; max-width:44px; }
    .vertical-text{ font-size:12px; padding:6px 4px; }
  }

</style>

<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Žebříček</h2>
      <div class="row" style="gap:12px; align-items:center; margin-top:8px;">
        <span class="muted">Soutěž:</span>
        <form method="post" action="{{ url_for('set_round') }}" style="margin:0;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
          <input type="hidden" name="next" value="{{ url_for('leaderboard') }}">
          <select name="round_id" onchange="this.form.submit()" style="min-width:200px;">
            {% for rnd in rounds_for_switch %}
              <option value="{{ rnd.id }}" {% if rnd.id == round.id %}selected{% endif %}>
                {{ rnd.name }}
              </option>
            {% endfor %}
          </select>
        </form>
        <a href="{{ url_for('mini_leaderboards') }}" class="btn" style="background: rgba(139,92,246,.15); color: #8b5cf6; border: 1px solid rgba(139,92,246,.3);">
          🏅 Mini žebříčky
        </a>
      </div>
    </div>
    {% if current_user.is_admin %}
      <div class="row" style="gap:8px;">
        <a href="{{ url_for('admin_match_new') }}" class="btn" style="background: rgba(51,209,122,.15); color: #33d17a; border: 1px solid rgba(51,209,122,.3);">
          ➕ Přidat zápas
        </a>
        <div class="muted" style="font-size:12px; padding:8px; background:rgba(110,168,254,0.1); border-radius:6px;">
          💡 Klikni na výsledek pro úpravu
        </div>
        <a class="btn" href="{{ url_for('matches') }}">Vyhodnocení zápasů</a>
      </div>
    {% endif %}
  </div>

  <hr class="sep">

  <div class="lb-wrap">
    <table class="lb">
      <thead>
        <!-- 1) kdo s kým hraje (vertikálně) -->
        <tr>
          <th class="sticky-name col-user" rowspan="2">Tipér</th>
          <th class="sticky-points col-total" rowspan="2">Body</th>
          {% for m in matches %}
            <th class="col-m">
              <div class="vertical-text">{{ abbr(m.home_team.name if m.home_team else '') }}-{{ abbr(m.away_team.name if m.away_team else '') }}</div>
            </th>
          {% endfor %}
          {% for eq in extra_questions %}
            <th class="col-extra">
              <div class="vertical-text">
                {{ eq.question[:30] }}{% if eq.question|length > 30 %}...{% endif %}
                {% if eq.deadline and eq.deadline > current_time %}
                  <br><small style="color:#888;">🔒 {{ eq.deadline.strftime('%d.%m.') }}</small>
                {% endif %}
              </div>
            </th>
          {% endfor %}
          <th class="col-exact" rowspan="2">Přesné</th>
        </tr>

        <!-- 2) skutečné skóre / extra odpovědi -->
        <tr>
          {% for m in matches %}
            <th class="col-m" {% if current_user.is_admin_effective %}onclick="openScoreModal({{ m.id }}, '{{ m.home_team.name }}', '{{ m.away_team.name }}', {{ m.home_score if m.home_score is not none else 'null' }}, {{ m.away_score if m.away_score is not none else 'null' }})" style="cursor:pointer;"{% endif %}>
              {% if m.home_score is not none and m.away_score is not none %}
                <span class="score">{{ m.home_score }}:{{ m.away_score }}</span>
              {% else %}
                <span class="cell-empty">{% if current_user.is_admin_effective %}✏️{% else %}-{% endif %}</span>
              {% endif %}
            </th>
          {% endfor %}
          {% for eq in extra_questions %}
            <th class="col-extra">
              <span class="cell-empty">-</span>
            </th>
          {% endfor %}
        </tr>
      </thead>

      <tbody>
        {% for row in rows %}
          <tr>
            <td class="sticky-name col-user" title="{{ row.user.full_name }} ({{ row.user.username }})">
              <div style="display: flex; align-items: center; gap: 6px;">
                <a href="{{ url_for('user_tips', user_id=row.user.id) }}" style="color:inherit; text-decoration:none; flex: 1;">
                  {{ row.user.display_name }}
                </a>
                {% if row.user.id != current_user.id %}
                  <a href="{{ url_for('compare', user1=current_user.id, user2=row.user.id) }}" 
                     title="Porovnat s {{ row.user.display_name }}"
                     style="opacity: 0.6; font-size: 12px; text-decoration: none; transition: opacity 0.2s;"
                     onmouseover="this.style.opacity='1'"
                     onmouseout="this.style.opacity='0.6'">
                    🆚
                  </a>
                {% endif %}
              </div>
              {% set user_achievements = achievements_map.get(row.user.id, []) %}
              {% if user_achievements|length > 0 %}
                <div style="font-size: 14px; margin-top: 2px;">
                  {% for ach in user_achievements %}
                    <span title="{{ ach.name }}: {{ ach.description }}">{{ ach.icon }}</span>
                  {% endfor %}
                </div>
              {% endif %}
              </div>
            </td>
            <td class="sticky-points col-total"><b>{{ row.total }}</b></td>

            {% for m in matches %}
              {% set t = row.tmap.get(m.id) %}
              {% set match_started = m.start_time and m.start_time <= current_time %}
              {% set has_result = m.home_score is not none and m.away_score is not none %}

              {% if t %}
                {% if match_started or has_result %}
                  {# Zápas už začal NEBO má výsledek - ukaž konkrétní tip #}
                  {% if has_result %}
                    {# Zápas má výsledek - obarvi podle bodů #}
                    {% set pts = calc_points(m, t) %}
                    {% if pts == 3 %}
                      <td class="col-m cell-exact">{{ t.tip_home }}:{{ t.tip_away }}</td>
                    {% elif pts == 1 %}
                      <td class="col-m cell-one">{{ t.tip_home }}:{{ t.tip_away }}</td>
                    {% else %}
                      <td class="col-m cell-bad">{{ t.tip_home }}:{{ t.tip_away }}</td>
                    {% endif %}
                  {% else %}
                    {# Zápas začal ale nemá výsledek - jen ukaž tip bez obarvení #}
                    <td class="col-m">{{ t.tip_home }}:{{ t.tip_away }}</td>
                  {% endif %}
                {% else %}
                  {# Zápas ještě nezačal - jen checkmark #}
                  <td class="col-m cell-tipped">✓</td>
                {% endif %}
              {% else %}
                <td class="col-m cell-bad">-</td>
              {% endif %}
            {% endfor %}

            {% for eq in extra_questions %}
              {% set user_extras = extra_map.get(row.user.id, {}) %}
              {% set ans = user_extras.get(eq.id) %}
              {# Zobraz TEXT odpovědi pokud je admin NEBO je po deadline (nebo deadline není nastaveno) #}
              {% set show_answer_text = current_user.is_admin_effective or (eq.deadline is none or eq.deadline <= current_time) %}
              {% if show_answer_text %}
                {# Po deadline nebo pro admina - zobraz TEXT odpovědi #}
                {% if ans %}
                  {% if ans.is_correct %}
                    <td class="col-extra cell-exact">{{ ans.answer_text }}</td>
                  {% else %}
                    <td class="col-extra cell-bad">{{ ans.answer_text }}</td>
                  {% endif %}
                {% else %}
                  <td class="col-extra cell-bad">-</td>
                {% endif %}
              {% else %}
                {# Před deadline - zobraz jen že user odpověděl #}
                {% if ans %}
                  <td class="col-extra cell-tipped" title="Odpovězeno (zobrazí se po {{ eq.deadline.strftime('%d.%m. %H:%M') }})">✓</td>
                {% else %}
                  <td class="col-extra cell-bad">-</td>
                {% endif %}
              {% endif %}
            {% endfor %}

            <td class="col-exact">{{ row.exact_count }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="muted" style="margin-top:10px;">
    Barvy: zeleně přesně (+3), oranžově za bod (+1), šedě špatně / nenatipováno.<br>
    ✓ = uživatel tipoval, ale zápas ještě nezačal (tipy se zobrazí po začátku zápasu)
  </div>
</div>

{% if current_user.is_admin_effective %}
<!-- Modální okno pro editaci výsledku -->
<div id="scoreModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:9999; align-items:center; justify-content:center;">
  <div class="card" style="width:90%; max-width:400px; padding:24px;">
    <h3 style="margin:0 0 16px 0;">Zadat výsledek</h3>

    <div style="margin-bottom:16px;">
      <div style="font-weight:900; font-size:16px; text-align:center;" id="modalMatchName">Zápas</div>
    </div>

    <form method="post" id="scoreForm" action="">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
      <div style="display:flex; gap:16px; align-items:center; justify-content:center; margin-bottom:20px;">
        <div style="text-align:center; flex:1;">
          <div class="muted" style="margin-bottom:8px; font-size:13px;" id="modalHomeName">Domácí</div>
          <input type="number" name="home_score" id="modalHomeScore" min="0" max="99"
                 style="width:100%; height:60px; font-size:32px; font-weight:900; text-align:center; padding:8px; border-radius:10px;"
                 placeholder="0" autofocus>
        </div>

        <div style="font-size:32px; font-weight:900; color:var(--muted); margin-top:20px;">:</div>

        <div style="text-align:center; flex:1;">
          <div class="muted" style="margin-bottom:8px; font-size:13px;" id="modalAwayName">Hosté</div>
          <input type="number" name="away_score" id="modalAwayScore" min="0" max="99"
                 style="width:100%; height:60px; font-size:32px; font-weight:900; text-align:center; padding:8px; border-radius:10px;"
                 placeholder="0">
        </div>
      </div>

      <div style="display:flex; gap:10px;">
        <button type="submit" class="btn btn-primary" style="flex:1; padding:12px; font-weight:900;">
          💾 Uložit výsledek
        </button>
        <button type="button" class="btn" onclick="closeScoreModal()" style="flex:1; padding:12px;">
          Zrušit
        </button>
      </div>

      <div style="margin-top:12px; text-align:center;">
        <button type="button" class="btn btn-sm" onclick="clearScore()"
                style="background:rgba(255,77,109,0.15); color:#ff4d6d; font-size:12px;">
          🗑️ Smazat výsledek
        </button>
      </div>
    </form>
  </div>
</div>

<script>
function openScoreModal(matchId, homeName, awayName, homeScore, awayScore) {
  const modal = document.getElementById('scoreModal');
  const form = document.getElementById('scoreForm');

  // Nastavit action URL
  form.action = '{{ url_for("admin_quick_score", match_id=0) }}'.replace('/0/', '/' + matchId + '/');

  // Nastavit názvy týmů
  document.getElementById('modalMatchName').textContent = homeName + ' vs ' + awayName;
  document.getElementById('modalHomeName').textContent = homeName;
  document.getElementById('modalAwayName').textContent = awayName;

  // Nastavit hodnoty
  document.getElementById('modalHomeScore').value = homeScore !== null ? homeScore : '';
  document.getElementById('modalAwayScore').value = awayScore !== null ? awayScore : '';

  // Zobrazit modal
  modal.style.display = 'flex';

  // Focus na první input
  setTimeout(() => document.getElementById('modalHomeScore').focus(), 100);
}

function closeScoreModal() {
  document.getElementById('scoreModal').style.display = 'none';
}

function clearScore() {
  document.getElementById('modalHomeScore').value = '';
  document.getElementById('modalAwayScore').value = '';
  document.getElementById('scoreForm').submit();
}

// Zavřít modal při kliknutí mimo
document.getElementById('scoreModal')?.addEventListener('click', function(e) {
  if (e.target === this) {
    closeScoreModal();
  }
});

// Zavřít modal při ESC
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeScoreModal();
  }
});
</script>
{% endif %}

""", round=r, matches=matches_q, rows=rows, abbr=abbr, calc_points=calc_points_for_tip,
     current_time=datetime.now(),
     extra_questions=extra_questions, extra_map=extra_map, achievements_map=achievements_map)

    @app.route("/mini-leaderboards")
    @login_required
    def mini_leaderboards():
        """Mini žebříčky - týden, měsíc, comeback, underdog"""
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for("matches"))
        
        from datetime import timedelta
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        # Načti všechny zápasy v soutěži
        all_matches = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
        all_users = User.query.all()
        
        # === 1. NEJLEPŠÍ TÝDEN ===
        week_matches = [m for m in all_matches if m.start_time and m.start_time >= week_ago and m.home_score is not None]
        week_leaders = []
        
        for u in all_users:
            tips = Tip.query.filter(
                Tip.user_id == u.id,
                Tip.match_id.in_([m.id for m in week_matches])
            ).all()
            
            if not tips:
                continue
            
            total = sum(calc_points_for_tip(t.match, t) for t in tips if t.match.home_score is not None)
            if total > 0:
                week_leaders.append({'user': u, 'points': total, 'matches': len(tips)})
        
        week_leaders.sort(key=lambda x: (-x['points'], x['user'].username.lower()))
        week_leaders = week_leaders[:10]  # Top 10
        
        # === 2. NEJLEPŠÍ MĚSÍC ===
        month_matches = [m for m in all_matches if m.start_time and m.start_time >= month_ago and m.home_score is not None]
        month_leaders = []
        
        for u in all_users:
            tips = Tip.query.filter(
                Tip.user_id == u.id,
                Tip.match_id.in_([m.id for m in month_matches])
            ).all()
            
            if not tips:
                continue
            
            total = sum(calc_points_for_tip(t.match, t) for t in tips if t.match.home_score is not None)
            if total > 0:
                month_leaders.append({'user': u, 'points': total, 'matches': len(tips)})
        
        month_leaders.sort(key=lambda x: (-x['points'], x['user'].username.lower()))
        month_leaders = month_leaders[:10]  # Top 10
        
        # === 3. COMEBACK KRÁL ===
        # Porovnáme current ranking vs half-way ranking
        evaluated_matches = [m for m in all_matches if m.home_score is not None]
        
        if len(evaluated_matches) >= 10:  # Min 10 zápasů
            half_way_count = len(evaluated_matches) // 2
            early_matches = evaluated_matches[:half_way_count]
            
            # Early rankings
            early_scores = {}
            for u in all_users:
                tips = Tip.query.filter(
                    Tip.user_id == u.id,
                    Tip.match_id.in_([m.id for m in early_matches])
                ).all()
                total = sum(calc_points_for_tip(t.match, t) for t in tips)
                if total > 0:
                    early_scores[u.id] = total
            
            early_sorted = sorted(early_scores.items(), key=lambda x: -x[1])
            early_positions = {user_id: idx for idx, (user_id, _) in enumerate(early_sorted)}
            
            # Current rankings
            current_scores = {}
            for u in all_users:
                tips = Tip.query.filter(
                    Tip.user_id == u.id,
                    Tip.match_id.in_([m.id for m in evaluated_matches])
                ).all()
                total = sum(calc_points_for_tip(t.match, t) for t in tips)
                if total > 0:
                    current_scores[u.id] = total
            
            current_sorted = sorted(current_scores.items(), key=lambda x: -x[1])
            current_positions = {user_id: idx for idx, (user_id, _) in enumerate(current_sorted)}
            
            # Calculate improvements
            comebacks = []
            for user_id in current_positions:
                if user_id in early_positions:
                    improvement = early_positions[user_id] - current_positions[user_id]
                    if improvement > 0:
                        u = db.session.get(User, user_id)
                        comebacks.append({
                            'user': u,
                            'improvement': improvement,
                            'early_pos': early_positions[user_id] + 1,
                            'current_pos': current_positions[user_id] + 1,
                            'points': current_scores[user_id]
                        })
            
            comebacks.sort(key=lambda x: (-x['improvement'], -x['points']))
            comebacks = comebacks[:10]
        else:
            comebacks = []
        
        # === 4. UNDERDOG ===
        # Nejlepší poměr body/počet tipů
        underdogs = []
        
        for u in all_users:
            tips = Tip.query.join(Match).filter(
                Tip.user_id == u.id,
                Match.round_id == r.id,
                Match.is_deleted == False,
                Match.home_score != None
            ).all()
            
            if not tips or len(tips) < 5:  # Min 5 tipů
                continue
            
            total = sum(calc_points_for_tip(t.match, t) for t in tips)
            ratio = total / len(tips) if len(tips) > 0 else 0
            
            # Jen pokud tipoval méně než 70% zápasů
            all_matches_count = len([m for m in all_matches if m.home_score is not None])
            if all_matches_count > 0 and len(tips) / all_matches_count < 0.7:
                underdogs.append({
                    'user': u,
                    'ratio': ratio,
                    'points': total,
                    'tips_count': len(tips),
                    'total_matches': all_matches_count,
                    'coverage': int(len(tips) / all_matches_count * 100)
                })
        
        underdogs.sort(key=lambda x: (-x['ratio'], -x['points']))
        underdogs = underdogs[:10]
        
        return render_page(r"""
<style>
  .mini-board {
    background: rgba(255,255,255,.03);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
  }
  
  .mini-board h3 {
    margin: 0 0 16px 0;
    font-size: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  .mini-rank {
    display: flex;
    align-items: center;
    padding: 12px;
    border-bottom: 1px solid var(--line);
    transition: all 0.2s;
  }
  
  .mini-rank:hover {
    background: rgba(255,255,255,.05);
  }
  
  .mini-rank:last-child {
    border-bottom: none;
  }
  
  .rank-pos {
    width: 40px;
    font-weight: 900;
    font-size: 18px;
    color: var(--muted);
  }
  
  .rank-pos.gold { color: #ffd700; }
  .rank-pos.silver { color: #c0c0c0; }
  .rank-pos.bronze { color: #cd7f32; }
  
  .rank-user {
    flex: 1;
    font-weight: 600;
  }
  
  .rank-stat {
    font-weight: 900;
    color: var(--accent);
    font-size: 18px;
  }
  
  .rank-detail {
    color: var(--muted);
    font-size: 13px;
    margin-left: 8px;
  }
  
  .improvement {
    background: linear-gradient(135deg, #33d17a 0%, #26a269 100%);
    color: white;
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 900;
    margin-left: 8px;
  }
</style>

<div class="card">
  <h2 style="margin: 0 0 8px 0;">📊 Mini Žebříčky</h2>
  <div class="muted">{{ r.name }} - Speciální kategorie</div>
</div>

<div class="mini-board">
  <h3>📅 Nejlepší týden (posledních 7 dní)</h3>
  {% if week_leaders %}
    {% for item in week_leaders %}
      <div class="mini-rank">
        <div class="rank-pos {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
          {{ loop.index }}.
        </div>
        <div class="rank-user">
          <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
            {{ item.user.display_name }}
          </a>
        </div>
        <div class="rank-stat">{{ item.points }}</div>
        <div class="rank-detail">bodů ({{ item.matches }} zápasů)</div>
      </div>
    {% endfor %}
  {% else %}
    <div class="muted" style="text-align: center; padding: 20px;">
      Žádné zápasy v posledním týdnu
    </div>
  {% endif %}
</div>

<div class="mini-board">
  <h3>📆 Nejlepší měsíc (posledních 30 dní)</h3>
  {% if month_leaders %}
    {% for item in month_leaders %}
      <div class="mini-rank">
        <div class="rank-pos {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
          {{ loop.index }}.
        </div>
        <div class="rank-user">
          <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
            {{ item.user.display_name }}
          </a>
        </div>
        <div class="rank-stat">{{ item.points }}</div>
        <div class="rank-detail">bodů ({{ item.matches }} zápasů)</div>
      </div>
    {% endfor %}
  {% else %}
    <div class="muted" style="text-align: center; padding: 20px;">
      Žádné zápasy v posledním měsíci
    </div>
  {% endif %}
</div>

<div class="mini-board">
  <h3>📈 Comeback Králové</h3>
  {% if comebacks %}
    {% for item in comebacks %}
      <div class="mini-rank">
        <div class="rank-pos {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
          {{ loop.index }}.
        </div>
        <div class="rank-user">
          <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
            {{ item.user.display_name }}
          </a>
        </div>
        <div class="improvement">+{{ item.improvement }} míst</div>
        <div class="rank-detail">{{ item.early_pos }}. → {{ item.current_pos }}.</div>
      </div>
    {% endfor %}
  {% else %}
    <div class="muted" style="text-align: center; padding: 20px;">
      Zatím není dost dat (min 10 vyhodnocených zápasů)
    </div>
  {% endif %}
</div>

<div class="mini-board">
  <h3>🐕 Underdog - Nejlepší poměr body/tipy</h3>
  {% if underdogs %}
    {% for item in underdogs %}
      <div class="mini-rank">
        <div class="rank-pos {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
          {{ loop.index }}.
        </div>
        <div class="rank-user">
          <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
            {{ item.user.display_name }}
          </a>
        </div>
        <div class="rank-stat">{{ "%.2f"|format(item.ratio) }}</div>
        <div class="rank-detail">bodů/tip ({{ item.points }} bodů, {{ item.coverage }}% pokrytí)</div>
      </div>
    {% endfor %}
  {% else %}
    <div class="muted" style="text-align: center; padding: 20px;">
      Žádní underdog hráči (všichni mají > 70% pokrytí)
    </div>
  {% endif %}
</div>

<div class="card">
  <a href="{{ url_for('leaderboard') }}" class="btn">← Zpět na hlavní žebříček</a>
</div>

""", r=r, week_leaders=week_leaders, month_leaders=month_leaders, 
     comebacks=comebacks, underdogs=underdogs)

    @app.route("/user/<int:user_id>/tips")
    @login_required
    def user_tips(user_id: int):
        """Zobrazí detail tipů konkrétního uživatele"""
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(400)

        user = db.session.get(User, user_id)
        if not user:
            abort(404)

        # Získat všechny zápasy v této soutěži
        matches = Match.query.filter_by(
            round_id=r.id,
            is_deleted=False
        ).order_by(
            Match.start_time.asc().nullslast(),
            Match.id.asc()
        ).all()

        # Získat tipy uživatele
        tips = Tip.query.join(Match).filter(
            Tip.user_id == user_id,
            Match.round_id == r.id,
            Match.is_deleted == False
        ).all()
        tip_map = {t.match_id: t for t in tips}

        # Výpočet statistik
        total_points = 0
        exact_count = 0
        winner_count = 0
        missed_count = 0

        match_data = []
        now = datetime.now()

        for m in matches:
            tip = tip_map.get(m.id)
            match_started = m.start_time and m.start_time <= now

            points = 0
            tip_type = None

            if tip and m.home_score is not None and m.away_score is not None:
                points = calculate_points(
                    tip.tip_home, tip.tip_away,
                    m.home_score, m.away_score
                )
                total_points += points

                if points == 3:
                    exact_count += 1
                    tip_type = "exact"
                elif points == 1:
                    winner_count += 1
                    tip_type = "winner"
                else:
                    missed_count += 1
                    tip_type = "missed"

            match_data.append({
                'match': m,
                'tip': tip,
                'match_started': match_started,
                'points': points,
                'tip_type': tip_type
            })

        # Extra otázky
        extra_points = 0
        extra_answers = ExtraAnswer.query.join(ExtraQuestion).filter(
            ExtraAnswer.user_id == user_id,
            ExtraQuestion.round_id == r.id,
            ExtraQuestion.is_deleted == False
        ).all()

        for ans in extra_answers:
            if ans.is_correct:
                extra_points += 1

        total_with_extra = total_points + extra_points

        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Tipy: {{ user.username }}</h2>
      <div class="muted">Soutěž: <b>{{ round.name }}</b></div>
    </div>
    <a class="btn" href="{{ url_for('leaderboard') }}">Zpět na žebříček</a>
  </div>

  <hr class="sep">

  <div class="row" style="gap:20px; margin-bottom:20px;">
    <div>
      <div class="muted">Celkem bodů</div>
      <div style="font-size:28px; font-weight:900; color:#33d17a;">{{ total_with_extra }}</div>
    </div>
    <div>
      <div class="muted">Body ze zápasů</div>
      <div style="font-size:28px; font-weight:900;">{{ total_points }}</div>
    </div>
    <div>
      <div class="muted">Přesné tipy</div>
      <div style="font-size:24px; font-weight:700; color:#33d17a;">{{ exact_count }}</div>
    </div>
    <div>
      <div class="muted">Tipy na vítěze</div>
      <div style="font-size:24px; font-weight:700; color:#f9c74f;">{{ winner_count }}</div>
    </div>
    <div>
      <div class="muted">Špatné tipy</div>
      <div style="font-size:24px; font-weight:700; color:rgba(233,238,252,.55);">{{ missed_count }}</div>
    </div>
    <div>
      <div class="muted">Body z extra</div>
      <div style="font-size:24px; font-weight:700; color:#33d17a;">{{ extra_points }}</div>
    </div>
  </div>

  <hr class="sep">

  <h3 style="margin:20px 0 10px 0;">Zápasy</h3>

  <table class="datatable">
    <thead>
      <tr>
        <th style="width:200px;">Zápas</th>
        <th style="text-align:center; width:100px;">Čas</th>
        <th style="text-align:center; width:100px;">Tip</th>
        <th style="text-align:center; width:100px;">Výsledek</th>
        <th style="text-align:center; width:80px;">Body</th>
      </tr>
    </thead>
    <tbody>
      {% for item in match_data %}
        {% set m = item.match %}
        {% set t = item.tip %}
        {% set started = item.match_started %}
        <tr>
          <td>
            <strong>{{ m.home_team.name if m.home_team else '?' }}</strong> -
            <strong>{{ m.away_team.name if m.away_team else '?' }}</strong>
          </td>
          <td style="text-align:center;" class="muted">
            {% if m.start_time %}
              {{ m.start_time.strftime('%d.%m. %H:%M') }}
            {% else %}
              —
            {% endif %}
          </td>
          <td style="text-align:center;">
            {% if t %}
              {% if started or (m.home_score is not none and m.away_score is not none) %}
                <strong>{{ t.tip_home }}:{{ t.tip_away }}</strong>
              {% else %}
                <span style="color:#33d17a;">✓ tipoval</span>
              {% endif %}
            {% else %}
              <span class="muted">— netipoval</span>
            {% endif %}
          </td>
          <td style="text-align:center;">
            {% if m.home_score is not none and m.away_score is not none %}
              <strong style="color:#ff4d6d;">{{ m.home_score }}:{{ m.away_score }}</strong>
            {% else %}
              <span class="muted">—</span>
            {% endif %}
          </td>
          <td style="text-align:center;">
            {% if item.tip_type == 'exact' %}
              <span style="color:#33d17a; font-weight:900;">+{{ item.points }}</span>
            {% elif item.tip_type == 'winner' %}
              <span style="color:#f9c74f; font-weight:900;">+{{ item.points }}</span>
            {% elif item.tip_type == 'missed' %}
              <span style="color:rgba(233,238,252,.55);">0</span>
            {% else %}
              <span class="muted">—</span>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
""",
            user=user,
            round=r,
            match_data=match_data,
            total_points=total_points,
            total_with_extra=total_with_extra,
            exact_count=exact_count,
            winner_count=winner_count,
            missed_count=missed_count,
            extra_points=extra_points
        )

    @app.route("/compare")
    @login_required
    def compare():
        """Porovnání dvou uživatelů"""
        user1_id = request.args.get('user1', type=int)
        user2_id = request.args.get('user2', type=int)
        
        # Pokud nejsou oba parametry, přesměruj na výběr
        if not user1_id or not user2_id:
            all_users = User.query.order_by(User.username.asc()).all()
            return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 16px 0;">🆚 Porovnat uživatele</h2>
  <div class="muted" style="margin-bottom: 20px;">Vyber dva uživatele pro porovnání</div>
  
  <form method="get" action="{{ url_for('compare') }}">
    <div style="display: grid; gap: 16px; margin-bottom: 20px;">
      <div>
        <label class="muted" style="display: block; margin-bottom: 8px;">Uživatel 1:</label>
        <select name="user1" required style="width: 100%;">
          <option value="">Vyber uživatele...</option>
          {% for u in users %}
            <option value="{{ u.id }}">{{ u.display_name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <div>
        <label class="muted" style="display: block; margin-bottom: 8px;">Uživatel 2:</label>
        <select name="user2" required style="width: 100%;">
          <option value="">Vyber uživatele...</option>
          {% for u in users %}
            <option value="{{ u.id }}">{{ u.display_name }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    
    <button type="submit" class="btn btn-primary">Porovnat</button>
  </form>
</div>
""", users=all_users)
        
        # Načti oba uživatele
        u1 = db.session.get(User, user1_id)
        u2 = db.session.get(User, user2_id)
        
        if not u1 or not u2:
            flash("Uživatel nenalezen.", "error")
            return redirect(url_for('compare'))
        
        # Načti aktuální soutěž
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Neexistuje žádná soutěž.", "error")
            return redirect(url_for('matches'))
        
        # Načti zápasy
        matches = Match.query.filter_by(
            round_id=r.id,
            is_deleted=False
        ).order_by(Match.start_time.asc().nullslast(), Match.id.asc()).all()
        
        # Načti tipy obou uživatelů
        u1_tips = Tip.query.filter_by(user_id=u1.id).all()
        u1_tip_map = {t.match_id: t for t in u1_tips}
        
        u2_tips = Tip.query.filter_by(user_id=u2.id).all()
        u2_tip_map = {t.match_id: t for t in u2_tips}
        
        # Vypočítej statistiky
        u1_total = 0
        u1_exact = 0
        u1_winner = 0
        u1_miss = 0
        
        u2_total = 0
        u2_exact = 0
        u2_winner = 0
        u2_miss = 0
        
        head_to_head_wins_u1 = 0
        head_to_head_wins_u2 = 0
        head_to_head_draws = 0
        
        comparison_data = []
        
        for m in matches:
            if m.home_score is None or m.away_score is None:
                continue  # Nehodnocený zápas
            
            t1 = u1_tip_map.get(m.id)
            t2 = u2_tip_map.get(m.id)
            
            p1 = calc_points_for_tip(m, t1) if t1 else 0
            p2 = calc_points_for_tip(m, t2) if t2 else 0
            
            u1_total += p1
            u2_total += p2
            
            if p1 == 3:
                u1_exact += 1
            elif p1 == 1:
                u1_winner += 1
            else:
                u1_miss += 1
            
            if p2 == 3:
                u2_exact += 1
            elif p2 == 1:
                u2_winner += 1
            else:
                u2_miss += 1
            
            # Head-to-head
            if p1 > p2:
                head_to_head_wins_u1 += 1
            elif p2 > p1:
                head_to_head_wins_u2 += 1
            else:
                head_to_head_draws += 1
            
            comparison_data.append({
                'match': m,
                'u1_tip': t1,
                'u2_tip': t2,
                'u1_points': p1,
                'u2_points': p2
            })
        
        return render_page(r"""
<style>
  .vs-header {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 20px;
    align-items: center;
    margin-bottom: 30px;
  }
  
  .vs-user {
    text-align: center;
    padding: 20px;
    background: rgba(255,255,255,.03);
    border: 1px solid var(--line);
    border-radius: 12px;
  }
  
  .vs-user h3 {
    margin: 0 0 8px 0;
    font-size: 24px;
  }
  
  .vs-divider {
    font-size: 32px;
    font-weight: 900;
    color: var(--muted);
  }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 30px;
  }
  
  .stat-box {
    background: rgba(255,255,255,.03);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
  }
  
  .stat-label {
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 8px;
  }
  
  .stat-value {
    font-size: 32px;
    font-weight: 900;
    color: var(--accent);
  }
  
  .stat-value.win {
    color: #33d17a;
  }
  
  .stat-value.lose {
    color: #ff4d6d;
  }
  
  .comparison-row {
    display: grid;
    grid-template-columns: 1fr 80px 100px 80px 1fr;
    gap: 12px;
    padding: 12px;
    border-bottom: 1px solid var(--line);
    align-items: center;
  }
  
  .comparison-row:hover {
    background: rgba(255,255,255,.03);
  }
  
  .tip-cell {
    text-align: center;
    font-weight: 600;
  }
  
  .tip-cell.exact {
    color: #33d17a;
  }
  
  .tip-cell.winner {
    color: #f9c74f;
  }
  
  .tip-cell.miss {
    color: var(--muted);
  }
  
  .match-result {
    text-align: center;
    font-weight: 900;
    color: #ff4d6d;
  }
  
  .winner-badge {
    background: linear-gradient(135deg, #33d17a 0%, #26a269 100%);
    color: white;
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 900;
  }
</style>

<div class="card">
  <a href="{{ url_for('compare') }}" class="btn" style="margin-bottom: 16px;">← Změnit uživatele</a>
  
  <div class="vs-header">
    <div class="vs-user">
      <h3>{{ u1.display_name }}</h3>
      <div class="stat-value {% if u1_total > u2_total %}win{% elif u1_total < u2_total %}lose{% endif %}">
        {{ u1_total }}
      </div>
      <div class="muted">bodů celkem</div>
    </div>
    
    <div class="vs-divider">🆚</div>
    
    <div class="vs-user">
      <h3>{{ u2.display_name }}</h3>
      <div class="stat-value {% if u2_total > u1_total %}win{% elif u2_total < u1_total %}lose{% endif %}">
        {{ u2_total }}
      </div>
      <div class="muted">bodů celkem</div>
    </div>
  </div>
  
  <h3 style="margin: 0 0 16px 0;">📊 Head-to-Head</h3>
  <div class="stats-grid">
    <div class="stat-box">
      <div class="stat-label">{{ u1.display_name }} výhry</div>
      <div class="stat-value {% if head_to_head_wins_u1 > head_to_head_wins_u2 %}win{% endif %}">
        {{ head_to_head_wins_u1 }}
      </div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">Remízy</div>
      <div class="stat-value">{{ head_to_head_draws }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u2.display_name }} výhry</div>
      <div class="stat-value {% if head_to_head_wins_u2 > head_to_head_wins_u1 %}win{% endif %}">
        {{ head_to_head_wins_u2 }}
      </div>
    </div>
  </div>
  
  <h3 style="margin: 0 0 16px 0;">🎯 Přesnost</h3>
  <div class="stats-grid">
    <div class="stat-box">
      <div class="stat-label">{{ u1.display_name }} přesné</div>
      <div class="stat-value">{{ u1_exact }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u1.display_name }} vítěz</div>
      <div class="stat-value">{{ u1_winner }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u1.display_name }} miss</div>
      <div class="stat-value">{{ u1_miss }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u2.display_name }} přesné</div>
      <div class="stat-value">{{ u2_exact }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u2.display_name }} vítěz</div>
      <div class="stat-value">{{ u2_winner }}</div>
    </div>
    
    <div class="stat-box">
      <div class="stat-label">{{ u2.display_name }} miss</div>
      <div class="stat-value">{{ u2_miss }}</div>
    </div>
  </div>
  
  <h3 style="margin: 20px 0 16px 0;">📋 Detail zápasů</h3>
  <div style="background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 12px; overflow: hidden;">
    <div class="comparison-row" style="background: rgba(255,255,255,.05); font-weight: 900;">
      <div style="text-align: center;">{{ u1.display_name }}</div>
      <div style="text-align: center;">Body</div>
      <div style="text-align: center;">Výsledek</div>
      <div style="text-align: center;">Body</div>
      <div style="text-align: center;">{{ u2.display_name }}</div>
    </div>
    
    {% for item in comparison_data %}
      <div class="comparison-row">
        <div class="tip-cell {% if item.u1_points == 3 %}exact{% elif item.u1_points == 1 %}winner{% else %}miss{% endif %}">
          {% if item.u1_tip %}
            {{ item.u1_tip.tip_home }}:{{ item.u1_tip.tip_away }}
          {% else %}
            —
          {% endif %}
        </div>
        
        <div style="text-align: center; font-weight: 900;">
          {{ item.u1_points }}
          {% if item.u1_points > item.u2_points %}
            <span class="winner-badge">W</span>
          {% endif %}
        </div>
        
        <div class="match-result">
          <div style="font-size: 11px; color: var(--muted); margin-bottom: 4px;">
            {{ item.match.home_team.name[:10] }} - {{ item.match.away_team.name[:10] }}
          </div>
          <div>{{ item.match.home_score }}:{{ item.match.away_score }}</div>
        </div>
        
        <div style="text-align: center; font-weight: 900;">
          {{ item.u2_points }}
          {% if item.u2_points > item.u1_points %}
            <span class="winner-badge">W</span>
          {% endif %}
        </div>
        
        <div class="tip-cell {% if item.u2_points == 3 %}exact{% elif item.u2_points == 1 %}winner{% else %}miss{% endif %}">
          {% if item.u2_tip %}
            {{ item.u2_tip.tip_home }}:{{ item.u2_tip.tip_away }}
          {% else %}
            —
          {% endif %}
        </div>
      </div>
    {% endfor %}
  </div>
</div>

""", u1=u1, u2=u2, r=r,
     u1_total=u1_total, u2_total=u2_total,
     u1_exact=u1_exact, u2_exact=u2_exact,
     u1_winner=u1_winner, u2_winner=u2_winner,
     u1_miss=u1_miss, u2_miss=u2_miss,
     head_to_head_wins_u1=head_to_head_wins_u1,
     head_to_head_wins_u2=head_to_head_wins_u2,
     head_to_head_draws=head_to_head_draws,
     comparison_data=comparison_data)

    # Moje tipy - jednoduchá verze
    @app.route("/my-tips")
    @login_required
    def my_tips():
        """Zobrazí tipy přihlášeného uživatele"""
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            flash("Vyber soutěž.", "error")
            return redirect(url_for("matches"))

        # Všechny zápasy
        matches = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(
            Match.start_time.asc().nullslast(), Match.id.asc()
        ).all()

        # Moje tipy
        tips = Tip.query.join(Match).filter(
            Tip.user_id == current_user.id,
            Match.round_id == r.id,
            Match.is_deleted == False
        ).all()
        tip_map = {t.match_id: t for t in tips}

        # Stats
        total_points = 0
        exact_count = 0
        winner_count = 0

        for m in matches:
            tip = tip_map.get(m.id)
            if tip and m.home_score is not None and m.away_score is not None:
                pts = calc_points_for_tip(m, tip)
                total_points += pts
                if pts == 3:
                    exact_count += 1
                elif pts == 1:
                    winner_count += 1

        missed_count = len([t for t in tips if t.match_id in [m.id for m in matches if m.home_score is not None]]) - exact_count - winner_count

        return render_page(r"""
<style>
  .tips-table {
    width: 100%;
    border-collapse: collapse;
  }
  
  .tips-table th,
  .tips-table td {
    padding: 10px 8px;
    text-align: left;
    border-bottom: 1px solid var(--line);
  }
  
  .tips-table th {
    background: rgba(255,255,255,.03);
    font-weight: 900;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  
  .tip-exact { background: rgba(51,209,122,.08); }
  .tip-winner { background: rgba(249,199,79,.08); }
  .tip-missed { background: rgba(255,77,109,.08); }
  
  @media (max-width: 768px) {
    .tips-table th, .tips-table td { padding: 8px 4px; font-size: 13px; }
  }
</style>

<div class="card">
  <div class="row" style="justify-content:space-between; flex-wrap: wrap;">
    <div>
      <h2 style="margin:0;">🎯 Moje tipy</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <div class="row" style="gap: 8px;">
      <div class="tag pill-ok">✅ {{ exact_count }}</div>
      <div class="tag pill-warn">👍 {{ winner_count }}</div>
      <div class="tag pill-bad">❌ {{ missed_count }}</div>
      <div class="tag" style="background: rgba(110,168,254,.15); border-color: rgba(110,168,254,.3);">📊 {{ total_points }}b</div>
    </div>
  </div>
</div>

<div class="card" style="margin-top: 16px;">
  <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
    <table class="tips-table">
      <thead>
        <tr>
          <th style="width: 40px;">#</th>
          <th>Domácí</th>
          <th style="width: 70px; text-align: center;">Tip</th>
          <th style="width: 70px; text-align: center;">Výsledek</th>
          <th>Hosté</th>
          <th style="width: 60px; text-align: center;">Body</th>
        </tr>
      </thead>
      <tbody>
        {% for m in matches %}
          {% set tip = tip_map.get(m.id) %}
          {% set pts = calc_points_for_tip(m, tip) if (tip and m.home_score is not none) else 0 %}
          <tr class="{% if pts == 3 %}tip-exact{% elif pts == 1 %}tip-winner{% elif tip and m.home_score is not none %}tip-missed{% endif %}">
            <td>{{ loop.index }}</td>
            <td><strong>{{ m.home_team.name }}</strong></td>
            <td style="text-align: center;">
              {% if tip %}
                <strong>{{ tip.tip_home }}:{{ tip.tip_away }}</strong>
              {% else %}
                <span class="muted">—</span>
              {% endif %}
            </td>
            <td style="text-align: center;">
              {% if m.home_score is not none %}
                <strong>{{ m.home_score }}:{{ m.away_score }}</strong>
              {% else %}
                <span class="muted">—</span>
              {% endif %}
            </td>
            <td><strong>{{ m.away_team.name }}</strong></td>
            <td style="text-align: center; font-weight: 900;">
              {% if tip and m.home_score is not none %}
                {% if pts == 3 %}
                  <span style="color: var(--ok);">+3</span>
                {% elif pts == 1 %}
                  <span style="color: var(--warn);">+1</span>
                {% else %}
                  <span style="color: var(--danger);">0</span>
                {% endif %}
              {% elif tip %}
                <span class="muted">⏳</span>
              {% else %}
                <span class="muted">—</span>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
""", r=r, matches=matches, tip_map=tip_map, calc_points_for_tip=calc_points_for_tip,
    total_points=total_points, exact_count=exact_count, winner_count=winner_count, missed_count=missed_count)
    
    @app.route("/profile")
    @login_required
    def profile():
        """Redirect na my_tips"""
        return redirect(url_for('my_tips'))

    @app.route("/extras"
, methods=["GET", "POST"])
    @login_required
    def extras():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("matches"))

        locked = is_extras_locked(r)

        if request.method == "POST":
            if locked:
                flash("Extra otázky jsou uzavřené.", "error")
                return redirect(url_for("extras"))

            qid = int(request.form["question_id"])
            txt = (request.form.get("answer_text") or "").strip()
            if not txt:
                flash("Vyplň odpověď.", "error")
                return redirect(url_for("extras"))

            q = db.session.get(ExtraQuestion, qid)
            if not q or q.round_id != r.id:
                abort(400)
            
            # Kontrola deadline konkrétní otázky
            if q.deadline and datetime.now() >= q.deadline:
                flash("Uzávěrka pro tuto otázku již vypršela.", "error")
                return redirect(url_for("extras"))

            existing = ExtraAnswer.query.filter_by(question_id=q.id, user_id=current_user.id).first()
            if existing:
                existing.answer_text = txt
            else:
                db.session.add(ExtraAnswer(question_id=q.id, user_id=current_user.id, answer_text=txt))
            db.session.commit()
            audit("extra.answer.upsert", "ExtraAnswer", existing.id if existing else None, question_id=q.id)
            flash("Extra odpověď uložena.", "ok")
            return redirect(url_for("extras"))

        questions = ExtraQuestion.query.filter_by(round_id=r.id, is_deleted=False).order_by(ExtraQuestion.id.asc()).all()
        my_answers = ExtraAnswer.query.join(ExtraQuestion).filter(
            ExtraAnswer.user_id == current_user.id,
            ExtraQuestion.round_id == r.id,
        ).all()
        ans_map = {a.question_id: a for a in my_answers}

        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Extra</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b>
        {% if locked %}<span class="tag pill-bad" style="margin-left:10px;">Uzavřeno</span>{% endif %}
      </div>
    </div>
    <div class="row">
      {% if current_user.is_admin_effective %}
        <a class="btn btn-primary" href="{{ url_for('admin_extra_new') }}">Přidat otázku</a>
        <a class="btn" href="{{ url_for('admin_extra_manage') }}">Správa odpovědí</a>
        <a class="btn" href="{{ url_for('export_extras_csv') }}">Export extra</a>
      {% endif %}
    </div>
  </div>

  <hr class="sep">

  {% for q in questions %}
    {% set q_deadline = q.deadline %}
    {% set q_locked = locked or (q_deadline and q_deadline <= current_time) %}
    <div class="card" style="background:rgba(255,255,255,.03); margin-bottom:10px;">
      <div style="font-weight:900;">
        {{ loop.index }}. {{ q.question }}
        {% if q_deadline %}
          <span class="muted" style="font-weight:400; font-size:13px;">
            (Uzávěrka: {{ q_deadline.strftime('%d.%m.%Y %H:%M') }})
          </span>
        {% endif %}
        {% if q_locked and q_deadline and q_deadline <= current_time %}
          <span class="tag pill-bad" style="margin-left:10px; font-size:12px;">Uzavřeno</span>
        {% endif %}
      </div>
      <hr class="sep">
      <form method="post" class="row" style="justify-content:space-between;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <input type="hidden" name="question_id" value="{{ q.id }}">
        <input name="answer_text" style="flex:1;" placeholder="Tvoje odpověď"
               value="{{ ans_map.get(q.id).answer_text if ans_map.get(q.id) else '' }}"
               required {% if q_locked %}disabled{% endif %}>
        <button class="btn btn-primary" type="submit" {% if q_locked %}disabled{% endif %}>
          {% if q_locked %}Uzavřeno{% else %}Uložit{% endif %}
        </button>
      </form>
    </div>
  {% endfor %}

  {% if questions|length == 0 %}
    <div class="muted">Zatím nejsou žádné extra otázky.</div>
  {% endif %}
</div>
""", r=r, questions=questions, ans_map=ans_map, locked=locked, current_time=datetime.now())

    # --- EXPORTS ---
    @app.route("/export/leaderboard.csv")
    @login_required
    def export_leaderboard_csv():
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)

        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
        users = User.query.order_by(User.username.asc()).all()

        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["round_id", "round_name", "username", "email", "points_total"])
        for u in users:
            total = 0
            tips_for_user = Tip.query.join(Match).filter(Tip.user_id == u.id, Match.round_id == r.id).all()
            if not tips_for_user:
                continue  # Přeskočit uživatele bez tipů v této soutěži
            tips_map = {t.match_id: t for t in tips_for_user}
            for m in matches_q:
                t = tips_map.get(m.id)
                if t:
                    total += calc_points_for_tip(m, t)
            w.writerow([r.id, r.name, u.username, u.email, total])
        audit("export.leaderboard", "Round", r.id)

        return csv_response("leaderboard.csv", out.getvalue())


    @app.route("/export/tips.csv")
    @login_required
    def export_tips_csv():
        """Export všech tipů (pro vybranou soutěž) do CSV."""
        admin_required()

        rid = ensure_selected_round()
        if not rid:
            abort(404)

        r = db.session.get(Round, rid)
        if not r:
            abort(404)

        # tipy + zápasy + uživatelé
        rows = (
            db.session.query(Tip, Match, User)
            .join(Match, Tip.match_id == Match.id)
            .join(User, Tip.user_id == User.id)
            .filter(Match.round_id == r.id)
            .order_by(Match.start_time.asc().nullslast(), Match.id.asc(), User.username.asc())
            .all()
        )

        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["round_id", "round_name", "match_id", "home", "away", "start_time", "user_id", "username", "email", "tip_home", "tip_away"])
        for tip, match, user in rows:
            w.writerow([
                r.id,
                r.name,
                match.id,
                match.home,
                match.away,
                match.start_time.strftime("%Y-%m-%d %H:%M") if match.start_time else "",
                user.id,
                user.username,
                user.email,
                tip.tip_home,
                tip.tip_away,
            ])

        return csv_response("tips.csv", out.getvalue())
    @app.route("/export/leaderboard.xlsx")
    @login_required
    def export_leaderboard_xlsx():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)

        from openpyxl import Workbook

        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(Match.start_time.asc().nullslast(), Match.id.asc()).all()
        users = User.query.order_by(User.username.asc()).all()

        wb = Workbook()
        ws = wb.active
        ws.title = "Leaderboard"
        ws.append(["round_id", "round_name", "username", "email", "points_total"])

        for u in users:
            total = 0
            tips_for_user = Tip.query.join(Match).filter(Tip.user_id == u.id, Match.round_id == r.id).all()
            if not tips_for_user:
                continue  # Přeskočit uživatele bez tipů v této soutěži
            tips_map = {t.match_id: t for t in tips_for_user}
            for m in matches_q:
                t = tips_map.get(m.id)
                if t:
                    total += calc_points_for_tip(m, t)
            ws.append([r.id, r.name, u.username, u.email, total])

        audit("export.leaderboard.xlsx", "Round", r.id)

        import io
        bio = io.BytesIO()
        wb.save(bio)
        bio.seek(0)
        return binary_response("leaderboard.xlsx", bio.read(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    @app.route("/export/leaderboard.pdf")
    @login_required
    def export_leaderboard_pdf():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)

        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(Match.start_time.asc().nullslast(), Match.id.asc()).all()
        users = User.query.order_by(User.username.asc()).all()

        rows = []
        for u in users:
            total = 0
            tips_for_user = Tip.query.join(Match).filter(Tip.user_id == u.id, Match.round_id == r.id).all()
            if not tips_for_user:
                continue  # Přeskočit uživatele bez tipů v této soutěži
            tips_map = {t.match_id: t for t in tips_for_user}
            for m in matches_q:
                t = tips_map.get(m.id)
                if t:
                    total += calc_points_for_tip(m, t)
            rows.append((u.username, u.email, total))
        rows.sort(key=lambda x: (-x[2], x[0].lower()))

        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        import io

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4
        y = height - 50
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, f"Leaderboard – {r.name} (ID {r.id})")
        y -= 24
        c.setFont("Helvetica", 11)

        c.drawString(40, y, "Pořadí")
        c.drawString(90, y, "Uživatel")
        c.drawString(340, y, "Email")
        c.drawString(520, y, "Body")
        y -= 14
        c.line(40, y, 560, y)
        y -= 16

        rank = 1
        for username, email, pts in rows:
            if y < 60:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica-Bold", 14)
                c.drawString(40, y, f"Leaderboard – {r.name} (ID {r.id})")
                y -= 24
                c.setFont("Helvetica", 11)

            c.drawString(40, y, str(rank))
            c.drawString(90, y, username[:32])
            c.drawString(340, y, (email or "")[:32])
            c.drawRightString(560, y, str(pts))
            y -= 16
            rank += 1

        c.showPage()
        c.save()
        buf.seek(0)

        audit("export.leaderboard.pdf", "Round", r.id)
        return binary_response("leaderboard.pdf", buf.read(), mimetype="application/pdf")


    @app.route("/export/matches.csv")
    @login_required
    def export_matches_csv():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)
        matches_q = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(Match.id.asc()).all()
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["round_id", "match_id", "home_team", "away_team", "start_time", "home_score", "away_score"])
        for m in matches_q:
            w.writerow([
                r.id, m.id, m.home_team.name, m.away_team.name,
                m.start_time.strftime("%Y-%m-%d %H:%M") if m.start_time else "",
                "" if m.home_score is None else m.home_score,
                "" if m.away_score is None else m.away_score,
            ])
        audit("export.matches", "Round", r.id)
        return csv_response("matches.csv", out.getvalue())

    @app.route("/export/teams.csv")
    @login_required
    def export_teams_csv():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)
        teams_q = Team.query.filter_by(round_id=r.id, is_deleted=False).order_by(Team.name.asc()).all()
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["round_id", "team_name"])
        for t in teams_q:
            w.writerow([r.id, t.name])
        audit("export.teams", "Round", r.id)
        return csv_response("teams.csv", out.getvalue())

    @app.route("/export/extras.csv")
    @login_required
    def export_extras_csv():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(404)

        qs = ExtraQuestion.query.filter_by(round_id=r.id, is_deleted=False).order_by(ExtraQuestion.id.asc()).all()
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["round_id", "question_id", "question", "username", "email", "answer_text"])
        for q in qs:
            answers = ExtraAnswer.query.filter_by(question_id=q.id).all()
            amap = {a.user_id: a for a in answers}
            for u in User.query.order_by(User.username.asc()).all():
                a = amap.get(u.id)
                w.writerow([r.id, q.id, q.question, u.username, u.email, a.answer_text if a else ""])
        audit("export.extras", "Round", r.id)
        return csv_response("extras.csv", out.getvalue())
    # ---------- ARCHIVE ----------
    @app.route("/archive")
    @login_required
    def archive():
        """
        Jednoduchý archiv - jen seznam archivovaných soutěží
        """
        # Jen archivované soutěže
        archived_rounds = Round.query.filter_by(is_archived=True).order_by(Round.id.desc()).all()
        
        # Rychlé základní stats (jen COUNT)
        rounds_data = []
        for r in archived_rounds:
            tippers_count = db.session.query(Tip.user_id).join(Match).filter(
                Match.round_id == r.id
            ).distinct().count()
            
            matches_count = Match.query.filter_by(round_id=r.id, is_deleted=False).count()
            
            finished_count = Match.query.filter(
                Match.round_id == r.id,
                Match.is_deleted == False,
                Match.home_score != None
            ).count()
            
            sport_emoji = "⚽" if r.sport.name.lower() == "fotbal" else "🏒" if "hokej" in r.sport.name.lower() else "🏀"
            
            rounds_data.append({
                'round': r,
                'tippers_count': tippers_count,
                'matches_count': matches_count,
                'finished_count': finished_count,
                'sport_emoji': sport_emoji,
                'progress_pct': int((finished_count / matches_count * 100) if matches_count > 0 else 0)
            })
        
        return render_page(r"""
<style>
.archive-card {
  background: rgba(110,168,254,0.08);
  border: 1px solid rgba(110,168,254,0.2);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 16px;
  transition: all 0.2s;
  border-left: 4px solid #8b5cf6;
}

.archive-card:hover {
  background: rgba(110,168,254,0.12);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.archive-title {
  font-size: 20px;
  font-weight: 900;
  margin-bottom: 4px;
}

.archive-stats {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  margin-top: 12px;
}

.stat-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  font-size: 13px;
}

.stat-value {
  font-weight: 900;
  color: var(--accent);
}

.progress-bar {
  width: 100%;
  height: 6px;
  background: rgba(0,0,0,0.2);
  border-radius: 3px;
  overflow: hidden;
  margin: 8px 0;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
  transition: width 0.3s;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  background: rgba(255,255,255,.03);
  border: 1px solid var(--line);
  border-radius: 12px;
}
</style>

<div class="card">
  <div class="row" style="justify-content:space-between; margin-bottom: 16px;">
    <div>
      <h2 style="margin:0;">📦 Archiv</h2>
      <div class="muted">Ukončené a archivované soutěže</div>
    </div>
    <a href="{{ url_for('archive_stats') }}" class="btn" style="background: rgba(139,92,246,.15); color: #8b5cf6; border: 1px solid rgba(139,92,246,.3);">
      📊 Hall of Fame
    </a>
  </div>
</div>

{% if rounds_data %}
  {% for rd in rounds_data %}
    <div class="archive-card">
      <div class="row" style="justify-content: space-between; margin-bottom: 12px;">
        <div>
          <div class="archive-title">
            {{ rd.sport_emoji }} {{ rd.round.name }}
          </div>
          <div class="muted" style="font-size: 13px;">
            {{ rd.round.sport.name }}
            {% if rd.round.created_at %}
              • Vytvořeno {{ rd.round.created_at.strftime('%d.%m.%Y') }}
            {% endif %}
          </div>
        </div>
        <a href="{{ url_for('archive_detail', round_id=rd.round.id) }}" class="btn btn-primary">
          📊 Detail
        </a>
      </div>
      
      <div class="progress-bar">
        <div class="progress-fill" style="width: {{ rd.progress_pct }}%;"></div>
      </div>
      
      <div class="archive-stats">
        <div class="stat-item">
          <span>⚽</span>
          <span><span class="stat-value">{{ rd.matches_count }}</span> zápasů</span>
        </div>
        <div class="stat-item">
          <span>✅</span>
          <span><span class="stat-value">{{ rd.finished_count }}</span> dokončeno</span>
        </div>
        <div class="stat-item">
          <span>👥</span>
          <span><span class="stat-value">{{ rd.tippers_count }}</span> tipérů</span>
        </div>
        <div class="stat-item">
          <span>📈</span>
          <span><span class="stat-value">{{ rd.progress_pct }}%</span> hotovo</span>
        </div>
      </div>
    </div>
  {% endfor %}
{% else %}
  <div class="empty-state">
    <div style="font-size: 64px; margin-bottom: 16px;">📦</div>
    <h3 style="margin: 0 0 8px 0;">Žádné archivované soutěže</h3>
    <div class="muted">
      Když admin archivuje soutěž, objeví se zde.<br>
      Archivuj soutěž v Správa soutěží → 📦 Archivovat
    </div>
  </div>
{% endif %}

""", rounds_data=rounds_data)

    @app.route("/archive/stats")
    @login_required
    def archive_stats():
        """
        Hall of Fame - celkové statistiky archivovaných soutěží
        """
        archived_rounds = Round.query.filter_by(is_archived=True).order_by(Round.id.desc()).all()
        
        if not archived_rounds:
            return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 16px 0;">🏆 Hall of Fame</h2>
  <div class="muted">Zatím nejsou žádné archivované soutěže.</div>
  <a href="{{ url_for('archive') }}" class="btn" style="margin-top: 16px;">← Zpět na archiv</a>
</div>
""")
        
        # Hall of Fame výpočty
        all_users = User.query.all()
        user_stats = []
        
        for user in all_users:
            wins = 0
            participations = 0
            total_points = 0
            total_exact = 0
            
            for r in archived_rounds:
                tips = Tip.query.join(Match).filter(
                    Match.round_id == r.id,
                    Tip.user_id == user.id,
                    Match.is_deleted == False
                ).all()
                
                if not tips:
                    continue
                
                participations += 1
                
                # Spočítej body
                r_points = 0
                for tip in tips:
                    if tip.match.home_score is not None:
                        pts = calc_points_for_tip(tip.match, tip)
                        r_points += pts
                        total_points += pts
                        if pts == 3:
                            total_exact += 1
                
                # Je vítěz?
                all_participants = db.session.query(Tip.user_id).join(Match).filter(
                    Match.round_id == r.id,
                    Match.is_deleted == False
                ).distinct().all()
                
                scores = []
                for (participant_id,) in all_participants:
                    p_tips = Tip.query.join(Match).filter(
                        Match.round_id == r.id,
                        Tip.user_id == participant_id,
                        Match.is_deleted == False,
                        Match.home_score != None
                    ).all()
                    
                    p_total = sum(calc_points_for_tip(t.match, t) for t in p_tips)
                    scores.append((participant_id, p_total))
                
                if scores:
                    scores.sort(key=lambda x: -x[1])
                    if scores[0][0] == user.id and scores[0][1] > 0:
                        if len(scores) == 1 or scores[0][1] > scores[1][1]:
                            wins += 1
            
            if participations > 0:
                avg_points = total_points / participations
                user_stats.append({
                    'user': user,
                    'wins': wins,
                    'participations': participations,
                    'total_points': total_points,
                    'total_exact': total_exact,
                    'avg_points': avg_points
                })
        
        # Sort
        most_wins = sorted(user_stats, key=lambda x: x['wins'], reverse=True)[:5]
        most_active = sorted(user_stats, key=lambda x: x['participations'], reverse=True)[:5]
        best_avg = sorted([u for u in user_stats if u['participations'] >= 3], 
                          key=lambda x: x['avg_points'], reverse=True)[:5]
        most_points = sorted(user_stats, key=lambda x: x['total_points'], reverse=True)[:5]
        most_exact = sorted(user_stats, key=lambda x: x['total_exact'], reverse=True)[:5]
        
        # Celkové stats
        total_rounds = len(archived_rounds)
        total_matches = Match.query.join(Round).filter(
            Round.is_archived == True,
            Match.is_deleted == False
        ).count()
        total_tips = Tip.query.join(Match).join(Round).filter(
            Round.is_archived == True,
            Match.is_deleted == False
        ).count()
        
        return render_page(r"""
<style>
.hof-section {
  background: rgba(255,255,255,.03);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 20px;
}

.hof-title {
  font-size: 20px;
  font-weight: 900;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.hof-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: rgba(0,0,0,0.2);
  border-radius: 8px;
  margin-bottom: 12px;
  transition: all 0.2s;
}

.hof-item:hover {
  background: rgba(0,0,0,0.3);
  transform: translateX(4px);
}

.hof-rank {
  font-size: 24px;
  font-weight: 900;
  width: 40px;
  text-align: center;
}

.hof-rank.gold { color: #ffd700; }
.hof-rank.silver { color: #c0c0c0; }
.hof-rank.bronze { color: #cd7f32; }

.hof-user {
  flex: 1;
  margin-left: 12px;
  font-weight: 600;
}

.hof-stat {
  font-weight: 900;
  color: var(--accent);
  font-size: 20px;
}

.hof-detail {
  color: var(--muted);
  font-size: 12px;
  margin-left: 8px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: rgba(110,168,254,0.1);
  border: 1px solid rgba(110,168,254,0.3);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.stat-card-value {
  font-size: 36px;
  font-weight: 900;
  color: var(--accent);
  margin-bottom: 8px;
}

.stat-card-label {
  color: var(--muted);
  font-size: 13px;
}
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; margin-bottom: 20px;">
    <div>
      <h2 style="margin: 0;">🏆 Hall of Fame</h2>
      <div class="muted">Celkové statistiky archivovaných soutěží</div>
    </div>
    <a href="{{ url_for('archive') }}" class="btn">← Zpět na archiv</a>
  </div>
  
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-card-value">{{ total_rounds }}</div>
      <div class="stat-card-label">Soutěží</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-value">{{ total_matches }}</div>
      <div class="stat-card-label">Zápasů</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-value">{{ total_tips }}</div>
      <div class="stat-card-label">Tipů</div>
    </div>
  </div>
</div>

<div class="hof-section">
  <div class="hof-title">👑 Nejvíc výher</div>
  {% for item in most_wins %}
    <div class="hof-item">
      <div class="hof-rank {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
        {{ loop.index }}.
      </div>
      <div class="hof-user">
        <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
          {{ item.user.display_name }}
        </a>
      </div>
      <div class="hof-stat">{{ item.wins }}</div>
      <div class="hof-detail">výher z {{ item.participations }}</div>
    </div>
  {% endfor %}
</div>

<div class="hof-section">
  <div class="hof-title">💯 Nejvíc účastí</div>
  {% for item in most_active %}
    <div class="hof-item">
      <div class="hof-rank {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
        {{ loop.index }}.
      </div>
      <div class="hof-user">
        <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
          {{ item.user.display_name }}
        </a>
      </div>
      <div class="hof-stat">{{ item.participations }}</div>
      <div class="hof-detail">soutěží</div>
    </div>
  {% endfor %}
</div>

<div class="hof-section">
  <div class="hof-title">📊 Nejlepší průměr (min 3)</div>
  {% for item in best_avg %}
    <div class="hof-item">
      <div class="hof-rank {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
        {{ loop.index }}.
      </div>
      <div class="hof-user">
        <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
          {{ item.user.display_name }}
        </a>
      </div>
      <div class="hof-stat">{{ "%.1f"|format(item.avg_points) }}</div>
      <div class="hof-detail">bodů/soutěž</div>
    </div>
  {% endfor %}
</div>

<div class="hof-section">
  <div class="hof-title">🎯 Nejvíc bodů celkem</div>
  {% for item in most_points %}
    <div class="hof-item">
      <div class="hof-rank {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
        {{ loop.index }}.
      </div>
      <div class="hof-user">
        <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
          {{ item.user.display_name }}
        </a>
      </div>
      <div class="hof-stat">{{ item.total_points }}</div>
      <div class="hof-detail">bodů</div>
    </div>
  {% endfor %}
</div>

<div class="hof-section">
  <div class="hof-title">💎 Nejvíc přesných</div>
  {% for item in most_exact %}
    <div class="hof-item">
      <div class="hof-rank {% if loop.index == 1 %}gold{% elif loop.index == 2 %}silver{% elif loop.index == 3 %}bronze{% endif %}">
        {{ loop.index }}.
      </div>
      <div class="hof-user">
        <a href="{{ url_for('user_tips', user_id=item.user.id) }}" style="color: inherit; text-decoration: none;">
          {{ item.user.display_name }}
        </a>
      </div>
      <div class="hof-stat">{{ item.total_exact }}</div>
      <div class="hof-detail">přesných</div>
    </div>
  {% endfor %}
</div>

""", most_wins=most_wins, most_active=most_active, best_avg=best_avg,
     most_points=most_points, most_exact=most_exact,
     total_rounds=total_rounds, total_matches=total_matches, total_tips=total_tips)


    @app.route("/archive/<int:round_id>")
    @login_required
    def archive_detail(round_id):
        """Detail soutěže s pokročilými statistikami a grafy"""
        r = db.session.get(Round, round_id)
        if not r:
            flash("Soutěž nenalezena.", "error")
            return redirect(url_for("archive"))
        
        # Active tab
        active_tab = request.args.get('tab', 'overview')
        
        # Základní stats
        matches = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
        finished_matches = [m for m in matches if m.home_score is not None]
        
        tippers = db.session.query(Tip.user_id).join(Match).filter(
            Match.round_id == r.id
        ).distinct().all()
        tippers_count = len(tippers)
        
        total_tips = Tip.query.join(Match).filter(Match.round_id == r.id).count()
        possible_tips = len(matches) * tippers_count
        
        # Leaderboard
        leaderboard = []
        users = User.query.all()
        for user in users:
            tips = Tip.query.join(Match).filter(
                Match.round_id == r.id,
                Tip.user_id == user.id
            ).all()
            
            if not tips:
                continue
            
            points = 0
            exact = 0
            outcome = 0
            wrong = 0
            
            for tip in tips:
                if tip.match.home_score is not None:
                    pts = calc_points_for_tip(tip.match, tip)
                    points += pts
                    if pts == 3:
                        exact += 1
                    elif pts == 1:
                        outcome += 1
                    else:
                        wrong += 1
            
            if points > 0 or len(tips) > 0:
                leaderboard.append({
                    'user': user,
                    'points': points,
                    'exact': exact,
                    'outcome': outcome,
                    'wrong': wrong,
                    'total_tips': len(tips),
                    'avg': round(points / len(tips), 2) if len(tips) > 0 else 0
                })
        
        leaderboard.sort(key=lambda x: x['points'], reverse=True)
        
        # Best/Worst matches (pro stats tab)
        match_stats = []
        for match in finished_matches:
            tips = Tip.query.filter_by(match_id=match.id).all()
            if not tips:
                continue
            
            exact_count = sum(1 for t in tips if calc_points_for_tip(match, t) == 3)
            outcome_count = sum(1 for t in tips if calc_points_for_tip(match, t) == 1)
            
            match_stats.append({
                'match': match,
                'exact_count': exact_count,
                'outcome_count': outcome_count,
                'accuracy': round(exact_count / len(tips) * 100) if len(tips) > 0 else 0,
                'total_goals': (match.home_score or 0) + (match.away_score or 0)
            })
        
        best_matches = sorted(match_stats, key=lambda x: x['accuracy'], reverse=True)[:5]
        worst_matches = sorted(match_stats, key=lambda x: x['accuracy'])[:5]
        highest_scoring = sorted(match_stats, key=lambda x: x['total_goals'], reverse=True)[:5]
        lowest_scoring = sorted(match_stats, key=lambda x: x['total_goals'])[:5]
        
        # Data pro grafy (JSON)
        chart_data = {
            'leaderboard_labels': [lb['user'].display_name for lb in leaderboard[:10]],
            'leaderboard_points': [lb['points'] for lb in leaderboard[:10]],
            'accuracy_labels': [f"{lb['user'].display_name}" for lb in leaderboard[:10]],
            'accuracy_exact': [lb['exact'] for lb in leaderboard[:10]],
            'accuracy_outcome': [lb['outcome'] for lb in leaderboard[:10]],
            'accuracy_wrong': [lb['wrong'] for lb in leaderboard[:10]]
        }
        
        return render_page(r"""
<style>
.tab-nav {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
  border-bottom: 2px solid rgba(110,168,254,0.2);
  overflow-x: auto;
}

.tab-btn {
  padding: 12px 20px;
  background: transparent;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -2px;
  transition: all 0.2s;
  white-space: nowrap;
}

.tab-btn:hover {
  color: #e9eefc;
}

.tab-btn.active {
  color: #6ea8fe;
  border-bottom-color: #6ea8fe;
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
}

.stat-card {
  background: rgba(110,168,254,0.08);
  border: 1px solid rgba(110,168,254,0.2);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 12px;
}

.match-card {
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 8px;
  border-left: 3px solid #6ea8fe;
}

canvas {
  max-height: 400px;
}

@media (max-width: 768px) {
  canvas {
    max-height: 300px;
  }
}
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
    <div>
      <h2 style="margin:0 0 4px 0;">
        {% if r.sport.name|lower == 'fotbal' %}⚽{% elif 'hokej' in r.sport.name|lower %}🏒{% else %}🏀{% endif %}
        {{ r.name }}
      </h2>
      <div class="muted">{{ r.sport.name }} • Detail soutěže</div>
    </div>
    <a href="{{ url_for('archive') }}" class="btn">← Zpět</a>
  </div>
  
  <!-- Tabs Navigation -->
  <div class="tab-nav">
    <button class="tab-btn {% if active_tab == 'overview' %}active{% endif %}" onclick="switchTab('overview')">📊 Přehled</button>
    <button class="tab-btn {% if active_tab == 'stats' %}active{% endif %}" onclick="switchTab('stats')">📈 Statistiky</button>
    <button class="tab-btn {% if active_tab == 'export' %}active{% endif %}" onclick="switchTab('export')">📥 Export</button>
    <button class="tab-btn {% if active_tab == 'import' %}active{% endif %}" onclick="switchTab('import')">📤 Import</button>
  </div>
  
  <!-- OVERVIEW TAB -->
  <div id="tab-overview" class="tab-content {% if active_tab == 'overview' %}active{% endif %}">
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">
      <div class="stat-card">
        <div style="font-size: 32px; font-weight: bold; color: #6ea8fe;">{{ matches|length }}</div>
        <div class="muted">Celkem zápasů</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 32px; font-weight: bold; color: #4ade80;">{{ finished_matches|length }}</div>
        <div class="muted">Dokončeno</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 32px; font-weight: bold; color: #6ea8fe;">{{ tippers_count }}</div>
        <div class="muted">Tipérů</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 32px; font-weight: bold; color: #6ea8fe;">{{ total_tips }}</div>
        <div class="muted">Celkem tipů</div>
      </div>
    </div>
    
    <h3 style="margin: 24px 0 12px 0;">🏆 Finální žebříček</h3>
    {% if leaderboard|length > 0 %}
    <div style="overflow-x: auto;">
      <table class="lb" style="width: 100%;">
        <thead>
          <tr>
            <th style="text-align: left;">Pořadí</th>
            <th style="text-align: left;">Tipér</th>
            <th>Body</th>
            <th>Přesné</th>
            <th>Výsledek</th>
            <th>Tipů</th>
            <th>Ø</th>
          </tr>
        </thead>
        <tbody>
          {% for lb in leaderboard[:10] %}
          <tr>
            <td style="text-align: left;">
              {% if loop.index == 1 %}🥇
              {% elif loop.index == 2 %}🥈
              {% elif loop.index == 3 %}🥉
              {% else %}{{ loop.index }}.
              {% endif %}
            </td>
            <td style="text-align: left;"><b>{{ lb.user.display_name }}</b></td>
            <td><b>{{ lb.points }}</b></td>
            <td>{{ lb.exact }}</td>
            <td>{{ lb.outcome }}</td>
            <td>{{ lb.total_tips }}</td>
            <td class="muted">{{ lb.avg }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="muted">Zatím žádné tipy</div>
    {% endif %}
  </div>
  
  <!-- STATS TAB -->
  <div id="tab-stats" class="tab-content {% if active_tab == 'stats' %}active{% endif %}">
    
    <h3 style="margin: 0 0 12px 0;">📊 Grafy</h3>
    
    <!-- Žebříček -->
    <div class="stat-card">
      <h4 style="margin: 0 0 12px 0;">Top 10 Žebříček</h4>
      <canvas id="leaderboard-chart"></canvas>
    </div>
    
    <!-- Přesnost -->
    <div class="stat-card">
      <h4 style="margin: 0 0 12px 0;">Přesnost tipů (Top 10)</h4>
      <canvas id="accuracy-chart"></canvas>
    </div>
    
    <h3 style="margin: 24px 0 12px 0;">🎯 Best & Worst Zápasy</h3>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">
      <div>
        <h4 style="margin: 0 0 12px 0; color: #4ade80;">✅ Nejlepší přesnost</h4>
        {% for ms in best_matches %}
        <div class="match-card" style="border-left-color: #4ade80;">
          <div><b>{{ ms.match.home_team.name }} vs {{ ms.match.away_team.name }}</b></div>
          <div class="muted" style="font-size: 12px;">
            {{ ms.match.home_score }}:{{ ms.match.away_score }} • 
            {{ ms.exact_count }} přesných ({{ ms.accuracy }}%)
          </div>
        </div>
        {% endfor %}
      </div>
      
      <div>
        <h4 style="margin: 0 0 12px 0; color: #ef4444;">❌ Nejtěžší zápasy</h4>
        {% for ms in worst_matches %}
        <div class="match-card" style="border-left-color: #ef4444;">
          <div><b>{{ ms.match.home_team.name }} vs {{ ms.match.away_team.name }}</b></div>
          <div class="muted" style="font-size: 12px;">
            {{ ms.match.home_score }}:{{ ms.match.away_score }} • 
            {{ ms.exact_count }} přesných ({{ ms.accuracy }}%)
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-top: 16px;">
      <div>
        <h4 style="margin: 0 0 12px 0; color: #fbbf24;">⚡ Nejvíce gólů</h4>
        {% for ms in highest_scoring %}
        <div class="match-card" style="border-left-color: #fbbf24;">
          <div><b>{{ ms.match.home_team.name }} vs {{ ms.match.away_team.name }}</b></div>
          <div class="muted" style="font-size: 12px;">
            {{ ms.match.home_score }}:{{ ms.match.away_score }} • 
            Celkem {{ ms.total_goals }} gólů
          </div>
        </div>
        {% endfor %}
      </div>
      
      <div>
        <h4 style="margin: 0 0 12px 0; color: #94a3b8;">🔒 Nejméně gólů</h4>
        {% for ms in lowest_scoring %}
        <div class="match-card" style="border-left-color: #94a3b8;">
          <div><b>{{ ms.match.home_team.name }} vs {{ ms.match.away_team.name }}</b></div>
          <div class="muted" style="font-size: 12px;">
            {{ ms.match.home_score }}:{{ ms.match.away_score }} • 
            Celkem {{ ms.total_goals }} gólů
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>
  
  <!-- EXPORT TAB -->
  <div id="tab-export" class="tab-content {% if active_tab == 'export' %}active{% endif %}">
    <h3 style="margin: 0 0 12px 0;">📥 Export dat</h3>
    <p class="muted">Stáhni data této soutěže v různých formátech</p>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-top: 20px;">
      
      <div class="stat-card">
        <h4 style="margin: 0 0 8px 0;">📊 Žebříček</h4>
        <p class="muted" style="font-size: 12px; margin-bottom: 12px;">Export finálního žebříčku</p>
        <div class="row" style="gap: 8px;">
          <a href="/archive/{{ r.id }}/export/leaderboard/csv" class="btn btn-sm">CSV</a>
          <a href="/archive/{{ r.id }}/export/leaderboard/json" class="btn btn-sm">JSON</a>
        </div>
      </div>
      
      <div class="stat-card">
        <h4 style="margin: 0 0 8px 0;">🎯 Všechny tipy</h4>
        <p class="muted" style="font-size: 12px; margin-bottom: 12px;">Kompletní tipy všech uživatelů</p>
        <div class="row" style="gap: 8px;">
          <a href="/archive/{{ r.id }}/export/tips/csv" class="btn btn-sm">CSV</a>
          <a href="/archive/{{ r.id }}/export/tips/json" class="btn btn-sm">JSON</a>
        </div>
      </div>
      
      <div class="stat-card">
        <h4 style="margin: 0 0 8px 0;">⚽ Zápasy</h4>
        <p class="muted" style="font-size: 12px; margin-bottom: 12px;">Seznam všech zápasů s výsledky</p>
        <div class="row" style="gap: 8px;">
          <a href="/archive/{{ r.id }}/export/matches/csv" class="btn btn-sm">CSV</a>
          <a href="/archive/{{ r.id }}/export/matches/json" class="btn btn-sm">JSON</a>
        </div>
      </div>
      
      <div class="stat-card">
        <h4 style="margin: 0 0 8px 0;">📦 Kompletní archiv</h4>
        <p class="muted" style="font-size: 12px; margin-bottom: 12px;">Všechna data najednou (backup)</p>
        <div class="row" style="gap: 8px;">
          <a href="/archive/{{ r.id }}/export/full/json" class="btn btn-sm">JSON</a>
        </div>
      </div>
      
    </div>
  </div>
  
  <!-- IMPORT TAB -->
  <div id="tab-import" class="tab-content {% if active_tab == 'import' %}active{% endif %}">
    <h3 style="margin: 0 0 12px 0;">📤 Import archivu</h3>
    <p class="muted">Obnov data z dříve exportovaného archivu (disaster recovery)</p>
    
    <div class="stat-card" style="background: rgba(251,191,36,0.1); border-color: rgba(251,191,36,0.3); margin-top: 20px;">
      <div style="display: flex; gap: 12px; align-items: flex-start;">
        <div style="font-size: 24px;">⚠️</div>
        <div>
          <h4 style="margin: 0 0 8px 0;">Důležité upozornění</h4>
          <ul style="margin: 0; padding-left: 20px; font-size: 14px;">
            <li>Import nahradí všechna data této soutěže</li>
            <li>Použij pouze soubory exportované z této aplikace</li>
            <li>Doporučujeme zálohovat před importem</li>
            <li>Podporované formáty: JSON</li>
          </ul>
        </div>
      </div>
    </div>
    
    <form action="/archive/{{ r.id }}/import" method="post" enctype="multipart/form-data" style="margin-top: 20px;">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
      <div style="margin-bottom: 16px;">
        <label style="display: block; margin-bottom: 8px; font-weight: 600;">Vyber soubor k importu:</label>
        <input type="file" name="import_file" accept=".json" required style="padding: 8px; background: rgba(0,0,0,0.2); border: 1px solid rgba(110,168,254,0.3); border-radius: 6px; color: #e9eefc;">
      </div>
      
      <div style="margin-bottom: 16px;">
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
          <input type="checkbox" name="confirm" required>
          <span>Rozumím, že tímto nahradím všechna současná data</span>
        </label>
      </div>
      
      <div class="row" style="gap: 8px;">
        <button type="submit" class="btn btn-primary">📤 Importovat archiv</button>
        <button type="button" class="btn" onclick="document.querySelector('input[type=file]').value = ''">Zrušit</button>
      </div>
    </form>
    
    <hr class="sep">
    
    <h4 style="margin: 16px 0 8px 0;">📝 Formát souboru</h4>
    <p class="muted" style="font-size: 14px;">Import soubor musí být JSON s následující strukturou:</p>
    <pre style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px;">
{
  "round": {...},
  "matches": [...],
  "tips": [...],
  "leaderboard": [...]
}</pre>
  </div>
  
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Tab switching
function switchTab(tabName) {
  // Hide all
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.remove('active');
  });
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  
  // Show selected
  document.getElementById('tab-' + tabName).classList.add('active');
  event.target.classList.add('active');
  
  // Update URL
  const url = new URL(window.location);
  url.searchParams.set('tab', tabName);
  window.history.pushState({}, '', url);
}

// Charts
const chartData = {{ chart_data|tojson }};

// Leaderboard chart
new Chart(document.getElementById('leaderboard-chart'), {
  type: 'bar',
  data: {
    labels: chartData.leaderboard_labels,
    datasets: [{
      label: 'Body',
      data: chartData.leaderboard_points,
      backgroundColor: 'rgba(110, 168, 254, 0.5)',
      borderColor: 'rgba(110, 168, 254, 1)',
      borderWidth: 1
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: { display: false }
    },
    scales: {
      y: { beginAtZero: true }
    }
  }
});

// Accuracy chart (stacked)
new Chart(document.getElementById('accuracy-chart'), {
  type: 'bar',
  data: {
    labels: chartData.accuracy_labels,
    datasets: [
      {
        label: 'Přesné (3b)',
        data: chartData.accuracy_exact,
        backgroundColor: 'rgba(74, 222, 128, 0.8)'
      },
      {
        label: 'Výsledek (1b)',
        data: chartData.accuracy_outcome,
        backgroundColor: 'rgba(251, 191, 36, 0.8)'
      },
      {
        label: 'Chybné (0b)',
        data: chartData.accuracy_wrong,
        backgroundColor: 'rgba(239, 68, 68, 0.8)'
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: { display: true }
    },
    scales: {
      x: { stacked: true },
      y: { stacked: true, beginAtZero: true }
    }
  }
});
</script>
""", r=r, matches=matches, finished_matches=finished_matches, 
    tippers_count=tippers_count, total_tips=total_tips, possible_tips=possible_tips,
    leaderboard=leaderboard, active_tab=active_tab,
    best_matches=best_matches, worst_matches=worst_matches,
    highest_scoring=highest_scoring, lowest_scoring=lowest_scoring,
    chart_data=chart_data)



    # --- ARCHIVE EXPORTS ---
    @app.route("/archive/<int:round_id>/export/<what>/<format>")
    @login_required
    def archive_export(round_id, what, format):
        """Export archivu v různých formátech"""
        r = db.session.get(Round, round_id)
        if not r:
            return "Round not found", 404
        
        import io
        
        if what == "leaderboard":
            # Export žebříčku
            users = User.query.all()
            leaderboard = []
            
            for user in users:
                tips = Tip.query.join(Match).filter(
                    Match.round_id == r.id,
                    Tip.user_id == user.id
                ).all()
                
                if not tips:
                    continue
                
                points = sum(calc_points_for_tip(t.match, t) for t in tips if t.match.home_score is not None)
                exact = sum(1 for t in tips if t.match.home_score is not None and calc_points_for_tip(t.match, t) == 3)
                
                leaderboard.append({
                    'user': user.display_name,
                    'points': points,
                    'exact': exact,
                    'total_tips': len(tips)
                })
            
            leaderboard.sort(key=lambda x: x['points'], reverse=True)
            
            if format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['Pořadí', 'Tipér', 'Body', 'Přesné tipy', 'Celkem tipů'])
                for i, lb in enumerate(leaderboard, 1):
                    writer.writerow([i, lb['user'], lb['points'], lb['exact'], lb['total_tips']])
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename=leaderboard_{r.name.replace(" ", "_")}.csv'}
                )
            
            elif format == "json":
                return jsonify({
                    'round': r.name,
                    'leaderboard': leaderboard
                })
        
        elif what == "tips":
            # Export všech tipů
            tips = Tip.query.join(Match).filter(Match.round_id == r.id).all()
            
            tips_data = []
            for tip in tips:
                tips_data.append({
                    'user': tip.user.display_name,
                    'match': f"{tip.match.home_team.name} vs {tip.match.away_team.name}",
                    'tip': f"{tip.home_score}:{tip.away_score}",
                    'result': f"{tip.match.home_score}:{tip.match.away_score}" if tip.match.home_score is not None else "—",
                    'points': calc_points_for_tip(tip.match, tip) if tip.match.home_score is not None else 0
                })
            
            if format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['Tipér', 'Zápas', 'Tip', 'Výsledek', 'Body'])
                for t in tips_data:
                    writer.writerow([t['user'], t['match'], t['tip'], t['result'], t['points']])
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename=tips_{r.name.replace(" ", "_")}.csv'}
                )
            
            elif format == "json":
                return jsonify({
                    'round': r.name,
                    'tips': tips_data
                })
        
        elif what == "matches":
            # Export zápasů
            matches = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
            
            matches_data = []
            for match in matches:
                matches_data.append({
                    'home_team': match.home_team.name,
                    'away_team': match.away_team.name,
                    'result': f"{match.home_score}:{match.away_score}" if match.home_score is not None else "—",
                    'date': match.match_datetime.isoformat() if match.match_datetime else ""
                })
            
            if format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['Domácí', 'Hosté', 'Výsledek', 'Datum'])
                for m in matches_data:
                    writer.writerow([m['home_team'], m['away_team'], m['result'], m['date']])
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename=matches_{r.name.replace(" ", "_")}.csv'}
                )
            
            elif format == "json":
                return jsonify({
                    'round': r.name,
                    'matches': matches_data
                })
        
        elif what == "full":
            # Kompletní backup
            matches = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
            tips = Tip.query.join(Match).filter(Match.round_id == r.id).all()
            
            full_data = {
                'round': {
                    'id': r.id,
                    'name': r.name,
                    'sport': r.sport.name,
                    'is_active': r.is_active
                },
                'matches': [{
                    'id': m.id,
                    'home_team': m.home_team.name,
                    'away_team': m.away_team.name,
                    'home_score': m.home_score,
                    'away_score': m.away_score,
                    'match_datetime': m.match_datetime.isoformat() if m.match_datetime else None
                } for m in matches],
                'tips': [{
                    'user': t.user.display_name,
                    'user_id': t.user.id,
                    'match_id': t.match.id,
                    'home_score': t.home_score,
                    'away_score': t.away_score
                } for t in tips],
                'export_date': datetime.utcnow().isoformat()
            }
            
            return Response(
                json.dumps(full_data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment;filename=full_archive_{r.name.replace(" ", "_")}.json'}
            )
        
        return "Invalid export type", 400
    
    
    # --- ARCHIVE IMPORT ---
    @app.route("/archive/<int:round_id>/import", methods=["POST"])
    @login_required
    def archive_import(round_id):
        """Import archivu z JSON (disaster recovery)"""
        admin_required()  # Jen admin může importovat
        
        r = db.session.get(Round, round_id)
        if not r:
            flash("Soutěž nenalezena.", "error")
            return redirect(url_for("archive"))
        
        file = request.files.get('import_file')
        if not file:
            flash("❌ Žádný soubor nebyl vybrán", "error")
            return redirect(url_for("archive_detail", round_id=round_id, tab='import'))
        
        try:
            # Načti JSON
            data = json.load(file)
            
            # Validace
            if 'round' not in data or 'matches' not in data or 'tips' not in data:
                flash("❌ Neplatný formát souboru", "error")
                return redirect(url_for("archive_detail", round_id=round_id, tab='import'))
            
            # BACKUP stávajících dat (do auditu)
            old_matches_count = Match.query.filter_by(round_id=r.id, is_deleted=False).count()
            old_tips_count = Tip.query.join(Match).filter(Match.round_id == r.id).count()
            
            # SMAZAT stávající data
            # Nejdřív tipy (kvůli foreign keys)
            Tip.query.filter(Tip.match_id.in_(
                db.session.query(Match.id).filter_by(round_id=r.id)
            )).delete(synchronize_session=False)
            
            # Pak zápasy
            Match.query.filter_by(round_id=r.id).delete(synchronize_session=False)
            
            # IMPORT nových dat
            match_id_mapping = {}  # old_id -> new_match_id
            
            # Import zápasů
            for match_data in data['matches']:
                # Najdi týmy (nebo vytvoř)
                home_team = Team.query.filter_by(name=match_data['home_team']).first()
                if not home_team:
                    home_team = Team(name=match_data['home_team'], sport_id=r.sport_id)
                    db.session.add(home_team)
                    db.session.flush()
                
                away_team = Team.query.filter_by(name=match_data['away_team']).first()
                if not away_team:
                    away_team = Team(name=match_data['away_team'], sport_id=r.sport_id)
                    db.session.add(away_team)
                    db.session.flush()
                
                # Vytvoř zápas
                match = Match(
                    round_id=r.id,
                    home_team_id=home_team.id,
                    away_team_id=away_team.id,
                    home_score=match_data.get('home_score'),
                    away_score=match_data.get('away_score'),
                    match_datetime=datetime.fromisoformat(match_data['match_datetime']) if match_data.get('match_datetime') else None,
                    is_deleted=False
                )
                db.session.add(match)
                db.session.flush()
                
                # Mapování pro tipy
                match_id_mapping[match_data['id']] = match.id
            
            # Import tipů
            imported_tips = 0
            for tip_data in data['tips']:
                # Najdi uživatele podle display_name nebo user_id
                user = None
                if 'user_id' in tip_data:
                    user = db.session.get(User, tip_data['user_id'])
                if not user:
                    user = User.query.filter(
                        (User.display_name == tip_data['user']) | 
                        (User.username == tip_data['user'])
                    ).first()
                
                if not user:
                    continue  # Skip tipy od neexistujících userů
                
                # Najdi nový match_id
                old_match_id = tip_data['match_id']
                new_match_id = match_id_mapping.get(old_match_id)
                
                if not new_match_id:
                    continue  # Skip pokud match nebyl importován
                
                # Vytvoř tip
                tip = Tip(
                    user_id=user.id,
                    match_id=new_match_id,
                    home_score=tip_data['home_score'],
                    away_score=tip_data['away_score']
                )
                db.session.add(tip)
                imported_tips += 1
            
            db.session.commit()
            
            # Audit
            audit("archive.import", "Round", r.id, 
                  description=f"Importováno {len(data['matches'])} zápasů a {imported_tips} tipů. Nahrazeno {old_matches_count} zápasů a {old_tips_count} tipů.")
            
            flash(f"✅ Import dokončen! Importováno {len(data['matches'])} zápasů a {imported_tips} tipů.", "ok")
            return redirect(url_for("archive_detail", round_id=round_id, tab='overview'))
            
        except json.JSONDecodeError:
            flash("❌ Chyba při čtení JSON souboru", "error")
            db.session.rollback()
        except Exception as e:
            flash(f"❌ Chyba při importu: {str(e)}", "error")
            db.session.rollback()
        
        return redirect(url_for("archive_detail", round_id=round_id, tab='import'))


    # --- ARCHIVE COMPARISON ---
    @app.route("/archive/compare")
    @login_required
    def archive_compare():
        """Srovnání 2 soutěží"""
        rounds = Round.query.order_by(Round.id.desc()).all()
        
        round_a_id = request.args.get('a', type=int)
        round_b_id = request.args.get('b', type=int)
        
        comparison = None
        
        if round_a_id and round_b_id:
            round_a = db.session.get(Round, round_a_id)
            round_b = db.session.get(Round, round_b_id)
            
            if round_a and round_b:
                # Stats pro A
                matches_a = Match.query.filter_by(round_id=round_a.id, is_deleted=False).count()
                tippers_a = db.session.query(Tip.user_id).join(Match).filter(Match.round_id == round_a.id).distinct().count()
                tips_a = Tip.query.join(Match).filter(Match.round_id == round_a.id).count()
                
                # Stats pro B
                matches_b = Match.query.filter_by(round_id=round_b.id, is_deleted=False).count()
                tippers_b = db.session.query(Tip.user_id).join(Match).filter(Match.round_id == round_b.id).distinct().count()
                tips_b = Tip.query.join(Match).filter(Match.round_id == round_b.id).count()
                
                # Vítěz A
                winner_a = None
                for user in User.query.all():
                    tips = Tip.query.join(Match).filter(Match.round_id == round_a.id, Tip.user_id == user.id).all()
                    if tips:
                        points = sum(calc_points_for_tip(t.match, t) for t in tips if t.match.home_score is not None)
                        if not winner_a or points > winner_a['points']:
                            winner_a = {'user': user.display_name, 'points': points}
                
                # Vítěz B
                winner_b = None
                for user in User.query.all():
                    tips = Tip.query.join(Match).filter(Match.round_id == round_b.id, Tip.user_id == user.id).all()
                    if tips:
                        points = sum(calc_points_for_tip(t.match, t) for t in tips if t.match.home_score is not None)
                        if not winner_b or points > winner_b['points']:
                            winner_b = {'user': user.display_name, 'points': points}
                
                comparison = {
                    'round_a': round_a,
                    'round_b': round_b,
                    'matches_a': matches_a,
                    'matches_b': matches_b,
                    'tippers_a': tippers_a,
                    'tippers_b': tippers_b,
                    'tips_a': tips_a,
                    'tips_b': tips_b,
                    'winner_a': winner_a,
                    'winner_b': winner_b,
                    'avg_a': round(tips_a / tippers_a, 1) if tippers_a > 0 else 0,
                    'avg_b': round(tips_b / tippers_b, 1) if tippers_b > 0 else 0
                }
        
        return render_page(r"""
<style>
.compare-card {
  background: rgba(110,168,254,0.08);
  border: 1px solid rgba(110,168,254,0.2);
  border-radius: 8px;
  padding: 20px;
}

.compare-grid {
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  gap: 20px;
  align-items: center;
  margin: 12px 0;
}

.compare-value {
  font-size: 24px;
  font-weight: bold;
  color: #6ea8fe;
}

@media (max-width: 768px) {
  .compare-grid {
    grid-template-columns: 1fr;
    gap: 8px;
  }
  
  .compare-grid > div:nth-child(2) {
    text-align: center;
  }
}
</style>

<div class="card">
  <h2 style="margin:0 0 8px 0;">🆚 Srovnání soutěží</h2>
  <div class="muted">Porovnej statistiky dvou soutěží</div>
  
  <hr class="sep">
  
  <form method="get" style="margin-bottom: 24px;">
    <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; align-items: end;">
      <div>
        <label style="display: block; margin-bottom: 6px; font-weight: 600;">Soutěž A:</label>
        <select name="a" class="form-select" required>
          <option value="">Vyber soutěž...</option>
          {% for r in rounds %}
          <option value="{{ r.id }}" {% if round_a_id == r.id %}selected{% endif %}>{{ r.name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <div>
        <label style="display: block; margin-bottom: 6px; font-weight: 600;">Soutěž B:</label>
        <select name="b" class="form-select" required>
          <option value="">Vyber soutěž...</option>
          {% for r in rounds %}
          <option value="{{ r.id }}" {% if round_b_id == r.id %}selected{% endif %}>{{ r.name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <button type="submit" class="btn btn-primary">Porovnat</button>
    </div>
  </form>
  
  {% if comparison %}
  <div class="compare-card">
    <h3 style="margin: 0 0 20px 0; text-align: center;">
      {{ comparison.round_a.name }} 🆚 {{ comparison.round_b.name }}
    </h3>
    
    <!-- Tipérů -->
    <div class="compare-grid">
      <div style="text-align: right;">
        <div class="compare-value">{{ comparison.tippers_a }}</div>
      </div>
      <div class="muted">👥 Tipérů</div>
      <div>
        <div class="compare-value">{{ comparison.tippers_b }}</div>
      </div>
    </div>
    
    <!-- Zápasů -->
    <div class="compare-grid">
      <div style="text-align: right;">
        <div class="compare-value">{{ comparison.matches_a }}</div>
      </div>
      <div class="muted">📊 Zápasů</div>
      <div>
        <div class="compare-value">{{ comparison.matches_b }}</div>
      </div>
    </div>
    
    <!-- Tipů -->
    <div class="compare-grid">
      <div style="text-align: right;">
        <div class="compare-value">{{ comparison.tips_a }}</div>
      </div>
      <div class="muted">🎯 Celkem tipů</div>
      <div>
        <div class="compare-value">{{ comparison.tips_b }}</div>
      </div>
    </div>
    
    <!-- Průměr -->
    <div class="compare-grid">
      <div style="text-align: right;">
        <div class="compare-value">{{ comparison.avg_a }}</div>
      </div>
      <div class="muted">📈 Ø tipů/tipér</div>
      <div>
        <div class="compare-value">{{ comparison.avg_b }}</div>
      </div>
    </div>
    
    <!-- Vítěz -->
    <div class="compare-grid">
      <div style="text-align: right;">
        {% if comparison.winner_a %}
        <div style="font-size: 18px; font-weight: bold;">🏆 {{ comparison.winner_a.user }}</div>
        <div class="muted">{{ comparison.winner_a.points }} bodů</div>
        {% else %}
        <div class="muted">—</div>
        {% endif %}
      </div>
      <div class="muted">Vítěz</div>
      <div>
        {% if comparison.winner_b %}
        <div style="font-size: 18px; font-weight: bold;">🏆 {{ comparison.winner_b.user }}</div>
        <div class="muted">{{ comparison.winner_b.points }} bodů</div>
        {% else %}
        <div class="muted">—</div>
        {% endif %}
      </div>
    </div>
    
  </div>
  {% else %}
  <div style="text-align: center; padding: 40px;">
    <div style="font-size: 48px; margin-bottom: 16px;">🆚</div>
    <div class="muted">Vyber 2 soutěže k porovnání</div>
  </div>
  {% endif %}
  
  <div style="margin-top: 20px;">
    <a href="{{ url_for('archive') }}" class="btn">← Zpět do archivu</a>
  </div>
</div>
""", rounds=rounds, round_a_id=round_a_id, round_b_id=round_b_id, comparison=comparison)


    # --- ARCHIVE CALENDAR ---
    @app.route("/archive/calendar")
    @login_required
    def archive_calendar():
        """Kalendářní zobrazení soutěží"""
        rounds = Round.query.order_by(Round.id.desc()).all()
        
        # Group by year and month
        calendar_data = {}
        
        for r in rounds:
            # Zjisti datum (použij první zápas nebo fallback)
            first_match = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(Match.start_time.asc().nullslast()).first()
            
            if first_match and first_match.start_time:
                date = first_match.start_time
            else:
                # Fallback na aktuální datum
                date = datetime.now()
            
            year = date.year
            month = date.month
            
            if year not in calendar_data:
                calendar_data[year] = {}
            
            if month not in calendar_data[year]:
                calendar_data[year][month] = []
            
            calendar_data[year][month].append({
                'round': r,
                'date': date,
                'sport_emoji': "⚽" if r.sport.name.lower() == "fotbal" else "🏒" if "hokej" in r.sport.name.lower() else "🏀"
            })
        
        # Sort
        for year in calendar_data:
            for month in calendar_data[year]:
                calendar_data[year][month].sort(key=lambda x: x['date'])
        
        month_names = {
            1: "Leden", 2: "Únor", 3: "Březen", 4: "Duben",
            5: "Květen", 6: "Červen", 7: "Červenec", 8: "Srpen",
            9: "Září", 10: "Říjen", 11: "Listopad", 12: "Prosinec"
        }
        
        return render_page(r"""
<style>
.calendar-year {
  margin-bottom: 32px;
}

.calendar-month {
  margin-left: 20px;
  margin-bottom: 20px;
}

.calendar-round {
  margin-left: 40px;
  padding: 12px;
  background: rgba(110,168,254,0.08);
  border-left: 3px solid #6ea8fe;
  border-radius: 6px;
  margin-bottom: 8px;
  transition: all 0.2s;
}

.calendar-round:hover {
  background: rgba(110,168,254,0.12);
  transform: translateX(4px);
}

.calendar-round.active {
  border-left-color: #4ade80;
}

@media (max-width: 768px) {
  .calendar-month {
    margin-left: 10px;
  }
  
  .calendar-round {
    margin-left: 20px;
  }
}
</style>

<div class="card">
  <h2 style="margin:0 0 8px 0;">📅 Kalendář soutěží</h2>
  <div class="muted">Chronologický přehled všech soutěží</div>
  
  <hr class="sep">
  
  {% if calendar_data|length > 0 %}
    {% for year in calendar_data|dictsort(reverse=True) %}
    <div class="calendar-year">
      <h3 style="margin: 0 0 16px 0; color: #6ea8fe;">📆 {{ year[0] }}</h3>
      
      {% for month in year[1]|dictsort(reverse=True) %}
      <div class="calendar-month">
        <h4 style="margin: 0 0 12px 0; color: #94a3b8;">{{ month_names[month[0]] }}</h4>
        
        {% for rd_data in month[1] %}
        <div class="calendar-round {% if rd_data.round.is_active %}active{% endif %}">
          <div class="row" style="justify-content: space-between; align-items: center;">
            <div>
              <div style="font-weight: 600;">
                {{ rd_data.sport_emoji }} {{ rd_data.round.name }}
                {% if rd_data.round.is_active %}
                  <span class="tag" style="background: #4ade80; color: #000; font-size: 11px; margin-left: 8px;">AKTIVNÍ</span>
                {% endif %}
              </div>
              <div class="muted" style="font-size: 12px;">{{ rd_data.date.strftime('%d.%m.%Y') }}</div>
            </div>
            <a href="/archive/{{ rd_data.round.id }}" class="btn btn-sm">Detail →</a>
          </div>
        </div>
        {% endfor %}
      </div>
      {% endfor %}
    </div>
    {% endfor %}
  {% else %}
  <div style="text-align: center; padding: 40px;">
    <div style="font-size: 48px; margin-bottom: 16px;">📅</div>
    <div class="muted">Zatím žádné soutěže</div>
  </div>
  {% endif %}
  
  <div style="margin-top: 20px;">
    <a href="{{ url_for('archive') }}" class="btn">← Zpět do archivu</a>
  </div>
</div>
""", calendar_data=calendar_data, month_names=month_names)


    # --- ADMIN USERS ---
    @app.route("/admin/users", methods=["GET", "POST"])
    @login_required
    def admin_users():
        admin_required()

        if request.method == "POST":
            action = request.form.get("bulk_action")
            user_ids = request.form.getlist("user_ids")

            if not user_ids:
                flash("Nevybral jsi žádné uživatele.", "error")
                return redirect(url_for("admin_users"))

            user_ids = [int(uid) for uid in user_ids]
            affected_users = User.query.filter(User.id.in_(user_ids)).all()

            # Ochrana proti smazání/úpravě ownera a sebe sama
            for u in affected_users:
                if u.is_owner:
                    flash(f"Nelze hromadně upravit ownera ({u.username}).", "error")
                    return redirect(url_for("admin_users"))
                if u.id == current_user.id:
                    flash("Nelze hromadně upravit sám sebe.", "error")
                    return redirect(url_for("admin_users"))

            if action == "delete":
                count = len(affected_users)
                for u in affected_users:
                    db.session.delete(u)
                db.session.commit()
                audit("users.bulk_delete", "User", None, count=count)
                flash(f"Smazáno {count} uživatelů.", "ok")

            elif action == "set_role":
                new_role = request.form.get("new_role")
                if new_role not in ["user", "viewer", "moderator", "admin"]:
                    flash("Neplatná role.", "error")
                    return redirect(url_for("admin_users"))

                for u in affected_users:
                    u.role = new_role
                db.session.commit()
                audit("users.bulk_role", "User", None, role=new_role, count=len(affected_users))
                flash(f"Změněna role pro {len(affected_users)} uživatelů na '{new_role}'.", "ok")

            elif action == "reset_password":
                new_password = request.form.get("new_password", "").strip()
                if not new_password:
                    flash("Zadej nové heslo.", "error")
                    return redirect(url_for("admin_users"))
                
                # Validace síly hesla
                is_valid, error_msg = validate_password(new_password)
                if not is_valid:
                    flash(error_msg, "error")
                    return redirect(url_for("admin_users"))

                for u in affected_users:
                    u.set_password(new_password)
                db.session.commit()
                audit("users.bulk_password", "User", None, count=len(affected_users))
                flash(f"Resetováno heslo pro {len(affected_users)} uživatelů.", "ok")
            
            elif action == "send_welcome_reset":
                # Pošli welcome email s reset linkem
                base_url = request.url_root.rstrip('/')
                sent_count = 0
                
                for u in affected_users:
                    try:
                        if send_welcome_with_reset_link(u, base_url):
                            sent_count += 1
                    except Exception as e:
                        continue
                
                audit("users.bulk_welcome", "User", None, count=sent_count)
                flash(f"📧 Welcome emaily odeslány: {sent_count} uživatelům. Mají 24h na nastavení hesla.", "ok")

            return redirect(url_for("admin_users"))

        users = User.query.order_by(User.username.asc()).all()
        users = [u for u in users if can_see_user_in_admin(u)]
        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0 0 8px 0;">Uživatelé</h2>
      <div class="muted">Owner = <b>{{ owner }}</b>. Tajný user je skrytý pro jiné adminy.</div>
    </div>
    <div class="row">
      {% if current_user.is_owner %}<span class="tag pill-ok">Owner admin</span>{% endif %}
      <a class="btn btn-primary" href="{{ url_for('admin_user_new') }}">➕ Nový uživatel</a>
      <a class="btn" href="{{ url_for('admin_users_import') }}" style="background:#667eea; color:white;">📤 Import uživatelů</a>
    </div>
  </div>

  <hr class="sep">

  {% if current_user.is_owner %}
  {# Hromadná správa #}
  <form method="post" id="bulkForm">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="card" style="background:rgba(110,168,254,0.08); border:1px solid rgba(110,168,254,0.2); margin-bottom:16px; padding:16px;">
      <h3 style="margin:0 0 12px 0;">Hromadná správa</h3>

      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:10px;">
        {# Změna role #}
        <div>
          <select name="new_role" id="bulk_role" style="width:100%;">
            <option value="">-- Vybrat roli --</option>
            <option value="user">User</option>
            <option value="viewer">Viewer</option>
            <option value="moderator">Moderátor</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button type="button" onclick="submitBulkAction('set_role')" class="btn btn-sm">
          👥 Změnit roli
        </button>

        {# Reset hesla #}
        <input type="password" name="new_password" id="bulk_password" placeholder="Nové heslo" style="width:100%;">
        <button type="button" onclick="submitBulkAction('reset_password')" class="btn btn-sm">
          🔑 Resetovat heslo
        </button>

        {# Poslat welcome email #}
        <div></div>
        <button type="button" onclick="submitBulkAction('send_welcome_reset')" class="btn btn-sm" style="background:rgba(110,168,254,0.3); color:#0b1020;">
          📧 Poslat welcome email
        </button>

        {# Smazat #}
        <div></div>
        <button type="button" onclick="submitBulkDelete()" class="btn btn-sm"
                style="background:rgba(255,77,109,0.2); color:#ff4d6d; border:1px solid rgba(255,77,109,0.4);">
          🗑️ Smazat vybrané
        </button>
      </div>

      <input type="hidden" name="bulk_action" id="bulk_action">
      <div class="muted" style="margin-top:10px; font-size:12px;">
        💡 Označ uživatele checkboxem, vyber akci a klikni na tlačítko<br>
        📧 Welcome email = pošle reset link pro nastavení hesla (24h platnost)
      </div>
    </div>

  <table class="datatable">
    <thead>
      <tr>
        <th style="width:40px;">
          <input type="checkbox" id="selectAll" onclick="toggleAll(this)"
                 title="Vybrat všechny">
        </th>
        <th>Username</th>
        <th>Email</th>
        <th style="text-align:center;">Role</th>
        <th style="text-align:center;">Registrace</th>
        <th style="text-align:center; min-width:400px;">Akce</th>
      </tr>
    </thead>
    <tbody>
      {% for u in users %}
      <tr>
        <td>
          {% if u.id != current_user.id and not u.is_owner %}
            <input type="checkbox" name="user_ids" value="{{ u.id }}" class="user-checkbox">
          {% endif %}
        </td>
        <td>
          <strong>{{ u.display_name }}</strong>
          {% if u.is_owner %} <span class="tag pill-ok">Owner</span>{% endif %}
          {% if u.nickname %}<br><span class="muted" style="font-size:11px;">Nick: {{ u.nickname }}</span>{% endif %}
          <div class="muted" style="font-size:11px;">Login: {{ u.username }}</div>
        </td>
        <td class="muted">{{ u.email }}</td>
        <td style="text-align:center;">
          {% if u.effective_role == 'admin' %}
            <span class="tag pill-bad">Admin</span>
          {% elif u.effective_role == 'moderator' %}
            <span class="tag pill-ok">Moderátor</span>
          {% elif u.effective_role == 'viewer' %}
            <span class="tag">Viewer</span>
          {% else %}
            <span class="tag pill-primary">User</span>
          {% endif %}
        </td>
        <td style="text-align:center;" class="muted">{{ u.created_at.strftime('%d.%m.%Y') }}</td>
        <td style="text-align:center;">
          <div style="display:flex; justify-content:center; gap:6px; flex-wrap:nowrap;">
              <a class="btn btn-sm" href="{{ url_for('admin_user_edit', user_id=u.id) }}">Upravit</a>
              <a class="btn btn-sm" href="{{ url_for('admin_user_reset_password', user_id=u.id) }}">Reset hesla</a>
              {% if u.id != current_user.id and not u.is_owner %}
                <a class="btn btn-sm" href="{{ url_for('admin_user_change_role', user_id=u.id) }}">Změnit roli</a>
                <form method="post" action="{{ url_for('admin_user_delete', user_id=u.id) }}" style="display:inline;" 
                      onsubmit="return confirm('Opravdu smazat uživatele {{ u.username }}?')">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                  <button type="submit" class="btn btn-sm btn-danger" 
                          style="background:rgba(255,77,109,0.2); color:#ff4d6d; border:none; cursor:pointer;">
                    Smazat
                  </button>
                </form>
              {% endif %}
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  </form>
  {% else %}
  {# Non-owner zobrazí jen tabulku bez hromadné správy #}
  <table class="datatable">
    <thead>
      <tr>
        <th>Username</th>
        <th>Email</th>
        <th style="text-align:center;">Role</th>
        <th style="text-align:center;">Registrace</th>
      </tr>
    </thead>
    <tbody>
      {% for u in users %}
      <tr>
        <td>
          <strong>{{ u.display_name }}</strong>
          {% if u.nickname %}<br><span class="muted" style="font-size:11px;">Nick: {{ u.nickname }}</span>{% endif %}
          <div class="muted" style="font-size:11px;">Login: {{ u.username }}</div>
        </td>
        <td class="muted">{{ u.email }}</td>
        <td style="text-align:center;">
          {% if u.effective_role == 'admin' %}
            <span class="tag pill-bad">Admin</span>
          {% elif u.effective_role == 'moderator' %}
            <span class="tag pill-ok">Moderátor</span>
          {% elif u.effective_role == 'viewer' %}
            <span class="tag">Viewer</span>
          {% else %}
            <span class="tag pill-primary">User</span>
          {% endif %}
        </td>
        <td style="text-align:center;" class="muted">{{ u.created_at.strftime('%d.%m.%Y') }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}
</div>

<script>
function toggleAll(checkbox) {
  const checkboxes = document.querySelectorAll('.user-checkbox');
  checkboxes.forEach(cb => cb.checked = checkbox.checked);
}

function getSelectedCount() {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  return checkboxes.length;
}

function submitBulkAction(action) {
  const count = getSelectedCount();
  if (count === 0) {
    alert('Nevybral jsi žádné uživatele!');
    return;
  }

  let confirmMsg = '';
  if (action === 'set_role') {
    const role = document.getElementById('bulk_role').value;
    if (!role) {
      alert('Vyber roli!');
      return;
    }
    confirmMsg = `Opravdu změnit roli pro ${count} uživatelů na '${role}'?`;
  } else if (action === 'reset_password') {
    const password = document.getElementById('bulk_password').value;
    if (!password) {
      alert('Zadej nové heslo!');
      return;
    }
    confirmMsg = `Opravdu resetovat heslo pro ${count} uživatelů?`;
  } else if (action === 'send_welcome_reset') {
    confirmMsg = `Poslat welcome email ${count} uživatelům?\n\nKaždý dostane email s odkazem pro nastavení hesla (platnost 24h).`;
  }

  if (confirmMsg && confirm(confirmMsg)) {
    document.getElementById('bulk_action').value = action;
    document.getElementById('bulkForm').submit();
  }
}

function submitBulkDelete() {
  const count = getSelectedCount();
  if (count === 0) {
    alert('Nevybral jsi žádné uživatele!');
    return;
  }

  if (confirm(`POZOR: Opravdu smazat ${count} uživatelů?\n\nTato akce je NEVRATNÁ!`)) {
    document.getElementById('bulk_action').value = 'delete';
    document.getElementById('bulkForm').submit();
  }
}
</script>

<style>
  .btn-danger {
    background: rgba(255, 77, 109, 0.15);
    color: #ff4d6d;
  }
  .btn-danger:hover {
    background: rgba(255, 77, 109, 0.25);
  }
</style>
""", users=users, owner=OWNER_ADMIN_EMAIL)

    @app.route("/admin/user/<int:user_id>/toggle-admin")
    @login_required
    def admin_toggle_admin(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)
        if u.id == current_user.id:
            flash("Sebe si nepřepínej.", "error")
            return redirect(url_for("admin_users"))
        u.is_admin = not u.is_admin
        db.session.commit()
        audit("user.toggle_admin", "User", u.id, is_admin=u.is_admin)
        return redirect(url_for("admin_users"))

    @app.route("/admin/user/new", methods=["GET", "POST"])
    @login_required
    def admin_user_new():
        admin_required()
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = (request.form.get("password") or "").strip()
            role = (request.form.get("role") or "user").strip()
            first_name = (request.form.get("first_name") or "").strip()
            last_name = (request.form.get("last_name") or "").strip()
            nickname = (request.form.get("nickname") or "").strip()

            if not username or not email or not password:
                flash("Vyplň všechna povinná pole.", "error")
                return redirect(url_for("admin_user_new"))
            
            # Validace síly hesla
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, "error")
                return redirect(url_for("admin_user_new"))

            # Kontrola, jestli už username nebo email neexistuje
            if User.query.filter_by(username=username).first():
                flash(f"Username '{username}' už existuje.", "error")
                return redirect(url_for("admin_user_new"))

            if User.query.filter_by(email=email).first():
                flash(f"Email '{email}' už existuje.", "error")
                return redirect(url_for("admin_user_new"))

            # Vytvoření nového uživatele
            new_user = User(
                username=username,
                email=email,
                role=role,
                first_name=first_name or None,
                last_name=last_name or None,
                nickname=nickname or None,
                email_verified=True  # Admin vytvořil uživatele, email je ověřený
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            audit("user.create", "User", new_user.id, username=username, email=email, role=role)
            flash(f"Uživatel '{username}' byl vytvořen.", "ok")
            return redirect(url_for("admin_users"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Nový uživatel</h2>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Username (login) *</label>
      <input name="username" placeholder="username" required>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Email *</label>
      <input name="email" type="email" placeholder="email@example.com" required>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Heslo *</label>
      <input name="password" type="password" placeholder="Min. 8 znaků" required minlength="8">
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Požadavky: min. 8 znaků, velké/malé písmeno, číslo
      </div>
    </div>
    <div class="grid2">
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Jméno</label>
        <input name="first_name" placeholder="Jan">
      </div>
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Příjmení</label>
        <input name="last_name" placeholder="Novák">
      </div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Přezdívka (Nick)</label>
      <input name="nickname" placeholder="JN23">
      <div class="muted" style="font-size:12px; margin-top:4px;">Zobrazí se v žebříčku</div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Role</label>
      <select name="role">
        <option value="user">User (může tipovat)</option>
        <option value="viewer">Viewer (jen prohlížet)</option>
        <option value="moderator">Moderátor (může tipovat + částečná správa)</option>
        <option value="admin">Admin (plná správa)</option>
      </select>
    </div>
    <div class="row" style="gap:10px; margin-top:10px;">
      <button class="btn btn-primary" type="submit">Vytvořit</button>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
</div>
""")

    @app.route("/admin/users/import", methods=["GET", "POST"])
    @login_required
    def admin_users_import():
        """Import uživatelů z Excel souboru - krok 1: Upload"""
        admin_required()
        
        if request.method == "POST":
            if 'file' not in request.files:
                flash("Žádný soubor nebyl vybrán.", "error")
                return redirect(url_for("admin_users_import"))
            
            file = request.files['file']
            if file.filename == '':
                flash("Žádný soubor nebyl vybrán.", "error")
                return redirect(url_for("admin_users_import"))
            
            if not file.filename.endswith(('.xlsx', '.xls', '.csv')):
                flash("Podporovány jsou pouze .xlsx, .xls a .csv soubory.", "error")
                return redirect(url_for("admin_users_import"))
            
            try:
                import openpyxl
                import pandas as pd
                import pickle
                
                # Načti soubor
                if file.filename.endswith('.csv'):
                    df = pd.read_csv(file)
                else:
                    df = pd.read_excel(file)
                
                # Očekávané sloupce
                required_cols = ['email', 'username', 'password']
                missing_cols = [col for col in required_cols if col not in df.columns]
                
                if missing_cols:
                    flash(f"Chybí povinné sloupce: {', '.join(missing_cols)}", "error")
                    return redirect(url_for("admin_users_import"))
                
                # Parsuj a validuj všechny uživatele
                users_preview = []
                
                for index, row in df.iterrows():
                    email = str(row['email']).strip().lower() if pd.notna(row['email']) else ''
                    username = str(row['username']).strip() if pd.notna(row['username']) else ''
                    password = str(row['password']).strip() if pd.notna(row['password']) else ''
                    
                    # Validace
                    errors = []
                    status = 'ok'
                    
                    if not email or not username or not password:
                        errors.append("Prázdné povinné pole")
                        status = 'error'
                    
                    # Kontrola duplicit
                    if email and User.query.filter_by(email=email).first():
                        errors.append(f"Email '{email}' už existuje")
                        status = 'duplicate'
                    
                    if username and User.query.filter_by(username=username).first():
                        errors.append(f"Username '{username}' už existuje")
                        status = 'duplicate'
                    
                    # Validace hesla
                    if password and status == 'ok':
                        is_valid, error_msg = validate_password(password)
                        if not is_valid:
                            errors.append(error_msg)
                            status = 'error'
                    
                    # Volitelné sloupce
                    first_name = str(row.get('first_name', '')).strip() if pd.notna(row.get('first_name')) else None
                    last_name = str(row.get('last_name', '')).strip() if pd.notna(row.get('last_name')) else None
                    nickname = str(row.get('nickname', '')).strip() if pd.notna(row.get('nickname')) else None
                    role = str(row.get('role', 'user')).strip().lower() if pd.notna(row.get('role')) else 'user'
                    
                    if role not in ['user', 'viewer', 'moderator', 'admin']:
                        role = 'user'
                    
                    users_preview.append({
                        'row_num': index + 2,  # +2 protože 1=header, Excel je 1-indexed
                        'email': email,
                        'username': username,
                        'password': password,
                        'first_name': first_name,
                        'last_name': last_name,
                        'nickname': nickname,
                        'role': role,
                        'status': status,
                        'errors': errors
                    })
                
                # Počet podle statusů
                ok_count = sum(1 for u in users_preview if u['status'] == 'ok')
                error_count = sum(1 for u in users_preview if u['status'] in ['error', 'duplicate'])
                
                # Ulož do temp file
                preview_fd, preview_path = tempfile.mkstemp(suffix='.pkl', prefix='users_import_')
                os.close(preview_fd)
                
                with open(preview_path, 'wb') as f:
                    pickle.dump(users_preview, f)
                
                session['users_import_preview_file'] = preview_path
                
                return redirect(url_for("admin_users_import_preview"))
                
            except Exception as e:
                flash(f"Chyba při zpracování souboru: {str(e)}", "error")
                return redirect(url_for("admin_users_import"))
        
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Import uživatelů - Krok 1</h2>
  <div class="muted">Nahraj Excel nebo CSV soubor s uživateli</div>
  <hr class="sep">
  
  <div style="background:rgba(110,168,254,0.08); padding:16px; border-radius:8px; margin-bottom:16px;">
    <h3 style="margin:0 0 8px 0;">📋 Formát souboru</h3>
    <p><strong>Povinné sloupce:</strong></p>
    <ul>
      <li><code>email</code> - Email uživatele</li>
      <li><code>username</code> - Uživatelské jméno (login)</li>
      <li><code>password</code> - Heslo (min. 8 znaků, velké/malé/číslo)</li>
    </ul>
    <p><strong>Volitelné sloupce:</strong></p>
    <ul>
      <li><code>first_name</code> - Jméno</li>
      <li><code>last_name</code> - Příjmení</li>
      <li><code>nickname</code> - Přezdívka (zobrazí se v žebříčku)</li>
      <li><code>role</code> - Role (user/viewer/moderator/admin, default: user)</li>
    </ul>
  </div>
  
  <form method="post" enctype="multipart/form-data" class="row" style="flex-direction:column; gap:16px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    
    <div style="background:rgba(110,168,254,0.1); padding:12px; border-left:4px solid #6ea8fe; margin-bottom:8px;">
      <strong>💡 Nemáš Excel?</strong> Stáhni si šablonu s hlavičkami a příkladem:
      <a href="{{ url_for('admin_users_import_template') }}" class="btn btn-sm" style="margin-left:8px;">
        📥 Stáhnout šablonu Excel
      </a>
    </div>
    
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Soubor (.xlsx, .xls, .csv)</label>
      <input type="file" name="file" accept=".xlsx,.xls,.csv" required>
    </div>
    
    <div class="row" style="gap:10px;">
      <button class="btn btn-primary" type="submit">➡️ Pokračovat na Preview</button>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
  
  <hr class="sep">
  
  <div class="muted" style="font-size:12px;">
    <p><strong>💡 Postup:</strong></p>
    <ol>
      <li><strong>Upload</strong> - Nahraj Excel soubor</li>
      <li><strong>Preview</strong> - Zkontroluj kdo se bude importovat a vyber komu poslat email</li>
      <li><strong>Potvrzení</strong> - Importuj vybrané uživatele</li>
    </ol>
  </div>
</div>
""")

    @app.route("/admin/users/import/template")
    @login_required
    def admin_users_import_template():
        """Stáhne Excel šablonu pro import uživatelů"""
        admin_required()
        
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Alignment
            from io import BytesIO
            
            # Vytvoř workbook
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Uživatelé"
            
            # Hlavička
            headers = ['email', 'username', 'password', 'first_name', 'last_name', 'nickname', 'role']
            ws.append(headers)
            
            # Stylování hlavičky
            header_fill = PatternFill(start_color="6EA8FE", end_color="6EA8FE", fill_type="solid")
            header_font = Font(bold=True, color="FFFFFF")
            
            for col_num, header in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col_num)
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal='center', vertical='center')
            
            # Příklad řádku (volitelně, pro ukázku)
            example_row = [
                'jan.novak@email.cz',
                'jan123',
                'Test1234',
                'Jan',
                'Novák',
                'JN',
                'user'
            ]
            ws.append(example_row)
            
            # Nastavení šířky sloupců
            ws.column_dimensions['A'].width = 25  # email
            ws.column_dimensions['B'].width = 15  # username
            ws.column_dimensions['C'].width = 15  # password
            ws.column_dimensions['D'].width = 15  # first_name
            ws.column_dimensions['E'].width = 15  # last_name
            ws.column_dimensions['F'].width = 12  # nickname
            ws.column_dimensions['G'].width = 12  # role
            
            # Přidej poznámku do druhého sheetu
            notes_ws = wb.create_sheet("Poznámky")
            notes_ws['A1'] = "NÁVOD K POUŽITÍ"
            notes_ws['A1'].font = Font(bold=True, size=14)
            
            notes = [
                "",
                "POVINNÉ SLOUPCE:",
                "• email - Email uživatele (musí být unikátní)",
                "• username - Uživatelské jméno pro login (musí být unikátní)",
                "• password - Heslo (min. 8 znaků, velké/malé písmeno, číslice)",
                "",
                "VOLITELNÉ SLOUPCE:",
                "• first_name - Křestní jméno",
                "• last_name - Příjmení",
                "• nickname - Přezdívka (zobrazí se v žebříčku)",
                "• role - Role (user/viewer/moderator/admin, výchozí: user)",
                "",
                "POSTUP:",
                "1. Vyplň uživatele do 1. sheetu (Uživatelé)",
                "2. První řádek s ukázkou můžeš smazat nebo upravit",
                "3. Ulož soubor",
                "4. Nahraj na stránce Import uživatelů",
                "",
                "PŘÍKLAD HESEL:",
                "✅ Test1234 - OK (8+ znaků, velké, malé, číslice)",
                "✅ Password123 - OK",
                "❌ test - Špatně (moc krátké, bez velkého, bez čísla)",
                "❌ TestTest - Špatně (bez čísla)",
            ]
            
            for i, note in enumerate(notes, 2):
                notes_ws[f'A{i}'] = note
            
            notes_ws.column_dimensions['A'].width = 60
            
            # Ulož do BytesIO
            output = BytesIO()
            wb.save(output)
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name='import_uzivatelu_sablona.xlsx'
            )
            
        except Exception as e:
            flash(f"Chyba při vytváření šablony: {str(e)}", "error")
            return redirect(url_for("admin_users_import"))

    @app.route("/admin/users/import/preview")
    @login_required
    def admin_users_import_preview():
        """Import uživatelů - krok 2: Preview a výběr komu poslat email"""
        admin_required()
        
        preview_file = session.get('users_import_preview_file')
        if not preview_file or not os.path.exists(preview_file):
            flash("Preview data nenalezena. Nahraj soubor znovu.", "error")
            return redirect(url_for("admin_users_import"))
        
        try:
            import pickle
            with open(preview_file, 'rb') as f:
                users_preview = pickle.load(f)
            
            ok_users = [u for u in users_preview if u['status'] == 'ok']
            error_users = [u for u in users_preview if u['status'] in ['error', 'duplicate']]
            
            return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Import uživatelů - Preview</h2>
  <div class="muted">Zkontroluj kdo se bude importovat</div>
  <hr class="sep">
  
  <div class="row" style="gap:12px; margin-bottom:16px;">
    <div class="tag pill-ok">✅ K importu: {{ ok_count }}</div>
    {% if error_count > 0 %}<div class="tag pill-error">❌ Chyby: {{ error_count }}</div>{% endif %}
  </div>
  
  <form method="post" action="{{ url_for('admin_users_import_confirm') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    
    {% if ok_users %}
    <h3 style="margin:16px 0 8px 0;">✅ Připraveno k importu ({{ ok_count }})</h3>
    <div style="background:#f8f9fa; padding:8px; border-radius:8px; margin-bottom:16px; max-height:400px; overflow-y:auto;">
      <table style="width:100%; font-size:13px;">
        <thead style="position:sticky; top:0; background:#e9ecef;">
          <tr>
            <th style="padding:8px; text-align:left;">Email</th>
            <th style="padding:8px; text-align:left;">Username</th>
            <th style="padding:8px; text-align:left;">Jméno</th>
            <th style="padding:8px; text-align:left;">Role</th>
          </tr>
        </thead>
        <tbody>
          {% for user in ok_users %}
          <tr style="border-bottom:1px solid #dee2e6;">
            <td style="padding:8px;">{{ user.email }}</td>
            <td style="padding:8px;">{{ user.username }}</td>
            <td style="padding:8px;">{{ user.first_name or '' }} {{ user.last_name or '' }}</td>
            <td style="padding:8px;"><span class="tag">{{ user.role }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    
    <div style="background:rgba(110,168,254,0.1); padding:12px; border-left:4px solid #6ea8fe; margin-bottom:16px;">
      <strong>💡 Info:</strong> Uživatelé budou importováni s ověřeným emailem a budou se moci přihlásit.
      Welcome emaily můžeš poslat později z Admin → Uživatelé → Hromadná správa.
    </div>
    {% endif %}
    
    {% if error_users %}
    <h3 style="margin:16px 0 8px 0;">❌ Chyby - nebudou importováni ({{ error_count }})</h3>
    <div style="background:#fff3cd; padding:12px; border-radius:8px; margin-bottom:16px; max-height:300px; overflow-y:auto;">
      {% for user in error_users %}
      <div style="padding:8px; border-bottom:1px solid #ffc107;">
        <strong>Řádek {{ user.row_num }}:</strong> {{ user.email }} / {{ user.username }}
        <div class="muted" style="font-size:12px;">
          {% for error in user.errors %}• {{ error }}<br>{% endfor %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% endif %}
    
    <hr class="sep">
    
    <div class="row" style="gap:10px;">
      <button class="btn btn-primary" type="submit" {% if ok_count == 0 %}disabled{% endif %}>
        ✅ Potvrdit import ({{ ok_count }} uživatelů)
      </button>
      <a class="btn" href="{{ url_for('admin_users_import') }}">⬅️ Zpět na upload</a>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
</div>
""", ok_users=ok_users, error_users=error_users, ok_count=len(ok_users), error_count=len(error_users))
        
        except Exception as e:
            flash(f"Chyba při načítání preview: {str(e)}", "error")
            return redirect(url_for("admin_users_import"))
    
    @app.route("/admin/users/import/confirm", methods=["POST"])
    @login_required
    def admin_users_import_confirm():
        """Import uživatelů - krok 3: Potvrzení a provedení importu"""
        admin_required()
        
        preview_file = session.get('users_import_preview_file')
        if not preview_file or not os.path.exists(preview_file):
            flash("Preview data nenalezena. Nahraj soubor znovu.", "error")
            return redirect(url_for("admin_users_import"))
        
        try:
            import pickle
            with open(preview_file, 'rb') as f:
                users_preview = pickle.load(f)
            
            created = 0
            ok_users = [u for u in users_preview if u['status'] == 'ok']
            
            for user_data in ok_users:
                try:
                    # Vytvoř uživatele
                    new_user = User(
                        email=user_data['email'],
                        username=user_data['username'],
                        first_name=user_data['first_name'],
                        last_name=user_data['last_name'],
                        nickname=user_data['nickname'],
                        role=user_data['role'],
                        email_verified=True  # Importovaní users mají ověřený email
                    )
                    new_user.set_password(user_data['password'])
                    db.session.add(new_user)
                    db.session.flush()
                    
                    audit("user.imported", "User", new_user.id, username=new_user.username, email=new_user.email)
                    created += 1
                    
                except Exception as e:
                    # Rollback tohoto usera, pokračuj dál
                    db.session.rollback()
                    continue
            
            db.session.commit()
            
            # Cleanup temp file
            try:
                os.remove(preview_file)
                session.pop('users_import_preview_file', None)
            except:
                pass
            
            # Flash výsledek
            flash(f"✅ Importováno: {created} uživatelů. Pro poslání welcome emailů jdi do Uživatelé → Hromadná správa.", "ok")
            return redirect(url_for("admin_users"))
            
        except Exception as e:
            flash(f"Chyba při importu: {str(e)}", "error")
            return redirect(url_for("admin_users_import"))

    @app.route("/admin/user/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_user_edit(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        if request.method == "POST":
            new_username = (request.form.get("username") or "").strip()
            new_email = (request.form.get("email") or "").strip().lower()
            new_first_name = (request.form.get("first_name") or "").strip()
            new_last_name = (request.form.get("last_name") or "").strip()
            new_nickname = (request.form.get("nickname") or "").strip()

            if not new_username or not new_email:
                flash("Vyplň username a email.", "error")
                return redirect(url_for("admin_user_edit", user_id=user_id))

            # Kontrola duplicit
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != u.id:
                flash(f"Username '{new_username}' už existuje.", "error")
                return redirect(url_for("admin_user_edit", user_id=user_id))

            existing_email = User.query.filter_by(email=new_email).first()
            if existing_email and existing_email.id != u.id:
                flash(f"Email '{new_email}' už existuje.", "error")
                return redirect(url_for("admin_user_edit", user_id=user_id))

            old_username = u.username
            old_email = u.email
            u.username = new_username
            u.email = new_email
            u.first_name = new_first_name or None
            u.last_name = new_last_name or None
            u.nickname = new_nickname or None
            db.session.commit()
            audit("user.update", "User", u.id, old_username=old_username, new_username=new_username, old_email=old_email, new_email=new_email)
            flash(f"Uživatel aktualizován.", "ok")
            return redirect(url_for("admin_users"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Upravit uživatele</h2>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Username (login) *</label>
      <input name="username" value="{{ u.username }}" required>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Email *</label>
      <input name="email" type="email" value="{{ u.email }}" required>
    </div>
    <div class="grid2">
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Jméno</label>
        <input name="first_name" value="{{ u.first_name or '' }}">
      </div>
      <div>
        <label class="muted" style="margin-bottom:6px; display:block;">Příjmení</label>
        <input name="last_name" value="{{ u.last_name or '' }}">
      </div>
    </div>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Přezdívka (Nick)</label>
      <input name="nickname" value="{{ u.nickname or '' }}">
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Zobrazí se v žebříčku. Současný nick: <strong>{{ u.display_name }}</strong>
      </div>
    </div>
    <div class="row" style="gap:10px; margin-top:10px;">
      <button class="btn btn-primary" type="submit">Uložit</button>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
</div>
""", u=u)

    @app.route("/admin/user/<int:user_id>/reset-password", methods=["GET", "POST"])
    @login_required
    def admin_user_reset_password(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        if request.method == "POST":
            new_password = (request.form.get("password") or "").strip()
            if not new_password:
                flash("Vyplň nové heslo.", "error")
                return redirect(url_for("admin_user_reset_password", user_id=user_id))
            
            # Validace síly hesla
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, "error")
                return redirect(url_for("admin_user_reset_password", user_id=user_id))

            u.set_password(new_password)
            db.session.commit()
            audit("user.reset_password", "User", u.id)
            flash(f"Heslo pro '{u.username}' bylo resetováno.", "ok")
            return redirect(url_for("admin_users"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Resetovat heslo</h2>
  <div class="muted">Uživatel: <b>{{ u.username }}</b> ({{ u.email }})</div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Nové heslo *</label>
      <input name="password" type="password" placeholder="Min. 8 znaků" required minlength="8">
      <div class="muted" style="font-size:12px; margin-top:4px;">
        Požadavky: min. 8 znaků, velké/malé písmeno, číslo
      </div>
    </div>
    <div class="row" style="gap:10px; margin-top:10px;">
      <button class="btn btn-primary" type="submit">Resetovat heslo</button>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
</div>
""", u=u)

    @app.route("/admin/user/<int:user_id>/change-role", methods=["GET", "POST"])
    @login_required
    def admin_user_change_role(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        if u.id == current_user.id:
            flash("Nemůžeš měnit roli sám sobě.", "error")
            return redirect(url_for("admin_users"))

        if request.method == "POST":
            new_role = (request.form.get("role") or "user").strip()
            old_role = u.effective_role

            # Nastavení role
            if new_role == "admin":
                u.is_admin = True
                u.role = "admin"
            else:
                u.is_admin = False
                u.role = new_role

            db.session.commit()
            audit("user.change_role", "User", u.id, old_role=old_role, new_role=new_role)
            flash(f"Role uživatele '{u.username}' změněna na '{new_role}'.", "ok")
            return redirect(url_for("admin_users"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Změnit roli</h2>
  <div class="muted">Uživatel: <b>{{ u.username }}</b> ({{ u.email }})</div>
  <div class="muted">Současná role: <b>{{ u.effective_role }}</b></div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <label class="muted" style="margin-bottom:6px; display:block;">Nová role</label>
      <select name="role">
        <option value="user" {% if u.effective_role == 'user' %}selected{% endif %}>User (může tipovat)</option>
        <option value="viewer" {% if u.effective_role == 'viewer' %}selected{% endif %}>Viewer (jen prohlížet)</option>
        <option value="moderator" {% if u.effective_role == 'moderator' %}selected{% endif %}>Moderátor (může tipovat + částečná správa)</option>
        <option value="admin" {% if u.effective_role == 'admin' %}selected{% endif %}>Admin (plná správa)</option>
      </select>
    </div>
    <div class="muted" style="margin-top:10px; padding:10px; background:rgba(249,199,79,0.1); border-radius:8px;">
      <b>Vysvětlení rolí:</b><br>
      • <b>User</b> - může tipovat zápasy a odpovídat na extra otázky<br>
      • <b>Viewer</b> - může jen prohlížet žebříček a výsledky, nemůže tipovat<br>
      • <b>Moderátor</b> - může tipovat + má přístup k některým admin funkcím<br>
      • <b>Admin</b> - plný přístup ke všem funkcím
    </div>
    <div class="row" style="gap:10px; margin-top:10px;">
      <button class="btn btn-primary" type="submit">Změnit roli</button>
      <a class="btn" href="{{ url_for('admin_users') }}">Zrušit</a>
    </div>
  </form>
</div>
""", u=u)

    @app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
    @login_required
    def admin_user_delete(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        if u.id == current_user.id:
            flash("Nemůžeš smazat sám sebe.", "error")
            return redirect(url_for("admin_users"))

        username = u.username
        # Smazat všechny tipy uživatele
        Tip.query.filter_by(user_id=u.id).delete()
        # Smazat všechny odpovědi na extra otázky
        ExtraAnswer.query.filter_by(user_id=u.id).delete()
        # Smazat uživatele
        db.session.delete(u)
        db.session.commit()
        audit("user.delete", "User", user_id, username=username)
        flash(f"Uživatel '{username}' byl smazán.", "ok")
        return redirect(url_for("admin_users"))

    # --- ADMIN ROUNDS ---
    # --- ADMIN SMART IMPORT ---
    # =========================================================
    # ULTRA SMART IMPORT - AI-POWERED MATCH PARSING
    # =========================================================

    def smart_parse_matches(text: str, round_id: int = None) -> List[Dict]:
        """
        🤖 ULTRA SMART PARSER V2 - Better whitespace handling
        
        Podporované formáty:
        - Table format: "27. 2. 2026DuklaSlavia18:00" 
        - With spaces: "27. 2. 2026 Sparta - Slavia 18:00"
        - Date + time first: "27. 2. 20:00 Sparta vs Slavia"
        - CSV, Fortuna, UEFA, etc.
        
        Improvements:
        - Skip non-match lines (headers like "24. kolo")
        - Auto year-fill for partial dates
        - Better team splitting
        """
        
        matches = []
        lines = text.strip().split('\n')
        
        print(f"🤖 Smart Parser V2: Zpracovávám {len(lines)} řádků")
        
        for line_num, line in enumerate(lines, 1):
            # Don't normalize whitespace yet - some formats need it
            line_raw = line.strip()
            
            if not line_raw or len(line_raw) < 5:
                continue
            
            # Skip lines that are obviously not matches
            if line_raw.lower() in ['kolo', 'round', 'zápasy', 'matches']:
                print(f"⏭️ Přeskakuji header: {line_raw}")
                continue
            if re.match(r'^\d+\.\s*kolo', line_raw, re.I):
                print(f"⏭️ Přeskakuji kolo header: {line_raw}")
                continue
            
            match_data = _parse_single_line(line_raw, line_num)
            if match_data:
                # Convert datetime to ISO string for JSON
                if 'start_time' in match_data and match_data['start_time']:
                    if isinstance(match_data['start_time'], datetime):
                        match_data['start_time'] = match_data['start_time'].isoformat()
                
                matches.append(match_data)
        
        print(f"✅ Smart Parser V2: Nalezeno {len(matches)} zápasů")
        return matches


    def _is_date(text: str) -> bool:
        """Check if text looks like a date"""
        date_patterns = [
            r'^\d{1,2}\.\s*\d{1,2}\.\s*\d{4}$',  # 27. 2. 2026
            r'^\d{1,2}/\d{1,2}/\d{4}$',          # 27/2/2026
            r'^\d{4}-\d{1,2}-\d{1,2}$',          # 2026-2-27
            r'^\d{1,2}\.\s*\d{1,2}\.\s*$',       # 27. 2.
            r'^\d{1,2}\.\s*\d{1,2}\.$',          # 27.2.
        ]
        text = text.strip()
        for pattern in date_patterns:
            if re.match(pattern, text):
                return True
        return False


    def _parse_date_first_format(line: str, parts: List[str]) -> Optional[Dict]:
        """Parse: 27. 2. 2026 Dukla - Slavia 18:00"""
        
        date_str = ' '.join(parts[:3])  # "27. 2. 2026"
        rest = ' '.join(parts[3:])       # "Dukla - Slavia 18:00"
        
        dt = _parse_datetime(date_str)
        
        # Check for time at end
        time_match = re.search(r'(\d{1,2}:\d{2})$', rest)
        if time_match:
            time_str = time_match.group(1)
            teams_part = rest[:rest.rfind(time_str)].strip()
            # Update datetime with time
            if dt:
                try:
                    time_obj = datetime.strptime(time_str, "%H:%M").time()
                    dt = dt.replace(hour=time_obj.hour, minute=time_obj.minute)
                except:
                    pass
        else:
            teams_part = rest
        
        # Parse teams
        if ' - ' in teams_part:
            teams = teams_part.split(' - ', 1)
        elif ' vs ' in teams_part.lower():
            teams = re.split(r'\s+vs\s+', teams_part, flags=re.I, maxsplit=1)
        else:
            # Single team or unparseable
            return {
                'home_team': teams_part.strip(),
                'away_team': '',
                'start_time': dt,
            }
        
        if len(teams) >= 2:
            return {
                'home_team': teams[0].strip(),
                'away_team': teams[1].strip(),
                'start_time': dt,
            }
        
        return None


    def _parse_date_time_first(line: str, parts: List[str]) -> Optional[Dict]:
        """Parse: 27. 2. 20:00 Sparta vs Slavia"""
        
        date_str = ' '.join(parts[:2])  # "27. 2."
        time_str = parts[2]              # "20:00"
        rest = ' '.join(parts[3:])       # "Sparta vs Slavia"
        
        dt = _parse_datetime(date_str + ' ' + time_str)
        
        # Parse teams
        if ' - ' in rest:
            teams = rest.split(' - ', 1)
        elif ' vs ' in rest.lower():
            teams = re.split(r'\s+vs\s+', rest, flags=re.I, maxsplit=1)
        else:
            return None
        
        if len(teams) >= 2:
            return {
                'home_team': teams[0].strip(),
                'away_team': teams[1].strip(),
                'start_time': dt,
            }
        
        return None



    def _parse_table_format(line: str) -> Optional[Dict]:
        """
        IMPROVED: Parse table copy/paste - handles NO SPACES between parts
        
        Examples:
        - 27. 2. 2026DuklaSlavia18:00
        - 28. 2. 2026Ml. Boleslav__Jablonec__15:00
        - 1. 3. 2026SpartaOstrava20:00
        """
        
        # Pattern: DATE (required) + TEAMS (any) + TIME (required)
        
        # Match date at start
        date_match = re.match(r'^(\d{1,2}\.\s*\d{1,2}\.\s*\d{4})', line)
        if not date_match:
            return None
        
        date_str = date_match.group(1)
        rest = line[len(date_str):].strip()
        
        # Match time at end
        time_match = re.search(r'(\d{1,2}:\d{2})$', rest)
        if not time_match:
            return None
        
        time_str = time_match.group(1)
        teams_part = rest[:rest.rfind(time_str)].strip()
        
        if not teams_part:
            return None
        
        # Parse teams
        # Check for __ separator first
        if '__' in teams_part:
            parts = [p.strip() for p in teams_part.split('__') if p.strip()]
            if len(parts) >= 2:
                home_team = parts[0]
                away_team = parts[1]
            else:
                return None
        else:
            # Smart split without separator
            home_team, away_team = _smart_split_teams(teams_part)
            if not home_team or not away_team:
                return None
        
        # Parse datetime
        try:
            dt = datetime.strptime(f"{date_str} {time_str}", "%d. %m. %Y %H:%M")
        except:
            dt = None
        
        return {
            'home_team': home_team,
            'away_team': away_team,
            'start_time': dt,
        }


    def _smart_split_teams(text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        IMPROVED: Smart split teams from text without separator
        
        Examples:
        - "DuklaSlavia" → "Dukla", "Slavia"
        - "SpartaOstrava" → "Sparta", "Ostrava"
        - "Ml. BoleslavJablonec" → "Ml. Boleslav", "Jablonec"
        """
        
        known_teams = [
            # Longer names first for greedy matching
            'Ml. Boleslav', 'Mladá Boleslav',
            'Hradec Kr.', 'Hradec Králové', 'Hradec',
            'FK Dukla Praha', 'SK Slavia Praha', 'AC Sparta Praha',
            'FC Viktoria Plzeň', 'FC Zlín', 'FC Slovan Liberec',
            'FC Baník Ostrava', 'FK Teplice', 'FK Jablonec',
            'MFK Karviná', '1.FC Slovácko', '1. FC Slovácko', 'FK Pardubice',
            'SK Sigma Olomouc', 'Bohemians Praha 1905',
            'FK Mladá Boleslav', 'FC Hradec Králové',
            # Short names
            'Dukla', 'Slavia', 'Sparta', 'Plzeň', 'Zlín',
            'Liberec', 'Ostrava', 'Baník', 'Teplice', 'Jablonec',
            'Karviná', 'Slovácko', 'Pardubice', 'Olomouc', 'Sigma',
            'Bohemians',
        ]
        
        # Try to match known team from start
        for team in sorted(known_teams, key=len, reverse=True):
            if text.startswith(team):
                home = team
                away = text[len(team):].strip()
                
                # Check if away is also a known team
                for away_team in known_teams:
                    if away == away_team or away.startswith(away_team):
                        return home, away_team
                
                # Try away as-is
                if away:
                    return home, away
        
        # Fallback: split at second capital letter
        capitals = [i for i, c in enumerate(text) if c.isupper()]
        if len(capitals) >= 2:
            split_pos = capitals[1]
            return text[:split_pos], text[split_pos:]
        
        return None, None


    def _parse_single_line(line: str, line_num: int = 0) -> Optional[Dict]:
        """
        IMPROVED: Better handling of different formats
        
        Priority:
        1. Table format (no spaces): 27. 2. 2026DuklaSlavia18:00
        2. Date with spaces: 27. 2. 2026 Dukla - Slavia 18:00
        3. Other formats
        """
        
        # TRY 1: Table format FIRST (before whitespace normalization!)
        result = _parse_table_format(line)
        if result:
            return result
        
        # TRY 2: Now normalize whitespace for other formats
        line_normalized = re.sub(r'\s+', ' ', line.replace('\t', ' ')).strip()
        
        # TRY 3: Date at start with spaces
        parts = line_normalized.split()
        
        # "27. 2. 2026 Dukla - Slavia 18:00"
        if len(parts) >= 3 and _is_date(' '.join(parts[:3])):
            return _parse_date_first_format(line_normalized, parts)
        
        # "27. 2. 20:00 Sparta vs Slavia"
        if len(parts) >= 4:
            potential_date = ' '.join(parts[:2])
            potential_time = parts[2]
            
            if _is_date(potential_date) and re.match(r'^\d{1,2}:\d{2}$', potential_time):
                return _parse_date_time_first(line_normalized, parts)
        
        # TRY 4: Other parsers
        parsers = [
            _parse_fortuna_style,
            _parse_uefa_style,
            _parse_csv_style,
            _parse_pipe_style,
            _parse_score_style,
            _parse_vs_style,
            _parse_dash_style,
        ]
        
        for parser in parsers:
            try:
                result = parser(line_normalized)
                if result:
                    return result
            except Exception:
                continue
        
        print(f"⚠️ Nepodařilo se parsovat řádek {line_num}: {line[:50]}")
        return None


    def _parse_fortuna_style(line: str) -> Optional[Dict]:
        """Fortuna Liga: #22 14/02/26Sat 15:00 DUK 0:0 FCZ"""
        pattern = r'#(\d+)\s+(\d{2})/(\d{2})/(\d{2})(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{1,2}):(\d{2})\s+([A-Z]{3,4})\s+(?:(\d+):(\d+)|[-–])\s+([A-Z]{3,4})'
        m = re.search(pattern, line)
        if not m:
            return None
    
        day, month, year_short = int(m.group(2)), int(m.group(3)), int(m.group(4))
        hour, minute = int(m.group(5)), int(m.group(6))
        home_code, away_code = m.group(7), m.group(10)
        home_score = int(m.group(8)) if m.group(8) else None
        away_score = int(m.group(9)) if m.group(9) else None
    
        year = 2000 + year_short if year_short < 50 else 1900 + year_short
    
        # Team code to name
        team_map = {
            'ACS': 'AC Sparta Praha', 'SKS': 'SK Slavia Praha',
            'PLZ': 'FC Viktoria Plzeň', 'LIB': 'FC Slovan Liberec',
            'FCB': 'FC Baník Ostrava', 'MBL': 'FK Mladá Boleslav',
            'FKJ': 'FK Jablonec', 'BOH': 'Bohemians Praha 1905',
            'FCS': '1.FC Slovácko', 'SIG': 'SK Sigma Olomouc',
            'TEP': 'FK Teplice', 'HKR': 'FC Hradec Králové',
            'PCE': 'FK Pardubice', 'KAR': 'MFK Karviná',
            'FCZ': 'FC Zlín', 'DUK': 'FK Dukla Praha',
        }
    
        return {
            'home_team': team_map.get(home_code, home_code),
            'away_team': team_map.get(away_code, away_code),
            'start_time': datetime(year, month, day, hour, minute),
            'home_score': home_score,
            'away_score': away_score,
        }


    def _parse_uefa_style(line: str) -> Optional[Dict]:
        """UEFA: Juventus 2-1 Galatasaray (18:45 CET)"""
        # S časem
        pattern = r'(.+?)\s+(\d+)[-–:](\d+)\s+(.+?)\s*\((\d{1,2}):(\d{2})'
        m = re.search(pattern, line)
        if m:
            home = m.group(1).strip()
            away = m.group(4).strip()
            hour, minute = int(m.group(5)), int(m.group(6))
            return {
                'home_team': home,
                'away_team': away,
                'home_score': int(m.group(2)),
                'away_score': int(m.group(3)),
                'start_time': datetime.now().replace(hour=hour, minute=minute),
            }
    
        # Bez času
        pattern = r'(.+?)\s+(\d+)[-–](\d+)\s+(.+?)$'
        m = re.search(pattern, line)
        if m:
            return {
                'home_team': m.group(1).strip(),
                'away_team': m.group(4).strip(),
                'home_score': int(m.group(2)),
                'away_score': int(m.group(3)),
            }
    
        return None


    def _parse_csv_style(line: str) -> Optional[Dict]:
        """CSV: Sparta,Slavia,2,1,14.2.2026 20:00

        Robustnější:
        - umí ignorovat úvodní kódový sloupec (např. "Ml."/"ACS"/"MBL")
        - umí ignorovat úvodní datumový sloupec (např. "27. 2. 2026,Sparta,Slavia,18:00")
        - umí sloučit rozpadlý název týmu typu "Ml." + "Boleslav"
        """
        if ',' not in line:
            return None

        parts = [p.strip() for p in line.split(',') if p.strip()]
        if len(parts) < 2:
            return None

        def _looks_like_code(tok: str) -> bool:
            t = (tok or '').strip()
            if not t or ' ' in t or len(t) > 5:
                return False
            if re.match(r'^[A-Za-z]{1,4}\.?$', t):
                return True
            if t.isupper() and re.match(r'^[A-Z0-9]{2,5}$', t):
                return True
            return False

        leading_dt = None
        if len(parts) >= 3 and _is_date(parts[0]):
            leading_dt = parts[0]
            parts = parts[1:]

        if len(parts) >= 3 and _looks_like_code(parts[0]) and (len(parts[1]) >= 5 or ' ' in parts[1]):
            parts = parts[1:]

        if len(parts) >= 3 and parts[0].endswith('.') and len(parts[0]) <= 4 and ' ' not in parts[1] and parts[1].isalpha():
            merged = f"{parts[0]} {parts[1]}"
            parts = [merged] + parts[2:]

        if len(parts) < 2:
            return None

        result: Dict[str, Any] = {'home_team': parts[0], 'away_team': parts[1]}
        tail = parts[2:]

        def _is_probable_time(tok: str) -> bool:
            # HH:MM typical kick-off time (minutes usually 00/15/30/45)
            m = re.match(r'^(\d{1,2}):(\d{2})$', (tok or '').strip())
            if not m:
                return False
            hh = int(m.group(1))
            mm = int(m.group(2))
            return 0 <= hh <= 23 and 0 <= mm <= 59 and mm in (0, 15, 30, 45) and hh >= 8

        def _is_score_colon(tok: str) -> bool:
            return bool(re.match(r'^(\d{1,2}):(\d{1,2})$', (tok or '').strip()))

        def _apply_dt_from_tail(tokens: list[str]) -> None:
            nonlocal result, leading_dt
            if not tokens:
                return
            last = tokens[-1].strip()

            # if we have leading date from first column, allow time-only last column
            if leading_dt and _is_probable_time(last):
                dt = _parse_datetime(f"{leading_dt} {last}")
                if dt:
                    result['start_time'] = dt
                return

            # full datetime in last token
            dt = _parse_datetime(last)
            if dt:
                result['start_time'] = dt

        # --- score/time parsing in tail ---
        if tail:
            # Handle scores like "0:2"
            if _is_score_colon(tail[0]):
                try:
                    hs, aw = tail[0].split(':', 1)
                    result['home_score'] = int(hs)
                    result['away_score'] = int(aw)
                except Exception:
                    pass
                _apply_dt_from_tail(tail[1:])
                # If we have only date (no time), set a sensible default so the match is tipovatelný.
                if leading_dt and 'start_time' not in result:
                    dt = _parse_datetime(f"{leading_dt} 18:00")
                    if dt:
                        result['start_time'] = dt
                return result

            # Handle numeric scores "2,1"
            if len(tail) >= 2 and re.match(r'^\d+$', tail[0]) and re.match(r'^\d+$', tail[1]):
                result['home_score'] = int(tail[0])
                result['away_score'] = int(tail[1])
                _apply_dt_from_tail(tail[2:])
                return result

        _apply_dt_from_tail(tail)
        if leading_dt and 'start_time' not in result:
            # date-only without time; keep empty for preview unless you want default time
            dt = _parse_datetime(f"{leading_dt} 18:00")
            if dt:
                result['start_time'] = dt

        return result



    def _parse_pipe_style(line: str) -> Optional[Dict]:
        """Pipe separated: Sparta|Slavia|2|1|14.2.2026 20:00

        Robustnější:
        - umí ignorovat úvodní kódový sloupec (např. "Ml."/"ACS"/"MBL")
        - umí ignorovat úvodní datumový sloupec (např. "27. 2. 2026 | Sparta | Slavia | 18:00")
        - umí sloučit rozpadlý název týmu typu "Ml." + "Boleslav"
        """
        if '|' not in line:
            return None

        parts = [p.strip() for p in line.split('|') if p.strip()]
        if len(parts) < 2:
            return None

        def _looks_like_code(tok: str) -> bool:
            t = (tok or '').strip()
            if not t or ' ' in t or len(t) > 5:
                return False
            if re.match(r'^[A-Za-z]{1,4}\.?$', t):
                return True
            if t.isupper() and re.match(r'^[A-Z0-9]{2,5}$', t):
                return True
            return False

        leading_date = None
        if len(parts) >= 3 and _is_date(parts[0]):
            leading_date = parts[0]
            parts = parts[1:]

        if len(parts) >= 3 and _looks_like_code(parts[0]) and (len(parts[1]) >= 5 or ' ' in parts[1]):
            parts = parts[1:]

        if len(parts) >= 3 and parts[0].endswith('.') and len(parts[0]) <= 4 and ' ' not in parts[1] and parts[1].isalpha():
            merged = f"{parts[0]} {parts[1]}"
            parts = [merged] + parts[2:]

        if len(parts) < 2:
            return None

        result: Dict[str, Any] = {'home_team': parts[0], 'away_team': parts[1]}
        tail = parts[2:]

        def _is_probable_time(tok: str) -> bool:
            m = re.match(r'^(\d{1,2}):(\d{2})$', (tok or '').strip())
            if not m:
                return False
            hh = int(m.group(1))
            mm = int(m.group(2))
            return 0 <= hh <= 23 and 0 <= mm <= 59 and mm in (0, 15, 30, 45) and hh >= 8

        def _is_score_colon(tok: str) -> bool:
            return bool(re.match(r'^(\d{1,2}):(\d{1,2})$', (tok or '').strip()))

        # If we have leading date and the next token is a time, treat it as kick-off time
        if leading_date and tail and _is_probable_time(tail[0]):
            dt = _parse_datetime(f"{leading_date} {tail[0]}")
            if dt:
                result['start_time'] = dt
            tail = tail[1:]

        # Handle score in format "0:2" (very common in pasted tables)
        if tail and _is_score_colon(tail[0]) and not _is_probable_time(tail[0]):
            try:
                hs, aw = tail[0].split(':', 1)
                result['home_score'] = int(hs)
                result['away_score'] = int(aw)
            except Exception:
                pass
            tail = tail[1:]
            if leading_date and 'start_time' not in result:
                dt = _parse_datetime(f"{leading_date} 18:00")
                if dt:
                    result['start_time'] = dt

        # Handle numeric scores "2|1"
        if len(tail) >= 2 and re.match(r'^\d+$', str(tail[0])) and re.match(r'^\d+$', str(tail[1])):
            result['home_score'] = int(tail[0])
            result['away_score'] = int(tail[1])
            tail = tail[2:]

        # Remaining tail may contain full datetime
        if tail:
            dt = _parse_datetime(tail[0])
            if dt:
                result['start_time'] = dt
            elif leading_date and _is_probable_time(tail[0]):
                dt = _parse_datetime(f"{leading_date} {tail[0]}")
                if dt:
                    result['start_time'] = dt

        if leading_date and 'start_time' not in result:
            dt = _parse_datetime(f"{leading_date} 18:00")
            if dt:
                result['start_time'] = dt

        return result



    def _parse_datetime_first(line: str) -> Optional[Dict]:
        """Datum první: 14.2. 20:00 Sparta vs Slavia"""
        pattern = r'(\d{1,2})\.(\d{1,2})\.?\s+(\d{1,2}):(\d{2})\s+(.+?)\s+(?:vs|versus|-|–)\s+(.+?)$'
        m = re.search(pattern, line)
        if not m:
            return None
    
        day, month = int(m.group(1)), int(m.group(2))
        hour, minute = int(m.group(3)), int(m.group(4))
        year = datetime.now().year
    
        # Pokud je měsíc v minulosti, použij příští rok
        if month < datetime.now().month:
            year += 1
    
        return {
            'home_team': m.group(5).strip(),
            'away_team': m.group(6).strip(),
            'start_time': datetime(year, month, day, hour, minute),
        }


    def _parse_score_style(line: str) -> Optional[Dict]:
        """Se skóre: Sparta - Slavia 2:1"""
        pattern = r'(.+?)\s+[-–]\s+(.+?)\s+(\d+)[:\-](\d+)'
        m = re.search(pattern, line)
        if not m:
            return None
    
        return {
            'home_team': m.group(1).strip(),
            'away_team': m.group(2).strip(),
            'home_score': int(m.group(3)),
            'away_score': int(m.group(4)),
        }


    def _parse_vs_style(line: str) -> Optional[Dict]:
        """Vs style: Sparta vs Slavia"""
        pattern = r'(.+?)\s+(?:vs|versus)\s+(.+?)$'
        m = re.search(pattern, line, re.I)
        if not m:
            return None
    
        return {
            'home_team': m.group(1).strip(),
            'away_team': m.group(2).strip(),
        }


    def _parse_dash_style(line: str) -> Optional[Dict]:
        """Dash style: Sparta - Slavia"""
        pattern = r'^(.+?)\s+[-–]\s+(.+?)$'
        m = re.search(pattern, line)
        if not m:
            return None
    
        return {
            'home_team': m.group(1).strip(),
            'away_team': m.group(2).strip(),
        }


    def _parse_datetime(s: str) -> Optional[datetime]:
        """
        Parse datetime from string
        IMPROVED: Auto-fill missing year
        """
        s = s.strip()
        
        formats = [
            '%d. %m. %Y %H:%M',
            '%d. %m. %Y',
            '%d.%m.%Y %H:%M',
            '%d.%m.%Y',
            '%d/%m/%Y %H:%M',
            '%d/%m/%Y',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%d',
            '%d. %m. %H:%M',
            '%d.%m. %H:%M',
            '%d. %m.',
            '%d.%m.',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                # IMPROVEMENT: If year is missing (1900), add current/next year
                if dt.year == 1900:
                    year = datetime.now().year
                    if dt.month < datetime.now().month:
                        year += 1
                    dt = dt.replace(year=year)
                return dt
            except:
                continue
        
        return None


    def normalize_team_name(name: str, round_id: int = None) -> str:
        """
        🧠 Inteligentní normalizace jména týmu
    
        - Opraví běžné překlepy
        - Doplní plný název (Slavia → SK Slavia Praha)
        - Najde podobné týmy v databázi
        """
    
        if name is None:
            return ""
        if isinstance(name, bool):
            return ""
        if not isinstance(name, str):
            name = str(name)
        name = name.strip()
        name = name.replace("\u00a0", " ").replace("\t", " ").strip()
        name = re.sub(r"\s+", " ", name)
        # Normalize common Czech football prefix patterns
        name = re.sub(r"\b1\.?\s*FC\b", "1. FC", name, flags=re.IGNORECASE)
        name = re.sub(r"\bFK\b", "FK", name)

        # Aliasy z DB (spravované v Admin UI)
        if round_id:
            try:
                al = TeamAlias.query.filter_by(round_id=round_id, alias=name).first()
                if not al:
                    # case-insensitive match
                    al = TeamAlias.query.filter(TeamAlias.round_id == round_id, db.func.lower(TeamAlias.alias) == name.lower()).first()
                if al and al.canonical_name:
                    return al.canonical_name
            except Exception as e:
                print(f"⚠️ Chyba v TeamAlias lookup: {e}")
    
        # Zkratky → plné názvy
        short_to_full = {
            # Zkratky / běžné názvy → názvy, které typicky chceš mít v DB
            'Dukla': 'FK Dukla Praha',
            'Slavia': 'SK Slavia Praha',
            'Sparta': 'AC Sparta Praha',
            'Ostrava': 'FC Baník Ostrava',
            'Baník': 'FC Baník Ostrava',

            'Liberec': 'FC Slovan Liberec',
            'Hradec Kr.': 'FC Hradec Králové',
            'Hradec': 'FC Hradec Králové',

            'Ml. Boleslav': 'FK Mladá Boleslav',
            'Mladá Boleslav': 'FK Mladá Boleslav',
            'Jablonec': 'FK Jablonec',

            'Pardubice': 'FK Pardubice',
            'Teplice': 'FK Teplice',

            'Karviná': 'MFK Karviná',
            'Slovácko': '1.FC Slovácko',

            'Zlín': 'FC Zlín',
            'Plzeň': 'FC Viktoria Plzeň',

            'Olomouc': 'SK Sigma Olomouc',
            'Sigma': 'SK Sigma Olomouc',

            'Bohemians': 'Bohemians Praha 1905',
        }

    
        # Přesná shoda
        if name in short_to_full:
            return short_to_full[name]
    
        # Case-insensitive hledání
        for short, full in short_to_full.items():
            if name.lower() == short.lower():
                return full
            if name.lower() == full.lower():
                return full
    
        # Částečná shoda
        for short, full in short_to_full.items():
            if short.lower() in name.lower() or name.lower() in short.lower():
                return full
        # Pokud je round_id, zkus najít v DB (fuzzy match na existující Team.name)
        if round_id:
            try:
                if not isinstance(name, str):
                    name = str(name)

                # Načti názvy týmů pro tuto soutěž
                team_names = [
                    (t.name or "").strip()
                    for t in Team.query.filter_by(round_id=round_id, is_deleted=False).all()
                    if t and t.name
                ]

                needle = name.lower()
                for tname in team_names:
                    t_low = tname.lower()
                    if needle in t_low or t_low in needle:
                        return tname
            except Exception as e:
                print(f"⚠️ Chyba v normalize_team_name: {e}")
                pass
        # Žádná shoda - vrať original
        return name


    @app.route("/admin/smart-import", methods=["GET", "POST"])
    @login_required
    def admin_smart_import():
        """
        🤖 ULTRA SMART IMPORT
    
        Nakopíruj zápasy odkudkoliv → AI je naparsuje → Preview → Import
        """
        admin_required()
    
        rounds = Round.query.order_by(Round.name).all()
    
        if request.method == "POST":
            action = request.form.get("action", "parse")
        
            if action == "parse":
                # KROK 1: Parsování
                text = request.form.get("raw_text", "")
                round_id = request.form.get("round_id")
                import_mode = request.form.get("import_mode", "fixtures")
            
                if not text.strip():
                    flash("❌ Zadej nějaký text k parsování!", "error")
                    return redirect(url_for("admin_smart_import"))
            
                # Parse!
                matches = smart_parse_matches(text, round_id=int(round_id) if round_id else None)
            
                if not matches:
                    flash("❌ Nepodařilo se naparsovat žádné zápasy. Zkus jiný formát.", "error")
                    return redirect(url_for("admin_smart_import"))
            
                # Normalize team names
                if round_id:
                    for m in matches:
                        m['home_team'] = normalize_team_name(m['home_team'], int(round_id))
                        m['away_team'] = normalize_team_name(m['away_team'], int(round_id))
            
                # Store preview server-side (DB) – v cookie jen ID (spolehlivé i na multi-worker hostingu)
                try:
                    payload = json.dumps({"round_id": round_id, "import_mode": import_mode, "matches": matches}, ensure_ascii=False)
                    imp = ImportSession(user_id=current_user.id, kind="smart_import_matches", payload_json=payload)
                    db.session.add(imp)
                    db.session.commit()
                    session['smart_import_session_id'] = imp.id
                    session['import_round_id'] = round_id
                except Exception as e:
                    db.session.rollback()
                    flash(f"❌ Nepodařilo se uložit preview importu: {e}", "error")
                    return redirect(url_for("admin_smart_import"))
            
                flash(f"✅ Naparsováno {len(matches)} zápasů! Zkontroluj a uprav pokud potřeba.", "ok")
                return redirect(url_for("admin_smart_import") + "?preview=1")
        
            elif action == "import":
                # KROK 2: Import do DB
                matches_json = request.form.get("matches_data", "[]")
                round_id = request.form.get("round_id")
                import_mode = request.form.get("import_mode", "fixtures")
            
                if not round_id:
                    flash("❌ Vyber soutěž/kolo!", "error")
                    return redirect(url_for("admin_smart_import"))
            
                try:
                    matches = json.loads(matches_json)
                except:
                    flash("❌ Chyba při parsování dat!", "error")
                    return redirect(url_for("admin_smart_import"))
            
                # Get round first
                r = db.session.get(Round, int(round_id))
                if not r:
                    flash("❌ Kolo nenalezeno!", "error")
                    return redirect(url_for("admin_smart_import"))
                
                # Store round data before expunging
                round_id_int = r.id
                round_name = r.name
                
                # CRITICAL: Expunge all objects from session to avoid pollution
                db.session.expunge_all()
                
                print(f"🔍 Using round_id: {round_id_int}, round_name: {round_name}")
            
                # Import!
                imported = 0
                errors = []
                skipped = 0
            
                for match_data in matches:
                    print(f"\n🔍 Processing match_data: {match_data}")
                    print(f"🔍 match_data type: {type(match_data)}")
                    print(f"🔍 match_data keys: {match_data.keys() if isinstance(match_data, dict) else 'NOT A DICT!'}")
                    
                    try:
                        home_team = match_data.get('home_team', '').strip()
                        away_team = match_data.get('away_team', '').strip()
                        
                        print(f"🔍 Extracted teams: home='{home_team}' ({type(home_team)}), away='{away_team}' ({type(away_team)})")
                    
                        if not home_team or not away_team:
                            print(f"⚠️ Přeskakuji zápas - chybí tým: home='{home_team}', away='{away_team}'")
                            skipped += 1
                            continue
                    
                        # Start time
                        start_time = None
                        if match_data.get('start_time'):
                            try:
                                start_time_str = match_data['start_time']
                                if isinstance(start_time_str, str):
                                    start_time = datetime.fromisoformat(start_time_str)
                                elif isinstance(start_time_str, datetime):
                                    start_time = start_time_str
                                else:
                                    print(f"⚠️ Neznámý typ start_time: {type(start_time_str)}")
                                    start_time = None
                            except Exception as e:
                                print(f"⚠️ Chyba parsování času '{match_data.get('start_time')}': {e}")
                                start_time = None
                    
                        # Scores
                        home_score = match_data.get('home_score')
                        away_score = match_data.get('away_score')

                        # Import mode handling
                        if import_mode == 'fixtures':
                            home_score = None
                            away_score = None
                        
                        # Validate scores are integers or None
                        if home_score is not None:
                            try:
                                home_score = int(home_score)
                            except:
                                home_score = None
                        
                        if away_score is not None:
                            try:
                                away_score = int(away_score)
                            except:
                                away_score = None
                    
                        # Debug log before creating Match
                        print(f"🔍 Match data:")
                        print(f"   round_id={round_id_int} (type={type(round_id_int)})")
                        print(f"   home_team={home_team} (type={type(home_team)})")
                        print(f"   away_team={away_team} (type={type(away_team)})")
                        print(f"   start_time={start_time} (type={type(start_time)})")
                        print(f"   home_score={home_score} (type={type(home_score)})")
                        print(f"   away_score={away_score} (type={type(away_score)})")
                        
                        # Ensure all values are correct types
                        if not isinstance(round_id_int, int):
                            print(f"❌ round_id není int: {type(round_id_int)}")
                            continue
                        
                        if not isinstance(home_team, str) or not isinstance(away_team, str):
                            print(f"❌ Týmy nejsou string")
                            continue
                        
                        if start_time is not None and not isinstance(start_time, datetime):
                            print(f"❌ start_time není datetime: {type(start_time)}")
                            start_time = None
                        
                        if home_score is not None and not isinstance(home_score, int):
                            print(f"❌ home_score není int: {type(home_score)}")
                            home_score = None
                        
                        if away_score is not None and not isinstance(away_score, int):
                            print(f"❌ away_score není int: {type(away_score)}")
                            away_score = None
                    
                                                # Results mode: must have scores
                        if import_mode == 'results':
                            if home_score is None or away_score is None:
                                skipped += 1
                                continue

                        # Create match
                        # Resolve Team objects (Match expects FK IDs, not strings)
                        home_team_obj = Team.query.filter_by(
                            round_id=round_id_int,
                            name=home_team,
                            is_deleted=False
                        ).first()
                        if not home_team_obj:
                            home_team_obj = Team(round_id=round_id_int, name=home_team)
                            db.session.add(home_team_obj)
                            db.session.flush()

                        away_team_obj = Team.query.filter_by(
                            round_id=round_id_int,
                            name=away_team,
                            is_deleted=False
                        ).first()
                        if not away_team_obj:
                            away_team_obj = Team(round_id=round_id_int, name=away_team)
                            db.session.add(away_team_obj)
                            db.session.flush()

                        # Results mode: try to find existing match and update scores
                        if import_mode == 'results':
                            q = Match.query.filter_by(round_id=round_id_int, home_team_id=home_team_obj.id, away_team_id=away_team_obj.id)
                            if start_time is not None:
                                exact = q.filter(Match.start_time == start_time).first()
                                if exact:
                                    exact.home_score = home_score
                                    exact.away_score = away_score
                                    imported += 1
                                    print(f"✅ Aktualizován výsledek (exact): {home_team} - {away_team} {home_score}:{away_score}")
                                    continue
                            existing = q.order_by(Match.start_time.asc()).first()
                            if existing:
                                existing.home_score = home_score
                                existing.away_score = away_score
                                imported += 1
                                print(f"✅ Aktualizován výsledek: {home_team} - {away_team} {home_score}:{away_score}")
                                continue
                            print(f"⚠️ Nenalezen existující zápas pro výsledek: {home_team} - {away_team}")
                            skipped += 1
                            continue

                        m = Match(
                            round_id=round_id_int,
                            home_team_id=home_team_obj.id,
                            away_team_id=away_team_obj.id,
                            start_time=start_time,
                            home_score=home_score,
                            away_score=away_score,
                        )
                        
                        print(f"🔍 Match object created: {m}")
                        print(f"🔍 Match type: {type(m)}")
                        print(f"🔍 Match.__dict__: {m.__dict__}")
                    
                        db.session.add(m)
                        
                        # Flush immediately to catch errors
                        try:
                            db.session.flush()
                            imported += 1
                            print(f"✅ Přidán zápas: {home_team} - {away_team}")
                        except Exception as flush_error:
                            db.session.rollback()
                            error_msg = f"{home_team} - {away_team}: FLUSH ERROR: {str(flush_error)}"
                            errors.append(error_msg)
                            print(f"❌ Flush error: {flush_error}")
                            print(f"❌ Match object: {m.__dict__}")
                            continue
                    
                    except Exception as e:
                        error_msg = f"{home_team} - {away_team}: {str(e)}"
                        errors.append(error_msg)
                        print(f"❌ Chyba při importu: {error_msg}")
                
                try:
                    db.session.commit()
                    print(f"✅ DB commit úspěšný: {imported} zápasů")
                except Exception as e:
                    db.session.rollback()
                    print(f"❌ DB commit selhal: {e}")
                    flash(f"❌ Chyba při ukládání do databáze: {str(e)}", "error")
                    return redirect(url_for("admin_smart_import"))
            
                # Clear session
                session.pop('parsed_matches', None)
                session.pop('import_round_id', None)
            
                if errors:
                    flash(f"⚠️ Importováno {imported} zápasů, přeskočeno {skipped}, {len(errors)} chyb: {', '.join(errors[:3])}", "warning")
                elif skipped > 0:
                    flash(f"✅ Importováno {imported} zápasů, přeskočeno {skipped} (chybějící týmy)", "ok")
                else:
                    flash(f"✅ Úspěšně importováno {imported} zápasů!", "ok")
            
                audit("smart_import", "Match", None, count=imported, round=round_name)
            
                return redirect(url_for("admin_rounds"))
    
        # GET request
        preview_mode = request.args.get("preview") == "1"
        parsed_matches: List[Dict[str, Any]] = []
        import_round_id = session.get('import_round_id')
        import_mode = 'fixtures'

        if preview_mode:
            sid = session.get('smart_import_session_id')
            if sid:
                imp = db.session.get(ImportSession, int(sid))
                if imp and imp.user_id == current_user.id and imp.kind == "smart_import_matches":
                    try:
                        payload = json.loads(imp.payload_json or "{}")
                        import_round_id = payload.get("round_id", import_round_id)
                        import_mode = payload.get('import_mode', import_mode) or import_mode
                        parsed_matches = payload.get("matches", []) or []
                    except Exception:
                        parsed_matches = []
    
        return render_template_string(SMART_IMPORT_TEMPLATE,
                                      rounds=rounds,
                                      preview_mode=preview_mode,
                                      parsed_matches=parsed_matches,
                                      import_round_id=import_round_id,
                                      import_mode=import_mode)


    # Template pro Smart Import
    SMART_IMPORT_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🤖 Smart Import | Tipovačka</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      padding: 20px;
      color: #e0e0e0;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    
    .card {
      background: rgba(30, 30, 46, 0.95);
      border-radius: 16px;
      padding: 32px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      margin-bottom: 24px;
      border: 1px solid rgba(255,255,255,0.1);
      backdrop-filter: blur(10px);
    }
    
    h1 {
      font-size: 32px;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    .subtitle {
      color: #a0a0a0;
      margin-bottom: 24px;
      font-size: 16px;
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: #e0e0e0;
    }
    
    .muted {
      color: #888;
      font-size: 14px;
      margin-top: 4px;
    }
    
    select, textarea, input[type="text"], input[type="number"], input[type="datetime-local"] {
      width: 100%;
      padding: 12px;
      border: 2px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      font-size: 16px;
      font-family: inherit;
      transition: all 0.2s;
      background: rgba(20, 20, 30, 0.8);
      color: #e0e0e0;
    }
    
    select:focus, textarea:focus, input:focus {
      outline: none;
      border-color: #667eea;
      background: rgba(20, 20, 30, 0.95);
    }
    
    textarea {
      min-height: 300px;
      font-family: 'Monaco', 'Courier New', monospace;
      resize: vertical;
      line-height: 1.6;
    }
    
    .btn {
      padding: 14px 28px;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-block;
    }
    
    .btn-primary {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }
    
    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
    }
    
    .btn-success {
      background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);
      color: white;
    }
    
    .btn-success:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(46, 204, 113, 0.4);
    }
    
    .btn-secondary {
      background: rgba(255,255,255,0.1);
      color: #e0e0e0;
      border: 1px solid rgba(255,255,255,0.2);
    }
    
    .btn-secondary:hover {
      background: rgba(255,255,255,0.15);
    }
    
    .examples {
      background: rgba(20, 20, 30, 0.6);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      border: 1px solid rgba(255,255,255,0.05);
    }
    
    .examples h3 {
      margin-bottom: 12px;
      font-size: 18px;
      color: #667eea;
    }
    
    .example-item {
      background: rgba(10, 10, 15, 0.8);
      padding: 8px 12px;
      border-radius: 4px;
      margin-bottom: 8px;
      font-family: 'Monaco', 'Courier New', monospace;
      font-size: 14px;
      border-left: 4px solid #667eea;
      color: #a0a0a0;
    }
    
    .preview-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    
    .preview-table th {
      background: rgba(102, 126, 234, 0.2);
      padding: 12px;
      text-align: left;
      font-weight: 600;
      border-bottom: 2px solid #667eea;
      color: #e0e0e0;
    }
    
    .preview-table td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    
    .preview-table input[type="text"],
    .preview-table input[type="number"],
    .preview-table input[type="datetime-local"],
    .preview-table input[type="checkbox"] {
      padding: 8px;
      font-size: 14px;
      background: rgba(20, 20, 30, 0.8);
      border: 1px solid rgba(255,255,255,0.1);
      color: #e0e0e0;
    }
    
    .preview-table input:focus {
      border-color: #667eea;
      background: rgba(20, 20, 30, 0.95);
    }
    
    .radio-group {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    
    .radio-group label {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      padding: 10px 16px;
      background: rgba(20, 20, 30, 0.6);
      border-radius: 8px;
      border: 2px solid rgba(255,255,255,0.1);
      transition: all 0.2s;
      margin-bottom: 0;
      font-weight: normal;
    }
    
    .radio-group label:hover {
      border-color: #667eea;
      background: rgba(20, 20, 30, 0.8);
    }
    
    .radio-group input[type="radio"] {
      width: auto;
      margin: 0;
    }
    
    .radio-group input[type="radio"]:checked + span {
      color: #667eea;
      font-weight: 600;
    }
    
    .flash {
      padding: 12px 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      border-left: 4px solid;
    }
    
    .flash.ok {
      background: rgba(46, 204, 113, 0.1);
      border-color: #2ecc71;
      color: #2ecc71;
    }
    
    .flash.error {
      background: rgba(231, 76, 60, 0.1);
      border-color: #e74c3c;
      color: #e74c3c;
    }
    
    .flash.warning {
      background: rgba(241, 196, 15, 0.1);
      border-color: #f1c40f;
      color: #f1c40f;
    }
    
    .back-link {
      color: #667eea;
      text-decoration: none;
      display: inline-block;
      margin-bottom: 20px;
      font-weight: 600;
    }
    
    .back-link:hover {
      text-decoration: underline;
    }
    
    @media (max-width: 768px) {
      body { padding: 10px; }
      .card { padding: 20px; }
      h1 { font-size: 24px; }
      .radio-group { flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="container">
    <a href="{{ url_for('admin_dashboard') }}" class="back-link">← Zpět na Admin</a>
    
    {% with messages = get_flashed_messages(with_categories=True) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="flash {{ category }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    
    {% if not preview_mode %}
    <div class="card">
      <h1>🤖 Smart Import V2</h1>
      <div class="subtitle">Nakopíruj zápasy odkudkoliv → AI je naparsuje → Preview → Import</div>
      
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <input type="hidden" name="action" value="parse"/>
        
        <div class="form-group">
          <label>Soutěž / Kolo *</label>
          <select name="round_id" required>
            <option value="">-- Vyber soutěž --</option>
            {% for r in rounds %}
            <option value="{{ r.id }}" {% if import_round_id and import_round_id|string == r.id|string %}selected{% endif %}>
              {{ r.name }}
            </option>
            {% endfor %}
          </select>
        </div>
        
        <div class="form-group">
          <label>Import Mode</label>
          <div class="radio-group">
            <label>
              <input type="radio" name="import_mode" value="fixtures" {% if import_mode != 'results' %}checked{% endif %}>
              <span>📅 Fixtures (rozpisy)</span>
            </label>
            <label>
              <input type="radio" name="import_mode" value="results" {% if import_mode == 'results' %}checked{% endif %}>
              <span>🎯 Results (výsledky)</span>
            </label>
          </div>
          <div class="muted">
            Fixtures = nové zápasy bez skóre | Results = aktualizuje skóre existujících
          </div>
        </div>
        
        <div class="form-group">
          <label>Zápasy *</label>
          <div class="examples">
            <h3>💡 Podporované formáty:</h3>
            <div class="example-item">27. 2. 2026DuklaSlavia18:00</div>
            <div class="example-item">27. 2. 2026 Sparta - Slavia 18:00</div>
            <div class="example-item">27. 2. 20:00 Sparta vs Slavia</div>
            <div class="example-item">1. 3. SpartaOstrava20:00 (auto rok)</div>
            <div class="example-item">Sparta - Slavia 2:1</div>
          </div>
          <textarea name="raw_text" placeholder="Paste zde své zápasy..." required></textarea>
          <div class="muted">💡 Tip: Headers jako "24. kolo" se automaticky přeskočí</div>
        </div>
        
        <button type="submit" class="btn btn-primary">🔍 Parsovat & Preview</button>
      </form>
    </div>
    {% else %}
    <div class="card">
      <h1>🔍 Preview - zkontroluj a uprav</h1>
      <div class="subtitle">Naparsováno {{ parsed_matches|length }} zápasů</div>
      
      <form method="post" id="importForm">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <input type="hidden" name="action" value="import"/>
        <input type="hidden" name="round_id" value="{{ import_round_id }}"/>
        <input type="hidden" name="import_mode" value="{{ import_mode }}"/>
        <input type="hidden" name="matches_data" id="matchesData" value=""/>
        
        <table class="preview-table">
          <thead>
            <tr>
              <th style="width: 40px;">
                <input type="checkbox" id="selectAll" checked>
              </th>
              <th>Domácí</th>
              <th>Hosté</th>
              <th style="width: 80px;">Skóre D</th>
              <th style="width: 80px;">Skóre H</th>
              <th style="width: 200px;">Datum & Čas</th>
            </tr>
          </thead>
          <tbody>
            {% for match in parsed_matches %}
            <tr>
              <td>
                <input type="checkbox" class="match-select" checked>
              </td>
              <td>
                <input type="text" 
                       class="home-team" 
                       value="{{ match.home_team }}"
                       data-original="{{ match.home_team }}">
              </td>
              <td>
                <input type="text" 
                       class="away-team" 
                       value="{{ match.away_team }}"
                       data-original="{{ match.away_team }}">
              </td>
              <td>
                <input type="number" 
                       class="home-score" 
                       value="{{ match.home_score if match.home_score is not none else '' }}"
                       min="0"
                       placeholder="-">
              </td>
              <td>
                <input type="number" 
                       class="away-score" 
                       value="{{ match.away_score if match.away_score is not none else '' }}"
                       min="0"
                       placeholder="-">
              </td>
              <td>
                <input type="datetime-local" 
                       class="start-time" 
                       value="{{ match.start_time[:16] if match.start_time else '' }}">
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        
        <div style="margin-top: 24px; display: flex; gap: 12px;">
          <button type="submit" class="btn btn-success">✅ Importovat vybrané zápasy</button>
          <a href="{{ url_for('admin_smart_import') }}" class="btn btn-secondary">← Zpět</a>
        </div>
      </form>
    </div>
    {% endif %}
  </div>
  
  <script>
    // Select all checkbox
    document.getElementById('selectAll')?.addEventListener('change', function() {
      document.querySelectorAll('.match-select').forEach(cb => cb.checked = this.checked);
    });
    
    // Collect data before submit
    document.getElementById('importForm')?.addEventListener('submit', function(e) {
      const rows = document.querySelectorAll('.preview-table tbody tr');
      const matches = [];
      
      rows.forEach(row => {
        if (row.querySelector('.match-select').checked) {
          const homeTeam = row.querySelector('.home-team').value;
          const awayTeam = row.querySelector('.away-team').value;
          const homeScore = row.querySelector('.home-score').value;
          const awayScore = row.querySelector('.away-score').value;
          const startTime = row.querySelector('.start-time').value;
          
          matches.push({
            home_team: homeTeam,
            away_team: awayTeam,
            home_score: homeScore ? parseInt(homeScore) : null,
            away_score: awayScore ? parseInt(awayScore) : null,
            start_time: startTime || null
          });
        }
      });
      
      document.getElementById('matchesData').value = JSON.stringify(matches);
    });
  </script>
</body>
</html>
"""


    @app.route("/admin/rounds")
    @login_required
    def admin_rounds():
        admin_required()
        rounds = Round.query.order_by(Round.is_active.desc(), Round.id.desc()).all()
        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Soutěže</h2>
      <div class="muted">Tipy/extra uzávěrky jsou v UTC (pro jednoduchost). Pokud chceš, doplníme lokální čas.</div>
    </div>
    <a class="btn btn-primary" href="{{ url_for('admin_round_new') }}">Nová soutěž</a>
  </div>

  <hr class="sep">

  {% for rr in rounds %}
    <div class="card" style="background:rgba(255,255,255,.03); margin-bottom:10px;">
      <div class="row" style="justify-content:space-between;">
        <div>
          <div style="font-weight:900;">
            {% if rr.is_active %}★ {% endif %}
            {% if rr.is_archived %}📦 {% endif %}
            {{ rr.name }}
          </div>
          <div class="muted">Sport: {{ rr.sport.name }}</div>
          <div class="muted">Tipy: {{ rr.tips_close_time.strftime("%Y-%m-%d %H:%M") if rr.tips_close_time else "—" }} |
            Extra: {{ rr.extra_close_time.strftime("%Y-%m-%d %H:%M") if rr.extra_close_time else "—" }}</div>
        </div>
        <div class="row" style="gap: 8px; flex-wrap: wrap;">
          <a class="btn" href="{{ url_for('admin_round_edit', round_id=rr.id) }}">Edit</a>
          <a class="btn" href="{{ url_for('admin_round_toggle', round_id=rr.id) }}">
            {% if rr.is_active %}Deaktivovat{% else %}Aktivovat{% endif %}
          </a>
          <a class="btn" href="{{ url_for('admin_round_toggle_archive', round_id=rr.id) }}"
             style="{% if rr.is_archived %}background:rgba(51,209,122,.15); color:#33d17a; border:1px solid rgba(51,209,122,.3);{% else %}background:rgba(139,92,246,.15); color:#8b5cf6; border:1px solid rgba(139,92,246,.3);{% endif %}">
            {% if rr.is_archived %}📤 Odarchivovat{% else %}📦 Archivovat{% endif %}
          </a>
          <a class="btn" href="{{ url_for('admin_round_delete_confirm', round_id=rr.id) }}"
             style="background:rgba(255,77,109,0.2); color:#ff4d6d; border:1px solid rgba(255,77,109,0.4);">
            🗑️ Smazat
          </a>
        </div>
      </div>
    </div>
  {% endfor %}
</div>
""", rounds=rounds)

    @app.route("/admin/round/new", methods=["GET", "POST"])
    @login_required
    def admin_round_new():
        admin_required()
        sports = Sport.query.order_by(Sport.name.asc()).all()
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            sport_id = int(request.form.get("sport_id") or "0")
            tips_close = parse_naive_datetime(request.form.get("tips_close") or "")
            extra_close = parse_naive_datetime(request.form.get("extra_close") or "")

            if not name or not sport_id:
                flash("Vyplň název a sport.", "error")
                return redirect(url_for("admin_round_new"))

            rr = Round(name=name, sport_id=sport_id, tips_close_time=tips_close, extra_close_time=extra_close, is_active=True)
            db.session.add(rr)
            for other in Round.query.all():
                other.is_active = False
            rr.is_active = True
            db.session.commit()
            set_selected_round_id(rr.id)
            audit("round.create", "Round", rr.id, name=rr.name)
            flash("Soutěž vytvořena.", "ok")
            return redirect(url_for("admin_rounds"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Nová soutěž</h2>
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input name="name" placeholder="Název soutěže" required>
    <select name="sport_id" required>
      {% for sp in sports %}
        <option value="{{ sp.id }}">{{ sp.name }}</option>
      {% endfor %}
    </select>
    <div class="grid2">
      <div>
        <div class="muted" style="margin-bottom:6px;">Uzávěrka tipů (volitelné)</div>
        <input name="tips_close" type="datetime-local">
      </div>
      <div>
        <div class="muted" style="margin-bottom:6px;">Uzávěrka extra (volitelné)</div>
        <input name="extra_close" type="datetime-local">
      </div>
    </div>
    <button class="btn btn-primary" type="submit">Vytvořit</button>
    <a class="btn" href="{{ url_for('admin_rounds') }}">Zpět</a>
  </form>
</div>
""", sports=sports)

    @app.route("/admin/round/<int:round_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_round_edit(round_id: int):
        admin_required()
        rr = db.session.get(Round, round_id)
        if not rr:
            abort(404)

        sports = Sport.query.order_by(Sport.name.asc()).all()

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            sport_id = int(request.form.get("sport_id") or rr.sport_id)
            tips_close = parse_naive_datetime(request.form.get("tips_close") or "")
            extra_close = parse_naive_datetime(request.form.get("extra_close") or "")

            if not name:
                flash("Vyplň název.", "error")
                return redirect(url_for("admin_round_edit", round_id=rr.id))

            rr.name = name
            rr.sport_id = sport_id
            rr.tips_close_time = tips_close
            rr.extra_close_time = extra_close
            db.session.commit()
            audit("round.edit", "Round", rr.id, name=rr.name)
            flash("Soutěž upravena.", "ok")
            return redirect(url_for("admin_rounds"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Upravit soutěž</h2>
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div>
      <div class="muted" style="margin-bottom:6px;">Název soutěže</div>
      <input name="name" value="{{ rr.name }}" required>
    </div>
    <div>
      <div class="muted" style="margin-bottom:6px;">Sport</div>
      <select name="sport_id" required>
        {% for sp in sports %}
          <option value="{{ sp.id }}" {% if sp.id == rr.sport_id %}selected{% endif %}>{{ sp.name }}</option>
        {% endfor %}
      </select>
    </div>
    <div class="grid2">
      <div>
        <div class="muted" style="margin-bottom:6px;">Uzávěrka tipů (volitelné)</div>
        <input name="tips_close" type="datetime-local" value="{{ dt_tips }}">
      </div>
      <div>
        <div class="muted" style="margin-bottom:6px;">Uzávěrka extra (volitelné)</div>
        <input name="extra_close" type="datetime-local" value="{{ dt_extra }}">
      </div>
    </div>
    <button class="btn btn-primary" type="submit">Uložit</button>
    <a class="btn" href="{{ url_for('admin_rounds') }}">Zpět</a>
  </form>
</div>
""", rr=rr, sports=sports, dt_tips=dt_to_input_value(rr.tips_close_time), dt_extra=dt_to_input_value(rr.extra_close_time))

    @app.route("/admin/round/<int:round_id>/toggle")
    @login_required
    def admin_round_toggle(round_id: int):
        admin_required()
        r = db.session.get(Round, round_id)
        if not r:
            abort(404)
        if not r.is_active:
            for other in Round.query.all():
                other.is_active = False
            r.is_active = True
            set_selected_round_id(r.id)
        else:
            r.is_active = False
        db.session.commit()
        audit("round.toggle_active", "Round", r.id, is_active=r.is_active)
        return redirect(url_for("admin_rounds"))

    @app.route("/admin/round/<int:round_id>/toggle-archive")
    @login_required
    def admin_round_toggle_archive(round_id: int):
        admin_required()
        r = db.session.get(Round, round_id)
        if not r:
            abort(404)
        
        # Toggle archived flag
        r.is_archived = not r.is_archived
        
        # Pokud archivujeme, deaktivujeme
        if r.is_archived and r.is_active:
            r.is_active = False
        
        db.session.commit()
        audit("round.toggle_archive", "Round", r.id, is_archived=r.is_archived)
        
        msg = "Soutěž archivována." if r.is_archived else "Soutěž vrácena z archivu."
        flash(msg, "ok")
        return redirect(url_for("admin_rounds"))

    @app.route("/admin/round/<int:round_id>/delete/confirm")
    @login_required
    def admin_round_delete_confirm(round_id: int):
        admin_required()
        r = db.session.get(Round, round_id)
        if not r:
            abort(404)

        # Spočítat co se smaže
        matches_count = Match.query.filter_by(round_id=r.id).count()
        teams_count = Team.query.filter_by(round_id=r.id).count()
        tips_count = db.session.query(Tip).join(Match).filter(Match.round_id == r.id).count()
        extra_questions_count = ExtraQuestion.query.filter_by(round_id=r.id).count()
        extra_answers_count = db.session.query(ExtraAnswer).join(ExtraQuestion).filter(ExtraQuestion.round_id == r.id).count()

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 16px 0; color:#ff4d6d;">⚠️ Smazat soutěž?</h2>

  <div class="card" style="background:rgba(255,77,109,0.1); border:2px solid #ff4d6d; padding:20px; margin-bottom:20px;">
    <h3 style="margin:0 0 12px 0; color:#ff4d6d;">POZOR: Tato akce je NEVRATNÁ!</h3>
    <div style="font-size:16px; line-height:1.8;">
      Chystáš se smazat soutěž: <strong style="font-size:18px;">{{ round.name }}</strong>
    </div>
  </div>

  <div class="card" style="background:rgba(255,255,255,0.03); padding:20px; margin-bottom:20px;">
    <h3 style="margin:0 0 16px 0;">Co se trvale odstraní:</h3>
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:16px;">
      <div class="card" style="background:rgba(255,77,109,0.05); padding:16px; text-align:center;">
        <div style="font-size:32px; font-weight:900; color:#ff4d6d;">{{ matches_count }}</div>
        <div class="muted">Zápasů</div>
      </div>
      <div class="card" style="background:rgba(255,77,109,0.05); padding:16px; text-align:center;">
        <div style="font-size:32px; font-weight:900; color:#ff4d6d;">{{ tips_count }}</div>
        <div class="muted">Tipů</div>
      </div>
      <div class="card" style="background:rgba(255,77,109,0.05); padding:16px; text-align:center;">
        <div style="font-size:32px; font-weight:900; color:#ff4d6d;">{{ teams_count }}</div>
        <div class="muted">Týmů</div>
      </div>
      <div class="card" style="background:rgba(255,77,109,0.05); padding:16px; text-align:center;">
        <div style="font-size:32px; font-weight:900; color:#ff4d6d;">{{ extra_questions_count }}</div>
        <div class="muted">Extra otázek</div>
      </div>
      <div class="card" style="background:rgba(255,77,109,0.05); padding:16px; text-align:center;">
        <div style="font-size:32px; font-weight:900; color:#ff4d6d;">{{ extra_answers_count }}</div>
        <div class="muted">Extra odpovědí</div>
      </div>
    </div>
  </div>

  <div class="card" style="background:rgba(255,199,79,0.08); border:1px solid rgba(255,199,79,0.4); padding:20px; margin-bottom:20px;">
    <h3 style="margin:0 0 12px 0;">⚠️ Potvrzení smazání</h3>
    <div class="muted" style="margin-bottom:12px;">
      Pro potvrzení napiš přesný název soutěže:
    </div>
    <div style="font-weight:900; font-size:18px; margin-bottom:16px; padding:12px; background:rgba(0,0,0,0.3); border-radius:8px; text-align:center;">
      {{ round.name }}
    </div>

    <form method="post" action="{{ url_for('admin_round_delete', round_id=round.id) }}" onsubmit="return validateDelete()">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
      <input type="text" id="confirm_name" name="confirm_name"
             placeholder="Napiš název soutěže pro potvrzení"
             style="width:100%; margin-bottom:16px; padding:12px; font-size:16px;"
             autocomplete="off" required>

      <div style="display:flex; gap:12px;">
        <button type="submit" class="btn"
                style="flex:1; padding:14px; font-size:16px; font-weight:900; background:rgba(255,77,109,0.3); color:#ff4d6d; border:2px solid #ff4d6d;">
          🗑️ ANO, SMAZAT TRVALE
        </button>
        <a href="{{ url_for('admin_rounds') }}" class="btn btn-primary" style="flex:1; padding:14px; font-size:16px; font-weight:900; text-align:center;">
          ✖️ Zrušit
        </a>
      </div>
    </form>
  </div>
</div>

<script>
const expectedName = {{ round.name|tojson }};

function validateDelete() {
  const input = document.getElementById('confirm_name').value.trim();
  if (input !== expectedName) {
    alert('Název nesouhlasí! Zkontroluj překlepy.\n\nOčekáváno: ' + expectedName + '\nZadáno: ' + input);
    return false;
  }
  return confirm('POSLEDNÍ VAROVÁNÍ!\n\nOpravdu TRVALE smazat soutěž "' + expectedName + '" a všechna související data?\n\nTato akce JE NEVRATNÁ!');
}
</script>
""", round=r, matches_count=matches_count, tips_count=tips_count, teams_count=teams_count,
     extra_questions_count=extra_questions_count, extra_answers_count=extra_answers_count)

    @app.route("/admin/round/<int:round_id>/delete", methods=["POST"])
    @login_required
    def admin_round_delete(round_id: int):
        admin_required()
        r = db.session.get(Round, round_id)
        if not r:
            abort(404)

        # Ověřit potvrzovací text
        confirm_name = request.form.get('confirm_name', '').strip()
        if confirm_name != r.name:
            flash("Název nesouhlasí! Soutěž nebyla smazána.", "error")
            return redirect(url_for("admin_round_delete_confirm", round_id=round_id))

        round_name = r.name

        # Smazat všechny extra odpovědi
        extra_questions = ExtraQuestion.query.filter_by(round_id=r.id).all()
        for eq in extra_questions:
            ExtraAnswer.query.filter_by(question_id=eq.id).delete()
            db.session.delete(eq)

        # Smazat všechny tipy
        matches = Match.query.filter_by(round_id=r.id).all()
        for m in matches:
            Tip.query.filter_by(match_id=m.id).delete()
            db.session.delete(m)

        # Smazat všechny týmy
        teams = Team.query.filter_by(round_id=r.id).all()
        for t in teams:
            db.session.delete(t)

        # Smazat soutěž
        db.session.delete(r)
        db.session.commit()

        audit("round.delete", "Round", round_id, name=round_name)
        flash(f"✅ Soutěž '{round_name}' byla trvale smazána včetně všech zápasů, tipů a týmů.", "ok")

        # Pokud byla aktivní, aktivovat jinou
        if r.is_active:
            other = Round.query.filter_by(is_active=False).first()
            if other:
                other.is_active = True
                db.session.commit()
                set_selected_round_id(other.id)

        return redirect(url_for("admin_rounds"))

    # --- ADMIN TEAM NEW ---
    @app.route("/admin/team/new", methods=["GET", "POST"])
    @login_required
    def admin_team_new():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("admin_rounds"))

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Vyplň název týmu.", "error")
                return redirect(url_for("admin_team_new"))
            if Team.query.filter_by(round_id=r.id, name=name, is_deleted=False).first():
                flash("Tým už existuje.", "error")
                return redirect(url_for("admin_team_new"))
            t = Team(round_id=r.id, name=name)
            db.session.add(t)
            db.session.commit()
            audit("team.create", "Team", t.id, round_id=r.id, name=t.name)
            flash("Tým přidán.", "ok")
            return redirect(url_for("teams"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Přidat tým</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input name="name" placeholder="Název týmu" required>
    <button class="btn btn-primary" type="submit">Vytvořit</button>
    <a class="btn" href="{{ url_for('teams') }}">Zpět</a>
  </form>
</div>
""", r=r)


    # --- ADMIN TEAM ALIASES ---
    @app.route("/admin/team-aliases", methods=["GET", "POST"])
    @login_required
    def admin_team_aliases():
        """
        Správa aliasů týmů (pro Smart Import a další importéry)
        - alias (krátký název / zkratka) -> canonical_name (plný název v DB)
        """
        admin_required()

        # Vybranou soutěž ber z query paramu, fallback na selected round
        rid = request.values.get("round_id")
        if rid is None or str(rid).strip() == "":
            rid = ensure_selected_round()
        try:
            rid = int(rid) if rid else None
        except:
            rid = None

        rounds = Round.query.order_by(Round.name.asc()).all()
        r = db.session.get(Round, rid) if rid else None

        if request.method == "POST":
            action = request.form.get("action", "").strip()

            # Switch selected round
            if action == "select_round":
                rid2 = request.form.get("round_id")
                try:
                    rid2 = int(rid2) if rid2 else None
                except:
                    rid2 = None
                if rid2:
                    set_selected_round_id(rid2)
                return redirect(url_for("admin_team_aliases", round_id=rid2))

            if not r:
                flash("Nejdřív vyber soutěž/kolo.", "error")
                return redirect(url_for("admin_team_aliases"))

            if action in ("add", "edit"):
                alias = (request.form.get("alias") or "").strip()
                canonical = (request.form.get("canonical_name") or "").strip()

                if not alias or not canonical:
                    flash("Vyplň alias i cílový (kanonický) název.", "error")
                    return redirect(url_for("admin_team_aliases", round_id=r.id))

                # normalizace (bez lower na bool apod.)
                alias_n = normalize_team_name(alias, round_id=r.id) if alias else ""
                # alias necháváme tak jak ho user zadal (trim), ale odstraníme nadbytečné mezery
                alias_n = re.sub(r"\s+", " ", alias).strip()
                canonical_n = re.sub(r"\s+", " ", canonical).strip()

                if action == "add":
                    exists = TeamAlias.query.filter(
                        TeamAlias.round_id == r.id,
                        db.func.lower(TeamAlias.alias) == alias_n.lower()
                    ).first()
                    if exists:
                        flash("Alias už existuje (v této soutěži).", "error")
                        return redirect(url_for("admin_team_aliases", round_id=r.id))
                    ta = TeamAlias(round_id=r.id, alias=alias_n, canonical_name=canonical_n)
                    db.session.add(ta)
                    db.session.commit()
                    audit("team_alias.create", "TeamAlias", ta.id, round_id=r.id, alias=ta.alias, canonical=ta.canonical_name)
                    flash("Alias uložen.", "ok")
                    return redirect(url_for("admin_team_aliases", round_id=r.id))

                # edit
                alias_id = request.form.get("alias_id")
                try:
                    alias_id = int(alias_id)
                except:
                    alias_id = None
                ta = db.session.get(TeamAlias, alias_id) if alias_id else None
                if not ta or ta.round_id != r.id:
                    flash("Alias nenalezen.", "error")
                    return redirect(url_for("admin_team_aliases", round_id=r.id))

                ta.alias = alias_n
                ta.canonical_name = canonical_n
                db.session.commit()
                audit("team_alias.edit", "TeamAlias", ta.id, round_id=r.id, alias=ta.alias, canonical=ta.canonical_name)
                flash("Alias upraven.", "ok")
                return redirect(url_for("admin_team_aliases", round_id=r.id))

            if action == "delete":
                if not r:
                    flash("Nejdřív vyber soutěž/kolo.", "error")
                    return redirect(url_for("admin_team_aliases"))

                alias_id = request.form.get("alias_id")
                try:
                    alias_id = int(alias_id)
                except:
                    alias_id = None
                ta = db.session.get(TeamAlias, alias_id) if alias_id else None
                if not ta or ta.round_id != r.id:
                    flash("Alias nenalezen.", "error")
                    return redirect(url_for("admin_team_aliases", round_id=r.id))

                db.session.delete(ta)
                db.session.commit()
                audit("team_alias.delete", "TeamAlias", alias_id, round_id=r.id)
                flash("Alias smazán.", "ok")
                return redirect(url_for("admin_team_aliases", round_id=r.id))

            flash("Neznámá akce.", "error")
            return redirect(url_for("admin_team_aliases", round_id=(r.id if r else None)))

        # GET
        aliases = []
        if r:
            aliases = TeamAlias.query.filter_by(round_id=r.id).order_by(TeamAlias.alias.asc()).all()

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">🔁 Aliasy týmů</h2>
  <div class="muted">Alias slouží pro importéry (Smart Import, API import), aby se krátké názvy mapovaly na plné názvy ve tvé DB.</div>
</div>

<div class="card">
  <form method="post" class="row" style="gap:10px; align-items:flex-end;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="action" value="select_round"/>
    <div style="flex:1; min-width:240px;">
      <div class="muted" style="margin-bottom:6px;">Soutěž / kolo</div>
      <select name="round_id" onchange="this.form.submit()">
        <option value="">— vyber —</option>
        {% for rr in rounds %}
          <option value="{{ rr.id }}" {% if r and rr.id==r.id %}selected{% endif %}>{{ rr.name }}</option>
        {% endfor %}
      </select>
    </div>
    {% if r %}
      <a class="btn" href="{{ url_for('teams') }}">➡️ Týmy</a>
      <a class="btn" href="{{ url_for('admin_smart_import') }}">🤖 Smart Import</a>
    {% endif %}
  </form>
</div>

{% if r %}
<div class="card">
  <h3 style="margin:0 0 10px 0;">➕ Přidat alias</h3>
  <form method="post" class="row" style="gap:10px; align-items:flex-end;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="action" value="add"/>
    <input type="hidden" name="round_id" value="{{ r.id }}"/>
    <div style="flex:1; min-width:220px;">
      <div class="muted" style="margin-bottom:6px;">Alias (co importér najde)</div>
      <input name="alias" placeholder="např. Sparta / Hradec Kr. / Ml. Boleslav" required>
    </div>
    <div style="flex:1; min-width:240px;">
      <div class="muted" style="margin-bottom:6px;">Kanonický název (jak chceš mít v DB)</div>
      <input name="canonical_name" placeholder="např. AC Sparta Praha" required>
    </div>
    <button class="btn btn-primary" type="submit">Uložit</button>
  </form>
</div>

<div class="card">
  <h3 style="margin:0 0 10px 0;">📋 Seznam aliasů</h3>
  {% if not aliases %}
    <div class="muted">Zatím žádné aliasy.</div>
  {% else %}
  <div style="overflow:auto;">
    <table class="table">
      <thead>
        <tr>
          <th>Alias</th>
          <th>Kanonický název</th>
          <th style="width:240px;">Akce</th>
        </tr>
      </thead>
      <tbody>
        {% for a in aliases %}
          <tr>
            <td><code>{{ a.alias }}</code></td>
            <td>{{ a.canonical_name }}</td>
            <td>
              <details>
                <summary class="btn" style="display:inline-block;">Upravit</summary>
                <div style="margin-top:10px;">
                  <form method="post" class="row" style="gap:8px; align-items:flex-end;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                    <input type="hidden" name="action" value="edit"/>
                    <input type="hidden" name="round_id" value="{{ r.id }}"/>
                    <input type="hidden" name="alias_id" value="{{ a.id }}"/>
                    <div style="flex:1; min-width:180px;">
                      <div class="muted" style="margin-bottom:6px;">Alias</div>
                      <input name="alias" value="{{ a.alias }}" required>
                    </div>
                    <div style="flex:1; min-width:220px;">
                      <div class="muted" style="margin-bottom:6px;">Kanonický název</div>
                      <input name="canonical_name" value="{{ a.canonical_name }}" required>
                    </div>
                    <button class="btn btn-primary" type="submit">Uložit</button>
                  </form>

                  <form method="post" style="margin-top:8px;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                    <input type="hidden" name="action" value="delete"/>
                    <input type="hidden" name="round_id" value="{{ r.id }}"/>
                    <input type="hidden" name="alias_id" value="{{ a.id }}"/>
                    <button class="btn btn-danger" type="submit" onclick="return confirm('Smazat alias {{ a.alias }}?')">Smazat</button>
                  </form>
                </div>
              </details>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</div>
{% else %}
<div class="card"><div class="muted">Vyber soutěž/kolo pro správu aliasů.</div></div>
{% endif %}
""", rounds=rounds, r=r, aliases=aliases)


    # --- ADMIN MATCH NEW/EDIT ---
    @app.route("/admin/match/new", methods=["GET", "POST"])
    @login_required
    def admin_match_new():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("admin_rounds"))
        teams_q = Team.query.filter_by(round_id=r.id, is_deleted=False).order_by(Team.name.asc()).all()
        if not teams_q:
            flash("Nejdřív přidej týmy pro tuhle soutěž.", "error")
            return redirect(url_for("admin_team_new"))

        if request.method == "POST":
            home_id = int(request.form.get("home_team_id") or "0")
            away_id = int(request.form.get("away_team_id") or "0")
            start = parse_naive_datetime(request.form.get("start_time") or "")
            if not home_id or not away_id or home_id == away_id:
                flash("Vyber domácí a hosty (různé týmy).", "error")
                return redirect(url_for("admin_match_new"))

            ht = db.session.get(Team, home_id)
            at = db.session.get(Team, away_id)
            if not ht or not at or ht.round_id != r.id or at.round_id != r.id:
                flash("Týmy nepatří do vybrané soutěže.", "error")
                return redirect(url_for("admin_match_new"))

            m = Match(round_id=r.id, home_team_id=ht.id, away_team_id=at.id, start_time=start)
            db.session.add(m)
            db.session.commit()
            audit("match.create", "Match", m.id, round_id=r.id)
            flash("Zápas vytvořen.", "ok")
            return redirect(url_for("matches"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Přidat zápas</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <select name="home_team_id" required>
      <option value="">Domácí tým…</option>
      {% for t in teams %}<option value="{{ t.id }}">{{ t.name }}</option>{% endfor %}
    </select>
    <select name="away_team_id" required>
      <option value="">Hosté…</option>
      {% for t in teams %}<option value="{{ t.id }}">{{ t.name }}</option>{% endfor %}
    </select>
    <div>
      <div class="muted" style="margin-bottom:6px;">Začátek (volitelné)</div>
      <input name="start_time" type="datetime-local">
    </div>
    <button class="btn btn-primary" type="submit">Vytvořit</button>
    <a class="btn" href="{{ url_for('matches') }}">Zpět</a>
  </form>
</div>
""", r=r, teams=teams_q)

    @app.route("/admin/match/<int:match_id>/quick-score", methods=["POST"])
    @login_required
    def admin_quick_score(match_id: int):
        admin_required()
        m = db.session.get(Match, match_id)
        if not m:
            abort(404)

        home_score_val = request.form.get("home_score", "").strip()
        away_score_val = request.form.get("away_score", "").strip()

        # Prázdné = None (smazat výsledek)
        m.home_score = int(home_score_val) if home_score_val else None
        m.away_score = int(away_score_val) if away_score_val else None

        db.session.commit()
        audit("match.quick_score", "Match", m.id, home=m.home_score, away=m.away_score)
        flash(f"Výsledek uložen: {m.home_team.name} {m.home_score or '-'}:{m.away_score or '-'} {m.away_team.name}", "ok")
        return redirect(url_for("leaderboard"))

    @app.route("/admin/match/<int:match_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_match_edit(match_id: int):
        admin_required()
        m = db.session.get(Match, match_id)
        if not m:
            abort(404)
        r = db.session.get(Round, m.round_id)
        teams_q = Team.query.filter_by(round_id=r.id, is_deleted=False).order_by(Team.name.asc()).all()

        def parse_int_or_none(x):
            x = (x or "").strip()
            if x == "":
                return None
            return int(x)

        if request.method == "POST":
            home_id = int(request.form.get("home_team_id") or m.home_team_id)
            away_id = int(request.form.get("away_team_id") or m.away_team_id)
            start = parse_naive_datetime(request.form.get("start_time") or "")
            hs = parse_int_or_none(request.form.get("home_score"))
            aas = parse_int_or_none(request.form.get("away_score"))
            if home_id == away_id:
                flash("Domácí a hosté musí být různé týmy.", "error")
                return redirect(url_for("admin_match_edit", match_id=m.id))

            ht = db.session.get(Team, home_id)
            at = db.session.get(Team, away_id)
            if not ht or not at or ht.round_id != r.id or at.round_id != r.id:
                flash("Týmy nepatří do téhle soutěže.", "error")
                return redirect(url_for("admin_match_edit", match_id=m.id))

            m.home_team_id = ht.id
            m.away_team_id = at.id
            m.start_time = start
            m.home_score = hs
            m.away_score = aas
            db.session.commit()
            audit("match.edit", "Match", m.id)
            flash("Zápas upraven.", "ok")
            return redirect(url_for("matches"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Edit zápasu</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <select name="home_team_id" required>
      {% for t in teams %}<option value="{{ t.id }}" {% if t.id == m.home_team_id %}selected{% endif %}>{{ t.name }}</option>{% endfor %}
    </select>
    <select name="away_team_id" required>
      {% for t in teams %}<option value="{{ t.id }}" {% if t.id == m.away_team_id %}selected{% endif %}>{{ t.name }}</option>{% endfor %}
    </select>
    <div>
      <div class="muted" style="margin-bottom:6px;">Začátek</div>
      <input name="start_time" type="datetime-local" value="{{ dt }}">
    </div>
    <div class="row">
      <input name="home_score" type="number" min="0" style="width:140px;" value="{{ m.home_score if m.home_score is not none else '' }}" placeholder="Domácí skóre">
      <div class="muted">:</div>
      <input name="away_score" type="number" min="0" style="width:140px;" value="{{ m.away_score if m.away_score is not none else '' }}" placeholder="Hosté skóre">
    </div>
    <button class="btn btn-primary" type="submit">Uložit</button>
    <a class="btn" href="{{ url_for('matches') }}">Zpět</a>
  </form>
</div>
""", r=r, m=m, teams=teams_q, dt=dt_to_input_value(m.start_time))

    @app.route("/admin/match/<int:match_id>/delete")
    @login_required
    def admin_match_delete(match_id: int):
        admin_required()
        m = db.session.get(Match, match_id)
        if not m:
            abort(404)

        # Smazat všechny tipy na tento zápas
        Tip.query.filter_by(match_id=m.id).delete()

        # Soft delete zápasu
        m.is_deleted = True
        db.session.commit()
        audit("match.delete", "Match", m.id)
        flash(f"Zápas smazán (včetně všech tipů).", "ok")
        return redirect(url_for("matches"))

    # --- ADMIN EXTRA NEW ---
    @app.route("/admin/extra/new", methods=["GET", "POST"])
    @login_required
    def admin_extra_new():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("admin_rounds"))
        if request.method == "POST":
            q = (request.form.get("question") or "").strip()
            deadline_str = (request.form.get("deadline") or "").strip()
            
            if not q:
                flash("Vyplň otázku.", "error")
                return redirect(url_for("admin_extra_new"))
            
            # Parse deadline pokud je vyplněno
            deadline = None
            if deadline_str:
                try:
                    # Očekáváme formát: YYYY-MM-DD HH:MM nebo YYYY-MM-DDTHH:MM
                    deadline = datetime.strptime(deadline_str.replace('T', ' '), '%Y-%m-%d %H:%M')
                except ValueError:
                    flash("Nesprávný formát data. Použij formát: YYYY-MM-DD HH:MM", "error")
                    return redirect(url_for("admin_extra_new"))
            
            eq = ExtraQuestion(round_id=r.id, question=q, deadline=deadline)
            db.session.add(eq)
            db.session.commit()
            audit("extra.question.create", "ExtraQuestion", eq.id)
            flash("Extra otázka přidána.", "ok")
            return redirect(url_for("extras"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Přidat extra otázku</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
  <hr class="sep">
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="form-group">
      <label>Text otázky</label>
      <input name="question" placeholder="Text otázky" required>
    </div>
    <div class="form-group">
      <label>Uzávěrka odpovědí (volitelné)</label>
      <input type="datetime-local" name="deadline" placeholder="YYYY-MM-DD HH:MM">
      <small class="muted">Po tomto datu budou odpovědi viditelné v žebříčku. Pokud nevyplníte, odpovědi budou viditelné ihned.</small>
    </div>
    <button class="btn btn-primary" type="submit">Vytvořit</button>
    <a class="btn" href="{{ url_for('extras') }}">Zpět</a>
  </form>
</div>
""", r=r)

    # --- ADMIN EXTRA MANAGE (správa odpovědí) ---
    @app.route("/admin/extra/manage")
    @login_required
    def admin_extra_manage():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            return redirect(url_for("admin_rounds"))
        
        # Načti všechny Extra otázky
        questions = ExtraQuestion.query.filter_by(
            round_id=r.id, 
            is_deleted=False
        ).order_by(ExtraQuestion.id.asc()).all()
        
        # Načti všechny uživatele
        users = User.query.order_by(User.username.asc()).all()
        
        # Načti všechny odpovědi pro tuto soutěž
        all_answers = ExtraAnswer.query.join(ExtraQuestion).filter(
            ExtraQuestion.round_id == r.id,
            ExtraQuestion.is_deleted == False
        ).all()
        
        # Vytvoř mapu odpovědí: {user_id: {question_id: answer}}
        answer_map = {}
        for ans in all_answers:
            if ans.user_id not in answer_map:
                answer_map[ans.user_id] = {}
            answer_map[ans.user_id][ans.question_id] = ans
        
        return render_page(r"""
<style>
  .extra-manage-table{ width:100%; border-collapse:collapse; }
  .extra-manage-table th, .extra-manage-table td{ 
    border:1px solid var(--line); 
    padding:8px; 
    text-align:left; 
  }
  .extra-manage-table th{ background:rgba(255,255,255,.05); font-weight:800; }
  .extra-manage-table td{ font-size:13px; }
  .answer-cell{ position:relative; }
  .answer-text{ display:block; margin-bottom:4px; }
  .answer-actions{ display:flex; gap:4px; }
  .answer-status{ 
    display:inline-block; 
    padding:2px 6px; 
    border-radius:4px; 
    font-size:11px; 
    font-weight:800;
  }
  .status-correct{ background:#28a745; color:white; }
  .status-wrong{ background:#dc3545; color:white; }
  .status-none{ background:#6c757d; color:white; }
  .q-actions { display:flex; gap:4px; margin-top:6px; justify-content:center; }
</style>

<div class="card">
  <div class="row" style="justify-content:space-between;">
    <div>
      <h2 style="margin:0;">Správa Extra odpovědí</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <div class="row" style="gap:8px;">
      <a class="btn" href="{{ url_for('admin_extra_new') }}">➕ Přidat otázku</a>
      <a class="btn" href="{{ url_for('extras') }}">Zpět</a>
    </div>
  </div>
  
  <hr class="sep">
  
  {% if questions|length == 0 %}
    <div class="muted">Zatím nejsou žádné extra otázky.</div>
  {% else %}
    <div style="overflow:auto;">
      <table class="extra-manage-table">
        <thead>
          <tr>
            <th style="min-width:120px;">Uživatel</th>
            {% for q in questions %}
              <th style="min-width:200px; text-align:center;">
                <div>{{ q.question }}</div>
                {% if q.deadline %}
                  <div><small class="muted">Uzávěrka: {{ q.deadline.strftime('%d.%m. %H:%M') }}</small></div>
                {% endif %}
                <div class="q-actions">
                  <a href="{{ url_for('admin_extra_edit_question', question_id=q.id) }}"
                     class="btn" style="font-size:11px; padding:3px 8px;">✏️ Edit</a>
                  <a href="{{ url_for('admin_extra_delete_question', question_id=q.id) }}"
                     class="btn" style="font-size:11px; padding:3px 8px; background:rgba(255,77,109,.2); color:#ff4d6d; border:1px solid rgba(255,77,109,.4);"
                     onclick="return confirm('Smazat otázku „{{ q.question }}" a VŠECHNY odpovědi na ni?')">🗑️</a>
                </div>
              </th>
            {% endfor %}
          </tr>
        </thead>
        <tbody>
          {% for u in users %}
            <tr>
              <td><b>{{ u.display_name }}</b><br><small class="muted">{{ u.email }}</small></td>
              {% for q in questions %}
                {% set ans = answer_map.get(u.id, {}).get(q.id) %}
                <td class="answer-cell">
                  {% if ans %}
                    <div class="answer-text">
                      <span class="answer-status {% if ans.is_correct %}status-correct{% else %}status-wrong{% endif %}">
                        {% if ans.is_correct %}✓ Správně{% else %}✗ Špatně{% endif %}
                      </span>
                      <br>
                      <span style="margin-top:4px; display:block;">{{ ans.answer_text }}</span>
                    </div>
                    <div class="answer-actions">
                      <a href="{{ url_for('admin_extra_edit_answer', question_id=q.id, user_id=u.id) }}" 
                         class="btn btn-sm" style="font-size:11px; padding:4px 8px;">Editovat</a>
                      <a href="{{ url_for('admin_extra_delete_answer', answer_id=ans.id) }}" 
                         class="btn btn-sm" style="font-size:11px; padding:4px 8px; background:#dc3545;"
                         onclick="return confirm('Opravdu smazat odpověď?')">Smazat</a>
                    </div>
                  {% else %}
                    <span class="answer-status status-none">Bez odpovědi</span>
                    <div style="margin-top:4px;">
                      <a href="{{ url_for('admin_extra_edit_answer', question_id=q.id, user_id=u.id) }}" 
                         class="btn btn-sm btn-primary" style="font-size:11px; padding:4px 8px;">Přidat</a>
                    </div>
                  {% endif %}
                </td>
              {% endfor %}
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  {% endif %}
</div>
""", r=r, questions=questions, users=users, answer_map=answer_map)

    # --- ADMIN EXTRA EDIT QUESTION (editace otázky) ---
    @app.route("/admin/extra/question/<int:question_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_extra_edit_question(question_id: int):
        admin_required()
        q = db.session.get(ExtraQuestion, question_id)
        if not q or q.is_deleted:
            abort(404)

        if request.method == "POST":
            text = (request.form.get("question") or "").strip()
            deadline_str = (request.form.get("deadline") or "").strip()

            if not text:
                flash("Otázka nesmí být prázdná.", "error")
                return redirect(url_for("admin_extra_edit_question", question_id=question_id))

            deadline = None
            if deadline_str:
                try:
                    deadline = datetime.strptime(deadline_str.replace("T", " ")[:16], "%Y-%m-%d %H:%M")
                except ValueError:
                    flash("Nesprávný formát data.", "error")
                    return redirect(url_for("admin_extra_edit_question", question_id=question_id))

            q.question = text
            q.deadline = deadline
            db.session.commit()
            audit("admin.extra.question.edit", "ExtraQuestion", q.id)
            flash("Otázka upravena.", "ok")
            return redirect(url_for("admin_extra_manage"))

        # Formát deadlinu pro input
        deadline_val = q.deadline.strftime("%Y-%m-%dT%H:%M") if q.deadline else ""

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">✏️ Editovat extra otázku</h2>
  <div class="muted">Soutěž: <b>{{ q.round.name }}</b></div>
  <hr class="sep">
  <form method="post" style="display:flex; flex-direction:column; gap:14px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="form-group">
      <label>Text otázky</label>
      <input name="question" value="{{ q.question }}" required autofocus>
    </div>
    <div class="form-group">
      <label>Uzávěrka odpovědí (volitelné)</label>
      <input type="datetime-local" name="deadline" value="{{ deadline_val }}">
      <small class="muted">Po tomto datu budou odpovědi viditelné v žebříčku.</small>
    </div>
    <div class="row" style="gap:10px;">
      <button class="btn btn-primary" type="submit">💾 Uložit</button>
      <a class="btn" href="{{ url_for('admin_extra_manage') }}">Zrušit</a>
    </div>
  </form>
</div>
""", q=q, deadline_val=deadline_val)

    # --- ADMIN EXTRA DELETE QUESTION (smazání otázky + odpovědí) ---
    @app.route("/admin/extra/question/<int:question_id>/delete")
    @login_required
    def admin_extra_delete_question(question_id: int):
        admin_required()
        q = db.session.get(ExtraQuestion, question_id)
        if not q or q.is_deleted:
            abort(404)

        # Soft-delete otázky
        q.is_deleted = True
        # Smaž všechny odpovědi (hard delete, nemají is_deleted)
        ExtraAnswer.query.filter_by(question_id=q.id).delete()
        db.session.commit()
        audit("admin.extra.question.delete", "ExtraQuestion", q.id)
        flash("Otazka smazana vcetne vsech odpovedi.", "ok")
        return redirect(url_for("admin_extra_manage"))

    # --- ADMIN EXTRA EDIT ANSWER (editace/přidání odpovědi) ---
    @app.route("/admin/extra/answer/<int:question_id>/<int:user_id>", methods=["GET", "POST"])
    @login_required
    def admin_extra_edit_answer(question_id: int, user_id: int):
        admin_required()
        
        q = db.session.get(ExtraQuestion, question_id)
        if not q:
            abort(404)
        
        u = db.session.get(User, user_id)
        if not u:
            abort(404)
        
        # Načti existující odpověď (pokud existuje)
        ans = ExtraAnswer.query.filter_by(question_id=question_id, user_id=user_id).first()
        
        if request.method == "POST":
            answer_text = (request.form.get("answer_text") or "").strip()
            is_correct = request.form.get("is_correct") == "1"
            
            if not answer_text:
                flash("Vyplň odpověď.", "error")
                return redirect(url_for("admin_extra_edit_answer", question_id=question_id, user_id=user_id))
            
            if ans:
                # Editace existující
                ans.answer_text = answer_text
                ans.is_correct = is_correct
                audit("admin.extra.answer.edit", "ExtraAnswer", ans.id)
                flash("Odpověď upravena.", "ok")
            else:
                # Vytvoření nové
                ans = ExtraAnswer(
                    question_id=question_id,
                    user_id=user_id,
                    answer_text=answer_text,
                    is_correct=is_correct
                )
                db.session.add(ans)
                audit("admin.extra.answer.create", "ExtraAnswer", None, question_id=question_id, user_id=user_id)
                flash("Odpověď přidána.", "ok")
            
            db.session.commit()
            return redirect(url_for("admin_extra_manage"))
        
        # GET - zobraz formulář
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">{% if ans %}Editovat{% else %}Přidat{% endif %} odpověď</h2>
  <div class="muted">
    <b>Uživatel:</b> {{ u.display_name }} ({{ u.email }})<br>
    <b>Otázka:</b> {{ q.question }}
  </div>
  <hr class="sep">
  
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="form-group">
      <label>Odpověď</label>
      <input name="answer_text" value="{{ ans.answer_text if ans else '' }}" required autofocus>
    </div>
    
    <div class="form-group">
      <label>Hodnocení</label>
      <div class="row" style="gap:10px;">
        <label style="display:flex; align-items:center; gap:6px;">
          <input type="radio" name="is_correct" value="1" 
                 {% if ans and ans.is_correct %}checked{% endif %} 
                 {% if not ans %}checked{% endif %}>
          <span style="color:#28a745; font-weight:800;">✓ Správně</span>
        </label>
        <label style="display:flex; align-items:center; gap:6px;">
          <input type="radio" name="is_correct" value="0" 
                 {% if ans and not ans.is_correct %}checked{% endif %}>
          <span style="color:#dc3545; font-weight:800;">✗ Špatně</span>
        </label>
      </div>
    </div>
    
    <div class="form-actions">
      <button type="submit" class="btn btn-primary">Uložit</button>
      <a href="{{ url_for('admin_extra_manage') }}" class="btn">Zrušit</a>
    </div>
  </form>
</div>
""", q=q, u=u, ans=ans)

    # --- ADMIN EXTRA DELETE ANSWER (smazání odpovědi) ---
    @app.route("/admin/extra/answer/<int:answer_id>/delete")
    @login_required
    def admin_extra_delete_answer(answer_id: int):
        admin_required()
        
        ans = db.session.get(ExtraAnswer, answer_id)
        if not ans:
            abort(404)
        
        db.session.delete(ans)
        db.session.commit()
        audit("admin.extra.answer.delete", "ExtraAnswer", answer_id)
        flash("Odpověď smazána.", "ok")
        return redirect(url_for("admin_extra_manage"))

    # --- ADMIN DASHBOARD ---
    @app.route("/admin/dashboard")
    @login_required
    def admin_dashboard():
        admin_required()
        
        # Stats
        total_users = User.query.count()
        total_rounds = Round.query.count()
        active_rounds = Round.query.filter_by(is_active=True).count()
        total_matches = Match.query.filter_by(is_deleted=False).count()
        total_tips = Tip.query.count()
        
        # Recent users
        recent_users = User.query.order_by(User.id.desc()).limit(5).all()
        
        # Active round stats
        active_round = Round.query.filter_by(is_active=True).first()
        active_round_stats = None
        if active_round:
            matches_total = Match.query.filter_by(round_id=active_round.id, is_deleted=False).count()
            matches_with_results = Match.query.filter(
                Match.round_id == active_round.id,
                Match.is_deleted == False,
                Match.home_score != None,
                Match.away_score != None
            ).count()
            tips_total = Tip.query.join(Match).filter(Match.round_id == active_round.id).count()
            
            active_round_stats = {
                'round': active_round,
                'matches_total': matches_total,
                'matches_with_results': matches_with_results,
                'tips_total': tips_total,
                'completion': int((matches_with_results / matches_total * 100) if matches_total > 0 else 0)
            }
        
        # Pending tasks
        matches_no_results = Match.query.filter(
            Match.is_deleted == False,
            db.or_(Match.home_score == None, Match.away_score == None)
        ).count()
        
        return render_page(r"""
<style>
  .admin-dashboard {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  
  .stat-card {
    background: rgba(255,255,255,.03);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 20px;
    transition: all 0.3s ease;
  }
  
  .stat-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0,0,0,.2);
  }
  
  .stat-value {
    font-size: 36px;
    font-weight: 900;
    margin-bottom: 8px;
    line-height: 1;
  }
  
  .progress-bar-container {
    background: rgba(255,255,255,.05);
    border-radius: 8px;
    height: 8px;
    margin-top: 12px;
    overflow: hidden;
  }
  
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--ok));
    border-radius: 8px;
    transition: width 0.5s ease;
  }
  
  /* Admin cards */
  .admin-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
  }

  .admin-card {
    background: rgba(110,168,254,0.08);
    border: 1px solid rgba(110,168,254,0.2);
    border-radius: 16px;
    padding: 16px;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
    color: #e9eefc;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .admin-card:hover {
    background: rgba(110,168,254,0.15);
    border-color: rgba(110,168,254,0.3);
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
  }

  .admin-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .admin-card-icon {
    font-size: 24px;
  }

  .admin-card-title {
    font-size: 15px;
    font-weight: 700;
  }

  .admin-card-desc {
    font-size: 12px;
    color: #94a3b8;
    line-height: 1.4;
  }
</style>

<div class="card">
  <h1 style="margin: 0 0 8px 0;">👨‍💼 Admin Dashboard</h1>
  <div class="muted">Přehled a rychlé akce</div>
</div>

<div class="admin-dashboard">
  <div class="stat-card">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: var(--muted);">👥 UŽIVATELÉ</h3>
    <div class="stat-value" style="color: var(--accent);">{{ total_users }}</div>
    <div class="muted" style="font-size: 13px;">Celkem registrovaných</div>
  </div>
  
  <div class="stat-card">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: var(--muted);">🏆 SOUTĚŽE</h3>
    <div class="stat-value" style="color: var(--ok);">{{ total_rounds }}</div>
    <div class="muted" style="font-size: 13px;">{{ active_rounds }} aktivních</div>
  </div>
  
  <div class="stat-card">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: var(--muted);">⚽ ZÁPASY</h3>
    <div class="stat-value" style="color: var(--warn);">{{ total_matches }}</div>
    <div class="muted" style="font-size: 13px;">V databázi</div>
  </div>
  
  <div class="stat-card">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: var(--muted);">🎯 TIPY</h3>
    <div class="stat-value" style="color: var(--danger);">{{ total_tips }}</div>
    <div class="muted" style="font-size: 13px;">Celkem odeslaných</div>
  </div>
</div>

{% if active_round_stats %}
<div class="card">
  <h3 style="margin: 0 0 16px 0;">⭐ Aktivní soutěž: {{ active_round_stats.round.name }}</h3>
  
  <div class="row" style="justify-content: space-between; margin-bottom: 16px;">
    <div>
      <div class="muted" style="font-size: 13px;">Zápasy s výsledky</div>
      <div style="font-size: 24px; font-weight: 900;">
        {{ active_round_stats.matches_with_results }} / {{ active_round_stats.matches_total }}
      </div>
    </div>
    
    <div>
      <div class="muted" style="font-size: 13px;">Odesláno tipů</div>
      <div style="font-size: 24px; font-weight: 900;">
        {{ active_round_stats.tips_total }}
      </div>
    </div>
    
    <div>
      <div class="muted" style="font-size: 13px;">Dokončení</div>
      <div style="font-size: 24px; font-weight: 900; color: var(--ok);">
        {{ active_round_stats.completion }}%
      </div>
    </div>
  </div>
  
  <div class="progress-bar-container">
    <div class="progress-bar-fill" style="width: {{ active_round_stats.completion }}%;"></div>
  </div>
</div>
{% endif %}

{% if matches_no_results > 0 %}
<div class="card" style="background: rgba(249,199,79,.08); border-color: rgba(249,199,79,.3);">
  <h3 style="margin: 0 0 12px 0; color: #f9c74f;">⚠️ Čeká na vyřízení</h3>
  <div>
    <strong>{{ matches_no_results }}</strong> zápasů bez výsledků
    <a href="{{ url_for('admin_bulk_edit') }}" class="btn btn-sm" style="margin-left: 12px;">Zadat výsledky</a>
  </div>
</div>
{% endif %}

<div class="card">
  <h3 style="margin: 0 0 16px 0;">👥 Noví uživatelé</h3>
  {% for user in recent_users %}
    <div style="padding: 8px 0; border-bottom: 1px solid var(--line);">
      <strong>{{ user.display_name }}</strong>
      <span class="muted" style="font-size: 12px; margin-left: 8px;">@{{ user.username }}</span>
      {% if user.is_admin %}<span class="tag pill-ok" style="margin-left: 8px;">Admin</span>{% endif %}
    </div>
  {% endfor %}
</div>

<div class="card">
  <h3 style="margin: 0 0 16px 0;">🔧 Admin nástroje</h3>
  <div class="admin-cards">
    
    <a href="{{ url_for('admin_bulk_edit') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">✏️</div>
        <div class="admin-card-title">Bulk Edit</div>
      </div>
      <div class="admin-card-desc">Zadávání výsledků</div>
    </a>
    
    <a href="{{ url_for('admin_import') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">📥</div>
        <div class="admin-card-title">Import</div>
      </div>
      <div class="admin-card-desc">Importovat data</div>
    </a>
    
    <a href="{{ url_for('admin_export_hub') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">📤</div>
        <div class="admin-card-title">Export</div>
      </div>
      <div class="admin-card-desc">Exportovat data</div>
    </a>
    
    <a href="{{ url_for('admin_undo') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">⏪</div>
        <div class="admin-card-title">Undo</div>
      </div>
      <div class="admin-card-desc">Vrátit změny</div>
    </a>
    
    <a href="{{ url_for('admin_rounds') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🎮</div>
        <div class="admin-card-title">Soutěže</div>
      </div>
      <div class="admin-card-desc">Správa soutěží</div>
    </a>
    
    <a href="{{ url_for('admin_users') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">👥</div>
        <div class="admin-card-title">Uživatelé</div>
      </div>
      <div class="admin-card-desc">Správa userů</div>
    </a>
    
    <a href="{{ url_for('admin_api_sources') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🔌</div>
        <div class="admin-card-title">API Zdroje</div>
      </div>
      <div class="admin-card-desc">Fotbal & hokej API</div>
    </a>
    
    <a href="{{ url_for('admin_smart_import') }}" class="admin-card">
      <div class="admin-card-header">
        <div class="admin-card-icon">🤖</div>
        <div class="admin-card-title">Smart Import</div>
      </div>
      <div class="admin-card-desc">AI parsování zápasů</div>
    </a>
    
  </div>
</div>

""", total_users=total_users, total_rounds=total_rounds, active_rounds=active_rounds,
     total_matches=total_matches, total_tips=total_tips, recent_users=recent_users,
     active_round_stats=active_round_stats, matches_no_results=matches_no_results)

    # --- ADMIN BULK EDIT ---
    @app.route("/admin/bulk-edit")
    @login_required
    def admin_bulk_edit():
        admin_required()
        
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        
        if not r:
            flash("Vyber soutěž pro bulk editaci.", "error")
            return redirect(url_for("admin_rounds"))
        
        # Načti všechny zápasy
        matches = Match.query.filter_by(
            round_id=r.id,
            is_deleted=False
        ).order_by(Match.start_time.asc(), Match.id.asc()).all()
        
        # Stats
        total = len(matches)
        with_results = sum(1 for m in matches if m.home_score is not None and m.away_score is not None)
        without_results = total - with_results
        
        return render_page(r"""
<style>
  .bulk-table {
    width: 100%;
    border-collapse: collapse;
  }
  
  .bulk-table th,
  .bulk-table td {
    padding: 12px 8px;
    text-align: left;
    border-bottom: 1px solid var(--line);
  }
  
  .bulk-table th {
    background: rgba(255,255,255,.03);
    font-weight: 900;
    position: sticky;
    top: 0;
  }
  
  .bulk-table input[type="number"] {
    width: 60px;
    text-align: center;
  }
  
  .match-row:hover {
    background: rgba(255,255,255,.03);
  }
  
  .match-row.has-result {
    background: rgba(51,209,122,.05);
  }
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: center;">
    <div>
      <h2 style="margin: 0 0 8px 0;">✏️ Bulk Edit - Hromadné úpravy</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <div class="row" style="gap: 8px;">
      <div class="tag pill-ok">✅ {{ with_results }}</div>
      <div class="tag pill-warn">⏳ {{ without_results }}</div>
    </div>
  </div>
</div>

<form method="post" action="{{ url_for('admin_bulk_edit_save') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <input type="hidden" name="round_id" value="{{ r.id }}">
  
  <div class="card">
    <div class="row" style="justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h3 style="margin: 0;">📋 Zápasy ({{ total }})</h3>
      <button type="submit" class="btn btn-primary">💾 Uložit všechny změny</button>
    </div>
    
    <div class="bulk-table-wrapper" style="overflow-x: auto;">
      <table class="bulk-table">
        <thead>
          <tr>
            <th style="width: 40px;">#</th>
            <th>Domácí</th>
            <th style="width: 60px; text-align: center;">Skóre</th>
            <th>Hosté</th>
            <th style="width: 60px; text-align: center;">Skóre</th>
          </tr>
        </thead>
        <tbody>
          {% for m in matches %}
            <tr class="match-row {% if m.home_score is not none and m.away_score is not none %}has-result{% endif %}">
              <td>{{ loop.index }}</td>
              <td><strong>{{ m.home_team.name if m.home_team else '?' }}</strong></td>
              <td style="text-align: center;">
                <input type="number" 
                       name="match_{{ m.id }}_home" 
                       value="{{ m.home_score if m.home_score is not none else '' }}"
                       min="0" max="20">
              </td>
              <td><strong>{{ m.away_team.name if m.away_team else '?' }}</strong></td>
              <td style="text-align: center;">
                <input type="number" 
                       name="match_{{ m.id }}_away" 
                       value="{{ m.away_score if m.away_score is not none else '' }}"
                       min="0" max="20">
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    
    <div style="margin-top: 16px; text-align: right;">
      <button type="submit" class="btn btn-primary">💾 Uložit všechny změny</button>
    </div>
  </div>
</form>

""", r=r, matches=matches, total=total, with_results=with_results, without_results=without_results)

    @app.route("/admin/bulk-edit/save", methods=["POST"])
    @login_required
    def admin_bulk_edit_save():
        admin_required()
        
        round_id = int(request.form.get("round_id"))
        r = db.session.get(Round, round_id)
        
        if not r:
            flash("Soutěž nenalezena.", "error")
            return redirect(url_for("admin_bulk_edit"))
        
        matches = Match.query.filter_by(round_id=r.id, is_deleted=False).all()
        
        updated_count = 0
        for match in matches:
            match_id = match.id
            
            home_score_str = request.form.get(f"match_{match_id}_home")
            away_score_str = request.form.get(f"match_{match_id}_away")
            
            old_home = match.home_score
            old_away = match.away_score
            
            if home_score_str and away_score_str:
                new_home = int(home_score_str)
                new_away = int(away_score_str)
                
                if old_home != new_home or old_away != new_away:
                    # Vytvoř undo point PŘED změnou
                    home_team_name = match.home_team.name if match.home_team else "?"
                    away_team_name = match.away_team.name if match.away_team else "?"
                    old_score_str = f"{old_home}:{old_away}" if old_home is not None and old_away is not None else "—"
                    new_score_str = f"{new_home}:{new_away}"
                    
                    create_undo_point(
                        action_type='update_score',
                        entity_type='Match',
                        entity_id=match.id,
                        before_state={
                            'home_score': old_home,
                            'away_score': old_away
                        },
                        description=f"{home_team_name} {old_score_str} → {new_score_str} {away_team_name}"
                    )
                    
                    # Teď proveď změnu
                    match.home_score = new_home
                    match.away_score = new_away
                    updated_count += 1
            elif home_score_str == '' and away_score_str == '':
                if match.home_score is not None or match.away_score is not None:
                    # Vytvoř undo point PŘED smazáním
                    home_team_name = match.home_team.name if match.home_team else "?"
                    away_team_name = match.away_team.name if match.away_team else "?"
                    old_score_str = f"{old_home}:{old_away}" if old_home is not None and old_away is not None else "—"
                    
                    create_undo_point(
                        action_type='clear_score',
                        entity_type='Match',
                        entity_id=match.id,
                        before_state={
                            'home_score': old_home,
                            'away_score': old_away
                        },
                        description=f"{home_team_name} {old_score_str} → smazáno {away_team_name}"
                    )
                    
                    match.home_score = None
                    match.away_score = None
                    updated_count += 1
        
        db.session.commit()
        audit("bulk_edit.save", "Match", None, details=f"Updated {updated_count} matches")
        
        # Pošli push notifikace o zadaných výsledcích
        if updated_count > 0:
            try:
                send_results_notification(round_id)
            except Exception as e:
                print(f"Error sending push notifications: {e}")
        
        flash(f"✅ Aktualizováno {updated_count} zápasů!", "ok")
        return redirect(url_for("admin_bulk_edit"))

    # --- ADMIN BULK IMPORT (CSV) WITH PREVIEW ---
    @app.route("/admin/bulk-import/template")
    @login_required
    def admin_bulk_import_template():
        """Stáhne CSV šablonu pro bulk import"""
        admin_required()
        
        try:
            from io import StringIO
            
            # Create CSV template
            output = StringIO()
            output.write("Domácí,Hosté,Datum,Čas\n")
            output.write("Sparta Praha,Slavia Praha,2024-03-15,18:00\n")
            output.write("Plzeň,Brno,2024-03-16,16:30\n")
            output.write("Baník,Bohemians,2024-03-17,15:00\n")
            
            # Create response
            from flask import Response
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers['Content-Disposition'] = 'attachment; filename=bulk_import_sablona.csv'
            return response
            
        except Exception as e:
            flash(f"Chyba: {str(e)}", "error")
            return redirect(url_for("admin_bulk_import"))
    
    @app.route("/admin/bulk-import", methods=["GET", "POST"])
    @login_required
    def admin_bulk_import():
        """Hromadný import týmů a zápasů z CSV - STEP 1: Upload"""
        admin_required()
        
        if request.method == "POST":
            import_type = request.form.get("import_type")
            round_id = request.form.get("round_id")
            
            if not round_id:
                flash("Vyber soutěž!", "error")
                return redirect(url_for("admin_bulk_import"))
            
            round_id = int(round_id)
            r = db.session.get(Round, round_id)
            
            if not r:
                flash("Soutěž nenalezena!", "error")
                return redirect(url_for("admin_bulk_import"))
            
            if 'csv_file' not in request.files:
                flash("Žádný soubor nevybrán!", "error")
                return redirect(url_for("admin_bulk_import"))
            
            file = request.files['csv_file']
            
            if file.filename == '':
                flash("Žádný soubor nevybrán!", "error")
                return redirect(url_for("admin_bulk_import"))
            
            if not file.filename.endswith('.csv'):
                flash("Musí být CSV soubor!", "error")
                return redirect(url_for("admin_bulk_import"))
            
            try:
                # Read CSV and store in temporary file (session cookies are limited to 4KB)
                csv_content = file.stream.read().decode("utf-8")
                
                # Create temporary file
                temp_fd, temp_path = tempfile.mkstemp(suffix='.csv', prefix='bulk_import_')
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    f.write(csv_content)
                
                # Store only the file path in session (small!)
                session['bulk_import_file'] = temp_path
                session['bulk_import_type'] = import_type
                session['bulk_import_round_id'] = round_id
                
                # Redirect to preview
                return redirect(url_for("admin_bulk_import_preview"))
                
            except Exception as e:
                flash(f"❌ Chyba při čtení CSV: {str(e)}", "error")
                return redirect(url_for("admin_bulk_import"))
        
        # GET request - show form
        rounds = Round.query.order_by(Round.id.desc()).all()
        
        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between; align-items:flex-start;">
    <div>
      <h2>📥 Hromadný import z CSV</h2>
      <div class="muted">Import týmů a zápasů z CSV souborů s preview</div>
    </div>
    <a href="{{ url_for('admin_bulk_import_template') }}" class="btn" style="background:#6ea8fe; color:white;">
      📥 Stáhnout šablonu CSV
    </a>
  </div>
</div>

<div class="card">
  <h3>📋 Import týmů</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="import_type" value="teams">
    
    <div style="margin-bottom: 16px;">
      <label class="muted">Soutěž *</label>
      <select name="round_id" required>
        <option value="">-- Vyber soutěž --</option>
        {% for r in rounds %}
          <option value="{{ r.id }}">{{ r.name }}</option>
        {% endfor %}
      </select>
    </div>
    
    <div style="margin-bottom: 16px;">
      <label class="muted">CSV soubor *</label>
      <input type="file" name="csv_file" accept=".csv" required>
      <div class="muted" style="font-size: 13px; margin-top: 4px;">
        Formát: <code>name</code> (1 sloupec)
      </div>
    </div>
    
    <button type="submit" class="btn btn-primary">👁️ Zobrazit preview</button>
  </form>
</div>

<div class="card">
  <h3>⚽ Import zápasů</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="import_type" value="matches">
    
    <div style="margin-bottom: 16px;">
      <label class="muted">Soutěž *</label>
      <select name="round_id" required>
        <option value="">-- Vyber soutěž --</option>
        {% for r in rounds %}
          <option value="{{ r.id }}">{{ r.name }}</option>
        {% endfor %}
      </select>
    </div>
    
    <div style="margin-bottom: 16px;">
      <label class="muted">CSV soubor *</label>
      <input type="file" name="csv_file" accept=".csv" required>
      <div class="muted" style="font-size: 13px; margin-top: 4px;">
        Formát: <code>home_team,away_team,start_time,home_score,away_score</code><br>
        Start time: <code>YYYY-MM-DD HH:MM</code> nebo <code>YYYY-MM-DD</code><br>
        Scores: Nechej prázdné pokud zápas ještě nebyl
      </div>
    </div>
    
    <button type="submit" class="btn btn-primary">👁️ Zobrazit preview</button>
  </form>
</div>

<div class="card">
  <h3>👤 Import tipů</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="import_type" value="tips">
    
    <div style="margin-bottom: 16px;">
      <label class="muted">Soutěž *</label>
      <select name="round_id" required>
        <option value="">-- Vyber soutěž --</option>
        {% for r in rounds %}
          <option value="{{ r.id }}">{{ r.name }}</option>
        {% endfor %}
      </select>
    </div>
    
    <div style="margin-bottom: 16px;">
      <label class="muted">CSV soubor *</label>
      <input type="file" name="csv_file" accept=".csv" required>
      <div class="muted" style="font-size: 13px; margin-top: 4px;">
        Formát: <code>user_email,home_team,away_team,home_score,away_score</code><br>
        Příklad: <code>mejlacz@gmail.com,Česko,Kanada,3,2</code><br>
        <strong>Možnost přepsání:</strong> Existující tipy budou označeny jako "Update"
      </div>
    </div>
    
    <button type="submit" class="btn btn-primary">👁️ Zobrazit preview</button>
  </form>
</div>

<div class="card" style="background: rgba(255,255,255,.02);">
  <h3>💡 Jak na to</h3>
  <ol style="margin: 0; padding-left: 20px;">
    <li>Vyber CSV soubor → zobrazí se <strong>preview</strong></li>
    <li>Zkontroluj data v tabulce</li>
    <li>Klikni "Potvrdit" nebo "Zrušit"</li>
    <li>Pořadí: <strong>týmy</strong> → <strong>zápasy</strong> → <strong>tipy</strong></li>
    <li><strong>Update tipů:</strong> Existující tipy lze přepsat (status "Update")</li>
  </ol>
</div>
""", rounds=rounds)
    
    @app.route("/admin/bulk-import/preview")
    @login_required
    def admin_bulk_import_preview():
        """STEP 2: Preview dat před importem"""
        admin_required()
        
        # Get data from session
        temp_file = session.get('bulk_import_file')
        import_type = session.get('bulk_import_type')
        round_id = session.get('bulk_import_round_id')
        
        if not temp_file or not import_type or not round_id:
            flash("Session expirovala, nahraj CSV znovu", "error")
            return redirect(url_for("admin_bulk_import"))
        
        # Check if temp file still exists
        if not os.path.exists(temp_file):
            flash("CSV soubor expiroval, nahraj znovu", "error")
            session.pop('bulk_import_file', None)
            return redirect(url_for("admin_bulk_import"))
        
        r = db.session.get(Round, round_id)
        if not r:
            flash("Soutěž nenalezena", "error")
            return redirect(url_for("admin_bulk_import"))
        
        try:
            # Read CSV from temp file
            with open(temp_file, 'r', encoding='utf-8') as f:
                csv_content = f.read()
            
            stream = io.StringIO(csv_content, newline=None)
            csv_reader = csv.DictReader(stream)
            rows = list(csv_reader)
            
            preview_data = []
            new_count = 0
            overwrite_count = 0
            error_count = 0
            errors = []
            
            if import_type == 'teams':
                for idx, row in enumerate(rows):
                    team_name = row.get('name', '').strip()
                    
                    if not team_name:
                        error_count += 1
                        errors.append("Prázdný název týmu")
                        continue
                    
                    existing = Team.query.filter_by(round_id=round_id, name=team_name).first()
                    
                    status = "overwrite" if existing else "new"
                    if status == "new":
                        new_count += 1
                    else:
                        overwrite_count += 1
                    
                    preview_data.append({
                        'index': idx,
                        'name': team_name,
                        'status': status,
                        'selected': status == 'new',  # Auto-select only new
                        'existing_id': existing.id if existing else None
                    })
            
            elif import_type == 'matches':
                for idx, row in enumerate(rows):
                    home_name = row.get('home_team', '').strip()
                    away_name = row.get('away_team', '').strip()
                    start_time_str = row.get('start_time', '').strip()
                    home_score_str = row.get('home_score', '').strip()
                    away_score_str = row.get('away_score', '').strip()
                    
                    if not home_name or not away_name:
                        error_count += 1
                        errors.append(f"Chybí název týmu")
                        preview_data.append({
                            'index': idx,
                            'home_team': home_name or '?',
                            'away_team': away_name or '?',
                            'start_time': start_time_str,
                            'home_score': home_score_str,
                            'away_score': away_score_str,
                            'status': 'error',
                            'error': 'Chybí název týmu',
                            'selected': False
                        })
                        continue
                    
                    home_team = Team.query.filter_by(round_id=round_id, name=home_name).first()
                    away_team = Team.query.filter_by(round_id=round_id, name=away_name).first()
                    
                    if not home_team or not away_team:
                        error_count += 1
                        missing = []
                        if not home_team:
                            missing.append(home_name)
                        if not away_team:
                            missing.append(away_name)
                        error_msg = f"Tým nenalezen: {', '.join(missing)}"
                        errors.append(error_msg)
                        preview_data.append({
                            'index': idx,
                            'home_team': home_name,
                            'away_team': away_name,
                            'start_time': start_time_str,
                            'home_score': home_score_str,
                            'away_score': away_score_str,
                            'status': 'error',
                            'error': error_msg,
                            'selected': False
                        })
                        continue
                    
                    # Check existing
                    existing = Match.query.filter_by(
                        round_id=round_id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()
                    
                    status = "new"
                    if existing:
                        # Zápas již existuje - můžeš ho přepsat
                        status = "overwrite"
                        overwrite_count += 1  # Count as overwrite
                    else:
                        new_count += 1
                    
                    preview_data.append({
                        'index': idx,
                        'home_team': home_name,
                        'away_team': away_name,
                        'start_time': start_time_str,
                        'home_score': home_score_str if home_score_str else '—',
                        'away_score': away_score_str if away_score_str else '—',
                        'status': status,
                        'selected': status == 'new',  # Auto-select only NEW (not overwrite by default)
                        'existing_id': existing.id if existing else None  # Store ID for update
                    })
            
            elif import_type == 'tips':
                for idx, row in enumerate(rows):
                    user_email = row.get('user_email', '').strip()
                    home_name = row.get('home_team', '').strip()
                    away_name = row.get('away_team', '').strip()
                    home_score_str = row.get('home_score', '').strip()
                    away_score_str = row.get('away_score', '').strip()
                    
                    # Validate basic data
                    if not user_email or not home_name or not away_name or not home_score_str or not away_score_str:
                        error_count += 1
                        errors.append(f"Neúplná data na řádku {idx+1}")
                        preview_data.append({
                            'index': idx,
                            'user_email': user_email or '?',
                            'home_team': home_name or '?',
                            'away_team': away_name or '?',
                            'tip': f"{home_score_str or '?'}:{away_score_str or '?'}",
                            'current_tip': '—',
                            'status': 'error',
                            'error': 'Neúplná data',
                            'selected': False
                        })
                        continue
                    
                    # Find user
                    user = User.query.filter_by(email=user_email).first()
                    if not user:
                        error_count += 1
                        errors.append(f"Uživatel nenalezen: {user_email}")
                        preview_data.append({
                            'index': idx,
                            'user_email': user_email,
                            'home_team': home_name,
                            'away_team': away_name,
                            'tip': f"{home_score_str}:{away_score_str}",
                            'current_tip': '—',
                            'status': 'error',
                            'error': 'Uživatel nenalezen',
                            'selected': False
                        })
                        continue
                    
                    # Find teams
                    home_team = Team.query.filter_by(round_id=round_id, name=home_name).first()
                    away_team = Team.query.filter_by(round_id=round_id, name=away_name).first()
                    
                    if not home_team or not away_team:
                        error_count += 1
                        missing = []
                        if not home_team:
                            missing.append(home_name)
                        if not away_team:
                            missing.append(away_name)
                        error_msg = f"Tým nenalezen: {', '.join(missing)}"
                        errors.append(error_msg)
                        preview_data.append({
                            'index': idx,
                            'user_email': user_email,
                            'home_team': home_name,
                            'away_team': away_name,
                            'tip': f"{home_score_str}:{away_score_str}",
                            'current_tip': '—',
                            'status': 'error',
                            'error': error_msg,
                            'selected': False
                        })
                        continue
                    
                    # Find match
                    match = Match.query.filter_by(
                        round_id=round_id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()
                    
                    if not match:
                        error_count += 1
                        errors.append(f"Zápas nenalezen: {home_name} vs {away_name}")
                        preview_data.append({
                            'index': idx,
                            'user_email': user_email,
                            'home_team': home_name,
                            'away_team': away_name,
                            'tip': f"{home_score_str}:{away_score_str}",
                            'current_tip': '—',
                            'status': 'error',
                            'error': 'Zápas nenalezen',
                            'selected': False
                        })
                        continue
                    
                    # Parse tip scores
                    try:
                        new_home = int(home_score_str)
                        new_away = int(away_score_str)
                    except:
                        error_count += 1
                        errors.append(f"Neplatné skóre: {home_score_str}:{away_score_str}")
                        preview_data.append({
                            'index': idx,
                            'user_email': user_email,
                            'home_team': home_name,
                            'away_team': away_name,
                            'tip': f"{home_score_str}:{away_score_str}",
                            'current_tip': '—',
                            'status': 'error',
                            'error': 'Neplatné skóre',
                            'selected': False
                        })
                        continue
                    
                    # Find existing tip
                    existing_tip = Tip.query.filter_by(
                        user_id=user.id,
                        match_id=match.id
                    ).first()
                    
                    # Determine status
                    status = "new"
                    current_tip = "—"
                    
                    if existing_tip:
                        current_tip = f"{existing_tip.home_score}:{existing_tip.away_score}"
                        if existing_tip.home_score != new_home or existing_tip.away_score != new_away:
                            status = "update"
                        else:
                            status = "skip"
                    
                    if status == "new":
                        new_count += 1
                    elif status == "skip":
                        skip_count += 1
                    elif status == "update":
                        update_count += 1
                    
                    preview_data.append({
                        'index': idx,
                        'user_email': user_email,
                        'user_name': user.username,
                        'home_team': home_name,
                        'away_team': away_name,
                        'tip': f"{new_home}:{new_away}",
                        'current_tip': current_tip,
                        'status': status,
                        'selected': status in ['new', 'update']  # Auto-select new and updates
                    })
            
            # Render preview
            if import_type == 'teams':
                table_html = """
<table style="width: 100%; border-collapse: collapse;">
  <tr style="border-bottom: 2px solid var(--line);">
    <th style="padding: 12px 8px; text-align: center; width: 50px;">
      <input type="checkbox" id="select-all" checked>
    </th>
    <th style="padding: 12px 8px; text-align: left;">Název týmu</th>
    <th style="padding: 12px 8px; text-align: center; width: 120px;">Status</th>
  </tr>
  {% for item in preview_data %}
  <tr style="border-bottom: 1px solid var(--line);">
    <td style="padding: 10px 8px; text-align: center;">
      <input type="checkbox" name="selected_rows" value="{{ item.index }}" {% if item.selected %}checked{% endif %} class="row-checkbox">
    </td>
    <td style="padding: 10px 8px;">{{ item.name }}</td>
    <td style="padding: 10px 8px; text-align: center;">
      {% if item.status == 'new' %}
        <span class="tag" style="background: rgba(51,209,122,.15); color: #33d17a;">Nový</span>
      {% elif item.status == 'overwrite' %}
        <span class="tag" style="background: rgba(99,179,237,.15); color: #63b3ed;">Přepsat</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
"""
            elif import_type == 'matches':
                table_html = """
<table style="width: 100%; border-collapse: collapse; font-size: 14px;">
  <tr style="border-bottom: 2px solid var(--line);">
    <th style="padding: 10px 8px; text-align: center; width: 50px;">
      <input type="checkbox" id="select-all" checked>
    </th>
    <th style="padding: 10px 8px; text-align: left;">Domácí</th>
    <th style="padding: 10px 8px; text-align: left;">Hosté</th>
    <th style="padding: 10px 8px; text-align: center; width: 100px;">Skóre</th>
    <th style="padding: 10px 8px; text-align: center; width: 120px;">Status</th>
  </tr>
  {% for item in preview_data %}
  <tr style="border-bottom: 1px solid var(--line);">
    <td style="padding: 8px; text-align: center;">
      <input type="checkbox" name="selected_rows" value="{{ item.index }}" {% if item.selected %}checked{% endif %} class="row-checkbox">
    </td>
    <td style="padding: 8px;">{{ item.home_team }}</td>
    <td style="padding: 8px;">{{ item.away_team }}</td>
    <td style="padding: 8px; text-align: center;">
      {% if item.home_score != '—' and item.away_score != '—' %}
        {{ item.home_score }}:{{ item.away_score }}
      {% else %}
        <span class="muted">—</span>
      {% endif %}
    </td>
    <td style="padding: 8px; text-align: center;">
      {% if item.status == 'new' %}
        <span class="tag" style="background: rgba(51,209,122,.15); color: #33d17a;">Nový</span>
      {% elif item.status == 'skip' %}
        <span class="tag" style="background: rgba(255,255,255,.05); color: var(--muted);">Přeskočit</span>
      {% elif item.status == 'overwrite' %}
        <span class="tag" style="background: rgba(99,179,237,.15); color: #63b3ed;">Přepsat</span>
      {% elif item.status == 'update' %}
        <span class="tag" style="background: rgba(249,199,79,.15); color: #f9c74f;">Update</span>
      {% elif item.status == 'error' %}
        <span class="tag" style="background: rgba(255,77,109,.15); color: #ff4d6d;">Chyba</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
"""
            else:  # tips
                table_html = """
<table style="width: 100%; border-collapse: collapse; font-size: 14px;">
  <tr style="border-bottom: 2px solid var(--line);">
    <th style="padding: 10px 8px; text-align: center; width: 50px;">
      <input type="checkbox" id="select-all" checked>
    </th>
    <th style="padding: 10px 8px; text-align: left;">Uživatel</th>
    <th style="padding: 10px 8px; text-align: left;">Domácí</th>
    <th style="padding: 10px 8px; text-align: left;">Hosté</th>
    <th style="padding: 10px 8px; text-align: center; width: 80px;">Nový tip</th>
    <th style="padding: 10px 8px; text-align: center; width: 80px;">Současný</th>
    <th style="padding: 10px 8px; text-align: center; width: 100px;">Status</th>
  </tr>
  {% for item in preview_data %}
  <tr style="border-bottom: 1px solid var(--line);">
    <td style="padding: 8px; text-align: center;">
      <input type="checkbox" name="selected_rows" value="{{ item.index }}" {% if item.selected %}checked{% endif %} class="row-checkbox">
    </td>
    <td style="padding: 8px;">
      {% if item.user_name %}
        <strong>{{ item.user_name }}</strong><br>
        <span class="muted" style="font-size: 11px;">{{ item.user_email }}</span>
      {% else %}
        {{ item.user_email }}
      {% endif %}
    </td>
    <td style="padding: 8px;">{{ item.home_team }}</td>
    <td style="padding: 8px;">{{ item.away_team }}</td>
    <td style="padding: 8px; text-align: center;">
      <strong>{{ item.tip }}</strong>
    </td>
    <td style="padding: 8px; text-align: center;">
      {% if item.current_tip != '—' %}
        {{ item.current_tip }}
      {% else %}
        <span class="muted">—</span>
      {% endif %}
    </td>
    <td style="padding: 8px; text-align: center;">
      {% if item.status == 'new' %}
        <span class="tag" style="background: rgba(51,209,122,.15); color: #33d17a;">Nový</span>
      {% elif item.status == 'skip' %}
        <span class="tag" style="background: rgba(255,255,255,.05); color: var(--muted);">Stejný</span>
      {% elif item.status == 'update' %}
        <span class="tag" style="background: rgba(249,199,79,.15); color: #f9c74f;">Přepsat</span>
      {% elif item.status == 'error' %}
        <span class="tag" style="background: rgba(255,77,109,.15); color: #ff4d6d;">Chyba</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
"""
            
            return render_page(r"""
<div class="card">
  <h2>👁️ Preview importu</h2>
  <div class="muted">Zkontroluj data před potvrzením</div>
</div>

<div class="card">
  <div class="row" style="gap: 32px;">
    <div>
      <div class="muted">Celkem</div>
      <div style="font-size: 28px; font-weight: 900;">{{ total }}</div>
    </div>
    <div>
      <div class="muted">Nové</div>
      <div style="font-size: 28px; font-weight: 900; color: #33d17a;">{{ new_count }}</div>
    </div>
    {% if overwrite_count > 0 %}
    <div>
      <div class="muted">Přepsat</div>
      <div style="font-size: 28px; font-weight: 900; color: #63b3ed;">{{ overwrite_count }}</div>
    </div>
    {% endif %}
    {% if error_count > 0 %}
    <div>
      <div class="muted">Chyby</div>
      <div style="font-size: 28px; font-weight: 900; color: #ff4d6d;">{{ error_count }}</div>
    </div>
    {% endif %}
  </div>
</div>

{% if errors|length > 0 %}
<div class="card" style="background: rgba(255,77,109,.08);">
  <h3>⚠️ Chyby ({{ errors|length }})</h3>
  {% for error in errors[:10] %}
    <div class="muted" style="font-size: 13px; margin-bottom: 4px;">• {{ error }}</div>
  {% endfor %}
  {% if errors|length > 10 %}
    <div class="muted" style="font-size: 13px; margin-top: 8px;">... a {{ errors|length - 10 }} dalších</div>
  {% endif %}
</div>
{% endif %}

<div class="card">
  <h3>📊 Data ({{ preview_data|length }})</h3>
  
  <div style="margin-bottom: 12px; display: flex; gap: 12px; flex-wrap: wrap;">
    <button type="button" onclick="selectAll()" class="btn" style="font-size: 13px; padding: 6px 12px;">
      ✅ Vybrat vše
    </button>
    <button type="button" onclick="deselectAll()" class="btn" style="font-size: 13px; padding: 6px 12px;">
      ❌ Zrušit vše
    </button>
    <button type="button" onclick="selectNew()" class="btn" style="font-size: 13px; padding: 6px 12px;">
      🟢 Jen nové
    </button>
    <button type="button" onclick="selectOverwrite()" class="btn" style="font-size: 13px; padding: 6px 12px;">
      🔵 Přepsat existující
    </button>
    <div style="flex: 1; text-align: right; line-height: 32px;">
      <span class="muted" style="font-size: 13px;">
        Vybráno: <strong id="selected-count">{{ new_count }}</strong> / {{ preview_data|length }}
      </span>
    </div>
  </div>
  
  <div style="overflow-x: auto; margin-top: 12px;">
    """ + table_html + """
  </div>
</div>

<script>
function updateCount() {
  const checked = document.querySelectorAll('.row-checkbox:checked').length;
  document.getElementById('selected-count').textContent = checked;
  document.getElementById('confirm-count').textContent = checked;
}

function selectAll() {
  document.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = true);
  document.getElementById('select-all').checked = true;
  updateCount();
}

function deselectAll() {
  document.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = false);
  document.getElementById('select-all').checked = false;
  updateCount();
}

function selectNew() {
  deselectAll();
  document.querySelectorAll('tr').forEach(row => {
    const tag = row.querySelector('.tag');
    const checkbox = row.querySelector('.row-checkbox');
    if (tag && tag.textContent.trim() === 'Nový' && checkbox) {
      checkbox.checked = true;
    }
  });
  updateCount();
}

function selectOverwrite() {
  deselectAll();
  document.querySelectorAll('tr').forEach(row => {
    const tag = row.querySelector('.tag');
    const checkbox = row.querySelector('.row-checkbox');
    if (tag && tag.textContent.trim() === 'Přepsat' && checkbox) {
      checkbox.checked = true;
    }
  });
  updateCount();
}

function selectUpdates() {
  deselectAll();
  document.querySelectorAll('tr').forEach(row => {
    const tag = row.querySelector('.tag');
    const checkbox = row.querySelector('.row-checkbox');
    if (tag && tag.textContent.trim() === 'Update' && checkbox) {
      checkbox.checked = true;
    }
  });
  updateCount();
}

// Select all checkbox handler
document.getElementById('select-all').addEventListener('change', function() {
  if (this.checked) {
    selectAll();
  } else {
    deselectAll();
  }
});

// Individual checkbox handler
document.querySelectorAll('.row-checkbox').forEach(cb => {
  cb.addEventListener('change', updateCount);
});

// Initial count
updateCount();
</script>

<form method="post" action="{{ url_for('admin_bulk_import_confirm') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <div class="card">
    <div class="row" style="gap: 12px;">
      <button type="submit" name="action" value="confirm" class="btn btn-primary" style="flex: 1;">
        ✅ Potvrdit import (<span id="confirm-count">{{ new_count + update_count }}</span>)
      </button>
      <a href="{{ url_for('admin_bulk_import') }}" class="btn" style="flex: 1; text-align: center; line-height: 40px;">
        ❌ Zrušit
      </a>
    </div>
  </div>
</form>
""", 
            preview_data=preview_data,
            total=len(preview_data),
            new_count=new_count,
            overwrite_count=overwrite_count,
            error_count=error_count,
            errors=errors,
            import_type=import_type,
            round_name=r.name
        )
        
        except Exception as e:
            flash(f"❌ Chyba při preview: {str(e)}", "error")
            import traceback
            traceback.print_exc()
            return redirect(url_for("admin_bulk_import"))
    
    @app.route("/admin/bulk-import/confirm", methods=["POST"])
    @login_required
    def admin_bulk_import_confirm():
        """STEP 3: Potvrzení a provedení importu"""
        admin_required()
        
        action = request.form.get("action")
        
        # Get temp file path
        temp_file = session.get('bulk_import_file')
        
        if action != "confirm":
            flash("Import zrušen", "ok")
            # Cleanup temp file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            session.pop('bulk_import_file', None)
            session.pop('bulk_import_type', None)
            session.pop('bulk_import_round_id', None)
            return redirect(url_for("admin_bulk_import"))
        
        # Get data from session
        import_type = session.get('bulk_import_type')
        round_id = session.get('bulk_import_round_id')
        
        if not temp_file or not import_type or not round_id:
            flash("Session expirovala, nahraj CSV znovu", "error")
            return redirect(url_for("admin_bulk_import"))
        
        # Check if temp file still exists
        if not os.path.exists(temp_file):
            flash("CSV soubor expiroval, nahraj znovu", "error")
            session.pop('bulk_import_file', None)
            return redirect(url_for("admin_bulk_import"))
        
        r = db.session.get(Round, round_id)
        if not r:
            flash("Soutěž nenalezena", "error")
            return redirect(url_for("admin_bulk_import"))
        
        # Get selected rows from form
        selected_rows = request.form.getlist('selected_rows')
        if not selected_rows:
            flash("Nevybrané žádné záznamy k importu", "error")
            # Cleanup temp file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            return redirect(url_for("admin_bulk_import_preview"))
        
        # Convert to set of integers for fast lookup
        selected_indices = set(int(idx) for idx in selected_rows)
        
        try:
            # Read CSV from temp file
            with open(temp_file, 'r', encoding='utf-8') as f:
                csv_content = f.read()
            
            stream = io.StringIO(csv_content, newline=None)
            csv_reader = csv.DictReader(stream)
            
            if import_type == 'teams':
                imported = 0
                skipped = 0
                
                for idx, row in enumerate(csv_reader):
                    # Skip if not selected
                    if idx not in selected_indices:
                        continue
                    
                    team_name = row.get('name', '').strip()
                    
                    if not team_name:
                        continue
                    
                    existing = Team.query.filter_by(round_id=round_id, name=team_name).first()
                    
                    if existing:
                        skipped += 1
                    else:
                        team = Team(round_id=round_id, name=team_name)
                        db.session.add(team)
                        imported += 1
                
                db.session.commit()
                audit("bulk_import.teams", "Team", None, details=f"Imported {imported}, skipped {skipped}")
                flash(f"✅ Importováno {imported} týmů, přeskočeno {skipped}", "ok")
            
            elif import_type == 'matches':
                imported = 0
                skipped = 0
                updated = 0
                errors = []
                
                for idx, row in enumerate(csv_reader):
                    # Skip if not selected
                    if idx not in selected_indices:
                        continue
                    
                    home_name = row.get('home_team', '').strip()
                    away_name = row.get('away_team', '').strip()
                    start_time_str = row.get('start_time', '').strip()
                    home_score_str = row.get('home_score', '').strip()
                    away_score_str = row.get('away_score', '').strip()
                    
                    if not home_name or not away_name:
                        continue
                    
                    home_team = Team.query.filter_by(round_id=round_id, name=home_name).first()
                    away_team = Team.query.filter_by(round_id=round_id, name=away_name).first()
                    
                    if not home_team or not away_team:
                        continue
                    
                    # Parse start time
                    start_time = None
                    if start_time_str:
                        try:
                            start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M')
                        except:
                            try:
                                start_time = datetime.strptime(start_time_str, '%Y-%m-%d')
                            except:
                                continue
                    
                    # Parse scores
                    home_score = None
                    away_score = None
                    
                    if home_score_str and away_score_str:
                        try:
                            home_score = int(home_score_str)
                            away_score = int(away_score_str)
                        except:
                            pass
                    
                    # Check if match exists
                    existing = Match.query.filter_by(
                        round_id=round_id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()
                    
                    if existing:
                        # OVERWRITE - přepsat existující zápas VŠEMI daty z CSV
                        if start_time is not None:
                            existing.start_time = start_time
                        existing.home_score = home_score
                        existing.away_score = away_score
                        updated += 1
                    else:
                        # Create new match
                        match = Match(
                            round_id=round_id,
                            home_team_id=home_team.id,
                            away_team_id=away_team.id,
                            start_time=start_time,
                            home_score=home_score,
                            away_score=away_score
                        )
                        db.session.add(match)
                        imported += 1
                
                db.session.commit()
                audit("bulk_import.matches", "Match", None, details=f"Imported {imported}, overwritten {updated}")
                
                if updated > 0:
                    flash(f"✅ Importováno {imported} nových zápasů, přepsáno {updated} existujících", "ok")
                else:
                    flash(f"✅ Importováno {imported} nových zápasů", "ok")
            
            elif import_type == 'tips':
                imported = 0
                updated = 0
                skipped = 0
                errors = []
                
                for idx, row in enumerate(csv_reader):
                    # Skip if not selected
                    if idx not in selected_indices:
                        continue
                    
                    user_email = row.get('user_email', '').strip()
                    home_name = row.get('home_team', '').strip()
                    away_name = row.get('away_team', '').strip()
                    home_score_str = row.get('home_score', '').strip()
                    away_score_str = row.get('away_score', '').strip()
                    
                    # Validate
                    if not user_email or not home_name or not away_name or not home_score_str or not away_score_str:
                        continue
                    
                    # Find user
                    user = User.query.filter_by(email=user_email).first()
                    if not user:
                        continue
                    
                    # Find teams
                    home_team = Team.query.filter_by(round_id=round_id, name=home_name).first()
                    away_team = Team.query.filter_by(round_id=round_id, name=away_name).first()
                    if not home_team or not away_team:
                        continue
                    
                    # Find match
                    match = Match.query.filter_by(
                        round_id=round_id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()
                    if not match:
                        continue
                    
                    # Parse scores
                    try:
                        new_home = int(home_score_str)
                        new_away = int(away_score_str)
                    except:
                        continue
                    
                    # Find existing tip
                    existing_tip = Tip.query.filter_by(
                        user_id=user.id,
                        match_id=match.id
                    ).first()
                    
                    if existing_tip:
                        # Update if different
                        if existing_tip.home_score != new_home or existing_tip.away_score != new_away:
                            existing_tip.home_score = new_home
                            existing_tip.away_score = new_away
                            updated += 1
                        else:
                            skipped += 1
                    else:
                        # Create new tip
                        tip = Tip(
                            user_id=user.id,
                            match_id=match.id,
                            home_score=new_home,
                            away_score=new_away
                        )
                        db.session.add(tip)
                        imported += 1
                
                db.session.commit()
                audit("bulk_import.tips", "Tip", None, details=f"Imported {imported}, updated {updated}, skipped {skipped}")
                
                if updated > 0:
                    flash(f"✅ Importováno {imported} tipů, přepsáno {updated}, přeskočeno {skipped}", "ok")
                else:
                    flash(f"✅ Importováno {imported} tipů, přeskočeno {skipped}", "ok")
            
            # Clear session and cleanup temp file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            session.pop('bulk_import_file', None)
            session.pop('bulk_import_type', None)
            session.pop('bulk_import_round_id', None)
            
        except Exception as e:
            flash(f"❌ Chyba při importu: {str(e)}", "error")
            import traceback
            traceback.print_exc()
            # Cleanup temp file on error too
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
        
        return redirect(url_for("admin_bulk_import"))

    # --- ADMIN EXPORT ---
    @app.route("/admin/export/<what>")
    @login_required
    def admin_export(what):
        admin_required()
        
        if what == "users":
            users = User.query.all()
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Username', 'Email', 'Jméno', 'Příjmení', 'Admin'])
            
            for u in users:
                writer.writerow([
                    u.id,
                    u.username,
                    u.email,
                    u.first_name or '',
                    u.last_name or '',
                    'Ano' if u.is_admin else 'Ne'
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=users_export.csv'}
            )
        
        elif what == "matches":
            rid = ensure_selected_round()
            r = db.session.get(Round, rid) if rid else None
            
            if not r:
                flash("Vyber soutěž.", "error")
                return redirect(url_for("admin_dashboard"))
            
            matches = Match.query.filter_by(round_id=r.id, is_deleted=False).order_by(Match.start_time).all()
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Domácí', 'Hosté', 'Skóre domácí', 'Skóre hosté'])
            
            for m in matches:
                writer.writerow([
                    m.id,
                    m.home_team.name if m.home_team else '',
                    m.away_team.name if m.away_team else '',
                    m.home_score if m.home_score is not None else '',
                    m.away_score if m.away_score is not None else ''
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=matches_{r.name.replace(" ", "_")}.csv'}
            )
        
        else:
            flash("Neznámý export typ.", "error")
            return redirect(url_for("admin_dashboard"))

    # --- ADMIN UNDO ---
    @app.route("/admin/undo")
    @login_required
    def admin_undo():
        admin_required()
        
        # Načti poslední undo pointy (maximálně 20)
        recent_undos = UndoStack.query.filter_by(
            user_id=current_user.id,
            is_undone=False
        ).order_by(UndoStack.created_at.desc()).limit(20).all()
        
        # Stats
        total_undos = UndoStack.query.filter_by(user_id=current_user.id).count()
        available_undos = UndoStack.query.filter_by(user_id=current_user.id, is_undone=False).count()
        
        return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 8px 0;">🔄 Undo - Vrátit změny</h2>
  <div class="muted">Možnost vrátit poslední akce zpět</div>
  <hr class="sep">
  
  <div class="row" style="gap: 12px; margin-bottom: 16px;">
    <div class="tag pill-ok">✅ {{ available_undos }} dostupných</div>
    <div class="tag">📊 {{ total_undos }} celkem</div>
  </div>
  
  {% if not recent_undos %}
    <div class="card" style="background: rgba(255,255,255,.03); text-align: center; padding: 32px;">
      <div style="font-size: 48px; margin-bottom: 16px;">📝</div>
      <div class="muted">Žádné akce k vrácení.</div>
      <div class="muted" style="font-size: 13px; margin-top: 8px;">
        Změny se zaznamenávají automaticky při Bulk Edit.
      </div>
    </div>
  {% else %}
    <table class="datatable">
      <thead>
        <tr>
          <th style="width: 140px;">Čas</th>
          <th style="width: 120px;">Typ</th>
          <th>Popis</th>
          <th style="width: 120px; text-align: center;">Akce</th>
        </tr>
      </thead>
      <tbody>
        {% for undo in recent_undos %}
          <tr>
            <td>{{ undo.created_at.strftime("%d.%m. %H:%M") }}</td>
            <td>
              <span class="tag pill-ok">{{ undo.entity_type }}</span>
            </td>
            <td>{{ undo.description or '-' }}</td>
            <td style="text-align: center;">
              <form method="post" action="{{ url_for('admin_undo_perform', undo_id=undo.id) }}" style="margin: 0;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <button type="submit" class="btn btn-sm btn-primary" 
                        onclick="return confirm('Opravdu vrátit tuto změnu?')">
                  ↶ Vrátit
                </button>
              </form>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}
</div>

<div class="card" style="background: rgba(110,168,254,.08); border-color: rgba(110,168,254,.3);">
  <h3 style="margin: 0 0 12px 0;">💡 Jak to funguje?</h3>
  <ul style="margin: 0; padding-left: 20px;">
    <li>Při každé důležité změně (Bulk Edit) se vytvoří undo point</li>
    <li>Můžeš kdykoli vrátit změnu pomocí tlačítka "Vrátit"</li>
    <li>Každý admin vidí pouze své vlastní undo pointy</li>
    <li>Akce lze vrátit pouze jednou</li>
    <li>Zobrazuje se max 20 posledních změn</li>
  </ul>
</div>

""", recent_undos=recent_undos, total_undos=total_undos, available_undos=available_undos)

    @app.route("/admin/undo/<int:undo_id>/perform", methods=["POST"])
    @login_required
    def admin_undo_perform(undo_id):
        admin_required()
        
        result = perform_undo(undo_id)
        
        if result['success']:
            flash(result['message'], "ok")
        else:
            flash(f"❌ {result['message']}", "error")
        
        return redirect(url_for("admin_undo"))

    # === BACKUP DATABÁZE ===
    
    @app.route("/admin/backup")
    @login_required
    def admin_backup():
        """Stránka pro správu záloh databáze"""
        admin_required()
        
        # Zjisti velikost aktuální databáze
        db_path = os.path.join(app.instance_path, 'tipovacka.db')
        try:
            db_size = os.path.getsize(db_path)
            db_size_mb = db_size / (1024 * 1024)
        except:
            db_size_mb = 0
        
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">💾 Záloha databáze</h2>
  <div class="muted">Pravidelně zálohuj data tipovačky</div>
  <hr class="sep">
  
  <div style="background:rgba(110,168,254,0.08); padding:16px; border-radius:8px; margin-bottom:16px;">
    <div class="row" style="justify-content:space-between;">
      <div>
        <strong>Aktuální databáze:</strong>
      </div>
      <div>
        <span class="tag">{{ "%.2f"|format(db_size_mb) }} MB</span>
      </div>
    </div>
  </div>
  
  <h3 style="margin:16px 0 8px 0;">Manual záloha</h3>
  <div class="muted" style="margin-bottom:12px;">
    Vytvoř zálohu kdykoliv kliknutím na tlačítko
  </div>
  
  <div class="row" style="gap:10px; margin-bottom:24px;">
    <a href="{{ url_for('admin_backup_download') }}" class="btn btn-primary">
      📥 Stáhnout backup
    </a>
    <a href="{{ url_for('admin_backup_email') }}" class="btn" style="background:#667eea; color:white;">
      📧 Poslat na email
    </a>
  </div>
  
  <div style="background:rgba(255,193,7,0.1); padding:12px; border-left:4px solid #ffc107; font-size:13px; margin-bottom:24px;">
    <strong>📧 Email backup:</strong> Odešle se na <strong>{{ current_user.email }}</strong>
  </div>
  
  <hr class="sep">
  
  <h3 style="margin:16px 0 8px 0;">⏰ Automatický backup</h3>
  <div class="muted" style="margin-bottom:12px;">
    Záloha se pošle automaticky každý den v 3:00
  </div>
  
  <div style="background:rgba(110,168,254,0.1); padding:16px; border-radius:8px; margin-bottom:16px;">
    <div class="row" style="gap:16px; align-items:flex-start;">
      <div style="flex:1;">
        <strong style="display:block; margin-bottom:8px;">FREE účet (PythonAnywhere)</strong>
        <div class="muted" style="font-size:13px; line-height:1.6;">
          ❌ Scheduled tasks nejsou dostupné<br>
          ✅ Použij manual backup tlačítka výše
        </div>
      </div>
      <div style="flex:1;">
        <strong style="display:block; margin-bottom:8px;">PAID účet / Wedos</strong>
        <div class="muted" style="font-size:13px; line-height:1.6;">
          ✅ Cron job dostupný<br>
          ✅ Denní automatický backup<br>
          ✅ Email všem adminům
        </div>
      </div>
    </div>
  </div>
  
  <details style="margin-top:16px;">
    <summary style="cursor:pointer; padding:12px; background:rgba(0,0,0,0.05); border-radius:4px; font-weight:600;">
      📖 Návod: Nastavení automatického backupu (pro budoucnost)
    </summary>
    <div style="padding:16px; background:rgba(0,0,0,0.02); border-radius:4px; margin-top:8px; font-size:13px;">
      <p><strong>Soubor: backup_daily.py</strong></p>
      <pre style="background:#0b1020; color:#6ea8fe; padding:12px; border-radius:4px; overflow-x:auto; font-size:11px; line-height:1.4;">#!/usr/bin/env python3
import os, sys
sys.path.insert(0, '/path/to/tipovacka')

os.environ['SECRET_KEY'] = 'tvuj-secret-key'
os.environ['SEND_REAL_EMAILS'] = 'true'
os.environ['FROM_EMAIL'] = 'noreply@tvoje-domena.cz'
os.environ['FROM_NAME'] = 'Tipovačka Backup'
os.environ['SMTP_SERVER'] = 'smtp.wedos.com'
os.environ['SMTP_PORT'] = '587'
os.environ['SMTP_USERNAME'] = 'noreply@tvoje-domena.cz'
os.environ['SMTP_PASSWORD'] = 'heslo'

from app2 import app, db, User, send_email_with_attachment
from datetime import datetime
import zipfile, os
from io import BytesIO

with app.app_context():
    admins = User.query.filter(User.role.in_(['admin', 'owner'])).all()
    db_path = os.path.join(app.instance_path, 'tipovacka.db')
    
    memory_file = BytesIO()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(db_path, f'tipovacka_{timestamp}.db')
    
    memory_file.seek(0)
    zip_data = memory_file.read()
    size_mb = len(zip_data) / (1024 * 1024)
    
    for admin in admins:
        html = f"&lt;h1&gt;Backup {datetime.now().strftime('%d.%m.%Y')}&lt;/h1&gt;&lt;p&gt;Velikost: {size_mb:.2f} MB&lt;/p&gt;"
        send_email_with_attachment(admin.email, f"Záloha {datetime.now().strftime('%d.%m.%Y')}", html, "Backup", zip_data, f'backup_{timestamp}.zip')
    
    print(f"{datetime.now()} - Backup odeslán {len(admins)} adminům")</pre>
      
      <p style="margin-top:16px;"><strong>Cron job (Wedos/VPS):</strong></p>
      <pre style="background:#0b1020; color:#6ea8fe; padding:12px; border-radius:4px; font-size:12px;">0 3 * * * /usr/bin/python3 /path/to/backup_daily.py >> /var/log/backup.log 2>&1</pre>
      
      <p class="muted" style="margin-top:12px;">
        = Každý den ve 3:00 se spustí backup a pošle email všem adminům
      </p>
    </div>
  </details>
  
  <hr class="sep">
  <a href="{{ url_for('admin_users') }}" class="btn">← Zpět do admin</a>
</div>
""", db_size_mb=db_size_mb)
    
    @app.route("/admin/backup/download")
    @login_required
    def admin_backup_download():
        """Stáhne aktuální databázi jako .zip"""
        admin_required()
        
        try:
            import zipfile
            from io import BytesIO
            from datetime import datetime
            
            db_path = os.path.join(app.instance_path, 'tipovacka.db')
            
            if not os.path.exists(db_path):
                flash("Databáze nenalezena!", "error")
                return redirect(url_for("admin_backup"))
            
            # Vytvoř zip v paměti
            memory_file = BytesIO()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(db_path, f'tipovacka_{timestamp}.db')
            
            memory_file.seek(0)
            
            audit("backup.download", "Database", None, timestamp=timestamp)
            
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name=f'tipovacka_backup_{timestamp}.zip'
            )
            
        except Exception as e:
            flash(f"Chyba při vytváření backupu: {str(e)}", "error")
            return redirect(url_for("admin_backup"))
    
    @app.route("/admin/backup/email")
    @login_required
    def admin_backup_email():
        """Pošle backup databáze na email aktuálního admina"""
        admin_required()
        
        try:
            import zipfile
            from io import BytesIO
            from datetime import datetime
            
            db_path = os.path.join(app.instance_path, 'tipovacka.db')
            
            if not os.path.exists(db_path):
                flash("Databáze nenalezena!", "error")
                return redirect(url_for("admin_backup"))
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
            timestamp_file = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Vytvoř zip
            memory_file = BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(db_path, f'tipovacka_{timestamp_file}.db')
            
            memory_file.seek(0)
            zip_data = memory_file.read()
            
            # Velikost backupu
            size_mb = len(zip_data) / (1024 * 1024)
            
            # Pošli email s přílohou
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"></head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: #0b1020; color: white; padding: 20px; text-align: center;">
                        <h1>💾 Záloha databáze</h1>
                    </div>
                    <div style="background: #f4f4f4; padding: 30px;">
                        <h2>Záloha tipovačky</h2>
                        <p><strong>Datum:</strong> {timestamp}</p>
                        <p><strong>Velikost:</strong> {size_mb:.2f} MB</p>
                        <p><strong>Soubor:</strong> tipovacka_backup_{timestamp_file}.zip</p>
                        
                        <div style="background: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0;">
                            <strong>💡 Doporučení:</strong><br>
                            • Ulož si backup na bezpečné místo<br>
                            • Nezveřejňuj ho (obsahuje všechna data)<br>
                            • Gmail: 15 GB free = ~5000 backupů
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text = f"""Záloha tipovačky

Datum: {timestamp}
Velikost: {size_mb:.2f} MB
Soubor: tipovacka_backup_{timestamp_file}.zip
            """
            
            # Odešli s přílohou
            success = send_email_with_attachment(
                to_email=current_user.email,
                subject=f"Záloha tipovačky - {timestamp}",
                html_body=html,
                text_body=text,
                attachment_data=zip_data,
                attachment_name=f'tipovacka_backup_{timestamp_file}.zip'
            )
            
            if success:
                flash(f"✅ Backup odeslán na: {current_user.email} ({size_mb:.2f} MB)", "ok")
                audit("backup.email", "Database", None, size_mb=f"{size_mb:.2f}")
            else:
                flash(f"⚠️ Chyba při odesílání. Zkus stáhnout manuálně.", "warning")
            
            return redirect(url_for("admin_backup"))
            
        except Exception as e:
            flash(f"Chyba: {str(e)}", "error")
            return redirect(url_for("admin_backup"))

    # --- ADMIN IMPORT ---
    @app.route("/admin/import")
    @login_required
    def admin_import():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Import (CSV)</h2>
  <div class="muted">Vybraná soutěž: <b>{{ r.name if r else "—" }}</b>. Pokud CSV obsahuje sloupec <b>round_id</b>, použije se.</div>
  <hr class="sep">
  <div class="row">
    <a class="btn btn-primary" href="{{ url_for('admin_import_teams') }}">Import týmů</a>
    <a class="btn btn-primary" href="{{ url_for('admin_import_matches') }}">Import zápasů</a>
    <a class="btn btn-primary" href="{{ url_for('admin_import_extras') }}">Import extra</a>
  </div>
  <hr class="sep">
  <div style="margin-top:20px;">
    <h3 style="margin:0 0 8px 0;">Import dat z jiné tipovačky</h3>
    <div class="muted" style="margin-bottom:10px;">Importuj kompletní data (uživatele, zápasy a tipy) z Excel žebříčku</div>
    <div class="row" style="gap: 12px;">
      <a class="btn btn-primary" href="{{ url_for('admin_import_leaderboard_smart') }}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
        ✨ Smart Import (s kontrolou duplicit)
      </a>
      <a class="btn" href="{{ url_for('admin_import_leaderboard') }}">
        📥 Klasický Import (bez kontroly)
      </a>
    </div>
    <div class="muted" style="margin-top: 8px; font-size: 12px;">
      💡 <strong>Smart Import</strong> ti ukáže preview a označí možné duplicity před importem!
    </div>
  </div>
</div>
""", r=r)

    # --- ADMIN SMART IMPORT (s kontrolou duplicit) ---
    @app.route("/admin/import/leaderboard-smart/template")
    @login_required
    def admin_import_leaderboard_smart_template():
        """Stáhne Excel šablonu pro smart import žebříčku"""
        admin_required()
        
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill
            from io import BytesIO
            
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Smart Import"
            
            # Hlavička - Jméno | Zápasy
            headers = ['Jméno', 'Sparta-Slavia', 'Plzeň-Brno', 'Baník-Bohemians']
            ws.append(headers)
            
            # Stylování
            for col in range(1, len(headers) + 1):
                cell = ws.cell(row=1, column=col)
                cell.fill = PatternFill(start_color="667EEA", end_color="667EEA", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF")
            
            # Příklady
            ws.append(['Jan Novák', '2:1', '1:1', '3:0'])
            ws.append(['Petr Svoboda', '1:2', '2:0', '1:1'])
            
            # Šířka
            ws.column_dimensions['A'].width = 20
            for col in ['B', 'C', 'D']:
                ws.column_dimensions[col].width = 15
            
            # Poznámky
            notes = wb.create_sheet("Poznámky")
            notes['A1'] = "SMART IMPORT - S KONTROLOU DUPLICIT"
            notes['A1'].font = Font(bold=True, size=14)
            notes['A3'] = "Formát stejný jako běžný import žebříčku."
            notes['A4'] = "Výhoda: Automaticky detekuje duplicitní zápasy!"
            notes['A6'] = "HLAVIČKA:"
            notes['A7'] = "   Jméno | Domácí-Hosté | Domácí-Hosté ..."
            notes['A9'] = "TIPY:"
            notes['A10'] = "   Jan | 2:1 | 1:0 | 3:2"
            notes.column_dimensions['A'].width = 50
            
            output = BytesIO()
            wb.save(output)
            output.seek(0)
            
            return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                           as_attachment=True, download_name='smart_import_sablona.xlsx')
        except Exception as e:
            flash(f"Chyba: {str(e)}", "error")
            return redirect(url_for("admin_import"))
    
    @app.route("/admin/import/leaderboard-smart", methods=["GET", "POST"])
    @login_required
    def admin_import_leaderboard_smart():
        admin_required()
        
        if request.method == "POST":
            file = request.files.get('excel_file')
            if not file or not file.filename:
                flash("Nahraj Excel soubor.", "error")
                return redirect(url_for("admin_import_leaderboard_smart"))
            
            # Určit cílovou soutěž
            import_target = request.form.get('import_target', 'existing')
            
            if import_target == 'new':
                new_round_name = request.form.get('new_round_name', '').strip()
                if not new_round_name:
                    flash("Zadej název nové soutěže.", "error")
                    return redirect(url_for("admin_import_leaderboard_smart"))
                
                sport = Sport.query.filter_by(name="Fotbal").first()
                if not sport:
                    sport = Sport(name="Fotbal")
                    db.session.add(sport)
                    db.session.flush()
                
                r = Round(name=new_round_name, sport_id=sport.id, is_active=False)
                db.session.add(r)
                db.session.flush()
                round_id = r.id
                audit("round.create.import", "Round", r.id, name=r.name)
            else:
                round_id = int(request.form.get('round_id', 0))
                r = db.session.get(Round, round_id)
                if not r:
                    flash("Vybraná soutěž neexistuje.", "error")
                    return redirect(url_for("admin_import_leaderboard_smart"))
            
            try:
                import openpyxl
                from io import BytesIO
                
                wb = openpyxl.load_workbook(BytesIO(file.read()))
                ws = wb.active
                
                rows = list(ws.iter_rows(values_only=True))
                if len(rows) < 2:
                    flash("Soubor musí mít alespoň hlavičku a jeden řádek.", "error")
                    return redirect(url_for("admin_import_leaderboard_smart"))
                
                header = rows[0]
                if not header or len(header) < 2:
                    flash("Hlavička musí mít alespoň 2 sloupce.", "error")
                    return redirect(url_for("admin_import_leaderboard_smart"))
                
                # Parsovat zápasy z hlavičky
                matches_data = []
                for i, match_name in enumerate(header[1:], start=1):
                    if not match_name or str(match_name).strip() == "":
                        continue
                    
                    match_str = str(match_name).strip()
                    for sep in ['-', ' vs ', ' x ', ':', ' – ']:
                        if sep in match_str:
                            parts = match_str.split(sep, 1)
                            if len(parts) == 2:
                                home = parts[0].strip()
                                away = parts[1].strip()
                                
                                # Detekovat možnou duplicitu
                                home_team_check = Team.query.filter(
                                    Team.round_id == round_id,
                                    Team.is_deleted == False,
                                    db.func.lower(Team.name) == home.lower()
                                ).first()
                                
                                away_team_check = Team.query.filter(
                                    Team.round_id == round_id,
                                    Team.is_deleted == False,
                                    db.func.lower(Team.name) == away.lower()
                                ).first()
                                
                                is_duplicate = False
                                existing_match_id = None
                                status = 'new'  # NOVÉ!
                                
                                if home_team_check and away_team_check:
                                    existing_match = Match.query.filter_by(
                                        round_id=round_id,
                                        home_team_id=home_team_check.id,
                                        away_team_id=away_team_check.id,
                                        is_deleted=False
                                    ).first()
                                    
                                    if existing_match:
                                        is_duplicate = True
                                        existing_match_id = existing_match.id
                                        status = 'overwrite'  # Může být přepsán!
                                
                                matches_data.append({
                                    'col': i,
                                    'home': home,
                                    'away': away,
                                    'is_duplicate': is_duplicate,  # Zpětná kompatibilita
                                    'status': status,  # NOVÉ!
                                    'existing_match_id': existing_match_id,
                                    'match_str': match_str
                                })
                                break
                
                if not matches_data:
                    flash("Nenalezeny žádné platné zápasy v hlavičce.", "error")
                    return redirect(url_for("admin_import_leaderboard_smart"))
                
                # Uložit preview data do TEMP FILE (ne session - cookie overflow!)
                import tempfile
                import pickle
                
                preview_data = {
                    'round_id': round_id,
                    'round_name': r.name,
                    'matches': matches_data,  # Velké data!
                    'total_matches': len(matches_data),
                    'overwrite_count': sum(1 for m in matches_data if m['status'] == 'overwrite'),
                    'new_count': sum(1 for m in matches_data if m['status'] == 'new')
                }
                
                # Uložit preview data do pickle file
                preview_fd, preview_path = tempfile.mkstemp(suffix='.pkl', prefix='smart_preview_')
                with os.fdopen(preview_fd, 'wb') as f:
                    pickle.dump(preview_data, f)
                
                # Do session jen cesta + základní info (malé!)
                session['smart_import_preview'] = {
                    'preview_file': preview_path,
                    'round_id': round_id,
                    'round_name': r.name,
                    'total_matches': len(matches_data),
                    'overwrite_count': sum(1 for m in matches_data if m['status'] == 'overwrite'),
                    'new_count': sum(1 for m in matches_data if m['status'] == 'new')
                }
                
                # Uložit Excel file do TEMP FILE
                file.seek(0)  # Reset file pointer
                excel_fd, excel_path = tempfile.mkstemp(suffix='.xlsx', prefix='smart_excel_')
                with os.fdopen(excel_fd, 'wb') as f:
                    f.write(file.read())
                session['smart_import_file'] = excel_path
                
                return redirect(url_for("admin_import_leaderboard_smart_preview"))
            
            except Exception as e:
                flash(f"Chyba při načítání souboru: {str(e)}", "error")
                db.session.rollback()
                return redirect(url_for("admin_import_leaderboard_smart"))
        
        # GET
        all_rounds = Round.query.order_by(Round.id.desc()).all()
        
        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between; align-items:flex-start;">
    <div>
      <h2 style="margin: 0 0 8px 0;">✨ Smart Import Žebříčku</h2>
      <div class="muted">Import s kontrolou duplicit a možností výběru</div>
    </div>
    <a href="{{ url_for('admin_import_leaderboard_smart_template') }}" class="btn" style="background:#667eea; color:white;">
      📥 Stáhnout šablonu Excel
    </a>
  </div>
  <hr class="sep">
  
  <div class="card" style="background: rgba(110,168,254,.08); border-color: rgba(110,168,254,.3); margin-bottom: 16px;">
    <h3 style="margin: 0 0 12px 0;">💡 Jak to funguje?</h3>
    <ul style="margin: 0; padding-left: 20px;">
      <li><strong>Preview před importem</strong> - Vidíš CO se chystá importovat</li>
      <li><strong>Detekce existujících</strong> - Modře označí zápasy které již existují (mohou být použity)</li>
      <li><strong>Checkboxy pro výběr</strong> - Ručně vyber co chceš/nechceš importovat</li>
      <li><strong>Quick select</strong> - Tlačítka "Jen nové" / "Přepsat existující"</li>
    </ul>
  </div>
  
  <form method="post" enctype="multipart/form-data" class="row" style="flex-direction:column; align-items:stretch; gap:16px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    
    <div class="card" style="background:rgba(255,255,255,0.03); padding:16px;">
      <h3 style="margin:0 0 12px 0;">1️⃣ Kam importovat data?</h3>
      
      <label style="display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer;">
        <input type="radio" name="import_target" value="existing" {% if all_rounds %}checked{% endif %}
               onchange="toggleImportTarget()" id="radio_existing">
        <span>Do existující soutěže</span>
      </label>
      
      <div id="existing_round_select" style="margin-left:28px; margin-bottom:16px;">
        <select name="round_id" style="width:100%; max-width:400px;">
          {% for rnd in all_rounds %}
            <option value="{{ rnd.id }}">
              {% if rnd.is_active %}★ {% endif %}{{ rnd.name }}
            </option>
          {% endfor %}
          {% if not all_rounds %}
            <option value="">-- Žádné soutěže --</option>
          {% endif %}
        </select>
      </div>
      
      <label style="display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer;">
        <input type="radio" name="import_target" value="new" {% if not all_rounds %}checked{% endif %}
               onchange="toggleImportTarget()" id="radio_new">
        <span>Vytvořit novou soutěž</span>
      </label>
      
      <div id="new_round_input" style="margin-left:28px; display:none;">
        <input type="text" name="new_round_name" placeholder="Název nové soutěže"
               style="width:100%; max-width:400px;">
      </div>
    </div>
    
    <div class="card" style="background:rgba(255,255,255,0.03); padding:16px;">
      <h3 style="margin:0 0 12px 0;">2️⃣ Vyber Excel soubor</h3>
      <input type="file" name="excel_file" accept=".xlsx,.xls" required>
    </div>
    
    <button class="btn btn-primary" type="submit" style="padding:14px; font-size:16px; font-weight:900;">
      📥 Načíst preview
    </button>
    <a class="btn" href="{{ url_for('admin_import') }}">Zpět</a>
  </form>
</div>

<script>
function toggleImportTarget() {
  const existingChecked = document.getElementById('radio_existing').checked;
  const existingDiv = document.getElementById('existing_round_select');
  const newDiv = document.getElementById('new_round_input');
  
  if (existingChecked) {
    existingDiv.style.display = 'block';
    newDiv.style.display = 'none';
  } else {
    existingDiv.style.display = 'none';
    newDiv.style.display = 'block';
  }
}

toggleImportTarget();
</script>
""", all_rounds=all_rounds)

    @app.route("/admin/import/leaderboard-smart/preview")
    @login_required
    def admin_import_leaderboard_smart_preview():
        admin_required()
        
        preview_meta = session.get('smart_import_preview')
        if not preview_meta:
            flash("Nejprve nahraj soubor.", "error")
            return redirect(url_for("admin_import_leaderboard_smart"))
        
        # Načti matches data z pickle file
        preview_file = preview_meta.get('preview_file')
        if not preview_file or not os.path.exists(preview_file):
            flash("Preview data expirovala, nahraj soubor znovu.", "error")
            return redirect(url_for("admin_import_leaderboard_smart"))
        
        import pickle
        with open(preview_file, 'rb') as f:
            preview = pickle.load(f)
        
        return render_page(r"""
<style>
  .match-preview {
    display: flex;
    align-items: center;
    padding: 12px;
    border: 1px solid var(--line);
    border-radius: 8px;
    margin-bottom: 8px;
    transition: all 0.2s ease;
  }
  
  .match-preview:hover {
    background: rgba(255,255,255,.03);
  }
  
  .match-preview.overwrite {
    background: rgba(99,179,237,.08);
    border-color: rgba(99,179,237,.3);
  }
  
  .match-preview.new {
    background: rgba(51,209,122,.05);
    border-color: rgba(51,209,122,.2);
  }
  
  .match-checkbox {
    margin-right: 12px;
    width: 20px;
    height: 20px;
    cursor: pointer;
  }
</style>

<div class="card">
  <h2 style="margin: 0 0 8px 0;">✨ Preview importu</h2>
  <div class="muted">Soutěž: <b>{{ preview.round_name }}</b></div>
  <hr class="sep">
  
  <div class="row" style="justify-content: space-between; margin-bottom: 16px;">
    <div>
      <div class="tag pill-ok" style="font-size: 14px;">✅ {{ preview.new_count }} nových</div>
      <div class="tag pill-info" style="font-size: 14px; background: rgba(99,179,237,.15); color: #63b3ed;">🔵 {{ preview.overwrite_count }} přepsat</div>
    </div>
    
    <div class="row" style="gap: 8px;">
      <button type="button" onclick="selectAll()" class="btn btn-sm">☑️ Vybrat vše</button>
      <button type="button" onclick="deselectAll()" class="btn btn-sm">☐ Zrušit výběr</button>
      <button type="button" onclick="selectNew()" class="btn btn-sm">🟢 Jen nové</button>
      <button type="button" onclick="selectOverwrite()" class="btn btn-sm btn-primary">🔵 Přepsat existující</button>
    </div>
  </div>
</div>

<form method="post" action="{{ url_for('admin_import_leaderboard_smart_confirm') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <div class="card">
    <h3 style="margin: 0 0 16px 0;">📋 Zápasy k importu ({{ preview.total_matches }})</h3>
    
    {% for match in preview.matches %}
      <div class="match-preview {{ match.status }}" data-status="{{ match.status }}">
        <input type="checkbox" 
               name="selected_matches" 
               value="{{ loop.index0 }}"
               class="match-checkbox"
               {% if match.status == 'new' %}checked{% endif %}
               id="match_{{ loop.index0 }}">
        
        <label for="match_{{ loop.index0 }}" style="flex: 1; cursor: pointer; margin: 0;">
          <div class="row" style="justify-content: space-between; align-items: center;">
            <div>
              <strong>{{ match.home }}</strong> 
              <span class="muted">vs</span> 
              <strong>{{ match.away }}</strong>
            </div>
            
            <div>
              {% if match.status == 'overwrite' %}
                <span class="tag pill-info" style="background: rgba(99,179,237,.15); color: #63b3ed;">🔵 PŘEPSAT</span>
              {% else %}
                <span class="tag pill-ok">✅ NOVÝ</span>
              {% endif %}
            </div>
          </div>
        </label>
      </div>
    {% endfor %}
  </div>
  
  <div class="card">
    <div class="row" style="justify-content: space-between; align-items: center;">
      <div>
        <div style="font-size: 14px; margin-bottom: 4px;">
          Importuje se: <strong><span id="selected-count">{{ preview.new_count }}</span></strong> zápasů
        </div>
        <div class="muted" style="font-size: 12px;">
          Duplicity budou přeskočeny
        </div>
      </div>
      
      <div class="row" style="gap: 12px;">
        <a href="{{ url_for('admin_import_leaderboard_smart') }}" class="btn">❌ Zrušit</a>
        <button type="submit" class="btn btn-primary" style="font-size: 16px; padding: 12px 24px;">
          ✅ Potvrdit a importovat
        </button>
      </div>
    </div>
  </div>
</form>

<script>
function updateCount() {
  const checkboxes = document.querySelectorAll('.match-checkbox:checked');
  document.getElementById('selected-count').textContent = checkboxes.length;
}

function selectAll() {
  document.querySelectorAll('.match-checkbox').forEach(cb => {
    cb.checked = true;
  });
  updateCount();
}

function deselectAll() {
  document.querySelectorAll('.match-checkbox').forEach(cb => {
    cb.checked = false;
  });
  updateCount();
}

function selectNew() {
  deselectAll();
  document.querySelectorAll('.match-preview').forEach(preview => {
    const status = preview.getAttribute('data-status');
    const checkbox = preview.querySelector('.match-checkbox');
    if (status === 'new' && checkbox) {
      checkbox.checked = true;
    }
  });
  updateCount();
}

function selectOverwrite() {
  deselectAll();
  document.querySelectorAll('.match-preview').forEach(preview => {
    const status = preview.getAttribute('data-status');
    const checkbox = preview.querySelector('.match-checkbox');
    if (status === 'overwrite' && checkbox) {
      checkbox.checked = true;
    }
  });
  updateCount();
}

// Update count on checkbox change
document.querySelectorAll('.match-checkbox').forEach(cb => {
  cb.addEventListener('change', updateCount);
});
</script>
""", preview=preview)

    def _resolve_round_id(row: dict[str, str], fallback_round_id: int) -> int:
        val = (row.get("round_id") or row.get("round") or "").strip()
        if val:
            try:
                return int(val)
            except Exception:
                pass
        return fallback_round_id

    @app.route("/admin/import/leaderboard-smart/confirm", methods=["POST"])
    @login_required
    def admin_import_leaderboard_smart_confirm():
        admin_required()
        
        preview_meta = session.get('smart_import_preview')
        temp_file = session.get('smart_import_file')
        
        if not preview_meta or not temp_file:
            flash("Session vypršela, nahraj soubor znovu.", "error")
            return redirect(url_for("admin_import_leaderboard_smart"))
        
        # Zkontroluj jestli temp files existují
        preview_file = preview_meta.get('preview_file')
        if not os.path.exists(temp_file) or not os.path.exists(preview_file):
            flash("Soubor expiroval, nahraj znovu.", "error")
            session.pop('smart_import_file', None)
            session.pop('smart_import_preview', None)
            return redirect(url_for("admin_import_leaderboard_smart"))
        
        try:
            # Načti preview data z pickle file
            import pickle
            with open(preview_file, 'rb') as f:
                preview = pickle.load(f)
            
            # Načti vybrané indexy
            selected_indices = request.form.getlist('selected_matches')
            selected_indices = [int(i) for i in selected_indices]
            
            if not selected_indices:
                flash("Nevybral jsi žádné zápasy k importu.", "error")
                return redirect(url_for("admin_import_leaderboard_smart_preview"))
            
            # Načti Excel file z TEMP FILE
            import openpyxl
            
            wb = openpyxl.load_workbook(temp_file)
            ws = wb.active
            
            rows = list(ws.iter_rows(values_only=True))
            header = rows[0]
            
            round_id = preview['round_id']
            r = db.session.get(Round, round_id)
            
            if not r:
                flash("Soutěž nenalezena.", "error")
                return redirect(url_for("admin_import_leaderboard_smart"))
            
            # Importuj pouze vybrané zápasy (vytvoř nové nebo použij existující)
            created_matches = 0
            skipped_matches = 0
            match_map = {}
            
            # KROK 1: Vytvoř/použij vybrané zápasy
            for idx in selected_indices:
                if idx >= len(preview['matches']):
                    continue
                
                match_data = preview['matches'][idx]
                
                home_team = _get_or_create_team(r.id, match_data['home'])
                away_team = _get_or_create_team(r.id, match_data['away'])
                
                # Zkusit najít existující zápas
                m = Match.query.filter_by(
                    round_id=r.id,
                    home_team_id=home_team.id,
                    away_team_id=away_team.id,
                    is_deleted=False
                ).first()
                
                if not m:
                    m = Match(round_id=r.id, home_team_id=home_team.id, away_team_id=away_team.id)
                    db.session.add(m)
                    db.session.flush()
                    created_matches += 1
                else:
                    skipped_matches += 1
                
                match_map[match_data['col']] = m
            
            # KROK 2: Pro NEVybrané zápasy - najdi existující (pro import tipů)
            for idx, match_data in enumerate(preview['matches']):
                if idx in selected_indices:
                    continue  # Už je v match_map
                
                # Zkus najít existující zápas (bez vytváření nového)
                # CASE-INSENSITIVE vyhledávání!
                home_team = Team.query.filter(
                    Team.round_id == r.id,
                    db.func.lower(Team.name) == match_data['home'].lower(),
                    Team.is_deleted == False
                ).first()
                
                away_team = Team.query.filter(
                    Team.round_id == r.id,
                    db.func.lower(Team.name) == match_data['away'].lower(),
                    Team.is_deleted == False
                ).first()
                
                if home_team and away_team:
                    existing_match = Match.query.filter_by(
                        round_id=r.id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()
                    
                    if existing_match:
                        # Přidej do match_map pro import tipů
                        match_map[match_data['col']] = existing_match
            
            # Import tipů (stejně jako v klasickém importu, ale jen pro vybrané zápasy)
            results_imported = 0
            data_rows_start = 1
            data_rows_end = len(rows)
            
            # Kontrola výsledků v prvním řádku
            if len(rows) > 1:
                first_data_row = rows[1]
                first_cell = str(first_data_row[0]).strip() if first_data_row[0] else ""
                
                if first_cell.lower() in ['', 'výsledek', 'result', 'skóre', 'score', 'vysledek']:
                    for col_idx, match in match_map.items():
                        if col_idx >= len(first_data_row):
                            continue
                        
                        result_value = first_data_row[col_idx]
                        if not result_value:
                            continue
                        
                        home_score = None
                        away_score = None
                        
                        if hasattr(result_value, 'hour') and hasattr(result_value, 'minute'):
                            home_score = result_value.hour if result_value.hour < 20 else None
                            away_score = result_value.minute if result_value.minute < 60 else None
                        elif isinstance(result_value, str) and ':' in result_value:
                            parts = result_value.split(':')
                            if len(parts) == 2:
                                try:
                                    home_score = int(parts[0].strip())
                                    away_score = int(parts[1].strip())
                                except:
                                    pass
                        
                        if home_score is not None and away_score is not None:
                            match.home_score = home_score
                            match.away_score = away_score
                            results_imported += 1
                    
                    data_rows_start = 2
            
            # Kontrola výsledků v posledním řádku
            if len(rows) > data_rows_start:
                last_row = rows[-1]
                last_cell = str(last_row[0]).strip() if last_row[0] else ""
                
                if last_cell.lower() in ['výsledek', 'result', 'skóre', 'score', 'vysledek']:
                    for col_idx, match in match_map.items():
                        if col_idx >= len(last_row):
                            continue
                        
                        result_value = last_row[col_idx]
                        if not result_value:
                            continue
                        
                        home_score = None
                        away_score = None
                        
                        if hasattr(result_value, 'hour') and hasattr(result_value, 'minute'):
                            home_score = result_value.hour if result_value.hour < 20 else None
                            away_score = result_value.minute if result_value.minute < 60 else None
                        elif isinstance(result_value, str) and ':' in result_value:
                            parts = result_value.split(':')
                            if len(parts) == 2:
                                try:
                                    home_score = int(parts[0].strip())
                                    away_score = int(parts[1].strip())
                                except:
                                    pass
                        
                        if home_score is not None and away_score is not None:
                            match.home_score = home_score
                            match.away_score = away_score
                            results_imported += 1
                    
                    data_rows_end = len(rows) - 1
            
            # Import tipů
            users_created = 0
            tips_imported = 0
            tips_overwritten = 0
            
            for row_idx in range(data_rows_start, data_rows_end):
                if row_idx >= len(rows):
                    break
                
                row = rows[row_idx]
                if not row or len(row) < 2:
                    continue
                
                username = str(row[0]).strip() if row[0] else ""
                if not username or username.lower() in ['výsledek', 'result', 'skóre', 'score', 'vysledek']:
                    continue
                
                # Normalize Unicode
                import unicodedata
                username = unicodedata.normalize('NFC', username)
                
                # Flush aby jsme viděli nově vytvořené uživatele
                db.session.flush()
                
                # PYTHON-based case-insensitive search (SPOLEHLIVĚJŠÍ!)
                all_users = User.query.all()
                u = None
                username_lower = username.lower()
                for user in all_users:
                    user_norm = unicodedata.normalize('NFC', user.username)
                    if user_norm.lower() == username_lower:
                        u = user
                        break
                
                if not u:
                    u = User(
                        username=username,
                        email=f"{username.lower()}@imported.local",
                        password_hash=generate_password_hash("changeme123"),
                        is_admin=False
                    )
                    db.session.add(u)
                    db.session.flush()
                    users_created += 1
                
                # Import tipů pro vybrané zápasy
                for col_idx, match in match_map.items():
                    if col_idx >= len(row):
                        continue
                    
                    tip_value = row[col_idx]
                    if not tip_value:
                        continue
                    
                    home_guess = None
                    away_guess = None
                    
                    if hasattr(tip_value, 'hour') and hasattr(tip_value, 'minute'):
                        home_guess = tip_value.hour if tip_value.hour < 20 else None
                        away_guess = tip_value.minute if tip_value.minute < 60 else None
                    elif isinstance(tip_value, str) and ':' in tip_value:
                        parts = tip_value.split(':')
                        if len(parts) == 2:
                            try:
                                home_guess = int(parts[0].strip())
                                away_guess = int(parts[1].strip())
                            except:
                                pass
                    
                    if home_guess is not None and away_guess is not None:
                        existing_tip = Tip.query.filter_by(user_id=u.id, match_id=match.id).first()
                        if existing_tip:
                            # PŘEPSAT existující tip novými daty
                            existing_tip.tip_home = home_guess
                            existing_tip.tip_away = away_guess
                            tips_overwritten += 1
                        else:
                            # Vytvořit nový tip
                            tip = Tip(
                                user_id=u.id,
                                match_id=match.id,
                                tip_home=home_guess,
                                tip_away=away_guess
                            )
                            db.session.add(tip)
                            tips_imported += 1
            
            db.session.commit()
            
            # Smaž temp files
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            
            if preview_file and os.path.exists(preview_file):
                try:
                    os.unlink(preview_file)
                except:
                    pass
            
            # Vyčisti session
            session.pop('smart_import_preview', None)
            session.pop('smart_import_file', None)
            
            audit("leaderboard.smart_import", "Round", r.id,
                  created_matches=created_matches,
                  skipped_matches=skipped_matches,
                  users_created=users_created,
                  tips_imported=tips_imported,
                  tips_overwritten=tips_overwritten,
                  results_imported=results_imported)
            
            tips_message = f"Importováno {tips_imported} nových tipů"
            if tips_overwritten > 0:
                tips_message += f", přepsáno {tips_overwritten} existujících"
            
            flash(f"""✅ Smart Import dokončen!
                  Vytvořeno {created_matches} nových zápasů
                  Použito {skipped_matches} existujících zápasů
                  Vytvořeno {users_created} nových uživatelů
                  {tips_message}
                  Importováno {results_imported} výsledků""", "ok")
            
            return redirect(url_for("admin_import"))
        
        except Exception as e:
            db.session.rollback()
            
            # Smaž temp files i při chybě
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            
            if preview_file and os.path.exists(preview_file):
                try:
                    os.unlink(preview_file)
                except:
                    pass
            
            flash(f"Chyba při importu: {str(e)}", "error")
            return redirect(url_for("admin_import_leaderboard_smart"))

    def _get_or_create_team(round_id: int, name: str) -> Team:
        import unicodedata
        
        name = (name or "").strip()
        if not name:
            raise ValueError("empty team")
        
        # Normalize Unicode (pro české znaky Š, Č, Ř, ...)
        name = unicodedata.normalize('NFC', name)
        
        # Flush změny aby jsme viděli všechny týmy včetně nově vytvořených
        db.session.flush()
        
        # PYTHON-based case-insensitive search (NEJSPOLEHLIVĚJŠÍ!)
        # Načti všechny týmy pro tento round
        all_teams = Team.query.filter_by(
            round_id=round_id,
            is_deleted=False
        ).all()
        
        # Najdi case-insensitive match s Unicode normalizací
        name_lower = name.lower()
        for t in all_teams:
            t_normalized = unicodedata.normalize('NFC', t.name)
            if t_normalized.lower() == name_lower:
                return t  # Našli jsme!
        
        # Tým neexistuje - vytvoř nový
        t = Team(round_id=round_id, name=name)
        db.session.add(t)
        db.session.flush()  # Flush aby byl dostupný pro další volání
        
        audit("team.create.auto", "Team", t.id, round_id=round_id, name=name)
        return t

    @app.route("/admin/import/teams/template")
    @login_required
    def admin_import_teams_template():
        """Stáhni Excel šablonu pro import týmů"""
        admin_required()
        import openpyxl
        from openpyxl.styles import PatternFill, Font, Alignment
        from io import BytesIO

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Týmy"

        # Header
        headers = ["name", "group", "country_code"]
        header_fill = PatternFill("solid", fgColor="4472C4")
        header_font = Font(color="FFFFFF", bold=True)

        for col, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=h)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")

        # Příklady
        examples = [
            ("Sparta Praha", "A", "CZ"),
            ("Slavia Praha", "A", "CZ"),
            ("Barcelona", "B", "ES"),
            ("Real Madrid", "B", "ES"),
        ]

        gray_fill = PatternFill("solid", fgColor="F2F2F2")
        for row_i, (name, grp, code) in enumerate(examples, 2):
            fill = gray_fill if row_i % 2 == 0 else PatternFill()
            for col, val in enumerate([name, grp, code], 1):
                cell = ws.cell(row=row_i, column=col, value=val)
                cell.fill = fill

        ws.column_dimensions["A"].width = 30
        ws.column_dimensions["B"].width = 12
        ws.column_dimensions["C"].width = 15

        # Popis
        ws2 = wb.create_sheet("Popis")
        ws2["A1"], ws2["B1"] = "Sloupec", "Popis"
        ws2["A1"].font = ws2["B1"].font = Font(bold=True)
        
        popis = [
            ("name", "POVINNÉ - název týmu"),
            ("group", "VOLITELNÉ - skupina (A, B, C...)"),
            ("country_code", "VOLITELNÉ - kód země (CZ, SK, DE...)"),
        ]
        for row_i, (col, desc) in enumerate(popis, 2):
            ws2[f"A{row_i}"] = col
            ws2[f"B{row_i}"] = desc
        ws2.column_dimensions["A"].width = 20
        ws2.column_dimensions["B"].width = 40

        out = BytesIO()
        wb.save(out)
        out.seek(0)
        from flask import send_file
        return send_file(out,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         download_name="sablona_tymy.xlsx",
                         as_attachment=True)

    @app.route("/admin/import/teams", methods=["GET", "POST"])
    @login_required
    def admin_import_teams():
        admin_required()
        import os, pickle
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(400)

        if request.method == "POST":
            action = request.form.get("action", "upload")

            # ── KROK 2: POTVRZENÍ ──────────────────────────────────────────
            if action == "confirm":
                preview_file = session.get("teams_import_preview_file")
                round_id = session.get("teams_import_round_id")
                overwrite = session.get("teams_import_overwrite", False)

                if not preview_file or not os.path.exists(preview_file):
                    flash("Session vypršela, nahraj soubor znovu.", "error")
                    return redirect(url_for("admin_import_teams"))

                r2 = db.session.get(Round, round_id) if round_id else r

                with open(preview_file, "rb") as f:
                    rows_data = pickle.load(f)
                os.unlink(preview_file)
                session.pop("teams_import_preview_file", None)
                session.pop("teams_import_round_id", None)
                session.pop("teams_import_overwrite", None)

                created = skipped = updated = 0
                for row in rows_data:
                    if row["status"] == "skip":
                        skipped += 1
                        continue

                    name = row["name"]
                    existing = Team.query.filter_by(
                        round_id=r2.id, is_deleted=False
                    ).filter(db.func.lower(Team.name) == name.lower()).first()

                    if existing:
                        if overwrite:
                            # Aktualizuj group/country_code pokud je v importu
                            if row.get("group"):
                                existing.group = row["group"]
                            if row.get("country_code"):
                                existing.country_code = row["country_code"]
                            db.session.flush()
                            updated += 1
                        else:
                            skipped += 1
                    else:
                        team = Team(
                            round_id=r2.id,
                            name=name,
                            group=row.get("group"),
                            country_code=row.get("country_code")
                        )
                        db.session.add(team)
                        db.session.flush()
                        created += 1

                db.session.commit()
                audit("import.teams.excel", "Round", r2.id, created=created, updated=updated, skipped=skipped)
                flash(f"Import týmů hotov: vytvořeno {created}, aktualizováno {updated}, přeskočeno {skipped}.", "ok")
                return redirect(url_for("teams"))

            # ── KROK 1: UPLOAD + PREVIEW ───────────────────────────────────
            import openpyxl, tempfile
            from io import BytesIO

            file = request.files.get("excel_file")
            if not file or not file.filename:
                flash("Nahraj Excel soubor.", "error")
                return redirect(url_for("admin_import_teams"))

            overwrite = request.form.get("overwrite") == "1"

            try:
                wb = openpyxl.load_workbook(BytesIO(file.read()))
                ws = wb.active
                rows = list(ws.iter_rows(values_only=True))

                if len(rows) < 2:
                    flash("Soubor musí mít hlavičku a alespoň jeden řádek.", "error")
                    return redirect(url_for("admin_import_teams"))

                header = [str(h).strip().lower() if h else "" for h in rows[0]]

                # Najdi sloupce
                def col(name):
                    return header.index(name) if name in header else None

                name_col = col("name")
                if name_col is None:
                    flash("Chybí sloupec 'name'. Zkontroluj šablonu.", "error")
                    return redirect(url_for("admin_import_teams"))

                grp_col = col("group")
                code_col = col("country_code")

                # Existující týmy
                existing_teams = Team.query.filter_by(
                    round_id=r.id, is_deleted=False
                ).all()
                existing_lower = {t.name.lower(): t for t in existing_teams}

                preview_rows = []
                for data_row in rows[1:]:
                    name = str(data_row[name_col]).strip() if data_row[name_col] else ""
                    if not name or name.lower() == "none":
                        continue

                    group = str(data_row[grp_col]).strip() if grp_col is not None and data_row[grp_col] else None
                    country_code = str(data_row[code_col]).strip() if code_col is not None and data_row[code_col] else None

                    # Status
                    if name.lower() in existing_lower:
                        status = "overwrite" if overwrite else "skip"
                    else:
                        status = "new"

                    preview_rows.append({
                        "name": name,
                        "group": group,
                        "country_code": country_code,
                        "status": status,
                    })

                if not preview_rows:
                    flash("Soubor neobsahuje žádné platné týmy.", "error")
                    return redirect(url_for("admin_import_teams"))

                # Ulož do temp file
                fd, preview_path = tempfile.mkstemp(suffix=".pkl", prefix="teams_import_")
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(preview_rows, f)

                session["teams_import_preview_file"] = preview_path
                session["teams_import_round_id"] = r.id
                session["teams_import_overwrite"] = overwrite

                new_count = sum(1 for x in preview_rows if x["status"] == "new")
                overwrite_count = sum(1 for x in preview_rows if x["status"] == "overwrite")
                skip_count = sum(1 for x in preview_rows if x["status"] == "skip")

                return render_page(r"""
<style>
.preview-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.preview-table th { background: rgba(255,255,255,.07); padding: 10px 12px; text-align: left; }
.preview-table td { padding: 10px 12px; border-bottom: 1px solid var(--line); }
.badge-new    { background: rgba(51,209,122,.2);  color: #33d17a; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.badge-skip   { background: rgba(167,178,214,.15); color: #a7b2d6; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.badge-over   { background: rgba(110,168,254,.2);  color: #6ea8fe; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
</style>

<div class="card">
  <h2 style="margin:0 0 4px 0;">📋 Preview – Týmy</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>

  <div class="row" style="gap:16px; margin: 16px 0; flex-wrap:wrap;">
    <div style="padding:12px 20px; background:rgba(51,209,122,.1); border:1px solid rgba(51,209,122,.3); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#33d17a;">{{ new_count }}</div>
      <div class="muted" style="font-size:12px;">Nových</div>
    </div>
    <div style="padding:12px 20px; background:rgba(110,168,254,.1); border:1px solid rgba(110,168,254,.3); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#6ea8fe;">{{ overwrite_count }}</div>
      <div class="muted" style="font-size:12px;">Aktualizovaných</div>
    </div>
    <div style="padding:12px 20px; background:rgba(167,178,214,.1); border:1px solid rgba(167,178,214,.2); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#a7b2d6;">{{ skip_count }}</div>
      <div class="muted" style="font-size:12px;">Přeskočených</div>
    </div>
  </div>

  <div style="overflow-x:auto; margin-bottom:20px;">
    <table class="preview-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Název týmu</th>
          <th>Skupina</th>
          <th>Země</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {% for row in preview_rows %}
        <tr>
          <td class="muted">{{ loop.index }}</td>
          <td>{{ row.name }}</td>
          <td class="muted">{{ row.group or '—' }}</td>
          <td class="muted">{{ row.country_code or '—' }}</td>
          <td>
            {% if row.status == 'new' %}
              <span class="badge-new">✨ Nový</span>
            {% elif row.status == 'overwrite' %}
              <span class="badge-over">✏️ Aktualizovat</span>
            {% else %}
              <span class="badge-skip">⏭ Přeskočit</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <form method="post" style="display:flex; gap:12px; flex-wrap:wrap;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="action" value="confirm">
    <button type="submit" class="btn btn-primary">✅ Potvrdit import</button>
    <a href="{{ url_for('admin_import_teams') }}" class="btn">✕ Zrušit</a>
  </form>
</div>
""", r=r, preview_rows=preview_rows,
     new_count=new_count, overwrite_count=overwrite_count, skip_count=skip_count)

            except Exception as e:
                flash(f"Chyba při čtení souboru: {e}", "error")
                return redirect(url_for("admin_import_teams"))

        # === GET: Zobraz formulář ===
        return render_page(r"""
<style>
.upload-zone {
  border: 2px dashed rgba(110,168,254,0.4);
  border-radius: 12px;
  padding: 40px;
  text-align: center;
  background: rgba(110,168,254,0.05);
  cursor: pointer;
  transition: all 0.2s;
}
.upload-zone:hover {
  border-color: rgba(110,168,254,0.7);
  background: rgba(110,168,254,0.1);
}
</style>

<div class="card">
  <div class="row" style="justify-content:space-between; margin-bottom:20px;">
    <div>
      <h2 style="margin:0 0 4px 0;">📥 Import týmů (Excel)</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <a href="{{ url_for('admin_import_teams_template') }}" class="btn"
       style="background:rgba(51,209,122,.15); color:#33d17a; border:1px solid rgba(51,209,122,.3);">
      📄 Stáhnout šablonu
    </a>
  </div>

  <div class="muted" style="margin-bottom:20px; padding:12px 16px; background:rgba(110,168,254,0.08); border:1px solid rgba(110,168,254,0.2); border-radius:8px;">
    💡 <strong>Formát Excel (sloupce):</strong><br>
    <code>name</code> – povinný, název týmu<br>
    <code>group</code> – volitelný, skupina (A, B, C...)<br>
    <code>country_code</code> – volitelný, kód země (CZ, SK, DE...)
  </div>

  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="upload-zone" onclick="document.getElementById('xl').click()">
      <div style="font-size:48px; margin-bottom:12px;">📊</div>
      <div style="font-weight:700; margin-bottom:8px;">Klikni nebo přetáhni Excel soubor</div>
      <div class="muted">.xlsx • max 10 MB</div>
      <input type="file" id="xl" name="excel_file" accept=".xlsx" style="display:none"
             onchange="document.getElementById('fname').textContent = this.files[0]?.name || ''">
    </div>
    <div id="fname" class="muted" style="margin-bottom:16px; text-align:center;"></div>

    <div style="padding:14px; background:rgba(110,168,254,.08); border:1px solid rgba(110,168,254,.2); border-radius:8px; margin-bottom:20px;">
      <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
        <input type="checkbox" name="overwrite" value="1" style="width:18px; height:18px;">
        <div>
          <strong>Přepsat existující týmy</strong>
          <div class="muted" style="font-size:12px;">Aktualizuje skupinu a kód země. Bez zaškrtnutí se přeskočí.</div>
        </div>
      </label>
    </div>

    <div class="row" style="gap:12px;">
      <button type="submit" class="btn btn-primary">📋 Zobrazit preview</button>
      <a href="{{ url_for('admin_import') }}" class="btn">← Zpět</a>
    </div>
  </form>
</div>
""", r=r)

    @app.route("/admin/import/matches/template")
    @login_required
    def admin_import_matches_template():
        """Stáhne Excel šablonu pro import zápasů"""
        admin_required()
        
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill
            from io import BytesIO
            
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Zápasy"
            
            # Hlavička
            headers = ['Datum', 'Domácí', 'Hosté', 'Čas']
            ws.append(headers)
            
            # Stylování
            for col in range(1, 5):
                cell = ws.cell(row=1, column=col)
                cell.fill = PatternFill(start_color="6EA8FE", end_color="6EA8FE", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF")
            
            # Příklad
            ws.append(['2024-03-15', 'Sparta Praha', 'Slavia Praha', '18:00'])
            ws.append(['2024-03-16', 'Plzeň', 'Brno', '16:30'])
            
            # Šířka sloupců
            ws.column_dimensions['A'].width = 12
            ws.column_dimensions['B'].width = 20
            ws.column_dimensions['C'].width = 20
            ws.column_dimensions['D'].width = 10
            
            # Poznámky
            notes = wb.create_sheet("Poznámky")
            notes['A1'] = "FORMÁT ZÁPASŮ"
            notes['A1'].font = Font(bold=True, size=14)
            notes['A3'] = "Datum: YYYY-MM-DD (např. 2024-03-15)"
            notes['A4'] = "Domácí: Název týmu"
            notes['A5'] = "Hosté: Název týmu"
            notes['A6'] = "Čas: HH:MM (např. 18:00)"
            notes.column_dimensions['A'].width = 50
            
            output = BytesIO()
            wb.save(output)
            output.seek(0)
            
            return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                           as_attachment=True, download_name='import_zapasu_sablona.xlsx')
        except Exception as e:
            flash(f"Chyba: {str(e)}", "error")
            return redirect(url_for("admin_import"))

    @app.route("/admin/import/matches", methods=["GET", "POST"])
    @login_required
    def admin_import_matches():
        admin_required()
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(400)

        if request.method == "POST":
            # Kontrola, jestli je CSV nebo Excel
            if 'excel_file' in request.files and request.files['excel_file'].filename:
                # Import z Excelu
                file = request.files['excel_file']
                try:
                    import openpyxl
                    from io import BytesIO

                    wb = openpyxl.load_workbook(BytesIO(file.read()))
                    ws = wb.active

                    created = 0
                    skipped = 0

                    for row in ws.iter_rows(min_row=2, values_only=True):  # Skip header
                        if not row or not any(row):
                            continue

                        # Formát: Datum, Domácí, Hosté, Čas, Liga
                        date_val = row[0] if len(row) > 0 else None
                        home = (str(row[1]) if len(row) > 1 and row[1] else "").strip()
                        away = (str(row[2]) if len(row) > 2 and row[2] else "").strip()
                        time_val = row[3] if len(row) > 3 else None

                        if not home or not away or home == away:
                            skipped += 1
                            continue

                        # Parsování datumu a času
                        start = None
                        if date_val and time_val:
                            try:
                                from datetime import datetime as dt_mod
                                if isinstance(date_val, str):
                                    date_str = date_val
                                else:
                                    date_str = date_val.strftime("%Y-%m-%d")

                                if isinstance(time_val, str):
                                    time_str = time_val
                                else:
                                    time_str = time_val.strftime("%H:%M")

                                start = dt_mod.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
                            except:
                                pass

                        ht = _get_or_create_team(r.id, home)
                        at = _get_or_create_team(r.id, away)

                        existing = Match.query.filter_by(
                            round_id=r.id,
                            home_team_id=ht.id,
                            away_team_id=at.id,
                            is_deleted=False
                        ).first()

                        if existing:
                            skipped += 1
                            continue

                        m = Match(round_id=r.id, home_team_id=ht.id, away_team_id=at.id, start_time=start)
                        db.session.add(m)
                        created += 1

                    db.session.commit()
                    audit("import.matches.excel", "Round", r.id, created=created, skipped=skipped)
                    flash(f"Import z Excelu hotov: vytvořeno {created}, přeskočeno {skipped}.", "ok")
                    return redirect(url_for("matches"))

                except Exception as e:
                    flash(f"Chyba při importu z Excelu: {str(e)}", "error")
                    return redirect(url_for("admin_import_matches"))
            else:
                # CSV import (původní kód)
                csv_text = (request.form.get("csv_text") or "").strip()
                if not csv_text:
                    flash("Vlož CSV nebo nahraj Excel soubor.", "error")
                    return redirect(url_for("admin_import_matches"))
                reader = csv.DictReader(io.StringIO(csv_text))
                created = 0
                skipped = 0
                for row in reader:
                    rrid = _resolve_round_id(row, r.id)
                    home = (row.get("home_team") or row.get("home") or "").strip()
                    away = (row.get("away_team") or row.get("away") or "").strip()
                    start = parse_naive_datetime((row.get("start_time") or row.get("start") or "").strip())
                    if not home or not away or home == away:
                        skipped += 1
                        continue
                    ht = _get_or_create_team(rrid, home)
                    at = _get_or_create_team(rrid, away)
                    existing = Match.query.filter_by(round_id=rrid, home_team_id=ht.id, away_team_id=at.id, start_time=start, is_deleted=False).first()
                    if existing:
                        skipped += 1
                        continue
                    m = Match(round_id=rrid, home_team_id=ht.id, away_team_id=at.id, start_time=start)
                    hs = (row.get("home_score") or "").strip()
                    aas = (row.get("away_score") or "").strip()
                    if hs != "":
                        m.home_score = int(hs)
                    if aas != "":
                        m.away_score = int(aas)
                    db.session.add(m)
                    created += 1
                db.session.commit()
                audit("import.matches", "Round", r.id, created=created, skipped=skipped)
                flash(f"Import zápasů hotov: vytvořeno {created}, přeskočeno {skipped}.", "ok")
                return redirect(url_for("matches"))

        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between; align-items:flex-start;">
    <div>
      <h2 style="margin:0 0 8px 0;">Import zápasů</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <a href="{{ url_for('admin_import_matches_template') }}" class="btn" style="background:#6ea8fe; color:white;">
      📥 Stáhnout šablonu Excel
    </a>
  </div>
  <hr class="sep">

  <h3 style="margin:20px 0 10px 0;">Import z Excel souboru</h3>
  <div class="muted" style="margin-bottom:10px;">
    Formát: 1. sloupec = Datum, 2. = Domácí, 3. = Hosté, 4. = Čas, 5. = Liga (volitelné)<br>
    První řádek je hlavička (přeskočí se)
  </div>
  <form method="post" enctype="multipart/form-data" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="file" name="excel_file" accept=".xlsx,.xls" required>
    <button class="btn btn-primary" type="submit">Importovat z Excelu</button>
  </form>

  <hr class="sep" style="margin:20px 0;">

  <h3 style="margin:20px 0 10px 0;">Import z CSV (klasický)</h3>
  <div class="muted">Sloupce: <b>round_id</b> (volitelné), <b>home_team</b>, <b>away_team</b>, <b>start_time</b> (YYYY-MM-DD HH:MM), volitelně <b>home_score</b>, <b>away_score</b></div>
  <form method="post" class="row" style="flex-direction:column; align-items:stretch; gap:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <textarea name="csv_text" placeholder="round_id,home_team,away_team,start_time,home_score,away_score&#10;{{ r.id }},Sparta,Slavia,2026-02-10 18:00,,"></textarea>
    <button class="btn btn-primary" type="submit">Importovat CSV</button>
  </form>

  <hr class="sep">
  <a class="btn" href="{{ url_for('admin_import') }}">Zpět</a>
</div>
""", r=r)

    @app.route("/admin/import/extras/template")
    @login_required
    def admin_import_extras_template():
        """Stáhni Excel šablonu pro import extra otázek"""
        admin_required()
        import openpyxl
        from openpyxl.styles import PatternFill, Font, Alignment
        from io import BytesIO

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Extra otázky"

        # Header - user + příklady otázek
        headers = ["user", "Vítězný tým", "Kanadaské bodování", "Střelec turnaje"]
        header_fill_user = PatternFill("solid", fgColor="2F4F8F")
        header_fill_q    = PatternFill("solid", fgColor="4472C4")
        header_font      = Font(color="FFFFFF", bold=True)

        for col, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=h)
            cell.fill = header_fill_user if col == 1 else header_fill_q
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")

        # Příklady
        examples = [
            ("Václav",   "Kanada",  "MacKinnon", "McDavid"),
            ("Mejla",    "Kanada",  "McDavid",   "McDavid"),
            ("Ondejsek", "Švédsko", "McDavid",   "MacKinnon"),
        ]
        gray_fill = PatternFill("solid", fgColor="F2F2F2")
        for row_i, row_data in enumerate(examples, 2):
            fill = gray_fill if row_i % 2 == 0 else PatternFill()
            for col, val in enumerate(row_data, 1):
                cell = ws.cell(row=row_i, column=col, value=val)
                cell.fill = fill

        ws.column_dimensions["A"].width = 18
        for col_letter in ["B", "C", "D"]:
            ws.column_dimensions[col_letter].width = 28

        # Sheet 2 - popis
        ws2 = wb.create_sheet("Popis")
        ws2["A1"], ws2["B1"] = "Sloupec", "Popis"
        ws2["A1"].font = ws2["B1"].font = Font(bold=True)
        ws2["A2"] = "user"
        ws2["B2"] = "POVINNÉ - přesný username uživatele (case-insensitive)"
        ws2["A3"] = "Název otázky (2. sloupec a dál)"
        ws2["B3"] = "Každý sloupec = jedna extra otázka. Buňka = odpověď uživatele."
        ws2.column_dimensions["A"].width = 30
        ws2.column_dimensions["B"].width = 55

        out = BytesIO()
        wb.save(out)
        out.seek(0)
        from flask import send_file
        return send_file(out,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         download_name="sablona_extra_otazky.xlsx",
                         as_attachment=True)

    @app.route("/admin/import/extras", methods=["GET", "POST"])
    @login_required
    def admin_import_extras():
        admin_required()
        import os, pickle
        rid = ensure_selected_round()
        r = db.session.get(Round, rid) if rid else None
        if not r:
            abort(400)

        if request.method == "POST":
            action = request.form.get("action", "upload")

            # ── KROK 2: POTVRZENÍ ──────────────────────────────────────────
            if action == "confirm":

                preview_file = session.get("extra_import_preview_file")
                round_id     = session.get("extra_import_round_id")
                overwrite    = session.get("extra_import_overwrite", False)

                if not preview_file or not os.path.exists(preview_file):
                    flash("Session vypršela, nahraj soubor znovu.", "error")
                    return redirect(url_for("admin_import_extras"))

                r2 = db.session.get(Round, round_id) if round_id else r

                with open(preview_file, "rb") as f:
                    preview_data = pickle.load(f)
                os.unlink(preview_file)
                session.pop("extra_import_preview_file", None)
                session.pop("extra_import_round_id", None)
                session.pop("extra_import_overwrite", None)

                questions_data = preview_data["questions"]   # [{text, q_obj_or_None}]
                rows_data      = preview_data["rows"]        # [{user, answers:[{q_idx, answer, status}]}]

                # 1) Vytvoř/najdi otázky
                q_objects = []
                for qd in questions_data:
                    q_text = qd["text"]
                    existing_q = ExtraQuestion.query.filter_by(
                        round_id=r2.id, is_deleted=False
                    ).filter(db.func.lower(ExtraQuestion.question) == q_text.lower()).first()
                    if not existing_q:
                        existing_q = ExtraQuestion(round_id=r2.id, question=q_text)
                        db.session.add(existing_q)
                        db.session.flush()
                    q_objects.append(existing_q)

                # 2) Zpracuj odpovědi
                created = skipped = updated = 0
                for row in rows_data:
                    user = row["user"]
                    if user is None:
                        skipped += len(row["answers"])
                        continue
                    for ans_data in row["answers"]:
                        if ans_data["status"] == "skip":
                            skipped += 1
                            continue
                        q_obj   = q_objects[ans_data["q_idx"]]
                        ans_txt = ans_data["answer"]
                        existing_ans = ExtraAnswer.query.filter_by(
                            question_id=q_obj.id, user_id=user.id
                        ).first()
                        if existing_ans:
                            if overwrite:
                                existing_ans.answer_text = ans_txt
                                updated += 1
                            else:
                                skipped += 1
                        else:
                            db.session.add(ExtraAnswer(
                                question_id=q_obj.id,
                                user_id=user.id,
                                answer_text=ans_txt
                            ))
                            created += 1

                db.session.commit()
                audit("import.extras.excel", "Round", r2.id,
                      created=created, updated=updated, skipped=skipped)
                flash(f"Import extra otázek hotov: vytvořeno {created}, "
                      f"aktualizováno {updated}, přeskočeno {skipped}.", "ok")
                return redirect(url_for("extras"))

            # ── KROK 1: UPLOAD + PREVIEW ───────────────────────────────────
            import openpyxl, tempfile
            from io import BytesIO

            file = request.files.get("excel_file")
            if not file or not file.filename:
                flash("Nahraj Excel soubor.", "error")
                return redirect(url_for("admin_import_extras"))

            overwrite = request.form.get("overwrite") == "1"

            try:
                wb   = openpyxl.load_workbook(BytesIO(file.read()))
                ws   = wb.active
                rows = list(ws.iter_rows(values_only=True))

                if len(rows) < 2:
                    flash("Soubor musí mít hlavičku a alespoň jeden řádek.", "error")
                    return redirect(url_for("admin_import_extras"))

                header = rows[0]
                if not header or len(header) < 2:
                    flash("Hlavička musí mít alespoň 2 sloupce (user + otázka).", "error")
                    return redirect(url_for("admin_import_extras"))

                # Otázky = sloupce 2..N
                question_texts = []
                for h in header[1:]:
                    if h and str(h).strip():
                        question_texts.append(str(h).strip())

                if not question_texts:
                    flash("Nenašel jsem žádné otázky v hlavičce.", "error")
                    return redirect(url_for("admin_import_extras"))

                # Existující otázky a odpovědi
                existing_qs = {
                    eq.question.lower(): eq
                    for eq in ExtraQuestion.query.filter_by(round_id=r.id, is_deleted=False).all()
                }
                existing_answers = {}  # (question_id, user_id) → ExtraAnswer
                for ans in ExtraAnswer.query.join(ExtraQuestion).filter(
                    ExtraQuestion.round_id == r.id,
                    ExtraQuestion.is_deleted == False
                ).all():
                    existing_answers[(ans.question_id, ans.user_id)] = ans

                # Všichni uživatelé (case-insensitive lookup)
                import unicodedata
                all_users = User.query.all()
                user_map  = {}
                for u in all_users:
                    norm = unicodedata.normalize("NFC", u.username).lower()
                    user_map[norm] = u

                # Info o otázkách pro preview
                questions_preview = []
                for qt in question_texts:
                    is_new = qt.lower() not in existing_qs
                    questions_preview.append({"text": qt, "is_new": is_new})

                # Zpracuj řádky
                preview_rows = []
                for data_row in rows[1:]:
                    username_raw = str(data_row[0]).strip() if data_row[0] else ""
                    if not username_raw or username_raw.lower() == "none":
                        continue

                    norm_name = unicodedata.normalize("NFC", username_raw).lower()
                    user_obj  = user_map.get(norm_name)

                    answers = []
                    for q_idx, qt in enumerate(question_texts):
                        col_idx = q_idx + 1
                        ans_val = str(data_row[col_idx]).strip() if (col_idx < len(data_row) and data_row[col_idx]) else ""
                        if not ans_val or ans_val.lower() == "none":
                            status = "skip"
                        elif user_obj is None:
                            status = "unknown_user"
                        else:
                            existing_q = existing_qs.get(qt.lower())
                            if existing_q and (existing_q.id, user_obj.id) in existing_answers:
                                status = "overwrite" if overwrite else "skip"
                            else:
                                status = "new"

                        answers.append({
                            "q_idx":  q_idx,
                            "answer": ans_val,
                            "status": status,
                        })

                    preview_rows.append({
                        "username_raw": username_raw,
                        "user":         user_obj,
                        "answers":      answers,
                    })

                if not preview_rows:
                    flash("Soubor neobsahuje žádné platné řádky.", "error")
                    return redirect(url_for("admin_import_extras"))

                # Ulož do temp souboru
                fd, preview_path = tempfile.mkstemp(suffix=".pkl", prefix="extra_import_")
                with os.fdopen(fd, "wb") as f:
                    pickle.dump({
                        "questions": [{"text": qt} for qt in question_texts],
                        "rows":      preview_rows,
                    }, f)

                session["extra_import_preview_file"] = preview_path
                session["extra_import_round_id"]     = r.id
                session["extra_import_overwrite"]    = overwrite

                # Počty pro preview
                new_cnt  = sum(1 for row in preview_rows for a in row["answers"] if a["status"] == "new")
                over_cnt = sum(1 for row in preview_rows for a in row["answers"] if a["status"] == "overwrite")
                skip_cnt = sum(1 for row in preview_rows for a in row["answers"] if a["status"] in ("skip", "unknown_user"))
                unk_users = [row["username_raw"] for row in preview_rows if row["user"] is None]

                return render_page(r"""
<style>
.prev-table { width:100%; border-collapse:collapse; font-size:13px; }
.prev-table th { background:rgba(255,255,255,.07); padding:10px 12px; text-align:left; white-space:nowrap; }
.prev-table td { padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:middle; }
.badge-new  { background:rgba(51,209,122,.2);  color:#33d17a; padding:3px 7px; border-radius:4px; font-size:11px; font-weight:700; }
.badge-skip { background:rgba(167,178,214,.15);color:#a7b2d6; padding:3px 7px; border-radius:4px; font-size:11px; font-weight:700; }
.badge-over { background:rgba(110,168,254,.2); color:#6ea8fe; padding:3px 7px; border-radius:4px; font-size:11px; font-weight:700; }
.badge-unk  { background:rgba(255,77,109,.2);  color:#ff4d6d; padding:3px 7px; border-radius:4px; font-size:11px; font-weight:700; }
.q-header   { writing-mode:vertical-rl; transform:rotate(180deg); white-space:nowrap; padding:8px 4px; max-height:120px; font-size:12px; }
</style>

<div class="card">
  <h2 style="margin:0 0 4px 0;">📋 Preview – Extra otázky</h2>
  <div class="muted">Soutěž: <b>{{ r.name }}</b></div>

  {% if unk_users %}
  <div style="margin:16px 0; padding:12px 16px; background:rgba(255,77,109,.1); border:1px solid rgba(255,77,109,.3); border-radius:8px;">
    ⚠️ <strong>Nenalezení uživatelé</strong> (budou přeskočeni):
    {% for u in unk_users %}<code style="margin-left:8px;">{{ u }}</code>{% endfor %}
  </div>
  {% endif %}

  <div class="row" style="gap:16px; margin:16px 0; flex-wrap:wrap;">
    <div style="padding:12px 20px; background:rgba(51,209,122,.1); border:1px solid rgba(51,209,122,.3); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#33d17a;">{{ new_cnt }}</div>
      <div class="muted" style="font-size:12px;">Nových odpovědí</div>
    </div>
    <div style="padding:12px 20px; background:rgba(110,168,254,.1); border:1px solid rgba(110,168,254,.3); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#6ea8fe;">{{ over_cnt }}</div>
      <div class="muted" style="font-size:12px;">Aktualizovaných</div>
    </div>
    <div style="padding:12px 20px; background:rgba(167,178,214,.1); border:1px solid rgba(167,178,214,.2); border-radius:8px; text-align:center;">
      <div style="font-size:28px; font-weight:900; color:#a7b2d6;">{{ skip_cnt }}</div>
      <div class="muted" style="font-size:12px;">Přeskočených</div>
    </div>
  </div>

  <div style="overflow-x:auto; margin-bottom:20px;">
    <table class="prev-table">
      <thead>
        <tr>
          <th>User</th>
          {% for q in questions_preview %}
            <th style="text-align:center;">
              <div class="q-header">
                {{ q.text }}
                {% if q.is_new %}<span style="color:#33d17a; font-size:10px;"> ✨</span>{% endif %}
              </div>
            </th>
          {% endfor %}
        </tr>
      </thead>
      <tbody>
        {% for row in preview_rows %}
        <tr>
          <td>
            {% if row.user %}
              <strong>{{ row.user.display_name }}</strong>
            {% else %}
              <span class="badge-unk">❓ {{ row.username_raw }}</span>
            {% endif %}
          </td>
          {% for ans in row.answers %}
          <td style="text-align:center;">
            {% if ans.status == 'new' %}
              <div style="font-size:12px; margin-bottom:3px;">{{ ans.answer }}</div>
              <span class="badge-new">✨</span>
            {% elif ans.status == 'overwrite' %}
              <div style="font-size:12px; margin-bottom:3px;">{{ ans.answer }}</div>
              <span class="badge-over">✏️</span>
            {% elif ans.status == 'unknown_user' %}
              <span class="badge-unk">—</span>
            {% else %}
              <span class="badge-skip">—</span>
            {% endif %}
          </td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <form method="post" style="display:flex; gap:12px; flex-wrap:wrap;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="hidden" name="action" value="confirm">
    <button type="submit" class="btn btn-primary">✅ Potvrdit import</button>
    <a href="{{ url_for('admin_import_extras') }}" class="btn">✕ Zrušit</a>
  </form>
</div>
""", r=r,
     preview_rows=preview_rows,
     questions_preview=questions_preview,
     new_cnt=new_cnt, over_cnt=over_cnt, skip_cnt=skip_cnt,
     unk_users=unk_users)

            except Exception as e:
                import traceback
                flash(f"Chyba při čtení souboru: {e}", "error")
                return redirect(url_for("admin_import_extras"))

        # ── GET: formulář ──────────────────────────────────────────────────
        return render_page(r"""
<style>
.upload-zone {
  border:2px dashed rgba(110,168,254,0.4); border-radius:12px; padding:40px;
  text-align:center; background:rgba(110,168,254,0.05); cursor:pointer; transition:all .2s;
}
.upload-zone:hover { border-color:rgba(110,168,254,0.7); background:rgba(110,168,254,0.1); }
</style>

<div class="card">
  <div class="row" style="justify-content:space-between; margin-bottom:20px;">
    <div>
      <h2 style="margin:0 0 4px 0;">📥 Import extra otázek (Excel)</h2>
      <div class="muted">Soutěž: <b>{{ r.name }}</b></div>
    </div>
    <a href="{{ url_for('admin_import_extras_template') }}" class="btn"
       style="background:rgba(51,209,122,.15); color:#33d17a; border:1px solid rgba(51,209,122,.3);">
      📄 Stáhnout šablonu
    </a>
  </div>

  <div style="margin-bottom:20px; padding:14px 16px; background:rgba(110,168,254,0.08); border:1px solid rgba(110,168,254,0.2); border-radius:8px; font-size:13px;">
    💡 <strong>Formát Excel:</strong><br><br>
    <table style="border-collapse:collapse; font-size:12px;">
      <thead>
        <tr style="background:rgba(255,255,255,.07);">
          <th style="padding:6px 12px; border:1px solid var(--line);">user</th>
          <th style="padding:6px 12px; border:1px solid var(--line);">Vítězný tým</th>
          <th style="padding:6px 12px; border:1px solid var(--line);">Kanadaské bodování</th>
          <th style="padding:6px 12px; border:1px solid var(--line);">Střelec</th>
        </tr>
      </thead>
      <tbody>
        <tr><td style="padding:6px 12px; border:1px solid var(--line);">Václav</td><td style="padding:6px 12px; border:1px solid var(--line);">Kanada</td><td style="padding:6px 12px; border:1px solid var(--line);">MacKinnon</td><td style="padding:6px 12px; border:1px solid var(--line);">McDavid</td></tr>
        <tr><td style="padding:6px 12px; border:1px solid var(--line);">Mejla</td><td style="padding:6px 12px; border:1px solid var(--line);">Kanada</td><td style="padding:6px 12px; border:1px solid var(--line);">McDavid</td><td style="padding:6px 12px; border:1px solid var(--line);">McDavid</td></tr>
      </tbody>
    </table>
    <div class="muted" style="margin-top:10px;">
      • 1. sloupec = <strong>user</strong> (username uživatele)<br>
      • Další sloupce = názvy extra otázek<br>
      • Buňky = odpovědi uživatelů<br>
      • Nové otázky se vytvoří automaticky ✨
    </div>
  </div>

  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div class="upload-zone" onclick="document.getElementById('xl').click()">
      <div style="font-size:48px; margin-bottom:12px;">📊</div>
      <div style="font-weight:700; margin-bottom:8px;">Klikni nebo přetáhni Excel soubor</div>
      <div class="muted">.xlsx • max 10 MB</div>
      <input type="file" id="xl" name="excel_file" accept=".xlsx" style="display:none"
             onchange="document.getElementById('fname').textContent = this.files[0]?.name || ''">
    </div>
    <div id="fname" class="muted" style="margin:8px 0 16px 0; text-align:center;"></div>

    <div style="padding:14px; background:rgba(110,168,254,.08); border:1px solid rgba(110,168,254,.2); border-radius:8px; margin-bottom:20px;">
      <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
        <input type="checkbox" name="overwrite" value="1" style="width:18px; height:18px;">
        <div>
          <strong>Přepsat existující odpovědi</strong>
          <div class="muted" style="font-size:12px;">Bez zaškrtnutí se existující odpovědi přeskočí.</div>
        </div>
      </label>
    </div>

    <div class="row" style="gap:12px;">
      <button type="submit" class="btn btn-primary">📋 Zobrazit preview</button>
      <a href="{{ url_for('admin_import') }}" class="btn">← Zpět</a>
    </div>
  </form>
</div>
""", r=r)

    @app.route("/admin/import/leaderboard/template")
    @login_required
    def admin_import_leaderboard_template():
        """Stáhne Excel šablonu pro import žebříčku"""
        admin_required()
        
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill
            from io import BytesIO
            
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Žebříček"
            
            # Hlavička - Jméno | Zápasy (formát: "Domácí-Hosté")
            headers = ['Jméno', 'Sparta-Slavia', 'Plzeň-Brno', 'Baník-Bohemians']
            ws.append(headers)
            
            # Stylování
            for col in range(1, len(headers) + 1):
                cell = ws.cell(row=1, column=col)
                cell.fill = PatternFill(start_color="6EA8FE", end_color="6EA8FE", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF")
            
            # Příklady
            ws.append(['Jan Novák', '2:1', '1:1', '3:0'])
            ws.append(['Petr Svoboda', '1:2', '2:0', '1:1'])
            
            # Šířka sloupců
            ws.column_dimensions['A'].width = 20
            for col in ['B', 'C', 'D']:
                ws.column_dimensions[col].width = 15
            
            # Poznámky
            notes = wb.create_sheet("Poznámky")
            notes['A1'] = "FORMÁT ŽEBŘÍČKU"
            notes['A1'].font = Font(bold=True, size=14)
            notes['A3'] = "1. řádek = Hlavička"
            notes['A4'] = "   - První sloupec: 'Jméno'"
            notes['A5'] = "   - Další sloupce: názvy zápasů (formát: 'Domácí-Hosté')"
            notes['A7'] = "2+ řádky = Tipy uživatelů"
            notes['A8'] = "   - První sloupec: Jméno uživatele"
            notes['A9'] = "   - Další sloupce: tipy (formát: '2:1' nebo '1:0')"
            notes.column_dimensions['A'].width = 50
            
            output = BytesIO()
            wb.save(output)
            output.seek(0)
            
            return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                           as_attachment=True, download_name='import_zebricku_sablona.xlsx')
        except Exception as e:
            flash(f"Chyba: {str(e)}", "error")
            return redirect(url_for("admin_import"))

    @app.route("/admin/import/leaderboard", methods=["GET", "POST"])
    @login_required
    def admin_import_leaderboard():
        admin_required()

        if request.method == "POST":
            file = request.files.get('excel_file')
            if not file or not file.filename:
                flash("Nahraj Excel soubor.", "error")
                return redirect(url_for("admin_import_leaderboard"))

            # Určit cílovou soutěž
            import_target = request.form.get('import_target', 'existing')

            if import_target == 'new':
                new_round_name = request.form.get('new_round_name', '').strip()
                if not new_round_name:
                    flash("Zadej název nové soutěže.", "error")
                    return redirect(url_for("admin_import_leaderboard"))
                
                sport = Sport.query.filter_by(name="Fotbal").first()
                if not sport:
                    sport = Sport(name="Fotbal")
                    db.session.add(sport)
                    db.session.flush()

                r = Round(name=new_round_name, sport_id=sport.id, is_active=False)
                db.session.add(r)
                db.session.flush()
                round_id = r.id
            else:
                round_id = int(request.form.get('round_id', 0))
                r = db.session.get(Round, round_id)
                if not r:
                    flash("Vybraná soutěž neexistuje.", "error")
                    return redirect(url_for("admin_import_leaderboard"))

            try:
                import openpyxl
                from io import BytesIO
                from datetime import datetime as dt_parse

                wb = openpyxl.load_workbook(BytesIO(file.read()))
                ws = wb.active

                rows = list(ws.iter_rows(values_only=True))
                if len(rows) < 2:
                    flash("Soubor musí mít alespoň hlavičku a jeden řádek.", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                header = rows[0]
                if not header or len(header) < 2:
                    flash("Hlavička musí mít alespoň 2 sloupce.", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                # Parsovat zápasy z hlavičky
                matches_data = []
                for i, match_name in enumerate(header[1:], start=1):
                    if not match_name or str(match_name).strip() == "":
                        continue

                    match_str = str(match_name).strip()
                    for sep in ['-', ' vs ', ' x ', ':', ' – ']:
                        if sep in match_str:
                            parts = match_str.split(sep, 1)
                            if len(parts) == 2:
                                home = parts[0].strip()
                                away = parts[1].strip()
                                
                                # Detekovat možnou duplicitu
                                home_team_check = Team.query.filter(
                                    Team.round_id == round_id,
                                    Team.is_deleted == False,
                                    db.func.lower(Team.name) == home.lower()
                                ).first()
                                
                                away_team_check = Team.query.filter(
                                    Team.round_id == round_id,
                                    Team.is_deleted == False,
                                    db.func.lower(Team.name) == away.lower()
                                ).first()
                                
                                is_duplicate = False
                                if home_team_check and away_team_check:
                                    existing_match = Match.query.filter_by(
                                        round_id=round_id,
                                        home_team_id=home_team_check.id,
                                        away_team_id=away_team_check.id,
                                        is_deleted=False
                                    ).first()
                                    
                                    if existing_match:
                                        is_duplicate = True
                                
                                matches_data.append({
                                    'col': i,
                                    'home': home,
                                    'away': away,
                                    'is_duplicate': is_duplicate,
                                    'match_str': match_str
                                })
                                break

                if not matches_data:
                    flash("Nenalezeny žádné platné zápasy v hlavičce.", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                # Uložit preview data do session
                session['import_preview'] = {
                    'round_id': round_id,
                    'round_name': r.name,
                    'matches': matches_data,
                    'total_matches': len(matches_data),
                    'duplicates_count': sum(1 for m in matches_data if m['is_duplicate'])
                }
                
                return redirect(url_for("admin_import_leaderboard_preview"))

            except Exception as e:
                flash(f"Chyba při načítání souboru: {str(e)}", "error")
                db.session.rollback()
                return redirect(url_for("admin_import_leaderboard"))

            try:
                import openpyxl
                from io import BytesIO

                wb = openpyxl.load_workbook(BytesIO(file.read()))
                ws = wb.active

                # Načíst všechny řádky
                rows = list(ws.iter_rows(values_only=True))
                if len(rows) < 2:
                    flash("Soubor musí mít alespoň hlavičku a jeden řádek.", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                # První řádek = hlavička
                header = rows[0]
                if not header or len(header) < 2:
                    flash("Hlavička musí mít alespoň 2 sloupce (Tipér + zápasy).", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                # Parsovat hlavičku zápasů (sloupce od 2. dál)
                matches_data = []
                for i, match_name in enumerate(header[1:], start=1):
                    if not match_name or str(match_name).strip() == "":
                        continue

                    match_str = str(match_name).strip()
                    # Očekáváme formát jako "Slavia-Sparta" nebo "Slavia vs Sparta"
                    for sep in ['-', ' vs ', ' x ', ':']:
                        if sep in match_str:
                            parts = match_str.split(sep, 1)
                            if len(parts) == 2:
                                home = parts[0].strip()
                                away = parts[1].strip()
                                matches_data.append({'col': i, 'home': home, 'away': away})
                                break

                if not matches_data:
                    flash("Nenalezeny žádné platné zápasy v hlavičce (očekáván formát 'Domácí-Hosté').", "error")
                    return redirect(url_for("admin_import_leaderboard"))

                # Vytvořit/najít zápasy
                created_matches = 0
                match_map = {}  # col_index -> Match
                for md in matches_data:
                    home_team = _get_or_create_team(r.id, md['home'])
                    away_team = _get_or_create_team(r.id, md['away'])

                    # Zkusit najít existující zápas
                    m = Match.query.filter_by(
                        round_id=r.id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        is_deleted=False
                    ).first()

                    if not m:
                        m = Match(round_id=r.id, home_team_id=home_team.id, away_team_id=away_team.id)
                        db.session.add(m)
                        db.session.flush()
                        created_matches += 1

                    match_map[md['col']] = m

                # Zkontrolovat první řádek po hlavičce - může obsahovat výsledky
                # NEBO poslední řádek - výsledky mohou být i dole
                results_imported = 0
                data_rows_start = 1  # Od kterého řádku začínají tipy
                data_rows_end = len(rows)  # Kde končí tipy (může být zkráceno o poslední řádek)

                # KONTROLA 1: První řádek po hlavičce (rows[1])
                if len(rows) > 1:
                    first_data_row = rows[1]
                    first_cell = str(first_data_row[0]).strip() if first_data_row[0] else ""

                    # Pokud první buňka je prázdná, "Výsledek", "Result" nebo "Skóre", jedná se o řádek s výsledky
                    if first_cell.lower() in ['', 'výsledek', 'result', 'skóre', 'score', 'vysledek']:
                        # Importovat výsledky z druhého řádku
                        for col_idx, match in match_map.items():
                            if col_idx >= len(first_data_row):
                                continue

                            result_value = first_data_row[col_idx]
                            if not result_value:
                                continue

                            # Parsovat výsledek
                            home_score = None
                            away_score = None

                            # Excel time format
                            if hasattr(result_value, 'hour') and hasattr(result_value, 'minute'):
                                home_score = result_value.hour
                                away_score = result_value.minute
                            else:
                                # String format
                                result_str = str(result_value).strip()
                                if result_str and result_str not in ['-', '—', '']:
                                    for sep in [':', '-']:
                                        if sep in result_str:
                                            parts = result_str.split(sep, 1)
                                            if len(parts) == 2:
                                                try:
                                                    home_score = int(parts[0].strip())
                                                    away_score = int(parts[1].strip())
                                                    break
                                                except:
                                                    pass

                            if home_score is not None and away_score is not None:
                                match.home_score = home_score
                                match.away_score = away_score
                                results_imported += 1

                        # Přeskočit tento řádek při zpracování tipů
                        data_rows_start = 2
                        db.session.flush()

                # KONTROLA 2: Poslední řádek (rows[-1]) - NOVĚ!
                # Pouze pokud jsme NENAŠLI výsledky v prvním řádku
                if results_imported == 0 and len(rows) > 2:
                    last_row = rows[-1]
                    last_cell = str(last_row[0]).strip() if last_row[0] else ""

                    # Pokud poslední řádek má "Výsledek" nebo je prázdný
                    if last_cell.lower() in ['', 'výsledek', 'result', 'skóre', 'score', 'vysledek']:
                        # Importovat výsledky z posledního řádku
                        for col_idx, match in match_map.items():
                            if col_idx >= len(last_row):
                                continue

                            result_value = last_row[col_idx]
                            if not result_value:
                                continue

                            # Parsovat výsledek
                            home_score = None
                            away_score = None

                            # Excel time format
                            if hasattr(result_value, 'hour') and hasattr(result_value, 'minute'):
                                home_score = result_value.hour
                                away_score = result_value.minute
                            else:
                                # String format
                                result_str = str(result_value).strip()
                                if result_str and result_str not in ['-', '—', '']:
                                    for sep in [':', '-']:
                                        if sep in result_str:
                                            parts = result_str.split(sep, 1)
                                            if len(parts) == 2:
                                                try:
                                                    home_score = int(parts[0].strip())
                                                    away_score = int(parts[1].strip())
                                                    break
                                                except:
                                                    pass

                            if home_score is not None and away_score is not None:
                                match.home_score = home_score
                                match.away_score = away_score
                                results_imported += 1

                        # Vynechat poslední řádek při zpracování tipů
                        data_rows_end = len(rows) - 1
                        db.session.flush()

                # Procházet řádky s tipéry
                created_users = 0
                created_tips = 0
                skipped_tips = 0
                skipped_tips_details = []  # Seznam přeskočených tipů pro Excel report

                for row in rows[data_rows_start:data_rows_end]:  # Skip header, případně výsledky nahoře a případně výsledky dole
                    if not row or not any(row):
                        continue

                    username = str(row[0]).strip() if row[0] else ""
                    if not username:
                        continue

                    # Najít nebo vytvořit uživatele
                    email = f"{username.lower().replace(' ', '_')}@import.tipovacka"
                    user = User.query.filter_by(username=username).first()

                    if not user:
                        user = User(
                            email=email,
                            username=username,
                            role='user'
                        )
                        user.set_password('tipovacka123')  # Výchozí heslo
                        db.session.add(user)
                        db.session.flush()
                        created_users += 1

                    # Importovat tipy
                    for col_idx, match in match_map.items():
                        if col_idx >= len(row):
                            continue

                        cell_value = row[col_idx]
                        if not cell_value:
                            continue

                        # Parsovat tip
                        tip_home = None
                        tip_away = None

                        # OPRAVA: Excel často převádí "2:1" na časový formát "2:01:00"
                        # Zkontrolovat jestli je to datetime.time objekt
                        if hasattr(cell_value, 'hour') and hasattr(cell_value, 'minute'):
                            # Je to time objekt - použít hour jako domácí, minute jako hosté
                            tip_home = cell_value.hour
                            tip_away = cell_value.minute
                        else:
                            # Je to string - parsovat běžně
                            tip_str = str(cell_value).strip()
                            if not tip_str or tip_str in ['-', '—', '']:
                                continue

                            # Parsovat formát "2:1" nebo "2-1"
                            for sep in [':', '-']:
                                if sep in tip_str:
                                    parts = tip_str.split(sep, 1)
                                    if len(parts) == 2:
                                        try:
                                            tip_home = int(parts[0].strip())
                                            tip_away = int(parts[1].strip())
                                            break
                                        except:
                                            pass

                        if tip_home is None or tip_away is None:
                            skipped_tips += 1
                            # Zaznamenat detail přeskočeného tipu
                            match_name = f"{match.home_team.name if match.home_team else '?'}-{match.away_team.name if match.away_team else '?'}"
                            skipped_tips_details.append({
                                'user': username,
                                'match': match_name,
                                'value': str(cell_value) if cell_value else '(prázdné)',
                                'reason': 'Nepodařilo se parsovat tip (očekáván formát "2:1" nebo "2-1")'
                            })
                            continue

                        # Vytvořit nebo aktualizovat tip
                        existing_tip = Tip.query.filter_by(
                            user_id=user.id,
                            match_id=match.id
                        ).first()

                        if existing_tip:
                            existing_tip.tip_home = tip_home
                            existing_tip.tip_away = tip_away
                        else:
                            db.session.add(Tip(
                                user_id=user.id,
                                match_id=match.id,
                                tip_home=tip_home,
                                tip_away=tip_away
                            ))
                            created_tips += 1

                db.session.commit()
                audit("import.leaderboard", "Round", r.id,
                      users=created_users, matches=created_matches, tips=created_tips, skipped=skipped_tips, results=results_imported)

                # Vytvořit Excel report pro přeskočené tipy
                skipped_report_path = None
                if skipped_tips > 0 and skipped_tips_details:
                    import openpyxl
                    from openpyxl.styles import Font, PatternFill, Alignment

                    wb_report = openpyxl.Workbook()
                    ws_report = wb_report.active
                    ws_report.title = "Přeskočené tipy"

                    # Hlavička
                    headers = ['Tipér', 'Zápas', 'Hodnota v buňce', 'Důvod přeskočení']
                    ws_report.append(headers)

                    # Styling hlavičky
                    for cell in ws_report[1]:
                        cell.font = Font(bold=True, color="FFFFFF")
                        cell.fill = PatternFill(start_color="FF4D6D", end_color="FF4D6D", fill_type="solid")
                        cell.alignment = Alignment(horizontal='center', vertical='center')

                    # Data
                    for detail in skipped_tips_details:
                        ws_report.append([
                            detail['user'],
                            detail['match'],
                            detail['value'],
                            detail['reason']
                        ])

                    # Automatická šířka sloupců
                    for column in ws_report.columns:
                        max_length = 0
                        column_letter = column[0].column_letter
                        for cell in column:
                            try:
                                if len(str(cell.value)) > max_length:
                                    max_length = len(str(cell.value))
                            except:
                                pass
                        adjusted_width = min(max_length + 2, 50)
                        ws_report.column_dimensions[column_letter].width = adjusted_width

                    # Uložit report do outputs
                    import os
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_dir = "/mnt/user-data/outputs"
                    os.makedirs(output_dir, exist_ok=True)
                    skipped_report_filename = f"preskocene_tipy_{timestamp}.xlsx"
                    skipped_report_path = os.path.join(output_dir, skipped_report_filename)
                    wb_report.save(skipped_report_path)

                msg = f"✅ Import dokončen do soutěže '{r.name}'! Vytvořeno: {created_users} uživatelů, {created_matches} zápasů, {created_tips} tipů."
                if results_imported > 0:
                    msg += f" Importováno {results_imported} výsledků."
                if skipped_tips > 0:
                    msg += f" Přeskočeno: {skipped_tips} tipů."
                flash(msg, "ok")

                # Přepnout na nově importovanou soutěž
                set_selected_round_id(r.id)

                # Pokud byly přeskočené tipy, nabídnout stažení reportu
                if skipped_report_path:
                    # Uložit cestu do session pro download
                    from flask import session as flask_session
                    flask_session['skipped_report_path'] = skipped_report_path
                    flask_session['skipped_report_filename'] = skipped_report_filename
                    return redirect(url_for("admin_import_leaderboard_report"))

                return redirect(url_for("leaderboard"))

            except Exception as e:
                db.session.rollback()
                flash(f"Chyba při importu: {str(e)}", "error")
                return redirect(url_for("admin_import_leaderboard"))

        # GET request - zobrazit formulář
        all_rounds = Round.query.order_by(Round.is_active.desc(), Round.id.desc()).all()

        return render_page(r"""
<div class="card">
  <div class="row" style="justify-content:space-between; align-items:flex-start;">
    <h2 style="margin:0 0 8px 0;">📊 Import žebříčku z jiné tipovačky</h2>
    <a href="{{ url_for('admin_import_leaderboard_template') }}" class="btn" style="background:#6ea8fe; color:white;">
      📥 Stáhnout šablonu Excel
    </a>
  </div>

  <div class="muted" style="margin-bottom:16px;">
    Importuj kompletní data (uživatele, zápasy a tipy) z Excel souboru s žebříčkem.
  </div>

  <div class="card" style="background:rgba(110,168,254,0.08); border:1px solid rgba(110,168,254,0.2); margin-bottom:16px;">
    <h3 style="margin:0 0 8px 0;">📋 Formát souboru</h3>
    <div class="muted" style="font-size:13px; line-height:1.6;">
      <strong>První řádek (hlavička):</strong><br>
      • Sloupec A: "Tipér" nebo "Jméno" (ignoruje se)<br>
      • Sloupec B+: Názvy zápasů ve formátu <strong>"Domácí-Hosté"</strong><br>
      &nbsp;&nbsp;Příklad: "Slavia-Sparta", "Plzeň-Liberec"<br><br>

      <strong>Druhý řádek NEBO poslední řádek (VOLITELNĚ - výsledky):</strong><br>
      • Sloupec A: prázdné NEBO "Výsledek" NEBO "Result"<br>
      • Sloupec B+: Výsledky zápasů <strong>"2:1"</strong><br>
      &nbsp;&nbsp;💡 Výsledky můžou být na <strong>druhém řádku</strong> (hned po hlavičce)<br>
      &nbsp;&nbsp;💡 NEBO na <strong>posledním řádku</strong> (dole pod tipéry) - NOVĚ!<br>
      &nbsp;&nbsp;💡 Pokud první sloupec je prázdný nebo obsahuje "Výsledek", importují se výsledky<br>
      &nbsp;&nbsp;💡 Pokud první sloupec obsahuje jméno, považuje se za tipéra<br><br>

      <strong>Další řádky (tipéři):</strong><br>
      • Sloupec A: Jméno tipéra<br>
      • Sloupec B+: Tipy ve formátu <strong>"2:1"</strong> nebo <strong>"2-1"</strong><br>
      &nbsp;&nbsp;💡 Funguje i časový formát "2:01" (Excel často automaticky převádí)<br><br>

      <strong>Co se stane:</strong><br>
      ✅ Vytvoří se uživatelé (heslo: "tipovacka123")<br>
      ✅ Vytvoří se zápasy a týmy<br>
      ✅ Naimportují se tipy<br>
      ✅ Naimportují se výsledky (pokud jsou)<br>
      ℹ️ Email uživatelů: <code>jmeno@import.tipovacka</code>
    </div>
  </div>

  <div class="card" style="background:rgba(255,199,79,0.08); border:1px solid rgba(255,199,79,0.2); margin-bottom:16px;">
    <strong>⚠️ Příklad Excel souboru S VÝSLEDKY:</strong>
    <table style="margin-top:8px; border-collapse:collapse; font-size:12px;">
      <tr style="background:rgba(255,255,255,0.05);">
        <th style="border:1px solid var(--line); padding:4px;">Tipér</th>
        <th style="border:1px solid var(--line); padding:4px;">Slavia-Sparta</th>
        <th style="border:1px solid var(--line); padding:4px;">Plzeň-Liberec</th>
        <th style="border:1px solid var(--line); padding:4px;">Baník-Sigma</th>
      </tr>
      <tr style="background:rgba(76,175,80,0.1);">
        <td style="border:1px solid var(--line); padding:4px; font-style:italic; color:#4CAF50;">Výsledek</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">3:1</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">2:2</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">1:0</td>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Petr</td>
        <td style="border:1px solid var(--line); padding:4px;">2:1</td>
        <td style="border:1px solid var(--line); padding:4px;">1:0</td>
        <td style="border:1px solid var(--line); padding:4px;">3:3</td>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Jana</td>
        <td style="border:1px solid var(--line); padding:4px;">1:1</td>
        <td style="border:1px solid var(--line); padding:4px;">2:1</td>
        <td style="border:1px solid var(--line); padding:4px;">0:2</td>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Martin</td>
        <td style="border:1px solid var(--line); padding:4px;">2:01</td>
        <td style="border:1px solid var(--line); padding:4px; font-size:10px;" class="muted">časový formát OK ✓</td>
        <td style="border:1px solid var(--line); padding:4px;">1:3</td>
      </tr>
    </table>
    <div class="muted" style="font-size:11px; margin-top:6px;">
      💡 Řádek "Výsledek" je volitelný. Pokud první sloupec je prázdný nebo obsahuje "Výsledek"/"Result"/"Skóre", importují se výsledky zápasů.
    </div>
  </div>

  <div class="card" style="background:rgba(255,199,79,0.08); border:1px solid rgba(255,199,79,0.2); margin-bottom:16px;">
    <strong>⚠️ Příklad Excel souboru s výsledky DOLE (NOVĚ):</strong>
    <table style="margin-top:8px; border-collapse:collapse; font-size:12px;">
      <tr style="background:rgba(255,255,255,0.05);">
        <th style="border:1px solid var(--line); padding:4px;">Tipér</th>
        <th style="border:1px solid var(--line); padding:4px;">Slavia-Sparta</th>
        <th style="border:1px solid var(--line); padding:4px;">Plzeň-Liberec</th>
        <th style="border:1px solid var(--line); padding:4px;">Baník-Sigma</th>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Petr</td>
        <td style="border:1px solid var(--line); padding:4px;">2:1</td>
        <td style="border:1px solid var(--line); padding:4px;">1:0</td>
        <td style="border:1px solid var(--line); padding:4px;">3:3</td>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Jana</td>
        <td style="border:1px solid var(--line); padding:4px;">1:1</td>
        <td style="border:1px solid var(--line); padding:4px;">2:1</td>
        <td style="border:1px solid var(--line); padding:4px;">0:2</td>
      </tr>
      <tr>
        <td style="border:1px solid var(--line); padding:4px;">Martin</td>
        <td style="border:1px solid var(--line); padding:4px;">2:01</td>
        <td style="border:1px solid var(--line); padding:4px;">1:1</td>
        <td style="border:1px solid var(--line); padding:4px;">1:3</td>
      </tr>
      <tr style="background:rgba(76,175,80,0.1);">
        <td style="border:1px solid var(--line); padding:4px; font-style:italic; color:#4CAF50;">Výsledek</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">3:1</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">2:2</td>
        <td style="border:1px solid var(--line); padding:4px; font-weight:900; color:#4CAF50;">1:0</td>
      </tr>
    </table>
    <div class="muted" style="font-size:11px; margin-top:6px;">
      💡 <strong>NOVĚ:</strong> Výsledky můžou být i v posledním řádku! Import automaticky detekuje řádek "Výsledek" ať je nahoře nebo dole.
    </div>
  </div>

  <form method="post" enctype="multipart/form-data" class="row" style="flex-direction:column; align-items:stretch; gap:16px;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

    {# Krok 1: Kam importovat #}
    <div class="card" style="background:rgba(255,255,255,0.03); padding:16px;">
      <h3 style="margin:0 0 12px 0;">1️⃣ Kam importovat data?</h3>

      <label style="display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer;">
        <input type="radio" name="import_target" value="existing" {% if all_rounds %}checked{% endif %}
               onchange="toggleImportTarget()" id="radio_existing">
        <span>Do existující soutěže</span>
      </label>

      <div id="existing_round_select" style="margin-left:28px; margin-bottom:16px;">
        <select name="round_id" style="width:100%; max-width:400px;">
          {% for rnd in all_rounds %}
            <option value="{{ rnd.id }}">
              {% if rnd.is_active %}★ {% endif %}{{ rnd.name }}
            </option>
          {% endfor %}
          {% if not all_rounds %}
            <option value="">-- Žádné soutěže --</option>
          {% endif %}
        </select>
      </div>

      <label style="display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer;">
        <input type="radio" name="import_target" value="new" {% if not all_rounds %}checked{% endif %}
               onchange="toggleImportTarget()" id="radio_new">
        <span>Vytvořit novou soutěž</span>
      </label>

      <div id="new_round_input" style="margin-left:28px; display:none;">
        <input type="text" name="new_round_name" placeholder="Název nové soutěže (např. CZ Liga fotbal 2026)"
               style="width:100%; max-width:400px;">
        <div class="muted" style="margin-top:6px; font-size:12px;">
          Vytvoří se nová soutěž se sportem "Fotbal"
        </div>
      </div>
    </div>

    {# Krok 2: Soubor #}
    <div class="card" style="background:rgba(255,255,255,0.03); padding:16px;">
      <h3 style="margin:0 0 12px 0;">2️⃣ Vyber Excel soubor</h3>
      <input type="file" name="excel_file" accept=".xlsx,.xls" required>
    </div>

    <button class="btn btn-primary" type="submit" style="padding:14px; font-size:16px; font-weight:900;">
      📥 Importovat žebříček
    </button>
    <a class="btn" href="{{ url_for('admin_import') }}">Zpět</a>
  </form>
</div>

<script>
function toggleImportTarget() {
  const existingChecked = document.getElementById('radio_existing').checked;
  const existingDiv = document.getElementById('existing_round_select');
  const newDiv = document.getElementById('new_round_input');

  if (existingChecked) {
    existingDiv.style.display = 'block';
    newDiv.style.display = 'none';
  } else {
    existingDiv.style.display = 'none';
    newDiv.style.display = 'block';
  }
}

// Inicializace při načtení
toggleImportTarget();
</script>
""", all_rounds=all_rounds)

    @app.route("/admin/import/leaderboard/report")
    @login_required
    def admin_import_leaderboard_report():
        admin_required()
        from flask import session as flask_session, send_file

        skipped_report_path = flask_session.get('skipped_report_path')
        skipped_report_filename = flask_session.get('skipped_report_filename', 'preskocene_tipy.xlsx')

        if not skipped_report_path or not os.path.exists(skipped_report_path):
            flash("Report přeskočených tipů není k dispozici.", "error")
            return redirect(url_for("admin_import"))

        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 16px 0;">⚠️ Přeskočené tipy při importu</h2>

  <div class="card" style="background:rgba(255,199,79,0.1); border:2px solid rgba(255,199,79,0.6); padding:20px; margin-bottom:20px;">
    <h3 style="margin:0 0 12px 0; color:#FFC74F;">Některé tipy nebyly importovány</h3>
    <div style="font-size:14px; line-height:1.6;">
      Při importu žebříčku byly některé tipy přeskočeny, protože se nepodařilo je správně parsovat.
      <br><br>
      <strong>Obvyklé důvody:</strong><br>
      • Neplatný formát (očekáván "2:1" nebo "2-1")<br>
      • Prázdná buňka nebo neplatná hodnota<br>
      • Text místo čísla<br><br>

      <strong>Stáhni Excel soubor</strong> s detailním přehledem všech přeskočených tipů.
      V souboru najdeš: tipéra, zápas, hodnotu v buňce a důvod přeskočení.
    </div>
  </div>

  <div style="display:flex; gap:12px; margin-bottom:20px;">
    <a href="{{ url_for('admin_import_leaderboard_download') }}"
       class="btn btn-primary"
       style="padding:14px 24px; font-size:16px; font-weight:900; background:#FFC74F; color:#000;">
      📥 Stáhnout Excel report
    </a>
    <a href="{{ url_for('leaderboard') }}" class="btn" style="padding:14px 24px; font-size:16px;">
      ➡️ Přejít do žebříčku
    </a>
  </div>

  <div class="muted" style="font-size:12px;">
    💡 Po opravě tipů v Excelu můžeš znovu importovat žebříček s opravenými daty.
  </div>
</div>
""")

    @app.route("/admin/import/leaderboard/download")
    @login_required
    def admin_import_leaderboard_download():
        admin_required()
        from flask import session as flask_session, send_file

        skipped_report_path = flask_session.get('skipped_report_path')
        skipped_report_filename = flask_session.get('skipped_report_filename', 'preskocene_tipy.xlsx')

        if not skipped_report_path or not os.path.exists(skipped_report_path):
            flash("Report přeskočených tipů není k dispozici.", "error")
            return redirect(url_for("admin_import"))

        # Smazat ze session po stažení
        flask_session.pop('skipped_report_path', None)
        flask_session.pop('skipped_report_filename', None)

        return send_file(
            skipped_report_path,
            as_attachment=True,
            download_name=skipped_report_filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )

    # --- ADMIN AUDIT ---
    @app.route("/admin/audit")
    @login_required
    def admin_audit():
        admin_required()
        logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(200).all()
        return render_page(r"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">Historie změn (posledních 200)</h2>
  <hr class="sep">
  {% for l in logs %}
    <div>
      <b>{{ l.action }}</b> <span class="muted">{{ l.entity }}{% if l.entity_id %}#{{ l.entity_id }}{% endif %}</span>
      <div class="muted">{{ l.at.strftime("%Y-%m-%d %H:%M:%S") }} | {% if l.actor %}{{ l.actor.username }}{% else %}—{% endif %}</div>
      {% if l.details %}<div class="muted" style="white-space:pre-wrap; margin-top:6px;">{{ l.details }}</div>{% endif %}
    </div>
    {% if not loop.last %}<hr class="sep">{% endif %}
  {% endfor %}
</div>
""", logs=logs)

    # --- PWA (Progressive Web App) ---
    @app.route("/manifest.json")
    def pwa_manifest():
        """PWA manifest pro instalaci aplikace"""
        manifest = {
            "name": "Tipovačka",
            "short_name": "Tipovačka",
            "description": "Tipovací aplikace pro sázení na sportovní výsledky",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0b1020",
            "theme_color": "#0b1020",
            "orientation": "any",
            "icons": [
                {
                    "src": url_for('pwa_icon', size=192, _external=True),
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable"
                },
                {
                    "src": url_for('pwa_icon', size=512, _external=True),
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any maskable"
                }
            ],
            "categories": ["sports", "entertainment"],
            "lang": "cs"
        }
        return jsonify(manifest)
    
    # --- PUSH NOTIFICATIONS ---
    @app.route("/api/push/subscribe", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_subscribe():
        """Subscribe k push notifikacím"""
        data = request.get_json()
        
        if not data or 'endpoint' not in data:
            return jsonify({"success": False, "message": "Missing endpoint"}), 400
        
        try:
            # Zkontroluj jestli už subscription existuje
            existing = PushSubscription.query.filter_by(
                user_id=current_user.id,
                endpoint=data['endpoint']
            ).first()
            
            if existing:
                # Update
                existing.p256dh = data['keys']['p256dh']
                existing.auth = data['keys']['auth']
                existing.user_agent = request.headers.get('User-Agent', '')
                existing.enabled = True
            else:
                # Vytvoř novou
                sub = PushSubscription(
                    user_id=current_user.id,
                    endpoint=data['endpoint'],
                    p256dh=data['keys']['p256dh'],
                    auth=data['keys']['auth'],
                    user_agent=request.headers.get('User-Agent', ''),
                    enabled=True
                )
                db.session.add(sub)
            
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "✅ Notifikace povoleny!"
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                "success": False,
                "message": f"Chyba: {str(e)}"
            }), 500
    
    @app.route("/api/push/unsubscribe", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_unsubscribe():
        """Unsubscribe od push notifikací"""
        data = request.get_json()
        
        if not data or 'endpoint' not in data:
            return jsonify({"success": False, "message": "Missing endpoint"}), 400
        
        try:
            # Najdi subscription
            sub = PushSubscription.query.filter_by(
                user_id=current_user.id,
                endpoint=data['endpoint']
            ).first()
            
            if sub:
                db.session.delete(sub)
                db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "✅ Notifikace zakázány"
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                "success": False,
                "message": f"Chyba: {str(e)}"
            }), 500
    
    @app.route("/api/push/vapid-public-key")
    def push_vapid_key():
        """Vrať public VAPID klíč pro frontend"""
        return jsonify({
            "publicKey": VAPID_PUBLIC_KEY
        })
    
    @app.route("/api/push/test", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_test():
        """Test notifikace (pro debugging)"""
        if not current_user.is_admin_effective:
            return jsonify({"success": False, "message": "Admin only"}), 403
        
        success = send_push_notification(
            current_user.id,
            "🔔 Test notifikace",
            "Funguje to! Tohle je testovací notifikace.",
            {"url": "/"}
        )
        
        if success:
            return jsonify({"success": True, "message": "✅ Notifikace odeslána!"})
        else:
            return jsonify({"success": False, "message": "❌ Žádná aktivní subscription"}), 400
    
    # --- NOTIFICATION SETTINGS ---
    @app.route("/notification-settings")
    @login_required
    def notification_settings():
        """Stránka s nastavením notifikací"""
        prefs = get_notification_preferences(current_user.id)
        
        return render_page(r"""
<div class="card">

  <div class="card" style="margin-bottom:16px;">
    <h3 style="margin-top:0;">🔔 Push notifikace</h3>
    <div id="pushStatus" class="muted">Načítám stav…</div>
    <div class="row" style="gap:8px; margin-top:12px; flex-wrap:wrap;">
      <button id="btnEnablePush" class="btn" type="button" style="background: rgba(110,168,254,.15); border: 1px solid rgba(110,168,254,.35);">Povolit push</button>
      <button id="btnDisablePush" class="btn" type="button" style="background: rgba(167,178,214,.10); border: 1px solid rgba(167,178,214,.25);">Zakázat push</button>
    </div>
    <div class="muted" style="margin-top:10px; font-size:13px;">
      Tip: Na Androidu musí být web otevřený v Chrome a povolené notifikace pro tuto stránku.
    </div>
  </div>

  <h2 style="margin:0 0 8px 0;">Nastavení notifikací 🔔</h2>
  <div class="muted">Vyber si, jaké notifikace chceš dostávat</div>
  
  <hr class="sep">
  
  <form id="notif-settings-form">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      
      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_results" {% if prefs.notify_results %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">⚽ Výsledky zadány</div>
          <div class="muted" style="font-size: 12px;">Dostaneš personalizovanou notifikaci s tvými body</div>
        </div>
      </label>
      
      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_deadline" {% if prefs.notify_deadline %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">⏰ Připomínka deadline</div>
          <div class="muted" style="font-size: 12px;">Připomene ti 1h před uzávěrkou, pokud ještě nemáš všechny tipy</div>
        </div>
      </label>
      
      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_new_round" {% if prefs.notify_new_round %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">🆕 Nová soutěž</div>
          <div class="muted" style="font-size: 12px;">Budeš první, kdo ví o nové soutěži</div>
        </div>
      </label>
      
      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_achievement" {% if prefs.notify_achievement %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">🏅 Achievementy</div>
          <div class="muted" style="font-size: 12px;">Oznámení když získáš nový achievement</div>
        </div>
      </label>
      
      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_leaderboard" {% if prefs.notify_leaderboard %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">📊 Změna v žebříčku</div>
          <div class="muted" style="font-size: 12px;">Upozornění když se změní tvoje pozice (může být častější)</div>
        </div>
      </label>
      
    </div>
    
    <hr class="sep">
    
    <div class="row" style="gap: 8px;">
      <button type="submit" class="btn btn-primary">💾 Uložit nastavení</button>
      <a href="/" class="btn">Zpět</a>
    </div>
  </form>
</div>

<script>
document.getElementById('notif-settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const formData = new FormData(e.target);
  const settings = {
    notify_results: formData.get('notify_results') === 'on',
    notify_deadline: formData.get('notify_deadline') === 'on',
    notify_new_round: formData.get('notify_new_round') === 'on',
    notify_achievement: formData.get('notify_achievement') === 'on',
    notify_leaderboard: formData.get('notify_leaderboard') === 'on'
  };
  
  try {
    const response = await fetchWithCSRF('/api/notification-settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(settings)
    });
    
    const result = await response.json();
    
    if (result.success) {
      alert('✅ Nastavení uloženo!');
    } else {
      alert('❌ ' + result.message);
    }
  } catch (error) {
    alert('❌ Chyba při ukládání: ' + error.message);
  }
});

// ------------------------------
// PUSH enable/disable (Android/Chrome)
// ------------------------------
const VAPID_PUBLIC_KEY = "{{ vapid_public_key }}";

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

async function getSWRegistration() {
  if (!('serviceWorker' in navigator)) throw new Error('Service Worker není podporován v tomto prohlížeči.');
  let reg = await navigator.serviceWorker.getRegistration();
  if (!reg) {
    reg = await navigator.serviceWorker.register('/service-worker.js');
  }
  await navigator.serviceWorker.ready;
  return reg;
}

function setPushStatus(html) {
  const el = document.getElementById('pushStatus');
  if (el) el.innerHTML = html;
}

async function refreshPushStatus() {
  try {
    const perm = (typeof Notification !== 'undefined') ? Notification.permission : 'unsupported';
    if (perm === 'denied') {
      setPushStatus('❌ Oznámení jsou pro tuto stránku blokovaná v prohlížeči. Povol je v Nastavení webu (Chrome).');
      return;
    }
    if (perm === 'default') {
      setPushStatus('ℹ️ Oznámení nejsou ještě povolená. Klikni na “Povolit push”.');
      return;
    }
    if (perm !== 'granted') {
      setPushStatus('❌ Prohlížeč nepodporuje Notification API.');
      return;
    }

    const reg = await getSWRegistration();
    if (!('pushManager' in reg)) {
      setPushStatus('❌ PushManager není dostupný (prohlížeč nepodporuje push).');
      return;
    }

    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      setPushStatus('✅ Push je zapnutý (subscription existuje).');
    } else {
      setPushStatus('ℹ️ Push je vypnutý (subscription neexistuje).');
    }
  } catch (e) {
    setPushStatus('❌ Chyba: ' + (e && e.message ? e.message : e));
  }
}

async function enablePush() {
  try {
    if (!VAPID_PUBLIC_KEY) throw new Error('Chybí VAPID public key na serveru.');
    if (typeof Notification === 'undefined') throw new Error('Prohlížeč nepodporuje notifikace.');
    let perm = Notification.permission;
    if (perm !== 'granted') {
      perm = await Notification.requestPermission();
    }
    if (perm !== 'granted') throw new Error('Notifikace nejsou povolené (permission=' + perm + ').');

    const reg = await getSWRegistration();
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
    });

    const resp = await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(sub)
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.success) {
      throw new Error(data.message || ('Subscribe API error (' + resp.status + ')'));
    }
    setPushStatus('✅ Push zapnutý. (Uloženo na serveru)');
  } catch (e) {
    alert('❌ Nepodařilo se zapnout push: ' + (e && e.message ? e.message : e));
  } finally {
    await refreshPushStatus();
  }
}

async function disablePush() {
  try {
    const reg = await getSWRegistration();
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      await sub.unsubscribe();
    }
    await fetch('/api/push/unsubscribe', {method: 'POST'}).catch(() => {});
    setPushStatus('ℹ️ Push vypnutý.');
  } catch (e) {
    alert('❌ Nepodařilo se vypnout push: ' + (e && e.message ? e.message : e));
  } finally {
    await refreshPushStatus();
  }
}

document.getElementById('btnEnablePush')?.addEventListener('click', enablePush);
document.getElementById('btnDisablePush')?.addEventListener('click', disablePush);
window.addEventListener('load', refreshPushStatus);

</script>
""", prefs=prefs, vapid_public_key=VAPID_PUBLIC_KEY)
    
    @app.route("/api/notification-settings", methods=["GET", "POST"])
    @csrf.exempt
    @login_required
    def api_notification_settings():
        """API pro získání/uložení nastavení notifikací"""
        
        if request.method == "GET":
            # Získej nastavení
            prefs = get_notification_preferences(current_user.id)
            return jsonify({
                "notify_results": prefs.notify_results,
                "notify_deadline": prefs.notify_deadline,
                "notify_new_round": prefs.notify_new_round,
                "notify_achievement": prefs.notify_achievement,
                "notify_leaderboard": prefs.notify_leaderboard
            })
        
        else:  # POST
            # Ulož nastavení
            data = request.get_json()
            
            if not data:
                return jsonify({"success": False, "message": "Missing data"}), 400
            
            try:
                prefs = get_notification_preferences(current_user.id)
                
                # Update preferences
                prefs.notify_results = data.get('notify_results', True)
                prefs.notify_deadline = data.get('notify_deadline', True)
                prefs.notify_new_round = data.get('notify_new_round', True)
                prefs.notify_achievement = data.get('notify_achievement', True)
                prefs.notify_leaderboard = data.get('notify_leaderboard', False)
                prefs.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                return jsonify({
                    "success": True,
                    "message": "✅ Nastavení uloženo!"
                })
                
            except Exception as e:
                db.session.rollback()
                return jsonify({
                    "success": False,
                    "message": f"Chyba: {str(e)}"
                }), 500
    
    @app.route("/service-worker.js")
    def service_worker():
        """Service Worker pro offline mode a caching"""
        sw_code = """
// Service Worker pro Tipovačka PWA
const CACHE_NAME = 'tipovacka-v1';
const urlsToCache = [
  '/',
  '/dashboard',
  '/matches',
  '/leaderboard',
  '/my-stats',
  '/achievements'
];

// Install
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

// Activate
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch - Network first, fallback to cache
self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Clone response a ulož do cache
        if (response.status === 200) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // Pokud není síť, použij cache
        return caches.match(event.request);
      })
  );
});

// Push Notification Handler
self.addEventListener('push', event => {
  console.log('[Service Worker] Push received:', event);
  
  let data = {
    title: '🏆 Tipovačka',
    body: 'Nová notifikace',
    icon: '/static/icon-192.png',
    badge: '/static/badge-96.png',
    data: {}
  };
  
  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch (e) {
    console.error('Error parsing push data:', e);
  }
  
  const options = {
    body: data.body,
    icon: data.icon || '/static/icon-192.png',
    badge: data.badge || '/static/badge-96.png',
    vibrate: [200, 100, 200],
    tag: 'tipovacka-notification',
    requireInteraction: false,
    data: data.data || {}
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Notification Click Handler
self.addEventListener('notificationclick', event => {
  console.log('[Service Worker] Notification click:', event);
  
  event.notification.close();
  
  // Kam otevřít
  let url = '/';
  if (event.notification.data && event.notification.data.url) {
    url = event.notification.data.url;
  }
  
  // Otevři nebo focusni existující okno
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(clientList => {
        // Zkus najít už otevřené okno
        for (let client of clientList) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        // Jinak otevři nové
        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
  );
});
"""
        response = Response(sw_code, mimetype='application/javascript')
        response.headers['Service-Worker-Allowed'] = '/'
        return response
    
    @app.route("/pwa-icon/<int:size>")
    def pwa_icon(size):
        """Generuj PWA ikonu jako SVG"""
        # Jednoduchá ikona - modrý kruh s písmeny T
        svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
  <rect width="{size}" height="{size}" fill="#0b1020"/>
  <circle cx="{size/2}" cy="{size/2}" r="{size/2.5}" fill="#6ea8fe"/>
  <text x="{size/2}" y="{size/1.8}" font-family="Arial, sans-serif" font-size="{size/2.5}" font-weight="900" fill="#fff" text-anchor="middle">T</text>
</svg>"""
        return Response(svg, mimetype='image/svg+xml')
    
    # =========================================================
    # API IMPORT ROUTES
    # =========================================================
    @app.route("/admin/api-sources")
    @login_required
    def admin_api_sources():
        """Správa API zdrojů"""
        admin_required()
        
        sources = APISource.query.all()
        
        return render_page(r"""
<style>
  .api-source-card {
    background: rgba(255,255,255,.03);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 16px;
    margin-bottom: 16px;
  }
  
  .api-source-card.active {
    border-color: rgba(51,209,122,.5);
    background: rgba(51,209,122,.08);
  }
  
  .api-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 700;
  }
  
  .api-badge.nhl { background: rgba(110,168,254,.2); color: #6ea8fe; }
  .api-badge.api-football { background: rgba(51,209,122,.2); color: #33d17a; }
</style>

<div class="card">
  <div class="row" style="justify-content: space-between; align-items: center;">
    <div>
      <h2 style="margin: 0 0 8px 0;">🔌 API Zdroje</h2>
      <div class="muted">Automatický import zápasů a výsledků</div>
    </div>
    <a href="{{ url_for('admin_api_source_new') }}" class="btn btn-primary">+ Nový zdroj</a>
  </div>
</div>

{% if sources|length == 0 %}
<div class="card">
  <div style="text-align: center; padding: 40px;">
    <div style="font-size: 48px; margin-bottom: 12px;">🔌</div>
    <h3 style="margin: 0 0 8px 0;">Žádné API zdroje</h3>
    <div class="muted">Přidej první API zdroj pro automatický import</div>
    <a href="{{ url_for('admin_api_source_new') }}" class="btn btn-primary" style="margin-top: 16px;">+ Přidat zdroj</a>
  </div>
</div>
{% else %}
  {% for source in sources %}
  <div class="api-source-card {% if source.is_active %}active{% endif %}">
    <div class="row" style="justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
      <div>
        <div class="row" style="gap: 8px; align-items: center; margin-bottom: 8px;">
          <span class="api-badge {{ source.api_type }}">{{ source.api_type.upper() }}</span>
          {% if source.is_active %}
            <span class="tag pill-ok">✅ Aktivní</span>
          {% else %}
            <span class="tag pill-bad">⏸️ Neaktivní</span>
          {% endif %}
        </div>
        <h3 style="margin: 0 0 4px 0;">{% if source.round %}{{ source.round.name }}{% else %}[Soutěž smazána]{% endif %}</h3>
        <div class="muted" style="font-size: 13px;">
          {% if source.league_id %}Liga/Sezóna: <b>{{ source.league_id }}</b> • {% endif %}
          Vytvořeno: {{ source.created_at.strftime('%d.%m.%Y') }}
        </div>
      </div>
      <div class="row" style="gap: 8px;">
        <a href="{{ url_for('admin_api_import_preview', source_id=source.id, import_type='matches') }}" 
           class="btn btn-sm">📥 Import zápasů</a>
        <a href="{{ url_for('admin_api_import_preview', source_id=source.id, import_type='results') }}" 
           class="btn btn-sm">📊 Import výsledků</a>
        <a href="{{ url_for('admin_api_source_edit', source_id=source.id) }}" 
           class="btn btn-sm">✏️ Upravit</a>
        <form method="post" action="{{ url_for('admin_api_source_delete', source_id=source.id) }}" 
              style="display:inline;" 
              onsubmit="return confirm('Opravdu smazat API zdroj {% if source.round %}\'{{ source.round.name }}\'{% else %}[Smazaná soutěž]{% endif %}?')">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
          <button type="submit" class="btn btn-sm btn-danger" 
                  style="background:rgba(255,77,109,0.2); color:#ff4d6d; border:none; cursor:pointer;">
            🗑️ Smazat
          </button>
        </form>
      </div>
    </div>
    
    <div class="row" style="gap: 16px; font-size: 13px;">
      <div>
        <div class="muted">Auto import zápasů:</div>
        <div><strong>{% if source.auto_import_matches %}Ano{% else %}Ne{% endif %}</strong></div>
      </div>
      <div>
        <div class="muted">Auto import výsledků:</div>
        <div><strong>{% if source.auto_import_results %}Ano{% else %}Ne{% endif %}</strong></div>
      </div>
      <div>
        <div class="muted">Vyžadovat potvrzení:</div>
        <div><strong>{% if source.require_admin_approval %}Ano{% else %}Ne{% endif %}</strong></div>
      </div>
      <div>
        <div class="muted">Ignorovat OT/SO:</div>
        <div><strong>{% if source.exclude_overtime %}Ano{% else %}Ne{% endif %}</strong></div>
      </div>
    </div>
    
    {% if source.last_import_at %}
    <div class="muted" style="margin-top: 12px; font-size: 12px;">
      Poslední import: {{ source.last_import_at.strftime('%d.%m.%Y %H:%M') }}
    </div>
    {% endif %}
  </div>
  {% endfor %}
{% endif %}

<div class="card" style="background: rgba(110,168,254,.08); border-color: rgba(110,168,254,.3);">
  <h3 style="margin: 0 0 12px 0;">ℹ️ Podporované API</h3>
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px;">
    <div>
      <div style="font-weight: 700; margin-bottom: 4px;">🏒 NHL API</div>
      <div class="muted" style="font-size: 13px;">Oficiální NHL API - zdarma, bez registrace</div>
    </div>
    <div>
      <div style="font-weight: 700; margin-bottom: 4px;">⚽ API-Football</div>
      <div class="muted" style="font-size: 13px;">Fotbalové ligy - vyžaduje API klíč (api-football.com)</div>
    </div>
    <div>
      <div style="font-weight: 700; margin-bottom: 4px;">⚽ TheSportsDB</div>
      <div class="muted" style="font-size: 13px;">Fotbalové ligy - zdarma (pozor na dostupnost aktuální sezóny)</div>
    </div>
    <div>
      <div style="font-weight: 700; margin-bottom: 4px;">🏆 UEFA UCL (All fixtures)</div>
      <div class="muted" style="font-size: 13px;">Liga mistrů - zdarma z oficiální UEFA stránky (scrape)</div>
    </div>
  </div>
</div>
""", sources=sources)
    
    @app.route("/admin/api-source/new", methods=["GET", "POST"])
    @login_required
    def admin_api_source_new():
        """Vytvoření nového API zdroje"""
        admin_required()
        
        if request.method == "POST":
            round_id = int(request.form["round_id"])
            api_type = request.form["api_type"]
            league_id = request.form.get("league_id", "").strip() or None
            api_key = request.form.get("api_key", "").strip() or None
            
            auto_import_matches = request.form.get("auto_import_matches") == "on"
            auto_import_results = request.form.get("auto_import_results") == "on"
            require_admin_approval = request.form.get("require_admin_approval") == "on"
            exclude_overtime = request.form.get("exclude_overtime") == "on"
            
            source = APISource(
                round_id=round_id,
                api_type=api_type,
                league_id=league_id,
                api_key=api_key,
                auto_import_matches=auto_import_matches,
                auto_import_results=auto_import_results,
                require_admin_approval=require_admin_approval,
                exclude_overtime=exclude_overtime,
                is_active=True,
                created_by_id=current_user.id
            )
            
            db.session.add(source)
            db.session.commit()
            
            audit("api_source.create", "APISource", source.id)
            flash("✅ API zdroj vytvořen!", "ok")
            return redirect(url_for("admin_api_sources"))
        
        rounds = Round.query.order_by(Round.id.desc()).all()
        
        return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 8px 0;">+ Nový API zdroj</h2>
  <div class="muted">Nastav automatický import zápasů a výsledků</div>
  <hr class="sep">
  
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div style="display: grid; gap: 16px;">
      
      <div>
        <label class="muted" style="margin-bottom: 6px; display: block;">Soutěž *</label>
        <select name="round_id" required>
          <option value="">-- Vyber soutěž --</option>
          {% for r in rounds %}
            <option value="{{ r.id }}">{{ r.name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <div>
        <label class="muted" style="margin-bottom: 6px; display: block;">Typ API *</label>
        <select name="api_type" id="api_type" required onchange="toggleAPIFields()">
          <option value="">-- Vyber API --</option>
          <option value="nhl">🏒 NHL API (hokej)</option>
          <option value="api-football">⚽ API-Football (fotbal - placené)</option>
          <option value="thesportsdb">⚽ TheSportsDB (fotbal - ZDARMA!)</option>
          <option value="uefa-ucl">🏆 UEFA UCL (All fixtures - ZDARMA!)</option>
        </select>
      </div>
      
      <div id="nhl_fields" style="display: none;">
        <label class="muted" style="margin-bottom: 6px; display: block;">Sezóna</label>
        <input id="nhl_league_id" name="league_id" placeholder="20252026" value="20252026" disabled>
        <div class="muted" style="font-size: 12px; margin-top: 4px;">
          Formát: YYYYYYYY (např. 20252026 pro sezónu 2025/26)
        </div>
      </div>
      
      <div id="football_fields" style="display: none;">
        <div style="margin-bottom: 12px;">
          <label class="muted" style="margin-bottom: 6px; display: block;">ID Ligy *</label>
          <input id="football_league_id" name="league_id" placeholder="39" disabled>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Např: 39 = Premier League, 140 = La Liga, 78 = Bundesliga, 345 = Chance Liga (CZ)<br>
            <a href="https://www.api-football.com/documentation-v3#tag/Leagues" target="_blank">Najdi ID ligy →</a>
          </div>
        </div>
        
        <div>
          <label class="muted" style="margin-bottom: 6px; display: block;">API Klíč *</label>
          <input id="football_api_key" name="api_key" type="password" placeholder="tvůj-api-klíč" disabled>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Registrace: <a href="https://www.api-football.com/" target="_blank">api-football.com</a>
          </div>
        </div>
      </div>
      
      <div id="thesportsdb_fields" style="display: none;">
        <div style="margin-bottom: 12px;">
          <label class="muted" style="margin-bottom: 6px; display: block;">ID Ligy *</label>
          <input id="thesportsdb_league_id" name="league_id" placeholder="4631" disabled>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            <strong>🇨🇿 Česko:</strong> 4631 = Chance Liga (1. liga)<br>
            <strong>🏆 Evropa:</strong> 4480 = Liga mistrů (Champions League)<br>
            <strong>🌍 TOP Ligy:</strong> 4328 = Premier League, 4335 = La Liga, 4332 = Serie A, 4331 = Bundesliga<br>
            <a href="https://www.thesportsdb.com/sport/Soccer" target="_blank">Najdi ID ligy →</a>
          </div>
        </div>
        
        <div>
          <label class="muted" style="margin-bottom: 6px; display: block;">Sezóna (volitelné)</label>
          <input id="thesportsdb_season" name="api_key" placeholder="2024-2025" disabled>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Formát: YYYY-YYYY (např. 2024-2025)<br>
            Ponech prázdné pro posledních 15 zápasů
          </div>
        </div>
        
        <div class="muted" style="font-size: 12px; margin-top: 12px; padding: 12px; background: rgba(46,213,115,.08); border-radius: 8px; border: 1px solid rgba(46,213,115,.2);">
          ✅ <strong>ZDARMA!</strong> Žádný API klíč není potřeba. Všechny sezóny dostupné. Bez rate limitů.
        </div>
      </div>
      
      <hr class="sep">
      
      <div>
        <h3 style="margin: 0 0 12px 0;">⚙️ Nastavení</h3>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="require_admin_approval" checked>
          <span>Vyžadovat potvrzení adminem před importem</span>
        </label>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="exclude_overtime" checked>
          <span>Ignorovat prodloužení/nájezdy (jen základní hrací doba)</span>
        </label>
        
        <div class="muted" style="font-size: 12px; margin-top: 8px; padding: 12px; background: rgba(110,168,254,.08); border-radius: 8px;">
          💡 <strong>Tip:</strong> Automatický import můžeš nastavit později po otestování manuálního importu.
        </div>
      </div>
      
      <div class="row" style="gap: 8px;">
        <button type="submit" class="btn btn-primary">✅ Vytvořit zdroj</button>
        <a href="{{ url_for('admin_api_sources') }}" class="btn">Zrušit</a>
      </div>
    </div>
  </form>
</div>

<script>
function toggleAPIFields() {
  const apiType = document.getElementById('api_type').value;
  const nhlFields = document.getElementById('nhl_fields');
  const footballFields = document.getElementById('football_fields');
  const thesportsdbFields = document.getElementById('thesportsdb_fields');
  const nhlInput = document.getElementById('nhl_league_id');
  const footballLeagueInput = document.getElementById('football_league_id');
  const footballKeyInput = document.getElementById('football_api_key');
  const thesportsdbLeagueInput = document.getElementById('thesportsdb_league_id');
  const thesportsdbSeasonInput = document.getElementById('thesportsdb_season');
  const uefaFields = document.getElementById('uefa_fields');
  const uefaUrlInput = document.getElementById('uefa_url');
  
  if (apiType === 'nhl') {
    // Show NHL, hide others
    nhlFields.style.display = 'block';
    footballFields.style.display = 'none';
    thesportsdbFields.style.display = 'none';
    uefaFields.style.display = 'none';
    uefaFields.style.display = 'none';
    uefaFields.style.display = 'none';
    // Enable NHL input, disable others
    nhlInput.disabled = false;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
    thesportsdbLeagueInput.disabled = true;
    thesportsdbSeasonInput.disabled = true;
    uefaUrlInput.disabled = true;
    uefaUrlInput.disabled = true;
    uefaUrlInput.disabled = true;
  } else if (apiType === 'api-football') {
    // Show API-Football, hide others
    nhlFields.style.display = 'none';
    footballFields.style.display = 'block';
    thesportsdbFields.style.display = 'none';
    // Enable Football inputs, disable others
    nhlInput.disabled = true;
    footballLeagueInput.disabled = false;
    footballKeyInput.disabled = false;
    thesportsdbLeagueInput.disabled = true;
    thesportsdbSeasonInput.disabled = true;
  } else if (apiType === 'thesportsdb') {
    // Show TheSportsDB, hide others
    nhlFields.style.display = 'none';
    footballFields.style.display = 'none';
    thesportsdbFields.style.display = 'block';
    uefaFields.style.display = 'none';
    // Enable TheSportsDB inputs, disable others
    nhlInput.disabled = true;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
    thesportsdbLeagueInput.disabled = false;
    thesportsdbSeasonInput.disabled = false;
    uefaUrlInput.disabled = true;
  } else if (apiType === 'uefa-ucl') {
    // Show UEFA UCL, hide others
    nhlFields.style.display = 'none';
    footballFields.style.display = 'none';
    thesportsdbFields.style.display = 'none';
    uefaFields.style.display = 'block';
    // Disable other inputs, enable UEFA URL
    nhlInput.disabled = true;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
    thesportsdbLeagueInput.disabled = true;
    thesportsdbSeasonInput.disabled = true;
    uefaUrlInput.disabled = false;
  } else {
    // Hide all
    nhlFields.style.display = 'none';
    footballFields.style.display = 'none';
    thesportsdbFields.style.display = 'none';
    nhlInput.disabled = true;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
    thesportsdbLeagueInput.disabled = true;
    thesportsdbSeasonInput.disabled = true;
  }
}
</script>
""", rounds=rounds)
    
    @app.route("/admin/api-source/<int:source_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_api_source_edit(source_id: int):
        """Úprava API zdroje"""
        admin_required()
        
        api_source = db.session.get(APISource, source_id)
        if not api_source:
            flash("❌ API zdroj nenalezen.", "error")
            return redirect(url_for("admin_api_sources"))
        
        if request.method == "POST":
            try:
                api_source.round_id = int(request.form["round_id"])
                api_source.api_type = request.form["api_type"]
                api_source.league_id = request.form.get("league_id", "").strip() or None
                
                # API klíč - pokud je prázdný (placeholder), ponechat původní
                new_api_key = request.form.get("api_key", "").strip()
                if new_api_key and new_api_key != "":
                    api_source.api_key = new_api_key
                
                api_source.auto_import_matches = request.form.get("auto_import_matches") == "on"
                api_source.auto_import_results = request.form.get("auto_import_results") == "on"
                api_source.require_admin_approval = request.form.get("require_admin_approval") == "on"
                api_source.exclude_overtime = request.form.get("exclude_overtime") == "on"
                api_source.is_active = request.form.get("is_active") == "on"
                
                db.session.commit()
                
                audit("api_source.edit", "APISource", api_source.id)
                flash("✅ API zdroj aktualizován!", "ok")
                return redirect(url_for("admin_api_sources"))
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Chyba při ukládání: {str(e)}", "error")
                return redirect(url_for("admin_api_source_edit", source_id=source_id))
        
        try:
            rounds = Round.query.order_by(Round.id.desc()).all()
            
            # Fallback pokud není žádná soutěž
            if not rounds:
                flash("⚠️ Nejsou k dispozici žádné soutěže. Vytvoř nejprve soutěž.", "error")
                return redirect(url_for("admin_api_sources"))
            
            return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 8px 0;">✏️ Upravit API zdroj</h2>
  <div class="muted">{% if api_source.round %}{{ api_source.round.name }}{% else %}Soutěž smazána{% endif %} - {{ api_source.api_type.upper() }}</div>
  <hr class="sep">
  
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <div style="display: grid; gap: 16px;">
      
      <div>
        <label class="muted" style="margin-bottom: 6px; display: block;">Soutěž *</label>
        <select name="round_id" required>
          {% for r in rounds %}
            <option value="{{ r.id }}" {% if r.id == api_source.round_id %}selected{% endif %}>{{ r.name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <div>
        <label class="muted" style="margin-bottom: 6px; display: block;">Typ API *</label>
        <select name="api_type" id="api_type" required onchange="toggleAPIFields()">
          <option value="nhl" {% if api_source.api_type == 'nhl' %}selected{% endif %}>🏒 NHL API (hokej)</option>
          <option value="api-football" {% if api_source.api_type == 'api-football' %}selected{% endif %}>⚽ API-Football (fotbal)</option>
        </select>
      </div>
      
      <div id="nhl_fields" style="{% if api_source.api_type != 'nhl' %}display: none;{% endif %}">
        <label class="muted" style="margin-bottom: 6px; display: block;">Sezóna</label>
        <input id="nhl_league_id" name="league_id" placeholder="20252026" value="{{ api_source.league_id or '20252026' }}" {% if api_source.api_type != 'nhl' %}disabled{% endif %}>
        <div class="muted" style="font-size: 12px; margin-top: 4px;">
          Formát: YYYYYYYY (např. 20252026 pro sezónu 2025/26)
        </div>
      </div>
      
      <div id="football_fields" style="{% if api_source.api_type != 'api-football' %}display: none;{% endif %}">
        <div style="margin-bottom: 12px;">
          <label class="muted" style="margin-bottom: 6px; display: block;">ID Ligy *</label>
          <input id="football_league_id" name="league_id" placeholder="39" value="{{ api_source.league_id or '' }}" {% if api_source.api_type != 'api-football' %}disabled{% endif %}>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Např: 39 = Premier League, 140 = La Liga, 78 = Bundesliga, 345 = Chance Liga (CZ)<br>
            <a href="https://www.api-football.com/documentation-v3#tag/Leagues" target="_blank">Najdi ID ligy →</a>
          </div>
        </div>
        
        <div>
          <label class="muted" style="margin-bottom: 6px; display: block;">API Klíč *</label>
          <input id="football_api_key" name="api_key" type="password" placeholder="{% if api_source.api_key %}••••••••{% else %}tvůj-api-klíč{% endif %}" value="{{ api_source.api_key or '' }}" {% if api_source.api_type != 'api-football' %}disabled{% endif %}>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Registrace: <a href="https://www.api-football.com/" target="_blank">api-football.com</a>
          </div>
        </div>
      </div>
      
      <hr class="sep">
      
      <div>
        <h3 style="margin: 0 0 12px 0;">⚙️ Nastavení</h3>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="is_active" {% if api_source.is_active %}checked{% endif %}>
          <span>✅ Aktivní (zapnuto)</span>
        </label>
        
        
      <!-- UEFA UCL (All fixtures) -->
      <div id="uefa_fields" style="display: none;">
        <div style="margin-bottom: 12px;">
          <label class="muted" style="margin-bottom: 6px; display: block;">UEFA "All fixtures" URL (volitelné)</label>
          <input id="uefa_url" name="league_id" placeholder="(nech prázdné pro default UEFA link)" {% if api_source is defined %}value="{{ api_source.league_id or '' }}"{% endif %} disabled>
          <div class="muted" style="font-size: 12px; margin-top: 4px;">
            Zdroj je oficiální UEFA článek "All the fixtures and results".<br>
            Pokud necháš prázdné, použije se výchozí URL pro sezonu 2025/26.
          </div>
        </div>
        <div class="muted" style="font-size: 12px; margin-top: 12px; padding: 12px; background: rgba(46,213,115,.08); border-radius: 8px; border: 1px solid rgba(46,213,115,.2);">
          ✅ <strong>ZDARMA!</strong> Nevyžaduje API klíč. Získáš: domácí/hosté/čas + po zápase skóre.
        </div>
      </div>

<label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="auto_import_matches" {% if api_source.auto_import_matches %}checked{% endif %}>
          <span>Automatický import zápasů</span>
        </label>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="auto_import_results" {% if api_source.auto_import_results %}checked{% endif %}>
          <span>Automatický import výsledků</span>
        </label>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="require_admin_approval" {% if api_source.require_admin_approval %}checked{% endif %}>
          <span>Vyžadovat potvrzení adminem</span>
        </label>
        
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 8px;">
          <input type="checkbox" name="exclude_overtime" {% if api_source.exclude_overtime %}checked{% endif %}>
          <span>Ignorovat prodloužení/nájezdy</span>
        </label>
      </div>
      
      <div class="row" style="gap: 12px; margin-top: 16px;">
        <button class="btn btn-primary" type="submit">💾 Uložit změny</button>
        <a class="btn" href="{{ url_for('admin_api_sources') }}">Zrušit</a>
      </div>
      
    </div>
  </form>
</div>

<script>
function toggleAPIFields() {
  const apiType = document.getElementById('api_type').value;
  const nhlFields = document.getElementById('nhl_fields');
  const footballFields = document.getElementById('football_fields');
  const nhlInput = document.getElementById('nhl_league_id');
  const footballLeagueInput = document.getElementById('football_league_id');
  const footballKeyInput = document.getElementById('football_api_key');
  
  if (apiType === 'nhl') {
    // Show NHL, hide Football
    nhlFields.style.display = 'block';
    footballFields.style.display = 'none';
    // Enable NHL input, disable Football inputs
    nhlInput.disabled = false;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
  } else if (apiType === 'api-football') {
    // Show Football, hide NHL
    nhlFields.style.display = 'none';
    footballFields.style.display = 'block';
    // Enable Football inputs, disable NHL input
    nhlInput.disabled = true;
    footballLeagueInput.disabled = false;
    footballKeyInput.disabled = false;
  } else {
    // Hide both
    nhlFields.style.display = 'none';
    footballFields.style.display = 'none';
    nhlInput.disabled = true;
    footballLeagueInput.disabled = true;
    footballKeyInput.disabled = true;
  }
}
</script>
""", api_source=api_source, rounds=rounds)
        except Exception as e:
            flash(f"❌ Chyba při zobrazení formuláře: {str(e)}", "error")
            return redirect(url_for("admin_api_sources"))
    
    @app.route("/admin/api-source/<int:source_id>/delete", methods=["POST"])
    @login_required
    def admin_api_source_delete(source_id: int):
        """Smazání API zdroje"""
        admin_required()
        
        api_source = db.session.get(APISource, source_id)
        if not api_source:
            flash("❌ API zdroj nenalezen.", "error")
            return redirect(url_for("admin_api_sources"))
        
        # Název pro audit log
        if api_source.round:
            source_name = f"{api_source.round.name} - {api_source.api_type.upper()}"
        else:
            source_name = f"[Smazaná soutěž] - {api_source.api_type.upper()}"
        
        # Smazat všechny import logy tohoto zdroje
        APIImportLog.query.filter_by(source_id=api_source.id).delete()
        
        # Smazat všechny mapování
        MatchAPIMapping.query.filter_by(source_id=api_source.id).delete()
        
        # Smazat zdroj
        db.session.delete(api_source)
        db.session.commit()
        
        audit("api_source.delete", "APISource", source_id, name=source_name)
        flash(f"🗑️ API zdroj '{source_name}' byl smazán.", "ok")
        return redirect(url_for("admin_api_sources"))
    
    @app.route("/admin/api-import/preview/<int:source_id>/<import_type>")
    @login_required
    def admin_api_import_preview(source_id: int, import_type: str):
        """Preview importu před potvrzením"""
        admin_required()
        
        source = db.session.get(APISource, source_id)
        if not source:
            abort(404)
        
        if import_type not in ['matches', 'results']:
            abort(400)
        
        # Stáhnout data z API
        try:
            games = fetch_api_games(source, import_type=import_type)
            
            if not games:
                # Konkrétnější chybová zpráva podle typu API
                if source.api_type == 'nhl':
                    flash("❌ Nepodařilo se stáhnout zápasy z NHL API. Zkontroluj Koyeb logy pro detaily.", "error")
                elif source.api_type == 'api-football':
                    flash("❌ Nepodařilo se stáhnout zápasy z API-Football. Zkontroluj API klíč a limit requestů (100/den).", "error")
                elif source.api_type == 'thesportsdb':
                    flash("❌ TheSportsDB nic nevrátil. Buď je špatné ID ligy, nebo free endpoint nemá data pro danou sezónu.", "error")
                elif source.api_type == 'uefa-ucl':
                    flash("❌ Nepodařilo se načíst data z UEFA (All fixtures). Zkontroluj, že stránka je dostupná a že se nezměnila struktura.", "error")
                else:
                    flash("❌ Nepodařilo se stáhnout data z API. Zkontroluj nastavení zdroje.", "error")
                return redirect(url_for("admin_api_sources"))
            
            # Vytvoř preview
            preview = {
                'source_id': source.id,
                'import_type': import_type,
                'total_games': len(games),
                'games': games[:50]  # Max 50 pro preview
            }
            
            # Dry run - zjisti co by se importovalo
            if import_type == 'matches':
                imported, skipped, errors = import_matches_from_api(source, games, commit=False)
            else:  # results
                imported, skipped, errors = import_results_from_api(source, games, commit=False)
            
            # Ulož preview do session nebo DB
            preview_json = json.dumps(preview)
            
            # Vytvoř import log s preview
            import_log = APIImportLog(
                source_id=source.id,
                import_type=import_type,
                status='pending',
                imported_count=imported,
                skipped_count=skipped,
                error_count=len(errors),
                preview_data=preview_json,
                error_details=json.dumps(errors) if errors else None
            )
            db.session.add(import_log)
            db.session.commit()
            
            return redirect(url_for('admin_api_import_confirm', log_id=import_log.id))
        
        except Exception as e:
            flash(f"❌ Chyba: {str(e)}", "error")
            return redirect(url_for("admin_api_sources"))
    
    @app.route("/admin/api-import/confirm/<int:log_id>", methods=["GET", "POST"])
    @login_required
    def admin_api_import_confirm(log_id: int):
        """Potvrzení nebo zamítnutí importu"""
        admin_required()
        
        import_log = db.session.get(APIImportLog, log_id)
        if not import_log:
            abort(404)
        
        if import_log.status != 'pending':
            flash("Import už byl zpracován", "error")
            return redirect(url_for("admin_api_sources"))
        
        if request.method == "POST":
            action = request.form.get("action")
            
            if action == "approve":
                # Proveď import
                try:
                    preview = json.loads(import_log.preview_data)
                    source = db.session.get(APISource, import_log.source_id)
                    
                    # Získat indexy vybraných zápasů
                    selected_indices = request.form.getlist("selected_games")
                    
                    if not selected_indices:
                        flash("⚠️ Nevybrali jste žádné zápasy k importu.", "error")
                        return redirect(url_for("admin_api_import_confirm", log_id=log_id))
                    
                    selected_indices = [int(idx) for idx in selected_indices]
                    
                    # Použij data z preview (zachová pořadí i filtrování), ne refetch
                    preview_games = preview.get('games', [])
                    selected_games = [preview_games[i] for i in selected_indices if 0 <= i < len(preview_games)]

                    if not selected_games:
                        flash("❌ Vybrané zápasy nebyly nalezeny.", "error")
                        return redirect(url_for("admin_api_sources"))
                    
                    if import_log.import_type == 'matches':
                        imported, skipped, errors = import_matches_from_api(source, selected_games, commit=True)
                    else:  # results
                        imported, skipped, errors = import_results_from_api(source, selected_games, commit=True)
                    
                    # Update log
                    import_log.status = 'completed'
                    import_log.imported_count = imported
                    import_log.skipped_count = skipped
                    import_log.error_count = len(errors)
                    import_log.error_details = json.dumps(errors) if errors else None
                    import_log.approved_by_id = current_user.id
                    import_log.approved_at = datetime.utcnow()
                    import_log.completed_at = datetime.utcnow()
                    
                    # Update source last import
                    source.last_import_at = datetime.utcnow()
                    
                    db.session.commit()
                    
                    audit("api_import.approved", "APIImportLog", import_log.id, 
                          imported=imported, skipped=skipped, errors=len(errors),
                          selected=len(selected_games))
                    
                    flash(f"✅ Import dokončen! Importováno: {imported}, Přeskočeno: {skipped}, Vybraných: {len(selected_games)}", "ok")
                    
                except Exception as e:
                    import_log.status = 'failed'
                    import_log.error_details = str(e)
                    db.session.commit()
                    
                    flash(f"❌ Chyba při importu: {str(e)}", "error")
            
            elif action == "reject":
                import_log.status = 'rejected'
                import_log.approved_by_id = current_user.id
                import_log.approved_at = datetime.utcnow()
                db.session.commit()
                
                audit("api_import.rejected", "APIImportLog", import_log.id)
                flash("Import zamítnut", "ok")
            
            return redirect(url_for("admin_api_sources"))
        
        # Parse preview data
        preview = json.loads(import_log.preview_data) if import_log.preview_data else {}
        games = preview.get('games', [])
        
        errors = []
        if import_log.error_details:
            try:
                errors = json.loads(import_log.error_details)
            except:
                errors = [import_log.error_details]
        
        return render_page(r"""
<style>
  .preview-table {
    width: 100%;
    border-collapse: collapse;
  }
  
  .preview-table th,
  .preview-table td {
    padding: 10px 8px;
    text-align: left;
    border-bottom: 1px solid var(--line);
  }
  
  .preview-table th {
    background: rgba(255,255,255,.03);
    font-weight: 900;
    position: sticky;
    top: 0;
  }
  
  .new-import { background: rgba(51,209,122,.08); }
  .skip-import { background: rgba(167,178,214,.08); }
  .error-import { background: rgba(255,77,109,.08); }
</style>

<div class="card">
  <h2 style="margin: 0 0 8px 0;">
    {% if import_log.import_type == 'matches' %}📥 Preview importu zápasů{% else %}📊 Preview importu výsledků{% endif %}
  </h2>
  <div class="muted">{{ import_log.source.round.name }} • {{ import_log.source.api_type.upper() }}</div>
</div>

<div class="card">
  <div class="row" style="justify-content: space-between; flex-wrap: wrap; gap: 16px;">
    <div>
      <div class="muted">Celkem záznamů</div>
      <div style="font-size: 24px; font-weight: 900;">{{ import_log.imported_count + import_log.skipped_count }}</div>
    </div>
    <div>
      <div class="muted">Nové k importu</div>
      <div style="font-size: 24px; font-weight: 900; color: var(--ok);">{{ import_log.imported_count }}</div>
    </div>
    <div>
      <div class="muted">Přeskočit (existující)</div>
      <div style="font-size: 24px; font-weight: 900; color: var(--muted);">{{ import_log.skipped_count }}</div>
    </div>
    {% if import_log.error_count > 0 %}
    <div>
      <div class="muted">Chyby</div>
      <div style="font-size: 24px; font-weight: 900; color: var(--danger);">{{ import_log.error_count }}</div>
    </div>
    {% endif %}
  </div>
</div>

{% if errors|length > 0 %}
<div class="card" style="background: rgba(255,77,109,.08); border-color: rgba(255,77,109,.3);">
  <h3 style="margin: 0 0 12px 0;">⚠️ Chyby ({{ errors|length }})</h3>
  <div style="max-height: 200px; overflow-y: auto;">
    {% for error in errors %}
      <div class="muted" style="font-size: 13px; margin-bottom: 4px;">• {{ error }}</div>
    {% endfor %}
  </div>
</div>
{% endif %}

<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
<div class="card">
  <h3 style="margin: 0 0 12px 0;">📋 Data k importu (zobrazeno max {{ games|length }})</h3>
  
  <div style="margin-bottom: 12px;">
    <button type="button" class="btn btn-sm" onclick="selectAll()">✅ Vybrat vše</button>
    <button type="button" class="btn btn-sm" onclick="deselectAll()">☐ Zrušit výběr</button>
    <span class="muted" style="margin-left: 12px;" id="selected-count">Vybrané: 0</span>
  </div>
  
  <div style="overflow-x: auto;">
    <table class="preview-table">
      <thead>
        <tr>
          <th style="width: 40px;">
            <input type="checkbox" id="select-all-header" onchange="toggleAll(this)">
          </th>
          <th style="width: 40px;">#</th>
          <th>Domácí</th>
          {% if import_log.import_type == 'results' %}
          <th style="width: 80px; text-align: center;">Výsledek</th>
          {% endif %}
          <th>Hosté</th>
          <th style="width: 140px;">Datum/Čas</th>
          {% if import_log.import_type == 'results' %}
          <th style="width: 80px;">OT/SO</th>
          {% endif %}
        </tr>
      </thead>
      <tbody>
        {% for game in games %}
        <tr>
          <td>
            <input type="checkbox" name="selected_games" value="{{ loop.index0 }}" 
                   class="game-checkbox" onchange="updateCount()">
          </td>
          <td>{{ loop.index }}</td>
          <td><strong>{{ game.home_team }}</strong></td>
          {% if import_log.import_type == 'results' %}
          <td style="text-align: center;">
            {% if game.home_score is not none %}
              <strong>{{ game.home_score }}:{{ game.away_score }}</strong>
            {% else %}
              <span class="muted">—</span>
            {% endif %}
          </td>
          {% endif %}
          <td><strong>{{ game.away_team }}</strong></td>
          <td class="muted">
            {% if game.start_time %}
              {{ game.start_time[:16].replace('T', ' ') }}
            {% else %}
              —
            {% endif %}
          </td>
          {% if import_log.import_type == 'results' %}
          <td>
            {% if game.overtime %}
              <span class="tag pill-warn">OT</span>
            {% elif game.shootout %}
              <span class="tag pill-warn">SO</span>
            {% else %}
              <span class="muted">—</span>
            {% endif %}
          </td>
          {% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<script>
function toggleAll(checkbox) {
  const checkboxes = document.querySelectorAll('.game-checkbox');
  checkboxes.forEach(cb => cb.checked = checkbox.checked);
  updateCount();
}

function selectAll() {
  const checkboxes = document.querySelectorAll('.game-checkbox');
  checkboxes.forEach(cb => cb.checked = true);
  document.getElementById('select-all-header').checked = true;
  updateCount();
}

function deselectAll() {
  const checkboxes = document.querySelectorAll('.game-checkbox');
  checkboxes.forEach(cb => cb.checked = false);
  document.getElementById('select-all-header').checked = false;
  updateCount();
}

function updateCount() {
  const checked = document.querySelectorAll('.game-checkbox:checked').length;
  document.getElementById('selected-count').textContent = `Vybrané: ${checked}`;
}

// Auto-select all on load
window.addEventListener('DOMContentLoaded', function() {
  selectAll();
});
</script>

<div class="card" style="background: rgba(110,168,254,.08); border-color: rgba(110,168,254,.3);">
  <h3 style="margin: 0 0 12px 0;">ℹ️ Co se stane po potvrzení?</h3>
  
  {% if import_log.import_type == 'matches' %}
  <ul style="margin: 0; padding-left: 20px;">
    <li>Vytvoří se <strong>{{ import_log.imported_count }} nových zápasů</strong></li>
    <li>Týmy budou vytvořeny automaticky (pokud neexistují)</li>
    <li>{{ import_log.skipped_count }} existujících zápasů bude přeskočeno</li>
    <li>Vytvoří se mapování mezi API ID a našimi záznamy</li>
  </ul>
  {% else %}
  <ul style="margin: 0; padding-left: 20px;">
    <li>Aktualizuje se <strong>{{ import_log.imported_count }} výsledků zápasů</strong></li>
    {% if import_log.source.exclude_overtime %}
    <li><strong>Zápasy s OT/SO budou přeskočeny</strong> (kontroluj manuálně)</li>
    {% endif %}
    <li>{{ import_log.skipped_count }} zápasů už má výsledek (přeskočeno)</li>
  </ul>
  {% endif %}
</div>

  <div class="card">
    <div class="row" style="gap: 12px;">
      <button type="submit" name="action" value="approve" class="btn btn-primary" 
              style="flex: 1;">
        ✅ Potvrdit a importovat
      </button>
      <button type="submit" name="action" value="reject" class="btn" 
              style="flex: 1; background: rgba(255,77,109,.15); color: var(--danger);">
        ❌ Zamítnout
      </button>
    </div>
  </div>
</form>
""", import_log=import_log, games=games, errors=errors)
    
    @app.route("/admin/api-import/history")
    @login_required
    def admin_api_import_history():
        """Historie importů"""
        admin_required()
        
        logs = APIImportLog.query.order_by(APIImportLog.id.desc()).limit(100).all()
        
        return render_page(r"""
<div class="card">
  <h2 style="margin: 0 0 8px 0;">📋 Historie importů</h2>
  <div class="muted">Posledních 100 importů</div>
</div>

{% if logs|length == 0 %}
<div class="card">
  <div style="text-align: center; padding: 40px;">
    <div style="font-size: 48px; margin-bottom: 12px;">📋</div>
    <h3 style="margin: 0;">Žádná historie</h3>
  </div>
</div>
{% else %}
  {% for log in logs %}
  <div class="card" style="margin-bottom: 12px;">
    <div class="row" style="justify-content: space-between; align-items: center;">
      <div>
        <div class="row" style="gap: 8px; margin-bottom: 4px;">
          {% if log.import_type == 'matches' %}
            <span class="tag">📥 Zápasy</span>
          {% else %}
            <span class="tag">📊 Výsledky</span>
          {% endif %}
          
          {% if log.status == 'completed' %}
            <span class="tag pill-ok">✅ Hotovo</span>
          {% elif log.status == 'pending' %}
            <span class="tag pill-warn">⏳ Čeká</span>
          {% elif log.status == 'rejected' %}
            <span class="tag pill-bad">❌ Zamítnuto</span>
          {% elif log.status == 'failed' %}
            <span class="tag pill-bad">⚠️ Chyba</span>
          {% endif %}
        </div>
        
        <div style="font-weight: 700; margin-bottom: 4px;">
          {{ log.source.round.name }} • {{ log.source.api_type.upper() }}
        </div>
        
        <div class="muted" style="font-size: 13px;">
          {{ log.created_at.strftime('%d.%m.%Y %H:%M') }}
          {% if log.approved_by %}
            • {{ log.approved_by.username }}
          {% endif %}
        </div>
      </div>
      
      <div style="text-align: right;">
        <div style="font-size: 20px; font-weight: 900; color: var(--ok);">
          +{{ log.imported_count }}
        </div>
        <div class="muted" style="font-size: 12px;">
          Přeskočeno: {{ log.skipped_count }}
          {% if log.error_count > 0 %} • Chyby: {{ log.error_count }}{% endif %}
        </div>
      </div>
    </div>
  </div>
  {% endfor %}
{% endif %}
""", logs=logs)
    
    # === EXPORT HUB ===
    @app.route("/admin/export-hub", methods=["GET", "POST"])
    @login_required
    def admin_export_hub():
        """Centrální export hub s filtry"""
        admin_required()
        
        if request.method == "POST":
            # Co exportovat
            export_teams = request.form.get("export_teams") == "1"
            export_matches = request.form.get("export_matches") == "1"
            export_tips = request.form.get("export_tips") == "1"
            export_extras = request.form.get("export_extras") == "1"
            export_leaderboard = request.form.get("export_leaderboard") == "1"
            
            # Filtry
            round_id_str = request.form.get("round_id", "")
            round_id = int(round_id_str) if round_id_str and round_id_str != "0" else None
            user_id_str = request.form.get("user_id", "")
            user_id = int(user_id_str) if user_id_str and user_id_str != "0" else None
            only_finished = request.form.get("only_finished") == "1"
            include_deleted = request.form.get("include_deleted") == "1"
            format_type = request.form.get("format", "xlsx")
            
            if not any([export_teams, export_matches, export_tips, export_extras, export_leaderboard]):
                flash("Vyber alespoň jednu kategorii dat.", "error")
                return redirect(url_for("admin_export_hub"))
            
            # Vytvoř export
            import openpyxl
            from openpyxl.styles import PatternFill, Font, Alignment
            from io import BytesIO
            import csv
            
            if format_type == "xlsx":
                wb = openpyxl.Workbook()
                wb.remove(wb.active)
                
                # TÝMY
                if export_teams:
                    ws = wb.create_sheet("Týmy")
                    headers = ["ID", "Soutěž", "Název", "Skupina", "Země"]
                    header_fill = PatternFill("solid", fgColor="4472C4")
                    header_font = Font(color="FFFFFF", bold=True)
                    
                    for col, h in enumerate(headers, 1):
                        cell = ws.cell(row=1, column=col, value=h)
                        cell.fill = header_fill
                        cell.font = header_font
                    
                    query = Team.query
                    if round_id:
                        query = query.filter_by(round_id=round_id)
                    if not include_deleted:
                        query = query.filter_by(is_deleted=False)
                    
                    teams = query.all()
                    for row_i, team in enumerate(teams, 2):
                        ws.cell(row=row_i, column=1, value=team.id)
                        ws.cell(row=row_i, column=2, value=team.round.name if team.round else "")
                        ws.cell(row=row_i, column=3, value=team.name)
                        ws.cell(row=row_i, column=4, value=team.group or "")
                        ws.cell(row=row_i, column=5, value=team.country_code or "")
                    
                    for col in range(1, 6):
                        ws.column_dimensions[chr(64 + col)].width = 20
                
                # ZÁPASY
                if export_matches:
                    ws = wb.create_sheet("Zápasy")
                    headers = ["ID", "Soutěž", "Datum", "Čas", "Domácí", "Hosté", "Skóre D", "Skóre H", "Stav"]
                    header_fill = PatternFill("solid", fgColor="217346")
                    header_font = Font(color="FFFFFF", bold=True)
                    
                    for col, h in enumerate(headers, 1):
                        cell = ws.cell(row=1, column=col, value=h)
                        cell.fill = header_fill
                        cell.font = header_font
                    
                    query = Match.query
                    if round_id:
                        query = query.filter_by(round_id=round_id)
                    if not include_deleted:
                        query = query.filter_by(is_deleted=False)
                    if only_finished:
                        query = query.filter(Match.home_score != None, Match.away_score != None)
                    
                    matches = query.order_by(Match.start_time.asc()).all()
                    for row_i, match in enumerate(matches, 2):
                        ws.cell(row=row_i, column=1, value=match.id)
                        ws.cell(row=row_i, column=2, value=match.round.name if match.round else "")
                        ws.cell(row=row_i, column=3, value=match.start_time.strftime("%Y-%m-%d") if match.start_time else "")
                        ws.cell(row=row_i, column=4, value=match.start_time.strftime("%H:%M") if match.start_time else "")
                        ws.cell(row=row_i, column=5, value=match.home_team.name if match.home_team else "")
                        ws.cell(row=row_i, column=6, value=match.away_team.name if match.away_team else "")
                        ws.cell(row=row_i, column=7, value=match.home_score if match.home_score is not None else "")
                        ws.cell(row=row_i, column=8, value=match.away_score if match.away_score is not None else "")
                        
                        status = "Ukončen" if match.home_score is not None else ("Smazán" if match.is_deleted else "Naplánován")
                        ws.cell(row=row_i, column=9, value=status)
                    
                    for col in range(1, 10):
                        ws.column_dimensions[chr(64 + col)].width = 15
                
                # TIPY
                if export_tips:
                    ws = wb.create_sheet("Tipy")
                    headers = ["ID", "Soutěž", "Uživatel", "Zápas", "Tip D", "Tip H", "Datum"]
                    header_fill = PatternFill("solid", fgColor="FFC000")
                    header_font = Font(color="000000", bold=True)
                    
                    for col, h in enumerate(headers, 1):
                        cell = ws.cell(row=1, column=col, value=h)
                        cell.fill = header_fill
                        cell.font = header_font
                    
                    query = Tip.query.join(Match)
                    if round_id:
                        query = query.filter(Match.round_id == round_id)
                    if user_id:
                        query = query.filter(Tip.user_id == user_id)
                    if not include_deleted:
                        query = query.filter(Match.is_deleted == False)
                    if only_finished:
                        query = query.filter(Match.home_score != None)
                    
                    tips = query.order_by(Tip.created_at.desc()).limit(10000).all()
                    for row_i, tip in enumerate(tips, 2):
                        ws.cell(row=row_i, column=1, value=tip.id)
                        ws.cell(row=row_i, column=2, value=tip.match.round.name if tip.match and tip.match.round else "")
                        ws.cell(row=row_i, column=3, value=tip.user.username if tip.user else "")
                        match_str = f"{tip.match.home_team.name} vs {tip.match.away_team.name}" if tip.match else ""
                        ws.cell(row=row_i, column=4, value=match_str)
                        ws.cell(row=row_i, column=5, value=tip.tip_home)
                        ws.cell(row=row_i, column=6, value=tip.tip_away)
                        ws.cell(row=row_i, column=7, value=tip.created_at.strftime("%Y-%m-%d %H:%M") if tip.created_at else "")
                    
                    for col in range(1, 8):
                        ws.column_dimensions[chr(64 + col)].width = 20
                
                # EXTRA OTÁZKY
                if export_extras:
                    ws = wb.create_sheet("Extra")
                    headers = ["ID", "Soutěž", "Otázka", "Uzávěrka", "Odpovědí"]
                    header_fill = PatternFill("solid", fgColor="C65911")
                    header_font = Font(color="FFFFFF", bold=True)
                    
                    for col, h in enumerate(headers, 1):
                        cell = ws.cell(row=1, column=col, value=h)
                        cell.fill = header_fill
                        cell.font = header_font
                    
                    query = ExtraQuestion.query
                    if round_id:
                        query = query.filter_by(round_id=round_id)
                    if not include_deleted:
                        query = query.filter_by(is_deleted=False)
                    
                    questions = query.all()
                    for row_i, q in enumerate(questions, 2):
                        ws.cell(row=row_i, column=1, value=q.id)
                        ws.cell(row=row_i, column=2, value=q.round.name if q.round else "")
                        ws.cell(row=row_i, column=3, value=q.question)
                        ws.cell(row=row_i, column=4, value=q.deadline.strftime("%Y-%m-%d %H:%M") if q.deadline else "")
                        answer_count = ExtraAnswer.query.filter_by(question_id=q.id).count()
                        ws.cell(row=row_i, column=5, value=answer_count)
                    
                    for col in range(1, 6):
                        ws.column_dimensions[chr(64 + col)].width = 25
                
                # ŽEBŘÍČEK
                if export_leaderboard and round_id:
                    r = db.session.get(Round, round_id)
                    if r:
                        ws = wb.create_sheet("Žebříček")
                        headers = ["Pořadí", "Uživatel", "Body", "Přesné", "Rozdíl", "Tendence", "Chybné"]
                        header_fill = PatternFill("solid", fgColor="70AD47")
                        header_font = Font(color="FFFFFF", bold=True)
                        
                        for col, h in enumerate(headers, 1):
                            cell = ws.cell(row=1, column=col, value=h)
                            cell.fill = header_fill
                            cell.font = header_font
                        
                        leaderboard = compute_leaderboard(r.id)
                        for row_i, entry in enumerate(leaderboard, 2):
                            ws.cell(row=row_i, column=1, value=entry.get("rank", ""))
                            ws.cell(row=row_i, column=2, value=entry.get("username", ""))
                            ws.cell(row=row_i, column=3, value=entry.get("total_points", 0))
                            ws.cell(row=row_i, column=4, value=entry.get("exact", 0))
                            ws.cell(row=row_i, column=5, value=entry.get("diff", 0))
                            ws.cell(row=row_i, column=6, value=entry.get("tend", 0))
                            ws.cell(row=row_i, column=7, value=entry.get("wrong", 0))
                        
                        for col in range(1, 8):
                            ws.column_dimensions[chr(64 + col)].width = 15
                
                out = BytesIO()
                wb.save(out)
                out.seek(0)
                filename = f"export_{round_id or 'all'}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
                return send_file(out,
                               mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                               download_name=filename,
                               as_attachment=True)
            
            else:  # CSV
                flash("CSV export coming soon!", "info")
                return redirect(url_for("admin_export_hub"))
        
        # GET: Formulář
        rounds = Round.query.order_by(Round.id.desc()).all()
        users = User.query.order_by(User.username.asc()).all()
        
        return render_page(r"""
<style>
.export-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) { .export-grid { grid-template-columns: 1fr; } }
.export-category { 
  padding: 16px; background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px;
}
.export-category:has(input:checked) { background: rgba(110,168,254,.1); border-color: rgba(110,168,254,.5); }
</style>

<div class="card">
  <h2 style="margin:0 0 4px 0;">📤 Export dat</h2>
  <div class="muted">Stáhni data z tipovačky ve strukturovaném formátu</div>
  <hr class="sep">
  
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <h3 style="margin:20px 0 12px 0;">Co exportovat</h3>
    <div class="export-grid">
      <label class="export-category">
        <input type="checkbox" name="export_teams" value="1" style="width:18px; height:18px;">
        <strong style="margin-left:8px;">🏟️ Týmy</strong>
        <div class="muted" style="font-size:12px; margin-top:4px;">Názvy týmů, skupiny, kódy zemí</div>
      </label>
      
      <label class="export-category">
        <input type="checkbox" name="export_matches" value="1" style="width:18px; height:18px;">
        <strong style="margin-left:8px;">⚽ Zápasy</strong>
        <div class="muted" style="font-size:12px; margin-top:4px;">Rozpis zápasů, data, časy, výsledky</div>
      </label>
      
      <label class="export-category">
        <input type="checkbox" name="export_tips" value="1" style="width:18px; height:18px;">
        <strong style="margin-left:8px;">🎯 Tipy</strong>
        <div class="muted" style="font-size:12px; margin-top:4px;">Všechny tipy uživatelů</div>
      </label>
      
      <label class="export-category">
        <input type="checkbox" name="export_extras" value="1" style="width:18px; height:18px;">
        <strong style="margin-left:8px;">❓ Extra otázky</strong>
        <div class="muted" style="font-size:12px; margin-top:4px;">Otázky a odpovědi</div>
      </label>
      
      <label class="export-category">
        <input type="checkbox" name="export_leaderboard" value="1" style="width:18px; height:18px;">
        <strong style="margin-left:8px;">🏆 Žebříček</strong>
        <div class="muted" style="font-size:12px; margin-top:4px;">Aktuální pořadí a statistiky</div>
      </label>
    </div>
    
    <h3 style="margin:24px 0 12px 0;">Filtry</h3>
    <div class="row" style="gap:16px; flex-wrap:wrap;">
      <div class="form-group" style="flex:1; min-width:200px;">
        <label>Soutěž</label>
        <select name="round_id">
          <option value="">Všechny soutěže</option>
          {% for round in rounds %}
            <option value="{{ round.id }}">{{ round.name }}</option>
          {% endfor %}
        </select>
      </div>
      
      <div class="form-group" style="flex:1; min-width:200px;">
        <label>Uživatel (jen pro tipy)</label>
        <select name="user_id">
          <option value="">Všichni uživatelé</option>
          {% for user in users %}
            <option value="{{ user.id }}">{{ user.username }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    
    <div style="margin:12px 0; display:flex; flex-direction:column; gap:8px;">
      <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
        <input type="checkbox" name="only_finished" value="1" style="width:18px; height:18px;">
        <span>Jen dokončené zápasy</span>
      </label>
      
      <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
        <input type="checkbox" name="include_deleted" value="1" style="width:18px; height:18px;">
        <span>Včetně smazaných</span>
      </label>
    </div>
    
    <h3 style="margin:24px 0 12px 0;">Formát</h3>
    <div class="row" style="gap:16px;">
      <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
        <input type="radio" name="format" value="xlsx" checked style="width:18px; height:18px;">
        <span>📊 Excel (.xlsx)</span>
      </label>
    </div>
    
    <div class="row" style="gap:12px; margin-top:24px;">
      <button type="submit" class="btn btn-primary">📥 Stáhnout export</button>
      <a href="{{ url_for('admin_dashboard') }}" class="btn">← Zpět</a>
    </div>
  </form>
</div>
""", rounds=rounds, users=users)



def ensure_sqlite_schema() -> None:
    """Lightweight 'migration' for SQLite: add missing columns when upgrading this single-file app."""
    if db.engine.dialect.name != "sqlite":
        return

    def cols(table: str) -> set[str]:
        res = db.session.execute(db.text(f"PRAGMA table_info({table})")).all()
        return {r[1] for r in res}

    def add_col(table: str, col_def: str) -> None:
        db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {col_def}"))

    c_user = cols("user")
    if "role" not in c_user:
        add_col("user", "role VARCHAR(20) NOT NULL DEFAULT 'user'")
    if "first_name" not in c_user:
        add_col("user", "first_name VARCHAR(100)")
    if "last_name" not in c_user:
        add_col("user", "last_name VARCHAR(100)")
    if "nickname" not in c_user:
        add_col("user", "nickname VARCHAR(80)")
    
    # Email verifikace a password reset (nové)
    if "email_verified" not in c_user:
        add_col("user", "email_verified BOOLEAN NOT NULL DEFAULT 0")
    if "verification_token" not in c_user:
        add_col("user", "verification_token VARCHAR(100)")
    if "verification_token_expires" not in c_user:
        add_col("user", "verification_token_expires DATETIME")
    if "reset_token" not in c_user:
        add_col("user", "reset_token VARCHAR(100)")
    if "reset_token_expires" not in c_user:
        add_col("user", "reset_token_expires DATETIME")

    c_match = cols("match")
    if "is_deleted" not in c_match:
        add_col("match", "is_deleted BOOLEAN NOT NULL DEFAULT 0")

    c_team = cols("team")
    if "is_deleted" not in c_team:
        add_col("team", "is_deleted BOOLEAN NOT NULL DEFAULT 0")

    c_eq = cols("extra_question")
    if "is_deleted" not in c_eq:
        add_col("extra_question", "is_deleted BOOLEAN NOT NULL DEFAULT 0")

    db.session.commit()

# =========================================================
# SEED
# =========================================================

def purge_test_chance_liga_data():
    """Idempotent purge of old test data (Chance Liga).

    Deletes ONLY rounds whose name contains 'Chance Liga' AND have no tips.
    This prevents test fixtures from reappearing after rebuilds when a bundled DB is used.
    Controlled by env PURGE_TEST_CHANCE_LIGA (default '1').
    """
    if os.getenv("PURGE_TEST_CHANCE_LIGA", "1").strip().lower() in ("0", "false", "no"):
        return
    try:
        # Candidate rounds: name/title contains Chance Liga
        candidates = Round.query.filter(Round.name.ilike("%Chance Liga%")).all()
        purged_rounds = 0
        purged_matches = 0
        for rnd in candidates:
            # Safety: purge only if there are no tips in this round
            has_tips = (
                db.session.query(Tip.id)
                .join(Match, Tip.match_id == Match.id)
                .filter(Match.round_id == rnd.id)
                .limit(1)
                .first()
                is not None
            )
            if has_tips:
                continue

            # Delete dependent rows (tips should be none anyway), then matches, then round
            match_ids = [m.id for m in Match.query.filter_by(round_id=rnd.id).all()]
            if match_ids:
                # Just in case: remove tips for these matches (should be empty due to has_tips)
                Tip.query.filter(Tip.match_id.in_(match_ids)).delete(synchronize_session=False)
                Match.query.filter(Match.id.in_(match_ids)).delete(synchronize_session=False)
                purged_matches += len(match_ids)

            # Extras / other relations
            ExtraQuestion.query.filter_by(round_id=rnd.id).delete(synchronize_session=False)
            ExtraAnswer.query.filter_by(round_id=rnd.id).delete(synchronize_session=False)
            NotificationSent.query.filter_by(round_id=rnd.id).delete(synchronize_session=False) if "NotificationSent" in globals() else None
            RoundUserScore.query.filter_by(round_id=rnd.id).delete(synchronize_session=False) if "RoundUserScore" in globals() else None

            db.session.delete(rnd)
            purged_rounds += 1

        if purged_rounds or purged_matches:
            db.session.commit()
            print(f"🧹 Purged test Chance Liga data: rounds={purged_rounds}, matches={purged_matches}")
    except Exception as e:
        print(f"⚠️ purge_test_chance_liga_data failed: {e}")
        db.session.rollback()


def seed_defaults_if_empty():
    purge_test_chance_liga_data()
    if Sport.query.count() == 0:
        db.session.add(Sport(name="Fotbal"))
        db.session.add(Sport(name="Hokej"))
        db.session.commit()

    if User.query.count() == 0:
        admin = User(
            email=(OWNER_ADMIN_EMAIL or "").lower(), 
            username="admin", 
            is_admin=True, 
            role="admin",
            email_verified=True  # Admin má ověřený email automaticky
        )
        admin.set_password("admin")  # po prvním loginu změň
        db.session.add(admin)
        db.session.commit()
    
    # FIX: Ensure all admin/owner accounts have email_verified=True
    try:
        admin_users = User.query.filter(
            (User.is_admin == True) | 
            (User.email == (OWNER_ADMIN_EMAIL or "").lower())
        ).all()
        
        for admin in admin_users:
            if not admin.email_verified:
                admin.email_verified = True
                print(f"✅ Auto-verified email for admin: {admin.email}")
        
        if admin_users:
            db.session.commit()
    except Exception as e:
        print(f"⚠️ Error auto-verifying admin emails: {e}")
        db.session.rollback()

    # Vytvoř tajného uživatele, pokud ještě neexistuje
    if SECRET_USER_EMAIL and not User.query.filter_by(email=SECRET_USER_EMAIL.lower()).first():
        secret_user = User(
            email=SECRET_USER_EMAIL.lower(), 
            username="Kubouš", 
            is_admin=False, 
            role="user",
            email_verified=True  # Tajný user má také ověřený email
        )
        secret_user.set_password("kubouskubouskubous")  # změň po prvním loginu
        db.session.add(secret_user)
        db.session.commit()

    # ODSTRANĚNO: Vzorová "Soutěž 1" s týmy Sparta a Slavia
    # Uživatel si vytvoří vlastní soutěže podle potřeby


# =========================================================
# RUN
# =========================================================
app = create_app()

# =========================================================
# ERROR HANDLERS (Custom error pages)
# =========================================================
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page"""
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🔍</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#6ea8fe;">404</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Stránka nenalezena</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Tato stránka neexistuje nebo byla přesunuta. Možná jsi zadal špatnou adresu nebo odkaz je zastaralý.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    <a href="{{ url_for('leaderboard') }}" class="btn">📊 Žebříček</a>
    <a href="{{ url_for('matches') }}" class="btn">⚽ Zápasy</a>
  </div>
</div>
"""), 404

@app.errorhandler(403)
def forbidden(e):
    """Custom 403 error page"""
    is_logged_in = current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False
    
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🚫</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#dc3545;">403</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Přístup zamítnut</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Nemáš oprávnění k této stránce. Tato sekce je přístupná pouze pro administrátory nebo uživatele s vyššími právy.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    {% if not current_user.is_authenticated %}
      <a href="{{ url_for('login') }}" class="btn" style="background:#6ea8fe; color:white;">🔐 Přihlásit se</a>
    {% else %}
      <a href="{{ url_for('leaderboard') }}" class="btn">📊 Žebříček</a>
    {% endif %}
  </div>
</div>
"""), 403

@app.errorhandler(500)
def internal_error(e):
    """Custom 500 error page"""
    # Rollback databáze v případě chyby
    try:
        db.session.rollback()
    except:
        pass
    
    # Log chybu (pro debugging)
    import traceback
    print("\n" + "="*60)
    print("500 INTERNAL SERVER ERROR")
    print("="*60)
    print(traceback.format_exc())
    print("="*60 + "\n")
    
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">💥</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#dc3545;">500</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Něco se pokazilo</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 16px auto;">
    Omlouváme se, na serveru došlo k neočekávané chybě. Tým byl automaticky informován a pracujeme na nápravě.
  </p>
  <p class="muted" style="font-size:13px; margin:0 auto 32px auto;">
    Zkus to prosím za chvíli znovu.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    <a href="javascript:location.reload()" class="btn">🔄 Zkusit znovu</a>
  </div>
</div>
"""), 500

@app.errorhandler(401)
def unauthorized(e):
    """Custom 401 error page"""
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🔐</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#ffc107;">401</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Vyžadováno přihlášení</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Pro přístup k této stránce se musíš přihlásit. Pokud nemáš účet, můžeš se zaregistrovat.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('login') }}" class="btn btn-primary">🔐 Přihlásit se</a>
    <a href="{{ url_for('register') }}" class="btn">📝 Registrovat se</a>
    <a href="{{ url_for('home') }}" class="btn">🏠 Domů</a>
  </div>
</div>
"""), 401

if __name__ == "__main__":
    app.run(debug=True)
