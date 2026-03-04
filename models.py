"""
Database Models
All SQLAlchemy models for Tipovacka
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(190), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)


class Sport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)


class Round(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False, index=True)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)


class TeamAlias(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)


class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)


class Tip(db.Model):
    id = db.Column(db.Integer, primary_key=True)


class RoundUserScore(db.Model):
    __tablename__ = "round_user_score"
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    points = db.Column(db.Integer, default=0, nullable=False)
    exact_count = db.Column(db.Integer, default=0, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


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


class ExtraAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("extra_question.id"), nullable=False, index=True)
    question = db.relationship("ExtraQuestion", lazy=True)


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

