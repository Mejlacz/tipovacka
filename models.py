"""
models.py
Všechny SQLAlchemy modely. Importují `db` z extensions.py – žádná jiná závislost.
"""
from __future__ import annotations
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db

OWNER_ADMIN_EMAIL = "3049@email.cz"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(190), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    nickname = db.Column(db.String(80), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(100), nullable=True, index=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), nullable=True, index=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def display_name(self) -> str:
        if self.nickname:
            return self.nickname
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        return self.username

    @property
    def full_name(self) -> str:
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        if self.last_name:
            return self.last_name
        return self.username

    @property
    def effective_role(self) -> str:
        if getattr(self, "is_admin", False):
            return "admin"
        return getattr(self, "role", "user") or "user"

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
    __table_args__ = (db.UniqueConstraint("round_id", "alias", name="uq_teamalias_round_alias"),)


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
    deadline = db.Column(db.DateTime, nullable=True)
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    achievement_type = db.Column(db.String(50), nullable=False)
    earned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=True)
    __table_args__ = (db.UniqueConstraint("user_id", "achievement_type", "round_id", name="uq_user_achievement"),)


class UndoStack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    action_type = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    before_state = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    is_undone = db.Column(db.Boolean, default=False)
    undone_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    endpoint = db.Column(db.Text, nullable=False)
    p256dh = db.Column(db.Text, nullable=False)
    auth = db.Column(db.Text, nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    __table_args__ = (db.UniqueConstraint("user_id", "endpoint", name="uq_user_endpoint"),)


class NotificationPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True, unique=True)
    user = db.relationship("User", lazy=True)
    notify_results = db.Column(db.Boolean, default=True)
    notify_deadline = db.Column(db.Boolean, default=True)
    notify_new_round = db.Column(db.Boolean, default=True)
    notify_achievement = db.Column(db.Boolean, default=True)
    notify_leaderboard = db.Column(db.Boolean, default=False)
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


class APISource(db.Model):
    __tablename__ = "api_source"
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)
    api_type = db.Column(db.String(50), nullable=False)
    api_url = db.Column(db.String(500), nullable=True)
    api_key = db.Column(db.String(200), nullable=True)
    league_id = db.Column(db.String(100), nullable=True)
    auto_import_matches = db.Column(db.Boolean, default=False)
    auto_import_results = db.Column(db.Boolean, default=False)
    require_admin_approval = db.Column(db.Boolean, default=True)
    exclude_overtime = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    last_import_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_by = db.relationship("User", lazy=True)


class APIImportLog(db.Model):
    __tablename__ = "api_import_log"
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("api_source.id"), nullable=False, index=True)
    source = db.relationship("APISource", lazy=True)
    import_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    imported_count = db.Column(db.Integer, default=0)
    skipped_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    preview_data = db.Column(db.Text, nullable=True)
    error_details = db.Column(db.Text, nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    approved_by = db.relationship("User", foreign_keys=[approved_by_id], lazy=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)


class MatchAPIMapping(db.Model):
    __tablename__ = "match_api_mapping"
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey("match.id"), nullable=False, unique=True)
    match = db.relationship("Match", lazy=True)
    source_id = db.Column(db.Integer, db.ForeignKey("api_source.id"), nullable=False)
    source = db.relationship("APISource", lazy=True)
    api_match_id = db.Column(db.String(100), nullable=False)
    api_home_team_id = db.Column(db.String(100), nullable=True)
    api_away_team_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("source_id", "api_match_id", name="uq_source_api_match"),)
