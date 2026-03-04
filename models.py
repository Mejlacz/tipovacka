"""
Database Models
Matching ACTUAL database schema (without migration)
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(190), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # NOTE: is_admin, is_verified, created_at NOT in database yet!
    # Will need migration to add them later


class Sport(db.Model):
    __tablename__ = 'sport'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)


class Round(db.Model):
    __tablename__ = 'round'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False, index=True)
    sport_id = db.Column(db.Integer, db.ForeignKey("sport.id"), nullable=True)
    sport = db.relationship("Sport", lazy=True)
    tips_close_time = db.Column(db.DateTime, nullable=True)
    extra_close_time = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Team(db.Model):
    __tablename__ = 'team'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)


class TeamAlias(db.Model):
    __tablename__ = 'team_alias'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False)
    alias = db.Column(db.String(100), nullable=False)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    round = db.relationship("Round", lazy=True)


class Match(db.Model):
    __tablename__ = 'match'
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    home_team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False)
    away_team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Tip(db.Model):
    __tablename__ = 'tip'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    match_id = db.Column(db.Integer, db.ForeignKey("match.id"), nullable=False, index=True)
    home_score = db.Column(db.Integer, nullable=False)
    away_score = db.Column(db.Integer, nullable=False)
    points = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)


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
    __tablename__ = 'extra_question'
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=False, index=True)
    question_text = db.Column(db.Text, nullable=False)
    correct_answer = db.Column(db.String(200), nullable=True)
    points = db.Column(db.Integer, default=1)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    round = db.relationship("Round", lazy=True)


class ExtraAnswer(db.Model):
    __tablename__ = 'extra_answer'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey("extra_question.id"), nullable=False, index=True)
    answer_text = db.Column(db.String(200), nullable=False)
    points = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    question = db.relationship("ExtraQuestion", lazy=True)


class Achievement(db.Model):
    __tablename__ = 'achievement'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user = db.relationship("User", lazy=True)
    achievement_type = db.Column(db.String(50), nullable=False)
    earned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    round_id = db.Column(db.Integer, db.ForeignKey("round.id"), nullable=True)
    __table_args__ = (db.UniqueConstraint("user_id", "achievement_type", "round_id", name="uq_user_achievement"),)


class UndoStack(db.Model):
    __tablename__ = 'undo_stack'
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
    __tablename__ = 'push_subscription'
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
    __tablename__ = 'notification_preferences'
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
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class APISource(db.Model):
    __tablename__ = 'api_source'
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
    __tablename__ = 'api_import_log'
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
    __tablename__ = 'match_api_mapping'
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
