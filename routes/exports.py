"""
routes/exports.py
"""

from io import BytesIO
import csv

from openpyxl import Workbook
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from flask import abort, session
from flask_login import login_required

from models import ExtraAnswer, ExtraQuestion, Match, Round, Team, Tip, User
from app_utils import admin_required, audit, binary_response, calc_points_for_tip, csv_response, ensure_selected_round
from extensions import db

def register_exports(app):
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

