"""
routes/admin_core.py
"""

import datetime
from typing import Optional
from io import BytesIO
import os
import csv
import json
import tempfile
import zipfile

from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font
from flask import request, flash, redirect, url_for, send_file, session, Response, render_template_string
from flask_login import current_user, login_required

from models import AuditLog, ExtraAnswer, ExtraQuestion, ImportSession, Match, Round, Team, Tip, UndoStack, User
from app_utils import admin_required, audit, compute_leaderboard, create_undo_point, ensure_selected_round, perform_undo, render_page, send_email_with_attachment, send_results_notification
from extensions import db

def register_admin_core(app):
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
                round_id = request.form.get("round_id")
                import_mode = request.form.get("import_mode", "fixtures")

                # Check if screenshot pasted from clipboard
                screenshot_data = request.form.get('screenshot_data', '')

                if screenshot_data and screenshot_data.startswith('data:image'):
                    # Clipboard screenshot mode
                    print("📸 Clipboard screenshot detected")

                    try:
                        # Extract base64 data
                        import base64
                        # Format: data:image/png;base64,iVBORw0KG...
                        base64_data = screenshot_data.split(',')[1]
                        image_data = base64.b64decode(base64_data)

                        # Extract text using OCR
                        text = extract_text_from_screenshot(image_data)

                        if not text:
                            flash("❌ Nepodařilo se přečíst screenshot. Zkus paste text ručně.", "error")
                            return redirect(url_for("admin_smart_import"))

                        print(f"✅ OCR extracted text ({len(text)} chars)")

                    except Exception as e:
                        print(f"❌ Screenshot processing error: {e}")
                        flash(f"❌ Chyba při zpracování screenshotu: {e}", "error")
                        return redirect(url_for("admin_smart_import"))
                else:
                    # Text mode (default)
                    text = request.form.get("raw_text", "")

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
      .paste-zone {
      position: relative;
    }

    .paste-instruction {
      text-align: center;
      padding: 20px;
      background: rgba(102, 126, 234, 0.1);
      border-radius: 8px;
      margin-bottom: 16px;
      border: 2px dashed rgba(102, 126, 234, 0.3);
    }

    .paste-zone.has-image .paste-instruction {
      display: none;
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

      <form method="post" >
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
          <label>Zápasy - screenshot NEBO text</label>

          <!-- Screenshot Upload -->


          <div class="examples">
            <h3>💡 Podporované formáty:</h3>
            <div class="example-item">27. 2. 2026DuklaSlavia18:00</div>
            <div class="example-item">27. 2. 2026 Sparta - Slavia 18:00</div>
            <div class="example-item">27. 2. 20:00 Sparta vs Slavia</div>
            <div class="example-item">1. 3. SpartaOstrava20:00 (auto rok)</div>
            <div class="example-item">Sparta - Slavia 2:1</div>
          </div>
          <div class="paste-zone" id="pasteZone">
            <div id="pasteInstruction" class="paste-instruction">
              📸 <strong>Napiš nebo vlož screenshot</strong>
              <div class="muted" style="margin-top: 8px;">
                Win+Shift+S → Ctrl+V zde → Auto OCR ✨
              </div>
            </div>

            <textarea name="raw_text" 
                      id="rawText"
                      placeholder="Paste text NEBO screenshot (Ctrl+V)..."
                      style="min-height: 300px;"></textarea>

            <input type="hidden" name="screenshot_data" id="screenshotData">

            <div id="imagePreview" style="display: none; margin-top: 12px;">
              <div style="color: #2ecc71; margin-bottom: 8px;">
                ✅ Screenshot načten - OCR se spustí při parsování
              </div>
              <img id="previewImg" style="max-width: 100%; max-height: 200px; border-radius: 8px; border: 2px solid #667eea;">
              <button type="button" onclick="clearPastedImage()" class="btn btn-secondary" style="margin-top: 8px;">
                ❌ Smazat screenshot
              </button>
            </div>
          </div>
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
            home_score: homeScore !== "" ? parseInt(homeScore, 10) : null,
            away_score: awayScore !== "" ? parseInt(awayScore, 10) : null,
            start_time: startTime || null
          });
        }
      });

      document.getElementById('matchesData').value = JSON.stringify(matches);
    });
      </script>

      <script>
    // Image preview
    document.getElementById('screenshot')?.addEventListener('change', function(e) {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
          document.getElementById('previewImg').src = e.target.result;
          document.getElementById('preview').style.display = 'block';
          document.getElementById('uploadZone').querySelector('.upload-label').style.display = 'none';
        };
        reader.readAsDataURL(file);
      }
    });

    function clearImage() {
      document.getElementById('screenshot').value = '';
      document.getElementById('preview').style.display = 'none';
      document.getElementById('uploadZone').querySelector('.upload-label').style.display = 'block';
    }

    // Drag & drop
    const uploadZone = document.getElementById('uploadZone');
    if (uploadZone) {
      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadZone.addEventListener(eventName, preventDefaults, false);
      });

      function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
      }

      ['dragenter', 'dragover'].forEach(eventName => {
        uploadZone.addEventListener(eventName, () => {
          uploadZone.classList.add('drag-over');
        });
      });

      ['dragleave', 'drop'].forEach(eventName => {
        uploadZone.addEventListener(eventName, () => {
          uploadZone.classList.remove('drag-over');
        });
      });

      uploadZone.addEventListener('drop', function(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
          document.getElementById('screenshot').files = files;
          const event = new Event('change');
          document.getElementById('screenshot').dispatchEvent(event);
        }
      });
    }
      </script>

      <script>
    let pastedImageData = null;

    // Listen for paste events on textarea
    document.getElementById('rawText')?.addEventListener('paste', function(e) {
      const items = (e.clipboardData || e.originalEvent.clipboardData).items;

      for (let item of items) {
        if (item.type.indexOf('image') !== -1) {
          // Image pasted!
          e.preventDefault();

          const blob = item.getAsFile();
          const reader = new FileReader();

          reader.onload = function(event) {
            const base64 = event.target.result;

            // Store in hidden field
            document.getElementById('screenshotData').value = base64;

            // Show preview
            document.getElementById('previewImg').src = base64;
            document.getElementById('imagePreview').style.display = 'block';
            document.getElementById('pasteZone').classList.add('has-image');

            // Clear textarea (user pasted image, not text)
            document.getElementById('rawText').value = '';

            console.log('✅ Screenshot pasted, will OCR on submit');
          };

          reader.readAsDataURL(blob);
          break;
        }
      }
    });

    function clearPastedImage() {
      document.getElementById('screenshotData').value = '';
      document.getElementById('imagePreview').style.display = 'none';
      document.getElementById('pasteZone').classList.remove('has-image');
      document.getElementById('rawText').focus();
    }
      </script>
    </body>
    </html>
    """

