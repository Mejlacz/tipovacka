"""
routes/archive.py
"""

import datetime
import csv
import json

from reportlab.pdfgen import canvas
from flask import request, flash, redirect, url_for, jsonify, session, Response
from flask_login import login_required

from models import Match, Round, Team, Tip, User
from app_utils import admin_required, audit, calc_points_for_tip, render_page
from extensions import db

def register_archive(app):
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

