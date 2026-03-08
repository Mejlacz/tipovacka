"""
routes/main.py
"""

from datetime import datetime, timedelta

from flask import request, flash, redirect, url_for, abort, session
from flask_login import current_user, login_required

from models import ExtraAnswer, ExtraQuestion, Match, Round, Team, Tip, User
from app_utils import audit, calc_points_for_tip, check_and_award_achievements, ensure_selected_round, get_user_achievements, is_extras_locked, is_tips_locked, now_utc, recompute_round_user_score, render_page
from extensions import db
from config import SECRET_USER_EMAIL, ACHIEVEMENTS

def register_main(app):
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

