"""
routes/admin_api.py
"""

import datetime
import json

from flask import request, flash, redirect, url_for, abort, session
from flask_login import current_user, login_required

from models import APIImportLog, APISource, MatchAPIMapping, Round, Tip
from app_utils import admin_required, audit, render_page
from api_parsers.py import fetch_api_games, import_matches_from_api, import_results_from_api
from extensions import db

def register_admin_api(app):
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

