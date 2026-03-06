"""
routes/admin_rounds.py
"""

import datetime
import re

from flask import request, flash, redirect, url_for, abort, session
from flask_login import login_required

from models import ExtraAnswer, ExtraQuestion, Match, Round, Team, TeamAlias, Tip, User
from app_utils import admin_required, audit, dt_to_input_value, ensure_selected_round, parse_naive_datetime, render_page, set_selected_round_id
from extensions import db

def register_admin_rounds(app):
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

