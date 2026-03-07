"""
Authentication Routes
Login, register, logout, password reset, email verification
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db
from models import User, PasswordReset, EmailVerification
from services.email_service import send_password_reset_email, send_verification_email, send_welcome_email
from datetime import datetime, timedelta
import secrets

auth_bp = Blueprint("auth", __name__)


    @auth_bp.route("/register", methods=["GET", "POST"])
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



    @auth_bp.route("/login", methods=["GET", "POST"])
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



    @auth_bp.route("/logout")
    @login_required
    def logout():
        audit("user.logout", "User", current_user.id)
        logout_user()
        return redirect(url_for("login"))

    # --- EMAIL VERIFIKACE ---


    @auth_bp.route("/verify-email/<token>")
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


    @auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
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

