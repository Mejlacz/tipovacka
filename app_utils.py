"""
app_utils.py
Helpery a servisní funkce – žádné Flask routes, žádný HTML.
Importuj kde potřebuješ, bez rizika circular importu.
"""
from __future__ import annotations
import os
import re
import json
import secrets
import smtplib
import pickle
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from flask import abort, request, session
from flask_login import current_user
from werkzeug.security import generate_password_hash
from flask import Response

from extensions import db
from models import (
    User, Round, Match, Tip, Team,
    RoundUserScore, UndoStack, AuditLog,
    Achievement, ExtraQuestion, ExtraAnswer,
    PushSubscription, NotificationPreferences,
    APISource, APIImportLog, MatchAPIMapping,
)

try:
    from pywebpush import webpush, WebPushException
    WEBPUSH_AVAILABLE = True
except ImportError:
    WEBPUSH_AVAILABLE = False

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

OWNER_ADMIN_EMAIL = os.environ.get("OWNER_ADMIN_EMAIL", "3049@email.cz")
SECRET_USER_EMAIL = os.environ.get("SECRET_USER_EMAIL", "kubamartinec97@gmail.com")



# =========================================================
# VALIDACE HESLA
# =========================================================


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Ověří sílu hesla podle bezpečnostní policy.
    
    Požadavky:
    - Minimálně 8 znaků
    - Alespoň jedno malé písmeno (a-z)
    - Alespoň jedno velké písmeno (A-Z)
    - Alespoň jedna číslice (0-9)
    
    Returns:
        (is_valid, error_message)
        Pokud je heslo v pořádku: (True, "OK")
        Pokud ne: (False, "důvod proč ne")
    """
    if len(password) < 8:
        return False, "Heslo musí mít alespoň 8 znaků"
    
    if not re.search(r"[a-z]", password):
        return False, "Heslo musí obsahovat alespoň jedno malé písmeno (a-z)"
    
    if not re.search(r"[A-Z]", password):
        return False, "Heslo musí obsahovat alespoň jedno velké písmeno (A-Z)"
    
    if not re.search(r"[0-9]", password):
        return False, "Heslo musí obsahovat alespoň jednu číslici (0-9)"
    
    return True, "OK"

# =========================================================
# EMAIL CONFIG + ODESÍLÁNÍ
# =========================================================


def get_email_config():
    """
    Vrátí konfiguraci pro email.
    Podporuje obě konvence názvů: MAIL_* (Flask-Mail) a SMTP_* (custom).
    """
    return {
        'SMTP_SERVER': os.environ.get('MAIL_SERVER') or os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
        'SMTP_PORT': int(os.environ.get('MAIL_PORT') or os.environ.get('SMTP_PORT', '587')),
        'SMTP_USERNAME': os.environ.get('MAIL_USERNAME') or os.environ.get('SMTP_USERNAME', ''),
        'SMTP_PASSWORD': os.environ.get('MAIL_PASSWORD') or os.environ.get('SMTP_PASSWORD', ''),
        'FROM_EMAIL': os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('FROM_EMAIL', 'noreply@tipovacka.cz'),
        'FROM_NAME': os.environ.get('FROM_NAME', 'Tipovačka'),
        'USE_TLS': os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
        'SEND_REAL_EMAILS': os.environ.get('SEND_REAL_EMAILS', 'false').lower() == 'true',
        'REQUIRE_EMAIL_VERIFICATION': os.environ.get('REQUIRE_EMAIL_VERIFICATION', 'true').lower() == 'true'
    }

def send_email(to_email: str, subject: str, html_body: str, text_body: str = None) -> bool:
    """
    Pošle email.
    
    Args:
        to_email: Příjemce
        subject: Předmět
        html_body: HTML verze emailu
        text_body: Plain text verze (volitelné)
    
    Returns:
        True pokud email odeslán, False pokud chyba
    """
    config = get_email_config()
    
    # Development mode - jen vypíše do console
    if not config['SEND_REAL_EMAILS']:
        print(f"\n{'='*60}")
        print(f"📧 EMAIL (Development Mode - neposílá se)")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"{'='*60}")
        print(html_body)
        print(f"{'='*60}\n")
        return True
    
    # Production mode - skutečně pošle email
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{config['FROM_NAME']} <{config['FROM_EMAIL']}>"
        msg['To'] = to_email
        
        # Text verze (fallback)
        if text_body:
            part1 = MIMEText(text_body, 'plain', 'utf-8')
            msg.attach(part1)
        
        # HTML verze
        part2 = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(part2)
        
        # Pošli email
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            if config.get('USE_TLS', True):  # Default True pro Gmail
                server.starttls()
            if config['SMTP_USERNAME'] and config['SMTP_PASSWORD']:
                server.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    
    except Exception as e:
        print(f"❌ Chyba při posílání emailu: {e}")
        return False

def send_email_with_attachment(to_email: str, subject: str, html_body: str, text_body: str,
                                 attachment_data: bytes, attachment_name: str) -> bool:
    """Pošle email s přílohou (např. backup databáze)"""
    
    config = get_email_config()
    
    # Development mode - jen vypsat do logu
    if not config['SEND_REAL_EMAILS']:
        print("\n" + "="*60)
        print("📧 EMAIL S PŘÍLOHOU (Development Mode - neposílá se)")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"Attachment: {attachment_name} ({len(attachment_data)} bytes = {len(attachment_data)/(1024*1024):.2f} MB)")
        print("="*60)
        print(html_body[:500] + "..." if len(html_body) > 500 else html_body)
        print("="*60 + "\n")
        return True
    
    # Production mode - poslat skutečně
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders
        
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = f"{config['FROM_NAME']} <{config['FROM_EMAIL']}>"
        msg['To'] = to_email
        
        # Text část
        if text_body:
            msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        
        # HTML část
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Příloha
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment_data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')
        msg.attach(part)
        
        # Odešli
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            if config.get('USE_TLS', True):  # Default True pro Gmail
                server.starttls()
            if config['SMTP_USERNAME'] and config['SMTP_PASSWORD']:
                server.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    
    except Exception as e:
        print(f"❌ Chyba při posílání emailu s přílohou: {e}")
        return False

def send_verification_email(user: User, base_url: str) -> bool:
    """Pošle potvrzovací email po registraci"""
    
    verification_url = f"{base_url}/verify-email/{user.verification_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
            .upload-zone {
      border: 3px dashed rgba(102, 126, 234, 0.3);
      border-radius: 12px;
      padding: 32px;
      text-align: center;
      transition: all 0.3s;
      background: rgba(20, 20, 30, 0.4);
      cursor: pointer;
    }
    
    .upload-zone:hover {
      border-color: #667eea;
      background: rgba(20, 20, 30, 0.6);
    }
    
    .upload-zone.drag-over {
      border-color: #667eea;
      background: rgba(102, 126, 234, 0.1);
    }
    
    .upload-label {
      cursor: pointer;
      font-size: 18px;
      color: #667eea;
      display: block;
    }
    
    .or-separator {
      text-align: center;
      margin: 20px 0;
      color: #888;
      font-weight: 600;
    }
  </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Tipovačka</h1>
            </div>
            <div class="content">
                <h2>Vítej v Tipovačce!</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Děkujeme za registraci! Zbývá už jen potvrdit tvůj email.</p>
                <p style="text-align: center;">
                    <a href="{verification_url}" class="button">
                        ✅ Potvrdit email
                    </a>
                </p>
                <p>Nebo zkopíruj tento odkaz do prohlížeče:</p>
                <p style="font-size: 12px; word-break: break-all;">{verification_url}</p>
                <p><strong>Platnost:</strong> 24 hodin</p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože někdo zaregistroval účet s tvým emailem.</p>
                <p>Pokud to nebyl ty, můžeš tento email ignorovat.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Děkujeme za registraci! Zbývá už jen potvrdit tvůj email.
    
    Klikni na tento odkaz pro potvrzení:
    {verification_url}
    
    Platnost: 24 hodin
    
    Pokud tento email jsi nedostal ty, můžeš ho ignorovat.
    """
    
    return send_email(
        to_email=user.email,
        subject="Potvrď svůj email - Tipovačka",
        html_body=html,
        text_body=text
    )

def send_password_reset_email(user: User, base_url: str) -> bool:
    """Pošle email s odkazem na reset hesla"""
    
    reset_url = f"{base_url}/reset-password/{user.reset_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .warning {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Tipovačka</h1>
            </div>
            <div class="content">
                <h2>Reset hesla</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Dostal jsi tento email protože někdo požádal o reset hesla pro tvůj účet.</p>
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">
                        🔑 Nastavit nové heslo
                    </a>
                </p>
                <p>Nebo zkopíruj tento odkaz do prohlížeče:</p>
                <p style="font-size: 12px; word-break: break-all;">{reset_url}</p>
                <div class="warning">
                    <strong>⚠️ Důležité:</strong>
                    <ul>
                        <li>Odkaz je platný <strong>1 hodinu</strong></li>
                        <li>Pokud jsi o reset nepožádal, ignoruj tento email</li>
                        <li>Tvé heslo zůstane nezměněné dokud neklikneš na odkaz</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>Pokud jsi o reset hesla nepožádal, někdo možná zadal tvůj email omylem.</p>
                <p>Tvé heslo je v bezpečí - změní se pouze pokud klikneš na odkaz výše.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Reset hesla - Tipovačka
    
    Ahoj {user.display_name},
    
    Dostal jsi tento email protože někdo požádal o reset hesla pro tvůj účet.
    
    Klikni na tento odkaz pro nastavení nového hesla:
    {reset_url}
    
    ⚠️ DŮLEŽITÉ:
    - Odkaz je platný 1 hodinu
    - Pokud jsi o reset nepožádal, ignoruj tento email
    - Tvé heslo zůstane nezměněné dokud neklikneš na odkaz
    
    Pokud jsi o reset hesla nepožádal, někdo možná zadal tvůj email omylem.
    Tvé heslo je v bezpečí - změní se pouze pokud klikneš na odkaz výše.
    """
    
    return send_email(
        to_email=user.email,
        subject="Reset hesla - Tipovačka",
        html_body=html,
        text_body=text
    )

def send_welcome_email_for_imported_user(user: User, password: str, base_url: str) -> bool:
    """Pošle welcome email importovanému uživateli s přihlašovacími údaji"""
    
    change_password_url = f"{base_url}/change-password"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .credentials {{ 
                background: white; 
                padding: 20px; 
                border-left: 4px solid #6ea8fe;
                margin: 20px 0;
                font-family: monospace;
            }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .warning {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Vítej v Tipovačce!</h1>
            </div>
            <div class="content">
                <h2>Tvůj účet byl vytvořen</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Byl jsi přidán do tipovací soutěže! Tady jsou tvoje přihlašovací údaje:</p>
                
                <div class="credentials">
                    <strong>🔐 Přihlašovací údaje:</strong><br><br>
                    <strong>Email:</strong> {user.email}<br>
                    <strong>Username:</strong> {user.username}<br>
                    <strong>Heslo:</strong> {password}
                </div>
                
                <div class="warning">
                    <strong>⚠️ DOPORUČUJEME:</strong><br>
                    Po prvním přihlášení si <strong>změň heslo</strong> na vlastní!
                </div>
                
                <p style="text-align: center;">
                    <a href="{base_url}" class="button">
                        🎯 Přihlásit se
                    </a>
                </p>
                
                <p>Po přihlášení můžeš jít na <strong>Profil → Změnit heslo</strong> nebo klikni sem:</p>
                <p style="font-size: 12px; word-break: break-all;">{change_password_url}</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                
                <p style="font-size: 14px; color: #666;">
                    <strong>Jak začít:</strong><br>
                    1. Přihlaš se pomocí údajů výše<br>
                    2. Změň si heslo (doporučeno)<br>
                    3. Začni tipovat!
                </p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože tě admin přidal do tipovací soutěže.</p>
                <p>Pokud máš dotazy, kontaktuj admina.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Byl jsi přidán do tipovací soutěže! Tady jsou tvoje přihlašovací údaje:
    
    🔐 PŘIHLAŠOVACÍ ÚDAJE:
    Email: {user.email}
    Username: {user.username}
    Heslo: {password}
    
    ⚠️ DOPORUČUJEME:
    Po prvním přihlášení si změň heslo na vlastní!
    
    Přihlásit se: {base_url}
    Změnit heslo: {change_password_url}
    
    JAK ZAČÍT:
    1. Přihlaš se pomocí údajů výše
    2. Změň si heslo (doporučeno)
    3. Začni tipovat!
    
    Tento email jsi dostal protože tě admin přidal do tipovací soutěže.
    Pokud máš dotazy, kontaktuj admina.
    """
    
    return send_email(
        to_email=user.email,
        subject="Vítej v Tipovačce - Přihlašovací údaje",
        html_body=html,
        text_body=text
    )

def send_welcome_with_reset_link(user: User, base_url: str) -> bool:
    """
    Pošle welcome email s reset linkem pro nastavení hesla.
    
    Používá se po importu uživatelů - user dostane email
    s odkazem pro nastavení vlastního hesla (bez hesla v emailu).
    """
    # Vygeneruj reset token
    user.reset_token = secrets.token_urlsafe(32)
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=24)  # 24h platnost
    db.session.commit()
    
    reset_url = f"{base_url}/reset-password/{user.reset_token}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #0b1020; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f4f4f4; padding: 30px; }}
            .credentials {{ 
                background: white; 
                padding: 20px; 
                border-left: 4px solid #6ea8fe;
                margin: 20px 0;
                font-family: monospace;
            }}
            .button {{ 
                display: inline-block; 
                background: #6ea8fe; 
                color: white; 
                padding: 12px 30px; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }}
            .info {{ background: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏆 Vítej v Tipovačce!</h1>
            </div>
            <div class="content">
                <h2>Byl jsi přidán do soutěže</h2>
                <p>Ahoj <strong>{user.display_name}</strong>,</p>
                <p>Byl jsi přidán do tipovací soutěže! Pro dokončení registrace si nastav vlastní heslo.</p>
                
                <div class="credentials">
                    <strong>🔐 Tvoje přihlašovací údaje:</strong><br><br>
                    <strong>Email:</strong> {user.email}<br>
                    <strong>Username:</strong> {user.username}<br>
                    <strong>Heslo:</strong> <em>Nastavíš si sám (viz níže)</em>
                </div>
                
                <div class="info">
                    <strong>🔑 KROK 1: Nastav si heslo</strong><br>
                    Klikni na tlačítko níže a nastav si vlastní heslo:
                </div>
                
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">
                        🔑 Nastavit heslo
                    </a>
                </p>
                
                <p style="font-size: 12px; word-break: break-all;">Nebo zkopíruj tento odkaz: {reset_url}</p>
                
                <div class="info">
                    <strong>⏰ Platnost:</strong> 24 hodin<br>
                    Po nastavení hesla se můžeš přihlásit a začít tipovat!
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                
                <p style="font-size: 14px; color: #666;">
                    <strong>Jak začít:</strong><br>
                    1. Klikni na "Nastavit heslo"<br>
                    2. Zadej si vlastní heslo (min. 8 znaků)<br>
                    3. Přihlaš se pomocí email/username a nového hesla<br>
                    4. Začni tipovat!
                </p>
            </div>
            <div class="footer">
                <p>Tento email jsi dostal protože tě admin přidal do tipovací soutěže.</p>
                <p>Pokud máš dotazy, kontaktuj admina.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
    Vítej v Tipovačce!
    
    Ahoj {user.display_name},
    
    Byl jsi přidán do tipovací soutěže!
    
    🔐 TVOJE PŘIHLAŠOVACÍ ÚDAJE:
    Email: {user.email}
    Username: {user.username}
    Heslo: Nastavíš si sám (viz níže)
    
    🔑 KROK 1: NASTAV SI HESLO
    Klikni na tento odkaz a nastav si vlastní heslo:
    {reset_url}
    
    ⏰ Platnost: 24 hodin
    
    JAK ZAČÍT:
    1. Klikni na odkaz výše
    2. Zadej si vlastní heslo (min. 8 znaků)
    3. Přihlaš se pomocí email/username a nového hesla
    4. Začni tipovat!
    
    Tento email jsi dostal protože tě admin přidal do tipovací soutěže.
    Pokud máš dotazy, kontaktuj admina.
    """
    
    return send_email(
        to_email=user.email,
        subject="Vítej v Tipovačce - Nastav si heslo",
        html_body=html,
        text_body=text
    )

# =========================================================
# DATETIME HELPERS
# =========================================================


def now_utc() -> datetime:
    """Returns current Czech local time (Europe/Prague) as naive datetime.

    The app stores match times as naive Czech time. Servers (Heroku/Koyeb) usually run in UTC,
    so using datetime.now() would incorrectly lock tips ~1h early/late depending on DST.
    """
    try:
        from zoneinfo import ZoneInfo
        cz = ZoneInfo("Europe/Prague")
        return datetime.now(cz).replace(tzinfo=None)
    except Exception:
        # Fallback: best-effort local time
        return datetime.now()

def parse_naive_datetime(s: str) -> Optional[datetime]:
    """Parse datetime from form input (Czech time)"""
    s = (s or "").strip()
    if not s:
        return None
    s = s.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            # Uložit přímo jako český čas (naive datetime)
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None

def dt_to_input_value(dt: Optional[datetime]) -> str:
    """Convert datetime to form display (Czech time)"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M")

# =========================================================
# AUTH / PERMISSION HELPERS
# =========================================================


def admin_required() -> None:
    if not current_user.is_authenticated or not getattr(current_user, 'is_admin_effective', False):
        abort(403)

def moderator_required() -> None:
    if not current_user.is_authenticated or not getattr(current_user, 'is_moderator_effective', False):
        abort(403)

def owner_required() -> None:
    if not current_user.is_authenticated or not current_user.is_owner:
        abort(403)

def can_see_user_in_admin(user: User) -> bool:
    if (user.email or "").lower() != (SECRET_USER_EMAIL or "").lower():
        return True
    return bool(current_user.is_authenticated and current_user.is_owner)

# =========================================================
# AUDIT LOG + UNDO
# =========================================================


def audit(action: str, entity: str, entity_id: Optional[int] = None, **details: Any) -> None:
    try:
        payload = {k: v for k, v in details.items() if v is not None}
        db.session.add(
            AuditLog(
                actor_user_id=(current_user.id if current_user.is_authenticated else None),
                action=action,
                entity=entity,
                entity_id=entity_id,
                details=(str(payload)[:4000] if payload else None),
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

def create_undo_point(action_type: str, entity_type: str, entity_id: int, before_state: dict, description: str = None):
    """
    Vytvoř undo point pro možnost vrácení změny
    """
    if not current_user.is_authenticated:
        return
    
    try:
        undo = UndoStack(
            user_id=current_user.id,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            before_state=json.dumps(before_state) if before_state else None,
            description=description
        )
        db.session.add(undo)
        db.session.commit()
        return undo.id
    except Exception:
        db.session.rollback()
        return None

def perform_undo(undo_id: int) -> dict:
    """
    Vrať změnu zpět
    """
    undo = db.session.get(UndoStack, undo_id)
    
    if not undo:
        return {'success': False, 'message': 'Undo záznam nenalezen'}
    
    if undo.is_undone:
        return {'success': False, 'message': 'Tato akce už byla vrácena'}
    
    try:
        before = json.loads(undo.before_state) if undo.before_state else {}
        
        # Restore podle typu entity
        if undo.entity_type == 'Match':
            match = db.session.get(Match, undo.entity_id)
            if match:
                if 'home_score' in before:
                    match.home_score = before['home_score']
                if 'away_score' in before:
                    match.away_score = before['away_score']
        
        # Označ jako undone
        undo.is_undone = True
        undo.undone_at = datetime.utcnow()
        
        db.session.commit()
        
        audit("undo.perform", "UndoStack", undo.id, description=undo.description)
        
        return {
            'success': True,
            'message': f'✅ Změna vrácena: {undo.description or ""}',
            'entity_type': undo.entity_type,
            'entity_id': undo.entity_id
        }
    
    except Exception as e:
        db.session.rollback()
        return {
            'success': False,
            'message': f'Chyba při vracení: {str(e)}'
        }

# =========================================================
# PUSH NOTIFIKACE
# =========================================================


def send_push_notification(user_id: int, title: str, body: str, data: dict = None, icon: str = "/static/icon-192.png"):
    """
    Pošle push notifikaci uživateli
    
    Args:
        user_id: ID uživatele
        title: Nadpis notifikace
        body: Text notifikace
        data: Extra data (URL kam otevřít, atd.)
        icon: Ikona notifikace
    """
    try:
        # Import pywebpush (lazy import aby nerozbil app pokud není nainstalováno)
        try:
            from pywebpush import webpush, WebPushException
        except ImportError:
            print("⚠️ pywebpush není nainstalováno - notifikace se nepošle")
            return False
        
        # Najdi všechny aktivní subscriptions pro uživatele
        subscriptions = PushSubscription.query.filter_by(
            user_id=user_id,
            enabled=True
        ).all()
        
        if not subscriptions:
            return False
        
        # Připrav payload
        payload = {
            "title": title,
            "body": body,
            "icon": icon,
            "badge": "/static/badge-96.png",
            "data": data or {}
        }
        
        sent_count = 0
        failed_subs = []
        
        # Pošli na všechny zařízení uživatele
        for sub in subscriptions:
            try:
                subscription_info = {
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": sub.p256dh,
                        "auth": sub.auth
                    }
                }
                
                webpush(
                    subscription_info=subscription_info,
                    data=json.dumps(payload),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims=VAPID_CLAIMS
                )
                
                # Update last_used_at
                sub.last_used_at = datetime.utcnow()
                sent_count += 1
                
            except WebPushException as e:
                print(f"Push failed for sub {sub.id}: {e}")
                # Pokud je subscription invalid (410), smaž ji
                if e.response and e.response.status_code == 410:
                    failed_subs.append(sub)
        
        # Smaž failed subscriptions
        for sub in failed_subs:
            db.session.delete(sub)
        
        db.session.commit()
        
        return sent_count > 0
        
    except Exception as e:
        print(f"Error sending push: {e}")
        return False

def send_push_to_all(title: str, body: str, data: dict = None):
    """
    Pošle notifikaci VŠEM uživatelům
    """
    users = User.query.all()
    sent = 0
    for user in users:
        if send_push_notification(user.id, title, body, data):
            sent += 1
    return sent

def get_notification_preferences(user_id: int):
    """
    Získá nastavení notifikací pro uživatele
    Pokud neexistuje, vytvoř s výchozími hodnotami
    """
    prefs = NotificationPreferences.query.filter_by(user_id=user_id).first()
    
    if not prefs:
        # Vytvoř výchozí nastavení
        prefs = NotificationPreferences(
            user_id=user_id,
            notify_results=True,
            notify_deadline=True,
            notify_new_round=True,
            notify_achievement=True,
            notify_leaderboard=False
        )
        db.session.add(prefs)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            # Vrať výchozí hodnoty i když se neuložilo
            class DefaultPrefs:
                notify_results = True
                notify_deadline = True
                notify_new_round = True
                notify_achievement = True
                notify_leaderboard = False
            return DefaultPrefs()
    
    return prefs

def send_results_notification(round_id: int):
    """
    Pošle notifikaci o zadaných výsledcích
    Personalizované - každý uživatel dostane svoje body
    """
    r = db.session.get(Round, round_id)
    if not r:
        return
    
    # Pro každého uživatele spočítej body
    users = User.query.all()
    
    for user in users:
        # Zkontroluj jestli uživatel chce tyto notifikace
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_results:
            continue  # User nechce notifikace o výsledcích
        
        # Spočítej body v této soutěži
        tips = Tip.query.join(Match).filter(
            Match.round_id == round_id,
            Tip.user_id == user.id
        ).all()
        
        if not tips:
            continue  # Uživatel netipoval
        
        total_points = 0
        exact_count = 0
        
        for tip in tips:
            match = tip.match
            if match.home_score is not None and match.away_score is not None:
                pts = calc_points_for_tip(match, tip)
                total_points += pts
                if pts == 3:
                    exact_count += 1
        
        # Vytvoř personalizovaný text
        if exact_count > 0:
            body = f"Máš {exact_count} přesných tipů! Celkem {total_points} bodů 🎯"
        elif total_points > 0:
            body = f"Získal jsi {total_points} bodů!"
        else:
            body = f"Bohužel žádný bod tentokrát..."
        
        send_push_notification(
            user.id,
            f"⚽ Výsledky - {r.name}",
            body,
            {"url": "/leaderboard"}
        )

def send_deadline_reminder(round_id: int):
    """
    Pošle připomínku o deadline
    Pouze uživatelům kteří ještě netipovali
    """
    r = db.session.get(Round, round_id)
    if not r:
        return
    
    # Najdi zápasy bez tipu
    users = User.query.all()
    
    for user in users:
        # Zkontroluj preferences
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_deadline:
            continue  # User nechce deadline reminders
        
        # Kolik zápasů je v soutěži
        total_matches = Match.query.filter_by(
            round_id=round_id,
            is_deleted=False
        ).count()
        
        # Kolik uživatel natipoval
        tipped_count = Tip.query.join(Match).filter(
            Match.round_id == round_id,
            Tip.user_id == user.id
        ).count()
        
        if tipped_count < total_matches:
            missing = total_matches - tipped_count
            send_push_notification(
                user.id,
                f"⏰ Deadline za 1 hodinu!",
                f"Ještě nemáš {missing} tipů v {r.name}",
                {"url": "/my-tips"}
            )

def send_achievement_notification(user_id: int, achievement_type: str):
    """
    Pošle notifikaci o získaném achievementu
    """
    # Zkontroluj preferences
    prefs = get_notification_preferences(user_id)
    if not prefs.notify_achievement:
        return  # User nechce achievement notifikace
    
    achievement_names = {
        "first_tip": "První krok! 🎯",
        "hattrick": "Hat-trick! ⚽⚽⚽",
        "perfect_round": "Perfektní kolo! 💯",
        "comeback": "Návrat z popela! 🔥",
        "striker": "Střelec! 🎯",
        "lucky_seven": "Šťastná 7! 🍀"
    }
    
    name = achievement_names.get(achievement_type, "Nový achievement!")
    
    send_push_notification(
        user_id,
        f"🏅 {name}",
        "Získal jsi nový achievement!",
        {"url": "/profile"}
    )

def send_leaderboard_change_notification(user_id: int, old_position: int, new_position: int, round_id: int):
    """
    Pošle notifikaci o změně pozice v žebříčku
    """
    # Zkontroluj preferences
    prefs = get_notification_preferences(user_id)
    if not prefs.notify_leaderboard:
        return  # User nechce leaderboard notifikace
    
    r = db.session.get(Round, round_id)
    
    if new_position < old_position:
        # Posun nahoru
        icon_emoji = "📈"
        text = f"Posunul ses na {new_position}. místo!"
    else:
        # Posun dolů
        icon_emoji = "📉"
        text = f"Klesnul jsi na {new_position}. místo"
    
    send_push_notification(
        user_id,
        f"{icon_emoji} Změna v žebříčku!",
        text,
        {"url": "/leaderboard"}
    )

def send_new_round_notification(round_name: str):
    """
    Pošle notifikaci o nové soutěži
    """
    users = User.query.all()
    
    for user in users:
        # Zkontroluj preferences
        prefs = get_notification_preferences(user.id)
        if not prefs.notify_new_round:
            continue  # User nechce notifikace o nových soutěžích
        
        send_push_notification(
            user.id,
            "🆕 Nová soutěž!",
            f"{round_name} - Tipuj teď!",
            {"url": "/matches"}
        )

# =========================================================
# ROUND SESSION HELPERS
# =========================================================


def get_selected_round_id() -> Optional[int]:
    rid = session.get("selected_round_id")
    if rid is None:
        return None
    try:
        return int(rid)
    except Exception:
        return None

def set_selected_round_id(round_id: int) -> None:
    session["selected_round_id"] = int(round_id)

def get_rounds_for_switch():
    if not current_user.is_authenticated:
        return []
    return Round.query.order_by(Round.is_active.desc(), Round.id.desc()).all()

def ensure_selected_round() -> Optional[int]:
    rounds = get_rounds_for_switch()
    if not rounds:
        return None
    selected = get_selected_round_id()
    if selected is None or not any(r.id == selected for r in rounds):
        active = next((r for r in rounds if r.is_active), None)
        selected = active.id if active else rounds[0].id
        set_selected_round_id(selected)
    return selected

# =========================================================
# HERNÍ LOGIKA
# =========================================================


def is_tips_locked(r: Round, m: Optional[Match] = None) -> bool:
    # lock by round deadline
    if r.tips_close_time and now_utc() >= r.tips_close_time:
        return True
    # lock by match start
    if m and m.start_time and now_utc() >= m.start_time:
        return True
    return False

def is_extras_locked(r: Round) -> bool:
    return bool(r.extra_close_time and now_utc() >= r.extra_close_time)

def check_and_award_achievements(user_id: int, round_id: int):
    """Zkontroluj a uděl achievementy pro uživatele v dané soutěži"""
    from flask import current_app
    
    user = db.session.get(User, user_id)
    r = db.session.get(Round, round_id)
    if not user or not r:
        return
    
    # Načti tipy uživatele
    my_tips = Tip.query.join(Match).filter(
        Tip.user_id == user_id,
        Match.round_id == round_id,
        Match.is_deleted == False
    ).all()
    
    if not my_tips:
        return
    
    # === FIRST TIP ===
    if len(my_tips) == 1:
        _award_achievement(user_id, 'first_tip', round_id)
    
    # Pro další achievementy potřebujeme vyhodnocené zápasy
    evaluated_tips = [t for t in my_tips if t.match.home_score is not None and t.match.away_score is not None]
    
    if not evaluated_tips:
        return
    
    # === HATTRICK & PERFECT 5 ===
    # Seřaď tipy podle data zápasu
    sorted_tips = sorted(evaluated_tips, key=lambda t: t.match.start_time or datetime.min)
    
    current_streak = 0
    max_streak = 0
    
    for tip in sorted_tips:
        points = calc_points_for_tip(tip.match, tip)
        if points == 3:  # Přesný tip
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 0
    
    if max_streak >= 3:
        _award_achievement(user_id, 'hattrick', round_id)
    if max_streak >= 5:
        _award_achievement(user_id, 'perfect_5', round_id)
    if max_streak >= 10:
        _award_achievement(user_id, 'sniper', round_id)  # NOVÉ: 10 přesných po sobě!
    
    # === PERFECT ROUND ===
    # Zkontroluj jestli všechny tipy jsou přesné
    all_exact = all(calc_points_for_tip(t.match, t) == 3 for t in evaluated_tips)
    if all_exact and len(evaluated_tips) >= 3:  # Min 3 zápasy
        _award_achievement(user_id, 'perfect_round', round_id)
    
    # === FULL ATTENDANCE ===
    # Zkontroluj jestli tipoval všechny zápasy
    all_matches = Match.query.filter_by(round_id=round_id, is_deleted=False).all()
    tipped_match_ids = {t.match_id for t in my_tips}
    all_match_ids = {m.id for m in all_matches}
    
    if tipped_match_ids == all_match_ids and len(all_matches) >= 5:  # Min 5 zápasů
        _award_achievement(user_id, 'full_attendance', round_id)
    
    # === CENTURY & HALF CENTURY ===
    total_points = sum(calc_points_for_tip(t.match, t) for t in evaluated_tips)
    
    if total_points >= 50:
        _award_achievement(user_id, 'half_century', round_id)
    if total_points >= 100:
        _award_achievement(user_id, 'century', round_id)
    
    # === TOP TIPPER ===
    # Zkontroluj jestli má nejvíc bodů v soutěži
    all_users = User.query.all()
    user_scores = []
    
    for u in all_users:
        u_tips = Tip.query.join(Match).filter(
            Tip.user_id == u.id,
            Match.round_id == round_id,
            Match.is_deleted == False,
            Match.home_score != None,
            Match.away_score != None
        ).all()
        
        u_total = sum(calc_points_for_tip(t.match, t) for t in u_tips)
        user_scores.append({'user_id': u.id, 'total': u_total})
    
    user_scores.sort(key=lambda x: -x['total'])
    
    # Pokud je první (a má alespoň nějaké body)
    if user_scores and user_scores[0]['user_id'] == user_id and user_scores[0]['total'] > 0:
        # Zkontroluj že nemá stejný počet bodů s někým jiným
        top_score = user_scores[0]['total']
        top_count = sum(1 for x in user_scores if x['total'] == top_score)
        if top_count == 1:  # Jen on má nejvíc
            _award_achievement(user_id, 'top_tipper', round_id)
    
    # === WARRIOR ===
    # Účast ve 3+ soutěžích (global achievement)
    rounds_participated = db.session.query(Round.id).join(Match).join(Tip).filter(
        Tip.user_id == user_id,
        Match.is_deleted == False
    ).distinct().count()
    
    if rounds_participated >= 3:
        _award_achievement(user_id, 'warrior', None)  # Global, ne per-round
    
    # === UNDERDOG ===
    # Top 3 s méně než 50% tipnutých zápasů
    if len(user_scores) >= 3:
        top_3_users = [x['user_id'] for x in user_scores[:3]]
        if user_id in top_3_users:
            # Počet tipnutých vs všech zápasů
            total_matches_count = len(all_matches)
            tipped_count = len(my_tips)
            if total_matches_count > 0 and tipped_count / total_matches_count < 0.5:
                _award_achievement(user_id, 'underdog', round_id)

def get_user_achievements(user_id: int, round_id: int = None):
    """Získej achievementy uživatele (volitelně filtrováno podle soutěže)"""
    query = Achievement.query.filter_by(user_id=user_id)
    
    if round_id is not None:
        query = query.filter_by(round_id=round_id)
    
    achievements = query.all()
    
    # Vrať seznam s detaily
    result = []
    for ach in achievements:
        if ach.achievement_type in ACHIEVEMENTS:
            info = ACHIEVEMENTS[ach.achievement_type].copy()
            info['earned_at'] = ach.earned_at
            info['type'] = ach.achievement_type
            result.append(info)
    
    return result

def calc_points_for_tip(match: Match, tip: Tip) -> int:
    if match.home_score is None or match.away_score is None:
        return 0
    if tip.tip_home == match.home_score and tip.tip_away == match.away_score:
        return 3
    m_diff = match.home_score - match.away_score
    t_diff = tip.tip_home - tip.tip_away
    if (m_diff == 0 and t_diff == 0) or (m_diff > 0 and t_diff > 0) or (m_diff < 0 and t_diff < 0):
        return 1
    return 0

def recompute_round_user_score(round_id: int, user_id: int) -> RoundUserScore:
    """Přepočítá a uloží cache bodů pro (round, user)."""
    tips = (
        Tip.query.join(Match)
        .filter(Match.round_id == round_id, Tip.user_id == user_id, Match.is_deleted == False)
        .all()
    )

    total_points = 0
    exact_count = 0

    for tip in tips:
        match = tip.match
        if not match:
            continue
        if match.home_score is None or match.away_score is None:
            continue
        pts = calc_points_for_tip(match, tip)
        total_points += pts
        if pts == 3:
            exact_count += 1

    row = RoundUserScore.query.filter_by(round_id=round_id, user_id=user_id).first()
    if not row:
        row = RoundUserScore(round_id=round_id, user_id=user_id)

    row.points = int(total_points)
    row.exact_count = int(exact_count)
    row.updated_at = datetime.utcnow()
    db.session.add(row)
    db.session.commit()
    return row

def recompute_round_scores(round_id: int) -> None:
    """Přepočítá cache bodů pro celé kolo."""
    users = User.query.all()
    for u in users:
        try:
            recompute_round_user_score(round_id, u.id)
        except Exception:
            db.session.rollback()
            continue

def get_cached_round_score(round_id: int, user_id: int) -> Optional[RoundUserScore]:
    row = RoundUserScore.query.filter_by(round_id=round_id, user_id=user_id).first()
    return row

# =========================================================
# RESPONSE HELPERS
# =========================================================


def csv_response(filename_ascii: str, content: str) -> Response:
    resp = Response(content, mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename_ascii}"'
    return resp

def binary_response(filename_ascii: str, content: bytes, mimetype: str) -> Response:
    resp = Response(content, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename_ascii}"'
    return resp


# =========================================================
# render_page  –  centrální helper pro všechny route soubory
# BASE_HTML importujeme tady, aby base_html.py nemohl
# importovat zpět z app_utils → žádný circular import.
# =========================================================
from base_html import BASE_HTML  # noqa: E402
from flask_wtf.csrf import generate_csrf  # noqa: E402 (uz importovano výše, ale bezpečné)


def render_page(
    content_html: str,
    ctx=None,
    selected=None,
):
    """Obalí content_html do BASE_HTML šablony.

    Args:
        content_html: Jinja2 string s HTML obsahem stránky.
        ctx:          Slovník proměnných pro šablonu (default None → {}).
        selected:     ID aktuálně zvolené soutěže (override).

    Returns:
        Hotový HTML string pro Flask response.
    """
    from flask import render_template_string  # lokální import – vyhne se circular

    if ctx is None:
        ctx = {}

    rounds = []
    if current_user.is_authenticated:
        rounds = get_rounds_for_switch(selected)
        ensure_selected_round()

    # Odstraň klíče které přidáváme sami – zabrání KeyError / duplicate
    ctx.pop("rounds_for_switch", None)
    ctx.pop("selected_round_id_for_switch", None)
    ctx.pop("csrf_token", None)
    ctx["csrf_token"] = generate_csrf()

    inner = render_template_string(
        content_html,
        rounds_for_switch=rounds,
        selected_round_id_for_switch=selected,
        **ctx,
    )
    return render_template_string(
        BASE_HTML,
        content=inner,
        rounds_for_switch=rounds,
        selected_round_id_for_switch=selected,
        **ctx,
    )
