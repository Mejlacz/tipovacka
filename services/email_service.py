"""
Email Service
Handles all email sending functionality
"""

from flask import render_template_string
from models import User
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os


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



