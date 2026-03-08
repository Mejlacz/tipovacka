"""
routes/errors.py
"""
from flask_login import current_user

from app_utils import render_page


def page_not_found(e):
    """Custom 404 error page"""
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🔍</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#6ea8fe;">404</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Stránka nenalezena</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Tato stránka neexistuje nebo byla přesunuta. Možná jsi zadal špatnou adresu nebo odkaz je zastaralý.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    <a href="{{ url_for('leaderboard') }}" class="btn">📊 Žebříček</a>
    <a href="{{ url_for('matches') }}" class="btn">⚽ Zápasy</a>
  </div>
</div>
"""), 404

def forbidden(e):
    """Custom 403 error page"""
    is_logged_in = current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False
    
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🚫</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#dc3545;">403</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Přístup zamítnut</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Nemáš oprávnění k této stránce. Tato sekce je přístupná pouze pro administrátory nebo uživatele s vyššími právy.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    {% if not current_user.is_authenticated %}
      <a href="{{ url_for('login') }}" class="btn" style="background:#6ea8fe; color:white;">🔐 Přihlásit se</a>
    {% else %}
      <a href="{{ url_for('leaderboard') }}" class="btn">📊 Žebříček</a>
    {% endif %}
  </div>
</div>
"""), 403

def internal_error(e):
    """Custom 500 error page"""
    # Rollback databáze v případě chyby
    try:
        db.session.rollback()
    except:
        pass
    
    # Log chybu (pro debugging)
    import traceback
    print("\n" + "="*60)
    print("500 INTERNAL SERVER ERROR")
    print("="*60)
    print(traceback.format_exc())
    print("="*60 + "\n")
    
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">💥</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#dc3545;">500</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Něco se pokazilo</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 16px auto;">
    Omlouváme se, na serveru došlo k neočekávané chybě. Tým byl automaticky informován a pracujeme na nápravě.
  </p>
  <p class="muted" style="font-size:13px; margin:0 auto 32px auto;">
    Zkus to prosím za chvíli znovu.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('home') }}" class="btn btn-primary">🏠 Domů</a>
    <a href="javascript:location.reload()" class="btn">🔄 Zkusit znovu</a>
  </div>
</div>
"""), 500

def unauthorized(e):
    """Custom 401 error page"""
    return render_page(r"""
<div class="card" style="text-align:center; padding:80px 20px; max-width:600px; margin:40px auto;">
  <div style="font-size:120px; margin:0; line-height:1;">🔐</div>
  <h1 style="font-size:48px; margin:20px 0 10px 0; color:#ffc107;">401</h1>
  <h2 style="margin:0 0 16px 0; font-weight:500;">Vyžadováno přihlášení</h2>
  <p class="muted" style="font-size:15px; line-height:1.6; max-width:400px; margin:0 auto 32px auto;">
    Pro přístup k této stránce se musíš přihlásit. Pokud nemáš účet, můžeš se zaregistrovat.
  </p>
  
  <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
    <a href="{{ url_for('login') }}" class="btn btn-primary">🔐 Přihlásit se</a>
    <a href="{{ url_for('register') }}" class="btn">📝 Registrovat se</a>
    <a href="{{ url_for('home') }}" class="btn">🏠 Domů</a>
  </div>
</div>
"""), 401

if __name__ == "__main__":
    # Production: Gunicorn starts the app via Procfile
    # Development: Uncomment below to run locally with: python app2.py
    # app.run(debug=True, host='0.0.0.0', port=5000)
    pass


def register_errors(app):
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(403, forbidden)
    app.register_error_handler(500, internal_error)
    app.register_error_handler(401, unauthorized)
