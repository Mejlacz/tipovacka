"""
routes/pwa.py
"""

import datetime
import json

from flask import request, url_for, jsonify, session, Response
from flask_login import current_user, login_required

from models import PushSubscription, Tip, User
from app_utils import get_notification_preferences, render_page, send_push_notification
from extensions import csrf, db

def register_pwa(app):
    @app.route("/manifest.json")
    def pwa_manifest():
        """PWA manifest pro instalaci aplikace"""
        manifest = {
            "name": "Tipovačka",
            "short_name": "Tipovačka",
            "description": "Tipovací aplikace pro sázení na sportovní výsledky",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0b1020",
            "theme_color": "#0b1020",
            "orientation": "any",
            "icons": [
                {
                    "src": url_for('pwa_icon', size=192, _external=True),
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable"
                },
                {
                    "src": url_for('pwa_icon', size=512, _external=True),
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any maskable"
                }
            ],
            "categories": ["sports", "entertainment"],
            "lang": "cs"
        }
        return jsonify(manifest)

    # --- PUSH NOTIFICATIONS ---

    @app.route("/service-worker.js")
    def service_worker():
        """Service Worker pro offline mode a caching"""
        sw_code = """
    // Service Worker pro Tipovačka PWA
    const CACHE_NAME = 'tipovacka-v1';
    const urlsToCache = [
      '/',
      '/dashboard',
      '/matches',
      '/leaderboard',
      '/my-stats',
      '/achievements'
    ];

    // Install
    self.addEventListener('install', event => {
      event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
      );
      self.skipWaiting();
    });

    // Activate
    self.addEventListener('activate', event => {
      event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
      );
      self.clients.claim();
    });

    // Fetch - Network first, fallback to cache
    self.addEventListener('fetch', event => {
      event.respondWith(
    fetch(event.request)
      .then(response => {
        // Clone response a ulož do cache
        if (response.status === 200) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // Pokud není síť, použij cache
        return caches.match(event.request);
      })
      );
    });

    // Push Notification Handler
    self.addEventListener('push', event => {
      console.log('[Service Worker] Push received:', event);

      let data = {
    title: '🏆 Tipovačka',
    body: 'Nová notifikace',
    icon: '/static/icon-192.png',
    badge: '/static/badge-96.png',
    data: {}
      };

      try {
    if (event.data) {
      data = event.data.json();
    }
      } catch (e) {
    console.error('Error parsing push data:', e);
      }

      const options = {
    body: data.body,
    icon: data.icon || '/static/icon-192.png',
    badge: data.badge || '/static/badge-96.png',
    vibrate: [200, 100, 200],
    tag: 'tipovacka-notification',
    requireInteraction: false,
    data: data.data || {}
      };

      event.waitUntil(
    self.registration.showNotification(data.title, options)
      );
    });

    // Notification Click Handler
    self.addEventListener('notificationclick', event => {
      console.log('[Service Worker] Notification click:', event);

      event.notification.close();

      // Kam otevřít
      let url = '/';
      if (event.notification.data && event.notification.data.url) {
    url = event.notification.data.url;
      }

      // Otevři nebo focusni existující okno
      event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(clientList => {
        // Zkus najít už otevřené okno
        for (let client of clientList) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        // Jinak otevři nové
        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
      );
    });
    """
        response = Response(sw_code, mimetype='application/javascript')
        response.headers['Service-Worker-Allowed'] = '/'
        return response

    @app.route("/pwa-icon/<int:size>")
    def pwa_icon(size):
        """Generuj PWA ikonu jako SVG"""
        # Jednoduchá ikona - modrý kruh s písmeny T
        svg = f"""<?xml version="1.0" encoding="UTF-8"?>
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
      <rect width="{size}" height="{size}" fill="#0b1020"/>
      <circle cx="{size/2}" cy="{size/2}" r="{size/2.5}" fill="#6ea8fe"/>
      <text x="{size/2}" y="{size/1.8}" font-family="Arial, sans-serif" font-size="{size/2.5}" font-weight="900" fill="#fff" text-anchor="middle">T</text>
    </svg>"""
        return Response(svg, mimetype='image/svg+xml')

    # =========================================================
    # API IMPORT ROUTES
    # =========================================================

    @app.route("/api/push/subscribe", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_subscribe():
        """Subscribe k push notifikacím"""
        data = request.get_json()

        if not data or 'endpoint' not in data:
            return jsonify({"success": False, "message": "Missing endpoint"}), 400

        try:
            # Zkontroluj jestli už subscription existuje
            existing = PushSubscription.query.filter_by(
                user_id=current_user.id,
                endpoint=data['endpoint']
            ).first()

            if existing:
                # Update
                existing.p256dh = data['keys']['p256dh']
                existing.auth = data['keys']['auth']
                existing.user_agent = request.headers.get('User-Agent', '')
                existing.enabled = True
            else:
                # Vytvoř novou
                sub = PushSubscription(
                    user_id=current_user.id,
                    endpoint=data['endpoint'],
                    p256dh=data['keys']['p256dh'],
                    auth=data['keys']['auth'],
                    user_agent=request.headers.get('User-Agent', ''),
                    enabled=True
                )
                db.session.add(sub)

            db.session.commit()

            return jsonify({
                "success": True,
                "message": "✅ Notifikace povoleny!"
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({
                "success": False,
                "message": f"Chyba: {str(e)}"
            }), 500

    @app.route("/api/push/unsubscribe", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_unsubscribe():
        """Unsubscribe od push notifikací"""
        data = request.get_json()

        if not data or 'endpoint' not in data:
            return jsonify({"success": False, "message": "Missing endpoint"}), 400

        try:
            # Najdi subscription
            sub = PushSubscription.query.filter_by(
                user_id=current_user.id,
                endpoint=data['endpoint']
            ).first()

            if sub:
                db.session.delete(sub)
                db.session.commit()

            return jsonify({
                "success": True,
                "message": "✅ Notifikace zakázány"
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({
                "success": False,
                "message": f"Chyba: {str(e)}"
            }), 500

    @app.route("/api/push/vapid-public-key")
    def push_vapid_key():
        """Vrať public VAPID klíč pro frontend"""
        return jsonify({
            "publicKey": VAPID_PUBLIC_KEY
        })

    @app.route("/api/push/test", methods=["POST"])
    @csrf.exempt
    @login_required
    def push_test():
        """Test notifikace (pro debugging)"""
        if not current_user.is_admin_effective:
            return jsonify({"success": False, "message": "Admin only"}), 403

        success = send_push_notification(
            current_user.id,
            "🔔 Test notifikace",
            "Funguje to! Tohle je testovací notifikace.",
            {"url": "/"}
        )

        if success:
            return jsonify({"success": True, "message": "✅ Notifikace odeslána!"})
        else:
            return jsonify({"success": False, "message": "❌ Žádná aktivní subscription"}), 400

    # --- NOTIFICATION SETTINGS ---

    @app.route("/notification-settings")
    @login_required
    def notification_settings():
        """Stránka s nastavením notifikací"""
        prefs = get_notification_preferences(current_user.id)

        return render_page(r"""
    <div class="card">

      <div class="card" style="margin-bottom:16px;">
    <h3 style="margin-top:0;">🔔 Push notifikace</h3>
    <div id="pushStatus" class="muted">Načítám stav…</div>
    <div class="row" style="gap:8px; margin-top:12px; flex-wrap:wrap;">
      <button id="btnEnablePush" class="btn" type="button" style="background: rgba(110,168,254,.15); border: 1px solid rgba(110,168,254,.35);">Povolit push</button>
      <button id="btnDisablePush" class="btn" type="button" style="background: rgba(167,178,214,.10); border: 1px solid rgba(167,178,214,.25);">Zakázat push</button>
    </div>
    <div class="muted" style="margin-top:10px; font-size:13px;">
      Tip: Na Androidu musí být web otevřený v Chrome a povolené notifikace pro tuto stránku.
    </div>
      </div>

      <h2 style="margin:0 0 8px 0;">Nastavení notifikací 🔔</h2>
      <div class="muted">Vyber si, jaké notifikace chceš dostávat</div>

      <hr class="sep">

      <form id="notif-settings-form">
    <div style="display: flex; flex-direction: column; gap: 16px;">

      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_results" {% if prefs.notify_results %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">⚽ Výsledky zadány</div>
          <div class="muted" style="font-size: 12px;">Dostaneš personalizovanou notifikaci s tvými body</div>
        </div>
      </label>

      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_deadline" {% if prefs.notify_deadline %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">⏰ Připomínka deadline</div>
          <div class="muted" style="font-size: 12px;">Připomene ti 1h před uzávěrkou, pokud ještě nemáš všechny tipy</div>
        </div>
      </label>

      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_new_round" {% if prefs.notify_new_round %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">🆕 Nová soutěž</div>
          <div class="muted" style="font-size: 12px;">Budeš první, kdo ví o nové soutěži</div>
        </div>
      </label>

      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_achievement" {% if prefs.notify_achievement %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">🏅 Achievementy</div>
          <div class="muted" style="font-size: 12px;">Oznámení když získáš nový achievement</div>
        </div>
      </label>

      <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; padding: 12px; background: rgba(110,168,254,0.08); border-radius: 8px;">
        <input type="checkbox" name="notify_leaderboard" {% if prefs.notify_leaderboard %}checked{% endif %} style="width: 20px; height: 20px;">
        <div>
          <div style="font-weight: 600;">📊 Změna v žebříčku</div>
          <div class="muted" style="font-size: 12px;">Upozornění když se změní tvoje pozice (může být častější)</div>
        </div>
      </label>

    </div>

    <hr class="sep">

    <div class="row" style="gap: 8px;">
      <button type="submit" class="btn btn-primary">💾 Uložit nastavení</button>
      <a href="/" class="btn">Zpět</a>
    </div>
      </form>
    </div>

    <script>
    document.getElementById('notif-settings-form').addEventListener('submit', async (e) => {
      e.preventDefault();

      const formData = new FormData(e.target);
      const settings = {
    notify_results: formData.get('notify_results') === 'on',
    notify_deadline: formData.get('notify_deadline') === 'on',
    notify_new_round: formData.get('notify_new_round') === 'on',
    notify_achievement: formData.get('notify_achievement') === 'on',
    notify_leaderboard: formData.get('notify_leaderboard') === 'on'
      };

      try {
    const response = await fetchWithCSRF('/api/notification-settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(settings)
    });

    const result = await response.json();

    if (result.success) {
      alert('✅ Nastavení uloženo!');
    } else {
      alert('❌ ' + result.message);
    }
      } catch (error) {
    alert('❌ Chyba při ukládání: ' + error.message);
      }
    });

    // ------------------------------
    // PUSH enable/disable (Android/Chrome)
    // ------------------------------
    const VAPID_PUBLIC_KEY = "{{ vapid_public_key }}";

    function urlBase64ToUint8Array(base64String) {
      const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
      const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
      const rawData = atob(base64);
      const outputArray = new Uint8Array(rawData.length);
      for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
      return outputArray;
    }

    async function getSWRegistration() {
      if (!('serviceWorker' in navigator)) throw new Error('Service Worker není podporován v tomto prohlížeči.');
      let reg = await navigator.serviceWorker.getRegistration();
      if (!reg) {
    reg = await navigator.serviceWorker.register('/service-worker.js');
      }
      await navigator.serviceWorker.ready;
      return reg;
    }

    function setPushStatus(html) {
      const el = document.getElementById('pushStatus');
      if (el) el.innerHTML = html;
    }

    async function refreshPushStatus() {
      try {
    const perm = (typeof Notification !== 'undefined') ? Notification.permission : 'unsupported';
    if (perm === 'denied') {
      setPushStatus('❌ Oznámení jsou pro tuto stránku blokovaná v prohlížeči. Povol je v Nastavení webu (Chrome).');
      return;
    }
    if (perm === 'default') {
      setPushStatus('ℹ️ Oznámení nejsou ještě povolená. Klikni na “Povolit push”.');
      return;
    }
    if (perm !== 'granted') {
      setPushStatus('❌ Prohlížeč nepodporuje Notification API.');
      return;
    }

    const reg = await getSWRegistration();
    if (!('pushManager' in reg)) {
      setPushStatus('❌ PushManager není dostupný (prohlížeč nepodporuje push).');
      return;
    }

    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      setPushStatus('✅ Push je zapnutý (subscription existuje).');
    } else {
      setPushStatus('ℹ️ Push je vypnutý (subscription neexistuje).');
    }
      } catch (e) {
    setPushStatus('❌ Chyba: ' + (e && e.message ? e.message : e));
      }
    }

    async function enablePush() {
      try {
    if (!VAPID_PUBLIC_KEY) throw new Error('Chybí VAPID public key na serveru.');
    if (typeof Notification === 'undefined') throw new Error('Prohlížeč nepodporuje notifikace.');
    let perm = Notification.permission;
    if (perm !== 'granted') {
      perm = await Notification.requestPermission();
    }
    if (perm !== 'granted') throw new Error('Notifikace nejsou povolené (permission=' + perm + ').');

    const reg = await getSWRegistration();
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
    });

    const resp = await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(sub)
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.success) {
      throw new Error(data.message || ('Subscribe API error (' + resp.status + ')'));
    }
    setPushStatus('✅ Push zapnutý. (Uloženo na serveru)');
      } catch (e) {
    alert('❌ Nepodařilo se zapnout push: ' + (e && e.message ? e.message : e));
      } finally {
    await refreshPushStatus();
      }
    }

    async function disablePush() {
      try {
    const reg = await getSWRegistration();
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      await sub.unsubscribe();
    }
    await fetch('/api/push/unsubscribe', {method: 'POST'}).catch(() => {});
    setPushStatus('ℹ️ Push vypnutý.');
      } catch (e) {
    alert('❌ Nepodařilo se vypnout push: ' + (e && e.message ? e.message : e));
      } finally {
    await refreshPushStatus();
      }
    }

    document.getElementById('btnEnablePush')?.addEventListener('click', enablePush);
    document.getElementById('btnDisablePush')?.addEventListener('click', disablePush);
    window.addEventListener('load', refreshPushStatus);

    </script>
    """, prefs=prefs, vapid_public_key=VAPID_PUBLIC_KEY)

    @app.route("/api/notification-settings", methods=["GET", "POST"])
    @csrf.exempt
    @login_required
    def api_notification_settings():
        """API pro získání/uložení nastavení notifikací"""

        if request.method == "GET":
            # Získej nastavení
            prefs = get_notification_preferences(current_user.id)
            return jsonify({
                "notify_results": prefs.notify_results,
                "notify_deadline": prefs.notify_deadline,
                "notify_new_round": prefs.notify_new_round,
                "notify_achievement": prefs.notify_achievement,
                "notify_leaderboard": prefs.notify_leaderboard
            })

        else:  # POST
            # Ulož nastavení
            data = request.get_json()

            if not data:
                return jsonify({"success": False, "message": "Missing data"}), 400

            try:
                prefs = get_notification_preferences(current_user.id)

                # Update preferences
                prefs.notify_results = data.get('notify_results', True)
                prefs.notify_deadline = data.get('notify_deadline', True)
                prefs.notify_new_round = data.get('notify_new_round', True)
                prefs.notify_achievement = data.get('notify_achievement', True)
                prefs.notify_leaderboard = data.get('notify_leaderboard', False)
                prefs.updated_at = datetime.utcnow()

                db.session.commit()

                return jsonify({
                    "success": True,
                    "message": "✅ Nastavení uloženo!"
                })

            except Exception as e:
                db.session.rollback()
                return jsonify({
                    "success": False,
                    "message": f"Chyba: {str(e)}"
                }), 500

