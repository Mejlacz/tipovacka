"""
config.py
Sdílené konstanty aplikace.
Žádné importy z našeho kódu – bezpečné pro import odkudkoliv bez circular deps.

Použití:
    from config import VAPID_PUBLIC_KEY, ACHIEVEMENTS
"""
import os

# =========================================================
# VLASTNÍK + TAJNÝ UŽIVATEL
# Definováno i v app_utils.py (routes importují odtamtud).
# Tady je kvůli app2.py factory a models.py.
# =========================================================

OWNER_ADMIN_EMAIL = os.environ.get("OWNER_ADMIN_EMAIL", "3049@email.cz")
SECRET_USER_EMAIL = os.environ.get("SECRET_USER_EMAIL", "kubamartinec97@gmail.com")

# =========================================================
# VAPID klíče pro Web Push notifikace
# V produkci nastav jako env variables na Koyebu!
# =========================================================

VAPID_PRIVATE_KEY = os.environ.get(
    "VAPID_PRIVATE_KEY",
    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0"
    "NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzhjWVNJc2R4aDhXenMrSWgKd0N5THoyTk9ZQk1o"
    "K3BBbFhKNy9SWE0yYmZxaFJBTkNBQVR4M2NORjZ0Q215KzloVEtzekQ2bUxCK3RtREhlTwp"
    "1YTZBRHF5SFhYRnB4enk3bkJzNFk5dHFEUnVGN1Z0c3orKzFQdFRaanl0WnpkZlRodk1TWG"
    "NUZQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg"
)

VAPID_PUBLIC_KEY = os.environ.get(
    "VAPID_PUBLIC_KEY",
    "BPHdw0Xq0KbL72FMqzMPqYsH62YMd465roAOrIddcWnHPLucGzhj22oNG4XtW2zP77U-1NmPK1nN19OG8xJdxN4"
)

VAPID_CLAIMS = {"sub": f"mailto:{OWNER_ADMIN_EMAIL}"}

# =========================================================
# ACHIEVEMENTS – metadata (ikona, název, popis, barva)
# Skutečná logika přidělování je v app_utils.check_and_award_achievements()
# =========================================================

ACHIEVEMENTS: dict = {
    "first_tip": {
        "name": "První krev",
        "icon": "🎯",
        "description": "Zadal jsi svůj první tip",
        "color": "#6ea8fe",
    },
    "hattrick": {
        "name": "Hattrick",
        "icon": "🔥",
        "description": "3 přesné tipy po sobě",
        "color": "#ff6b6b",
    },
    "perfect_5": {
        "name": "Pětka",
        "icon": "⭐",
        "description": "5 přesných tipů po sobě",
        "color": "#ffc107",
    },
    "sniper": {
        "name": "Sniper",
        "icon": "🎯",
        "description": "10 přesných tipů po sobě",
        "color": "#ff4d6d",
    },
    "perfect_round": {
        "name": "Perfekcionista",
        "icon": "💎",
        "description": "Všechny tipy v kole přesné",
        "color": "#33d17a",
    },
    "top_tipper": {
        "name": "Stratég",
        "icon": "👑",
        "description": "Nejlepší tipér v kole",
        "color": "#ffd700",
    },
    "full_attendance": {
        "name": "Věrný fanoušek",
        "icon": "💯",
        "description": "100% účast – tipoval jsi všechny zápasy",
        "color": "#33d17a",
    },
    "comeback_king": {
        "name": "Comeback",
        "icon": "📈",
        "description": "Posun o 3+ místa nahoru v žebříčku",
        "color": "#26a269",
    },
    "century": {
        "name": "Stovka",
        "icon": "💯",
        "description": "Získal jsi 100 bodů",
        "color": "#ffc107",
    },
    "half_century": {
        "name": "Padesátka",
        "icon": "5️⃣0️⃣",
        "description": "Získal jsi 50 bodů",
        "color": "#6ea8fe",
    },
    "nostradamus": {
        "name": "Nostradamus",
        "icon": "🔮",
        "description": "Tipoval jsi překvapení jako první (velký outsider)",
        "color": "#a78bfa",
    },
    "warrior": {
        "name": "Warrior",
        "icon": "⚔️",
        "description": "Účast ve 3+ soutěžích",
        "color": "#f97316",
    },
    "lucky_strike": {
        "name": "Štěstí přeje připraveným",
        "icon": "🍀",
        "description": "Správný tip na zápas s kurzem 5:1+",
        "color": "#10b981",
    },
    "underdog": {
        "name": "Underdog",
        "icon": "🐕",
        "description": "Top 3 s méně než 50% tipnutých zápasů",
        "color": "#8b5cf6",
    },
}
