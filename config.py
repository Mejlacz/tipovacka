"""
config.py
Centrální konfigurace aplikace Tipovačka.
Všechny konstanty, session klíče a bodování na jednom místě.
"""

# ── Vlastníci / speciální účty ────────────────────────────────────────────────
OWNER_ADMIN_EMAIL  = "3049@email.cz"            # owner – plná práva, vidí tajného usera
SECRET_USER_EMAIL  = "kubamartinec97@gmail.com"  # skrytý user v admin přehledu

# ── Heslo ─────────────────────────────────────────────────────────────────────
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# ── Bodování tipů ─────────────────────────────────────────────────────────────
POINTS_EXACT  = 3   # přesný výsledek (např. 2:1 tipováno 2:1)
POINTS_DIFF   = 2   # správný rozdíl  (např. 2:0 tipováno 3:1)
POINTS_TEND   = 1   # správná tendence (výhra/remíza/prohra)
POINTS_WRONG  = 0   # špatný tip

# ── Session klíče ─────────────────────────────────────────────────────────────
SESSION_SELECTED_ROUND      = "selected_round_id"

SESSION_BULK_FILE           = "bulk_import_file"
SESSION_BULK_ROUND_ID       = "bulk_import_round_id"
SESSION_BULK_TYPE           = "bulk_import_type"

SESSION_SMART_FILE          = "smart_import_file"
SESSION_SMART_PREVIEW       = "smart_import_preview"
SESSION_SMART_SESSION_ID    = "smart_import_session_id"

SESSION_TEAMS_FILE          = "teams_import_preview_file"
SESSION_TEAMS_ROUND_ID      = "teams_import_round_id"
SESSION_TEAMS_OVERWRITE     = "teams_import_overwrite"

SESSION_EXTRA_FILE          = "extra_import_preview_file"
SESSION_EXTRA_ROUND_ID      = "extra_import_round_id"
SESSION_EXTRA_OVERWRITE     = "extra_import_overwrite"

SESSION_USERS_FILE          = "users_import_preview_file"

SESSION_IMPORT_PREVIEW      = "import_preview"
SESSION_IMPORT_ROUND_ID     = "import_round_id"

SESSION_SKIPPED_PATH        = "skipped_report_path"
SESSION_SKIPPED_FILENAME    = "skipped_report_filename"

# ── Flash kategorie ───────────────────────────────────────────────────────────
FLASH_OK      = "ok"
FLASH_ERROR   = "error"
FLASH_WARNING = "warning"
FLASH_INFO    = "info"

# ── Role ──────────────────────────────────────────────────────────────────────
ROLE_USER      = "user"
ROLE_MODERATOR = "moderator"
ROLE_ADMIN     = "admin"
ROLE_OWNER     = "owner"
ROLE_VIEWER    = "viewer"

# ── Limity exportů / importů ──────────────────────────────────────────────────
EXPORT_MAX_TIPS_ROWS = 10_000
IMPORT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# ── VAPID (Push notifikace) ───────────────────────────────────────────────────
VAPID_CLAIMS = {"sub": "mailto:admin@tipovacka.cz"}
