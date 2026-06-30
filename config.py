"""
config.py
─────────
Punto central de configuración. Lee el .env y expone todas las
claves al resto del código. Si necesitas añadir una clave nueva,
añádela aquí y en el .env. No la leas con os.getenv() directamente
en otros módulos.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Identidad de marca ───────────────────────────────────────
APP_NAME    = "Alek"
APP_TAGLINE = "Inteligencia de superficie de ataque"

# ── APIs externas ─────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
NETLAS_API_KEY    = os.getenv("NETLAS_API_KEY", "")
HIBP_API_KEY      = os.getenv("HIBP_API_KEY", "")
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")

# ── Email ─────────────────────────────────────────────────────
ALERT_EMAIL_ORIGEN   = os.getenv("ALERT_EMAIL_ORIGEN", "")
ALERT_EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD", "")

# ── Acceso al dashboard ──────────────────────────────────────
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")

# ── Red ───────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10
USER_AGENT      = "Alek/1.0 (investigacion-seguridad)"
