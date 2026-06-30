"""
scheduler/alertas.py
────────────────────
Sistema de alertas por email — Alek.

¿Cómo funciona el email?
  Usamos Gmail como servidor de envío. Para que funcione necesitas
  crear una "Contraseña de aplicación" en tu cuenta Google:

  1. Ve a myaccount.google.com
  2. Seguridad → Verificación en dos pasos (actívala si no la tienes)
  3. Seguridad → Contraseñas de aplicaciones
  4. Selecciona "Correo" y "Windows" → Generar
  5. Copia la clave de 16 caracteres y ponla en .env como ALERT_EMAIL_PASSWORD

  Esto es más seguro que usar tu contraseña real de Gmail.

¿Cuándo se envía una alerta?
  - Cuando la puntuación baja más de 10 puntos respecto al análisis anterior
  - Cuando aparece un nuevo subdominio sensible que antes no existía
  - Cuando aparece un puerto crítico nuevo
  - Resumen semanal siempre, aunque no haya cambios
"""

import smtplib
import os
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

EMAIL_ORIGEN   = os.getenv("ALERT_EMAIL_ORIGEN", "")
EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD", "")

APP_NAME = "Alek"

# ── Logo embebido en base64 para que se muestre en cualquier cliente
# de correo sin depender de una URL externa ──────────────────────────────
_ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
_LOGO_PATH  = os.path.join(_ASSETS_DIR, "alek_icon_header.png")

def _logo_base64() -> str:
    try:
        with open(_LOGO_PATH, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return ""

_LOGO_B64 = _logo_base64()

# ── Paleta de marca (coherente con el dashboard) ─────────────────────────
COLOR_BG       = "#04060F"
COLOR_PANEL    = "#0B0F1D"
COLOR_BORDER   = "#1B2236"
COLOR_ACCENT   = "#E8EAF0"
COLOR_MUTED    = "#7E879C"
COLOR_TEXT     = "#E6E9F2"

SEV_COLORS = {
    "CRÍTICO": "#C0392B", "CRITICO": "#C0392B",
    "ALTO":    "#B8841C",
    "MEDIO":   "#3A6FB0",
    "BAJO":    "#3C8A5C",
}


def _enviar_email(destinatario: str, asunto: str, cuerpo_html: str) -> bool:
    """
    Función interna que envía el email via Gmail SMTP.
    Retorna True si se envió correctamente, False si hubo error.
    """
    if not EMAIL_ORIGEN or not EMAIL_PASSWORD:
        print("  [AVISO] Email no configurado. Añade ALERT_EMAIL_ORIGEN y ALERT_EMAIL_PASSWORD en .env")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = asunto
        msg["From"]    = f"{APP_NAME} <{EMAIL_ORIGEN}>"
        msg["To"]      = destinatario
        msg.attach(MIMEText(cuerpo_html, "html", "utf-8"))

        # Conexión segura con Gmail
        with smtplib.SMTP("smtp.gmail.com", 587) as servidor:
            servidor.ehlo()
            servidor.starttls()
            servidor.ehlo()
            servidor.login(EMAIL_ORIGEN, EMAIL_PASSWORD)
            servidor.sendmail(EMAIL_ORIGEN, destinatario, msg.as_string())

        print(f"  [OK] Email enviado a {destinatario}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("  [ERROR] Fallo de autenticación Gmail. Verifica la contraseña de aplicación.")
        return False
    except Exception as e:
        print(f"  [ERROR] Error enviando email: {str(e)}")
        return False


def _plantilla_email(dominio: str, puntuacion: int, nivel: str,
                     hallazgos: list, cambios: dict) -> str:
    """Genera el HTML del email de alerta con identidad Alek."""

    color_nivel = SEV_COLORS.get(nivel, COLOR_MUTED)

    # Construimos las filas de hallazgos
    filas_hallazgos = ""
    for h in hallazgos[:5]:  # máximo 5 en el email
        color_sev = SEV_COLORS.get(h.get("severidad",""), COLOR_MUTED)
        filas_hallazgos += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid {COLOR_BORDER}">
                <span style="background:{color_sev};color:#fff;padding:2px 8px;
                border-radius:20px;font-size:11px;font-weight:600">
                    {h.get('severidad','')}
                </span>
            </td>
            <td style="padding:8px;border-bottom:1px solid {COLOR_BORDER};color:{COLOR_TEXT}">
                {h.get('titulo','')}
            </td>
        </tr>"""

    if not filas_hallazgos:
        filas_hallazgos = f"""
        <tr><td colspan="2" style="padding:8px;color:{COLOR_MUTED};font-size:13px">
            No se han detectado hallazgos relevantes en este análisis.
        </td></tr>"""

    # Sección de cambios detectados
    seccion_cambios = ""
    if cambios.get("nueva_puntuacion_menor"):
        seccion_cambios += f"""
        <div style="background:#1E1606;border:1px solid {SEV_COLORS['ALTO']};border-radius:8px;
        padding:12px 16px;margin:16px 0;color:{SEV_COLORS['ALTO']}">
            <strong>La puntuación ha bajado {cambios['diferencia_puntuacion']} puntos</strong>
            respecto al análisis anterior ({cambios['puntuacion_anterior']} &rarr; {puntuacion})
        </div>"""

    if cambios.get("nuevos_subdominios"):
        lista = ", ".join(cambios["nuevos_subdominios"])
        seccion_cambios += f"""
        <div style="background:#1A0B0A;border:1px solid {SEV_COLORS['CRÍTICO']};border-radius:8px;
        padding:12px 16px;margin:16px 0;color:{SEV_COLORS['CRÍTICO']}">
            <strong>Nuevos subdominios sensibles detectados:</strong> {lista}
        </div>"""

    logo_img = (
        f'<img src="data:image/png;base64,{_LOGO_B64}" width="40" height="40" '
        f'style="vertical-align:middle;margin-right:12px">'
        if _LOGO_B64 else ""
    )

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:{COLOR_BG};font-family:Arial,Helvetica,sans-serif;padding:24px;color:{COLOR_TEXT};margin:0">
    <div style="max-width:600px;margin:0 auto">

        <!-- Cabecera -->
        <div style="background:{COLOR_PANEL};border:1px solid {COLOR_BORDER};border-radius:12px;
        padding:24px;margin-bottom:24px">
            <table style="width:100%;border-collapse:collapse">
                <tr>
                    <td style="width:48px">{logo_img}</td>
                    <td>
                        <h1 style="color:{COLOR_ACCENT};margin:0;font-size:19px;letter-spacing:.04em">{APP_NAME.upper()}</h1>
                        <p style="color:{COLOR_MUTED};margin:4px 0 0;font-size:13px">
                            Informe de seguridad — {dominio}
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Puntuación -->
        <div style="background:{COLOR_PANEL};border:1px solid {COLOR_BORDER};border-radius:10px;
        padding:20px;margin-bottom:16px;text-align:center">
            <div style="font-size:12px;color:{COLOR_MUTED};text-transform:uppercase;
            letter-spacing:.08em;margin-bottom:8px">Puntuación de seguridad</div>
            <div style="font-size:48px;font-weight:700;color:{color_nivel}">{puntuacion}</div>
            <div style="font-size:14px;color:{color_nivel};font-weight:600">{nivel}</div>
        </div>

        {seccion_cambios}

        <!-- Hallazgos -->
        <div style="background:{COLOR_PANEL};border:1px solid {COLOR_BORDER};border-radius:10px;
        padding:20px;margin-bottom:16px">
            <h3 style="margin:0 0 16px;font-size:15px;color:{COLOR_TEXT}">
                Hallazgos detectados
            </h3>
            <table style="width:100%;border-collapse:collapse">
                {filas_hallazgos}
            </table>
        </div>

        <!-- Footer -->
        <div style="text-align:center;color:{COLOR_MUTED};font-size:12px;padding:16px">
            Generado automáticamente por {APP_NAME}<br>
            Este informe es confidencial y se ha generado para el destinatario indicado.
        </div>
    </div>
</body>
</html>"""


def enviar_alerta_cambios(dominio: str, email: str, puntuacion: int,
                          nivel: str, hallazgos: list, cambios: dict) -> bool:
    """Envía alerta cuando se detectan cambios significativos."""
    asunto = f"Alerta de seguridad — {dominio} ({nivel})"
    cuerpo = _plantilla_email(dominio, puntuacion, nivel, hallazgos, cambios)
    return _enviar_email(email, asunto, cuerpo)


def enviar_resumen_semanal(dominio: str, email: str, puntuacion: int,
                           nivel: str, hallazgos: list) -> bool:
    """Envía el resumen semanal aunque no haya cambios."""
    asunto = f"Resumen semanal de seguridad — {dominio}"
    cuerpo = _plantilla_email(dominio, puntuacion, nivel, hallazgos, {})
    return _enviar_email(email, asunto, cuerpo)
