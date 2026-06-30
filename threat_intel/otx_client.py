"""
threat_intel/otx_client.py
──────────────────────────
FUENTE A: AlienVault OTX (Open Threat Exchange)

¿Qué es OTX?
  La mayor base de datos colaborativa de inteligencia de amenazas del mundo.
  Más de 100.000 investigadores de seguridad contribuyen con indicadores
  de compromiso (IoCs): IPs maliciosas, dominios usados en ataques,
  hashes de malware, patrones de campañas activas.

  Es completamente gratuita con registro.

¿Cómo conseguir la API key?
  1. Ve a otx.alienvault.com
  2. Regístrate gratis
  3. Ve a tu perfil → API Key
  4. Copia la clave y ponla en .env como OTX_API_KEY

¿Qué consultamos?
  - Si la IP del dominio aparece en feeds de amenazas conocidos
  - Si el dominio aparece en listas de dominios maliciosos
  - Pulsos (informes de amenazas) relacionados con el dominio o su IP
"""

import os
import requests
from dotenv import load_dotenv
from config import REQUEST_TIMEOUT

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE    = "https://otx.alienvault.com/api/v1"


def _cabeceras() -> dict:
    return {"X-OTX-API-KEY": OTX_API_KEY}


def analizar_ip(ip: str) -> dict:
    """
    Comprueba si una IP aparece en feeds de amenazas de OTX.

    Retorna dict con:
      - "reputacion":    "MALICIOSA", "SOSPECHOSA" o "LIMPIA"
      - "pulsos":        número de informes de amenaza que la mencionan
      - "paises":        países desde donde se han visto ataques
      - "categorias":    tipos de amenaza (malware, phishing, etc.)
      - "error":         None o mensaje de error
    """
    if not OTX_API_KEY:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "paises": [], "categorias": [],
                "error": "OTX_API_KEY no configurada"}

    if not ip:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "paises": [], "categorias": [],
                "error": "No hay IP para analizar"}

    try:
        url = f"{OTX_BASE}/indicators/IPv4/{ip}/general"
        resp = requests.get(url, headers=_cabeceras(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        datos = resp.json()

        pulsos     = datos.get("pulse_info", {}).get("count", 0)
        categorias = list(set([
            tag for p in datos.get("pulse_info", {}).get("pulses", [])
            for tag in p.get("tags", [])
        ]))[:10]

        paises = list(set([
            p.get("targeted_countries", [None])[0]
            for p in datos.get("pulse_info", {}).get("pulses", [])
            if p.get("targeted_countries")
        ]))[:5]

        if pulsos >= 5:
            reputacion = "MALICIOSA"
        elif pulsos >= 1:
            reputacion = "SOSPECHOSA"
        else:
            reputacion = "LIMPIA"

        return {
            "reputacion": reputacion,
            "pulsos":     pulsos,
            "paises":     paises,
            "categorias": categorias,
            "error":      None
        }

    except requests.exceptions.Timeout:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "paises": [], "categorias": [],
                "error": "Timeout al consultar OTX"}
    except Exception as e:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "paises": [], "categorias": [],
                "error": f"Error con OTX: {str(e)}"}


def analizar_dominio(dominio: str) -> dict:
    """
    Comprueba si el dominio aparece en feeds de amenazas de OTX.
    """
    if not OTX_API_KEY:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "categorias": [], "error": "OTX_API_KEY no configurada"}

    try:
        url = f"{OTX_BASE}/indicators/domain/{dominio}/general"
        resp = requests.get(url, headers=_cabeceras(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        datos = resp.json()

        pulsos     = datos.get("pulse_info", {}).get("count", 0)
        categorias = list(set([
            tag for p in datos.get("pulse_info", {}).get("pulses", [])
            for tag in p.get("tags", [])
        ]))[:10]

        if pulsos >= 3:
            reputacion = "MALICIOSA"
        elif pulsos >= 1:
            reputacion = "SOSPECHOSA"
        else:
            reputacion = "LIMPIA"

        return {
            "reputacion": reputacion,
            "pulsos":     pulsos,
            "categorias": categorias,
            "error":      None
        }

    except Exception as e:
        return {"reputacion": "DESCONOCIDA", "pulsos": 0,
                "categorias": [], "error": f"Error con OTX: {str(e)}"}
