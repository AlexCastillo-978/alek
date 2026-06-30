"""
recon/crtsh.py
──────────────
FUENTE 1: Subdominios vía crt.sh

crt.sh registra certificados históricos, lo que significa que puede
devolver subdominios que existieron en el pasado pero ya no están activos.
Por eso verificamos con DNS que cada subdominio resuelve a una IP real
antes de incluirlo como hallazgo. Así evitamos falsos positivos.
"""

import socket
import requests
from config import REQUEST_TIMEOUT, USER_AGENT


def _esta_activo(subdominio: str) -> bool:
    """
    Verifica si un subdominio resuelve a una IP real.
    Si DNS no lo conoce, el subdominio no está activo.
    """
    try:
        socket.gethostbyname(subdominio)
        return True
    except socket.gaierror:
        return False


def obtener_subdominios(dominio: str) -> dict:
    url = f"https://crt.sh/?q=%.{dominio}&output=json"

    try:
        respuesta = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT}
        )
        respuesta.raise_for_status()
        datos = respuesta.json()

        subdominios_raw = set()
        for entrada in datos:
            nombres = entrada.get("name_value", "").split("\n")
            for nombre in nombres:
                nombre = nombre.strip()
                if nombre and dominio in nombre and not nombre.startswith("*"):
                    subdominios_raw.add(nombre.lower())

        # Filtramos solo los que están activos en DNS
        subdominios_activos = sorted([s for s in subdominios_raw if _esta_activo(s)])

        return {
            "subdominios": subdominios_activos,
            "total": len(subdominios_activos),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"subdominios": [], "total": 0,
                "error": "Timeout: crt.sh tardó demasiado en responder"}
    except requests.exceptions.RequestException as e:
        return {"subdominios": [], "total": 0,
                "error": f"Error de red al consultar crt.sh: {str(e)}"}
    except Exception as e:
        return {"subdominios": [], "total": 0,
                "error": f"Error inesperado en crt.sh: {str(e)}"}
