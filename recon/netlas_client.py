"""
recon/netlas_client.py
──────────────────────
FUENTE 3 (v3): Puertos, servicios y subdominios vía Netlas

Plan gratuito: 50 peticiones/día sin tarjeta.
API key: netlas.io → perfil → API key
"""

import socket
import requests
from config import REQUEST_TIMEOUT

import os
from dotenv import load_dotenv
load_dotenv()

NETLAS_API_KEY = os.getenv("NETLAS_API_KEY", "")

PUERTOS_RIESGO_ALTO  = {21, 23, 3306, 5432, 6379, 27017, 1433, 5900}
PUERTOS_RIESGO_MEDIO = {22, 25, 8080, 8443, 3389}


def obtener_info_host(dominio: str) -> dict:
    """
    Consulta Netlas para obtener puertos, servicios y tecnologías
    expuestas del dominio.
    """

    if not NETLAS_API_KEY:
        return {
            "ips": [], "puertos_abiertos": [], "puertos_criticos": [],
            "servicios": [], "advertencias": [],
            "error": "NETLAS_API_KEY no configurada en .env"
        }

    # Resolver dominio → IP
    try:
        ip = socket.gethostbyname(dominio)
    except socket.gaierror:
        return {
            "ips": [], "puertos_abiertos": [], "puertos_criticos": [],
            "servicios": [], "advertencias": [],
            "error": f"No se pudo resolver {dominio} a una IP"
        }

    try:
        # Consulta al endpoint de host de Netlas
        url = f"https://app.netlas.io/api/responses/?q=ip:{ip}&source_type=include&start=0&fields=*"
        headers = {
            "X-API-Key": NETLAS_API_KEY,
            "accept": "application/json"
        }
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        datos = resp.json()

        items = datos.get("items", [])

        if not items:
            return {
                "ips": [ip], "puertos_abiertos": [], "puertos_criticos": [],
                "servicios": [], "advertencias": [],
                "error": None
            }

        advertencias  = []
        servicios     = []
        todos_puertos = set()

        for item in items:
            data = item.get("data", {})
            puerto = data.get("port")
            if not puerto:
                continue

            todos_puertos.add(puerto)
            proto   = data.get("protocol", "tcp")
            app     = data.get("app", {})
            product = app.get("name", "Desconocido") if app else "Desconocido"

            servicios.append({
                "ip":        ip,
                "puerto":    puerto,
                "protocolo": proto,
                "producto":  product,
                "version":   app.get("version", "") if app else "",
                "banner":    ""
            })

            if puerto in PUERTOS_RIESGO_ALTO:
                advertencias.append(
                    f"[CRITICO] Puerto {puerto} ({product}) expuesto en {ip} — "
                    f"no deberia ser accesible desde internet"
                )
            elif puerto in PUERTOS_RIESGO_MEDIO:
                advertencias.append(
                    f"[MEDIO] Puerto {puerto} ({product}) expuesto en {ip} — "
                    f"verificar configuracion"
                )

        puertos_criticos = [p for p in todos_puertos if p in PUERTOS_RIESGO_ALTO]

        return {
            "ips":              [ip],
            "puertos_abiertos": sorted(list(todos_puertos)),
            "puertos_criticos": sorted(puertos_criticos),
            "servicios":        servicios,
            "advertencias":     advertencias,
            "error":            None
        }

    except requests.exceptions.Timeout:
        return {
            "ips": [ip], "puertos_abiertos": [], "puertos_criticos": [],
            "servicios": [], "advertencias": [],
            "error": "Timeout al consultar Netlas"
        }
    except requests.exceptions.RequestException as e:
        return {
            "ips": [ip], "puertos_abiertos": [], "puertos_criticos": [],
            "servicios": [], "advertencias": [],
            "error": f"Error de red con Netlas: {str(e)}"
        }
