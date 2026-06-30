"""
threat_intel/cve_client.py
──────────────────────────
FUENTE B: CVEs recientes vía NVD (National Vulnerability Database)

¿Qué es NVD?
  La base de datos oficial del gobierno de EEUU con todas las
  vulnerabilidades conocidas de software. Cada vulnerabilidad tiene
  un código CVE (ej: CVE-2024-1234) y una puntuación de severidad
  CVSS (0-10).

¿Qué hacemos?
  Si el escáner detectó que el servidor usa nginx, Apache, OpenResty, etc.,
  buscamos CVEs publicados en los últimos 90 días para ese software.

  Esto le dice al cliente: "El software que usas tiene vulnerabilidades
  conocidas y públicas que un atacante puede explotar ahora mismo."

  Es gratuito y no requiere API key.
"""

import requests
from datetime import datetime, timedelta
from config import REQUEST_TIMEOUT

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves(producto: str, dias: int = 90) -> dict:
    """
    Busca CVEs recientes para un producto de software.

    Parámetros:
        producto (str): Nombre del software (ej: "nginx", "apache", "openresty")
        dias (int):     Cuántos días hacia atrás buscar (por defecto 90)

    Retorna dict con:
      - "total":       número de CVEs encontrados
      - "criticos":    CVEs con CVSS >= 9.0
      - "altos":       CVEs con CVSS >= 7.0
      - "cves":        lista de los 5 más graves con detalle
      - "error":       None o mensaje de error
    """
    if not producto or producto.lower() in ["desconocido", "no revelado", ""]:
        return {"total": 0, "criticos": 0, "altos": 0, "cves": [], "error": None}

    # Normalizamos el nombre del producto
    producto_limpio = producto.lower().split("/")[0].strip()

    # Calculamos el rango de fechas
    fecha_fin    = datetime.now()
    fecha_inicio = fecha_fin - timedelta(days=dias)

    params = {
        "keywordSearch":    producto_limpio,
        "pubStartDate":     fecha_inicio.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate":       fecha_fin.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage":   20,
        "startIndex":       0
    }

    try:
        resp = requests.get(NVD_BASE, params=params, timeout=REQUEST_TIMEOUT * 2)
        resp.raise_for_status()
        datos = resp.json()

        vulnerabilidades = datos.get("vulnerabilities", [])
        cves_detalle     = []
        criticos         = 0
        altos            = 0

        for vuln in vulnerabilidades:
            cve   = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Extraemos la puntuación CVSS
            metricas = cve.get("metrics", {})
            cvss     = 0.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metricas and metricas[version]:
                    cvss = metricas[version][0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            # Extraemos descripción en español si existe, si no en inglés
            descripcion = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "es":
                    descripcion = desc.get("value", "")
                    break
            if not descripcion:
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        descripcion = desc.get("value", "")[:200]
                        break

            if cvss >= 9.0:
                criticos += 1
            elif cvss >= 7.0:
                altos += 1

            if cvss >= 7.0:  # Solo incluimos los graves en el detalle
                cves_detalle.append({
                    "id":          cve_id,
                    "cvss":        cvss,
                    "descripcion": descripcion,
                    "fecha":       cve.get("published", "")[:10]
                })

        # Ordenamos por CVSS descendente
        cves_detalle = sorted(cves_detalle, key=lambda x: x["cvss"], reverse=True)[:5]

        return {
            "total":    len(vulnerabilidades),
            "criticos": criticos,
            "altos":    altos,
            "cves":     cves_detalle,
            "error":    None
        }

    except requests.exceptions.Timeout:
        return {"total": 0, "criticos": 0, "altos": 0, "cves": [],
                "error": "Timeout al consultar NVD"}
    except Exception as e:
        return {"total": 0, "criticos": 0, "altos": 0, "cves": [],
                "error": f"Error consultando NVD: {str(e)}"}
