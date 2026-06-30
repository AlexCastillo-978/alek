"""
recon/hibp.py
─────────────
FUENTE 4: Filtraciones de datos vía Have I Been Pwned (HIBP)

¿Qué es Have I Been Pwned?
  Es una base de datos creada por el investigador de seguridad Troy Hunt
  que recopila más de 12 mil millones de credenciales filtradas en
  brechas de seguridad conocidas (LinkedIn 2012, Adobe, Yahoo, etc.).

¿Qué consultamos nosotros?
  No preguntamos por emails individuales (eso sería invasión de privacidad).
  Consultamos si el DOMINIO de la empresa aparece en alguna filtración
  conocida. Por ejemplo: si "empresa.com" aparece en la filtración de
  algún servicio donde empleados se registraron con su email corporativo.

  Esto le dice al cliente: "Tus empleados tienen credenciales expuestas
  en internet. Esas contraseñas podrían reutilizarse para acceder a
  vuestros sistemas."

Nota sobre la API de HIBP:
  La API de dominio de HIBP requiere una API key de pago (3$/mes).
  Es la única fuente de pago en nuestro stack. Merece la pena porque
  añade mucho valor al informe.

  Si no tienes la key, el módulo devuelve un resultado parcial informativo.
"""

import requests
from config import HIBP_API_KEY, REQUEST_TIMEOUT, USER_AGENT


def verificar_filtraciones_dominio(dominio: str) -> dict:
    """
    Consulta HIBP para ver si el dominio aparece en brechas conocidas.

    Parámetros:
        dominio (str): El dominio a analizar. Ej: "ejemplo.es"

    Retorna:
        dict con:
          - "filtraciones":     Lista de brechas donde aparece el dominio
          - "total":            Número de brechas encontradas
          - "nivel_riesgo":     "ALTO", "MEDIO", "BAJO" o "NINGUNO"
          - "resumen":          Texto explicativo para el informe
          - "error":            None o mensaje de error
    """

    if not HIBP_API_KEY:
        return {
            "filtraciones": [],
            "total": 0,
            "nivel_riesgo": "DESCONOCIDO",
            "resumen": "No se pudo verificar filtraciones: API key de HIBP no configurada.",
            "error": "API key de HIBP no configurada"
        }

    try:
        # La API de HIBP para dominios devuelve las brechas asociadas
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{dominio}"
        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": USER_AGENT
        }

        respuesta = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        # 404 significa "no encontrado en ninguna brecha" → buena noticia
        if respuesta.status_code == 404:
            return {
                "filtraciones": [],
                "total": 0,
                "nivel_riesgo": "NINGUNO",
                "resumen": "No se encontraron filtraciones conocidas para este dominio.",
                "error": None
            }

        respuesta.raise_for_status()
        datos = respuesta.json()

        # Los datos vienen como un dict donde las claves son aliases
        # de brechas y los valores son listas de emails afectados.
        # Nosotros solo necesitamos los nombres de las brechas.
        filtraciones = []
        for nombre_brecha, emails_afectados in datos.items():
            filtraciones.append({
                "brecha": nombre_brecha,
                "cuentas_expuestas": len(emails_afectados)
            })

        total = len(filtraciones)

        # Calculamos nivel de riesgo según número de brechas
        if total == 0:
            nivel = "NINGUNO"
        elif total <= 2:
            nivel = "BAJO"
        elif total <= 5:
            nivel = "MEDIO"
        else:
            nivel = "ALTO"

        resumen = (
            f"Se encontraron {total} filtración(es) de datos que afectan "
            f"a cuentas del dominio {dominio}. "
            f"Las credenciales expuestas podrían utilizarse en ataques "
            f"de credential stuffing contra vuestros sistemas."
        )

        return {
            "filtraciones": filtraciones,
            "total": total,
            "nivel_riesgo": nivel,
            "resumen": resumen,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "filtraciones": [], "total": 0, "nivel_riesgo": "DESCONOCIDO",
            "resumen": "No se pudo verificar: timeout en la consulta.",
            "error": "Timeout al consultar HIBP"
        }
    except requests.exceptions.RequestException as e:
        return {
            "filtraciones": [], "total": 0, "nivel_riesgo": "DESCONOCIDO",
            "resumen": "No se pudo verificar por error de red.",
            "error": f"Error de red con HIBP: {str(e)}"
        }
