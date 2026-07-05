"""
recon/headers.py
────────────────
FUENTE 2: Análisis de cabeceras HTTP de seguridad

¿Qué son las cabeceras HTTP?
  Cuando tu navegador visita una web, el servidor responde con dos cosas:
  1. El contenido de la página (HTML, imágenes, etc.)
  2. Una serie de "meta-instrucciones" llamadas cabeceras (headers).

  Algunas de esas cabeceras son de seguridad: le dicen al navegador cómo
  debe comportarse para proteger al usuario. Si faltan, hay riesgo.

¿Qué analizamos?
  Las 6 cabeceras de seguridad más importantes según OWASP:

  HSTS            → Fuerza HTTPS. Sin ella, posibles ataques man-in-the-middle.
  X-Frame-Options → Evita que la web sea embebida en iframes (clickjacking).
  CSP             → Controla qué scripts pueden ejecutarse (XSS).
  X-Content-Type  → Evita que el navegador "adivine" tipos de fichero.
  Referrer-Policy → Controla qué info se envía al navegar entre páginas.
  Permissions-Policy → Controla acceso a cámara, micrófono, geolocalización.
"""

import requests
from config import REQUEST_TIMEOUT, USER_AGENT

# Diccionario con las cabeceras que buscamos y una descripción
# del riesgo cuando están ausentes.
CABECERAS_SEGURIDAD = {
    "Strict-Transport-Security": {
        "alias": "HSTS",
        "riesgo": "Sin HSTS, un atacante puede forzar conexiones HTTP sin cifrar (man-in-the-middle).",
        "severidad": "ALTA"
    },
    "X-Frame-Options": {
        "alias": "X-Frame-Options",
        "riesgo": "Sin esta cabecera, la web puede ser embebida en páginas maliciosas (clickjacking).",
        "severidad": "MEDIA"
    },
    "Content-Security-Policy": {
        "alias": "CSP",
        "riesgo": "Sin CSP, scripts maliciosos pueden ejecutarse en el navegador del usuario (XSS).",
        "severidad": "ALTA"
    },
    "X-Content-Type-Options": {
        "alias": "X-Content-Type-Options",
        "riesgo": "Sin esta cabecera, el navegador puede interpretar ficheros de forma insegura (MIME sniffing).",
        "severidad": "BAJA"
    },
    "Referrer-Policy": {
        "alias": "Referrer-Policy",
        "riesgo": "Sin esta cabecera, se puede filtrar información sensible de URLs internas.",
        "severidad": "BAJA"
    },
    "Permissions-Policy": {
        "alias": "Permissions-Policy",
        "riesgo": "Sin esta cabecera, scripts de terceros pueden acceder a cámara o micrófono.",
        "severidad": "MEDIA"
    },
}


def analizar_headers(dominio: str) -> dict:
    """
    Hace una petición HTTP al dominio y analiza sus cabeceras de seguridad.

    Parámetros:
        dominio (str): El dominio a analizar. Ej: "ejemplo.es"

    Retorna:
        dict con:
          - "url_analizada":     La URL que se consultó realmente
          - "presentes":         Lista de cabeceras de seguridad que SÍ están
          - "ausentes":          Lista de cabeceras que faltan, con detalle del riesgo
          - "puntuacion":        Porcentaje de cabeceras presentes (0-100)
          - "servidor":          Software del servidor web si lo revela
          - "https":             True/False si usa HTTPS
          - "error":             None o mensaje de error
    """

    # Intentamos primero con HTTPS, que es lo correcto.
    # Si falla, lo intentamos con HTTP (algunos sitios aún no redirigen bien).
    for protocolo in ["https", "http"]:
        url = f"{protocolo}://{dominio}"
        try:
            # Usamos GET con stream=True en vez de HEAD.
            #
            # BUG CORREGIDO: muchos servidores, CDNs y WAF (Cloudflare,
            # balanceadores, frameworks con middleware de seguridad...)
            # solo añaden las cabeceras de seguridad en respuestas GET,
            # y devuelven HEAD con un juego de cabeceras incompleto o
            # directamente rechazan el método. Esto hacía que el widget
            # de "Cabeceras HTTP" apareciera vacío o mostrara casi todas
            # las cabeceras como "ausentes" aunque sí estuvieran configuradas.
            # Con stream=True no descargamos el cuerpo de la página: leemos
            # las cabeceras y cerramos la conexión inmediatamente, así que
            # seguimos siendo ligeros y rápidos como con HEAD.
            # allow_redirects=True seguimos redirecciones (ej: http → https)
            respuesta = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                verify=True,  # verificamos el certificado SSL
                stream=True   # no descargamos el cuerpo, solo cabeceras
            )

            cabeceras_respuesta = respuesta.headers

            # Cerramos la conexión ya: con stream=True el cuerpo de la
            # página no se ha descargado todavía, así que esto libera el
            # socket sin gastar ancho de banda ni tiempo de más.
            respuesta.close()

            presentes = []
            ausentes = []

            for cabecera, info in CABECERAS_SEGURIDAD.items():
                if cabecera in cabeceras_respuesta:
                    presentes.append({
                        "nombre": cabecera,
                        "alias": info["alias"],
                        "valor": cabeceras_respuesta[cabecera]
                    })
                else:
                    ausentes.append({
                        "nombre": cabecera,
                        "alias": info["alias"],
                        "riesgo": info["riesgo"],
                        "severidad": info["severidad"]
                    })

            # Calculamos puntuación: % de cabeceras presentes
            total = len(CABECERAS_SEGURIDAD)
            puntuacion = round((len(presentes) / total) * 100)

            # El servidor a veces revela su software (Apache, nginx, IIS...)
            # Esto es información útil para un atacante, y para nosotros.
            servidor = cabeceras_respuesta.get("Server", "No revelado")

            return {
                "url_analizada": respuesta.url,  # URL final tras redirecciones
                "https": respuesta.url.startswith("https"),
                "presentes": presentes,
                "ausentes": ausentes,
                "puntuacion": puntuacion,
                "servidor": servidor,
                "error": None
            }

        except requests.exceptions.SSLError:
            # El certificado SSL tiene un problema (expirado, inválido...)
            # Anotamos esto y continuamos con HTTP
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            return {
                "url_analizada": url,
                "https": False,
                "presentes": [],
                "ausentes": [],
                "puntuacion": 0,
                "servidor": "Desconocido",
                "error": f"Timeout: el servidor no respondió en {REQUEST_TIMEOUT}s"
            }
        except requests.exceptions.RequestException:
            # Cualquier otro fallo de red (demasiadas redirecciones,
            # respuesta mal formada, etc.) — probamos el otro protocolo
            # en vez de dejar el widget completamente vacío.
            continue

    # Si llegamos aquí, ningún protocolo funcionó
    return {
        "url_analizada": f"https://{dominio}",
        "https": False,
        "presentes": [],
        "ausentes": [],
        "puntuacion": 0,
        "servidor": "Desconocido",
        "error": "No se pudo conectar al dominio en HTTPS ni HTTP"
    }
