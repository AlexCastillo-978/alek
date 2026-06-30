"""
analyst/prompt.py
─────────────────
Versión 2 — Claude devuelve JSON estructurado en vez de texto libre.

¿Por qué este cambio es crítico?
  Antes: Claude devolvía markdown. Útil para leer, inútil para procesar.
  Ahora: Claude devuelve JSON. El dashboard puede coger cada hallazgo,
  renderizarlo con su color, contarlos, filtrarlos y exportarlos.

  Es la diferencia entre tener datos y tener un documento.
"""

SYSTEM_PROMPT = """
Eres un analista senior de ciberseguridad especializado en análisis de 
superficie de ataque para empresas españolas.

Recibirás datos técnicos de reconocimiento de un dominio y debes analizarlos
con criterio profesional.

REGLAS ESTRICTAS:
- Responde ÚNICAMENTE con un objeto JSON válido. Sin texto antes ni después.
- Sin bloques de código markdown (no uses ```json).
- Escribe en español formal pero accesible. Sin jerga técnica sin explicar.
- Sé directo. Cada hallazgo debe tener qué es, qué riesgo supone y cómo se arregla.
- Nunca inventes datos que no estén en los datos que recibes.
- Si un módulo devolvió error, indícalo en el campo correspondiente.
- Ordena los hallazgos de mayor a menor severidad.

FORMATO DE RESPUESTA — objeto JSON con esta estructura exacta:
{
  "resumen_ejecutivo": "3-4 frases que resuman la situación de seguridad del dominio",
  "puntuacion": {
    "valor": 0,
    "nivel": "CRÍTICO|ALTO|MEDIO|BAJO",
    "explicacion": "Una frase explicando qué significa la puntuación"
  },
  "hallazgos": [
    {
      "titulo": "Título corto del hallazgo",
      "severidad": "CRÍTICO|ALTO|MEDIO|BAJO|INFORMATIVO",
      "que_es": "Explicación sin tecnicismos de qué es el problema",
      "riesgo": "Qué puede pasar si no se corrige",
      "solucion": "Cómo se arregla, de forma concreta y accionable"
    }
  ],
  "recomendaciones": [
    "Recomendación prioritaria 1",
    "Recomendación prioritaria 2",
    "Recomendación prioritaria 3"
  ],
  "proximos_pasos": [
    "Acción concreta que el cliente debería hacer esta semana",
    "Segunda acción para las próximas dos semanas"
  ]
}
"""


def construir_mensaje_usuario(dominio: str, datos_recon: dict) -> str:
    import json

    subdominios  = datos_recon.get("subdominios", {})
    headers      = datos_recon.get("headers", {})
    shodan       = datos_recon.get("puertos", {})
    filtraciones = datos_recon.get("filtraciones", {})
    riesgo       = datos_recon.get("riesgo_global", {})

    return f"""
Analiza los siguientes datos de reconocimiento para el dominio: {dominio}

=== PUNTUACIÓN CALCULADA ===
Nivel: {riesgo.get('nivel', 'DESCONOCIDO')}
Puntuación: {riesgo.get('puntuacion', 0)}/100

=== SUBDOMINIOS ===
Total: {subdominios.get('total', 0)}
Lista: {', '.join(subdominios.get('subdominios', [])) or 'No disponible'}
Subdominios sensibles (administración expuesta): {', '.join(subdominios.get('sensibles', [])) or 'Ninguno'}
Error: {subdominios.get('error') or 'Ninguno'}

=== CABECERAS HTTP ===
URL: {headers.get('url_analizada', dominio)}
HTTPS: {headers.get('https', False)}
Servidor revelado: {headers.get('servidor', 'No revelado')}
Puntuación cabeceras: {headers.get('puntuacion', 0)}/100
Presentes: {json.dumps(headers.get('presentes', []), ensure_ascii=False)}
Ausentes: {json.dumps(headers.get('ausentes', []), ensure_ascii=False)}

=== PUERTOS Y SERVICIOS ===
IPs: {', '.join(shodan.get('ips', [])) or 'No disponible'}
Puertos abiertos: {shodan.get('puertos_abiertos', []) or 'No disponible'}
Puertos críticos: {shodan.get('puertos_criticos', []) or 'Ninguno'}
Advertencias: {json.dumps(shodan.get('advertencias', []), ensure_ascii=False)}
Error: {shodan.get('error') or 'Ninguno'}

=== FILTRACIONES ===
Total: {filtraciones.get('total', 0)}
Nivel: {filtraciones.get('nivel_riesgo', 'DESCONOCIDO')}
Detalle: {json.dumps(filtraciones.get('filtraciones', []), ensure_ascii=False)}
Error: {filtraciones.get('error') or 'Ninguno'}

Genera el análisis en el formato JSON especificado.
""".strip()


def construir_mensaje_con_threat_intel(dominio: str, datos_recon: dict,
                                       threat_intel: dict) -> str:
    """
    Versión extendida del mensaje que incluye inteligencia de amenazas.
    Usada cuando el Módulo 5 está disponible.
    """
    import json

    base = construir_mensaje_usuario(dominio, datos_recon)

    ti = threat_intel or {}
    ip_rep  = ti.get("ip_reputacion", {})
    dom_rep = ti.get("dominio_reputacion", {})
    cves    = ti.get("cves", {})

    bloque_ti = f"""

=== INTELIGENCIA DE AMENAZAS ===
Nivel de amenaza global: {ti.get('nivel_amenaza', 'DESCONOCIDO')}
Resumen: {ti.get('resumen', 'No disponible')}

Reputación IP en OTX:
  Estado: {ip_rep.get('reputacion', 'DESCONOCIDA')}
  Aparece en {ip_rep.get('pulsos', 0)} informe(s) de amenazas
  Categorías: {', '.join(ip_rep.get('categorias', [])) or 'Ninguna'}

Reputación dominio en OTX:
  Estado: {dom_rep.get('reputacion', 'DESCONOCIDA')}
  Aparece en {dom_rep.get('pulsos', 0)} informe(s) de amenazas

CVEs recientes del servidor:
  Total: {cves.get('total', 0)} en últimos 90 días
  Críticos (CVSS >= 9.0): {cves.get('criticos', 0)}
  Altos (CVSS >= 7.0): {cves.get('altos', 0)}
  Detalle: {json.dumps(cves.get('cves', []), ensure_ascii=False)}

Incluye los hallazgos de inteligencia de amenazas en tu análisis.
Si la IP es maliciosa o hay CVEs críticos, añádelos como hallazgos
de severidad CRÍTICO o ALTO en el JSON de respuesta.
"""

    return base + bloque_ti
