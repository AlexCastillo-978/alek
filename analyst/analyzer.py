"""
analyst/analyzer.py
───────────────────
Versión 2 — Devuelve JSON estructurado en vez de texto markdown.

Cambios respecto a v1:
  - MAX_TOKENS subido a 3500 (evita informes cortados)
  - Parsea la respuesta de Claude como JSON
  - Devuelve un dict estructurado que el dashboard puede usar directamente
"""

import os
import json
import anthropic
from dotenv import load_dotenv
from analyst.prompt import SYSTEM_PROMPT, construir_mensaje_usuario, construir_mensaje_con_threat_intel

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODELO     = "claude-sonnet-4-6"
MAX_TOKENS = 3500  # Subido de 1500 — evita informes truncados


def generar_informe(dominio: str, datos_recon: dict, verbose: bool = True) -> dict:
    """
    Llama a Claude API y devuelve el análisis como JSON estructurado.

    Retorna dict con:
      - "analisis":  dict con resumen, hallazgos, recomendaciones, etc.
      - "dominio":   dominio analizado
      - "tokens":    tokens consumidos
      - "error":     None o mensaje de error
    """

    if not ANTHROPIC_API_KEY:
        return {
            "analisis": None, "dominio": dominio, "tokens": 0,
            "error": "ANTHROPIC_API_KEY no configurada en el fichero .env"
        }

    if verbose:
        print("\n  [IA] Enviando datos a Claude para análisis... ", end="", flush=True)

    try:
        cliente          = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        # Usamos el mensaje enriquecido si hay threat intel disponible
        threat_intel = datos_recon.get("threat_intel")
        if threat_intel:
            mensaje_usuario = construir_mensaje_con_threat_intel(dominio, datos_recon, threat_intel)
        else:
            mensaje_usuario = construir_mensaje_usuario(dominio, datos_recon)

        respuesta = cliente.messages.create(
            model=MODELO,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": mensaje_usuario}]
        )

        texto_respuesta = respuesta.content[0].text.strip()

        # Limpiamos por si Claude añadió bloques ```json``` a pesar de las instrucciones
        if texto_respuesta.startswith("```"):
            texto_respuesta = texto_respuesta.split("\n", 1)[1]
        if texto_respuesta.endswith("```"):
            texto_respuesta = texto_respuesta.rsplit("```", 1)[0]

        analisis = json.loads(texto_respuesta.strip())

        tokens_total = respuesta.usage.input_tokens + respuesta.usage.output_tokens

        if verbose:
            n_hallazgos = len(analisis.get("hallazgos", []))
            print(f"[OK] {n_hallazgos} hallazgos · {tokens_total} tokens")

        return {
            "analisis": analisis,
            "dominio":  dominio,
            "tokens":   {"entrada": respuesta.usage.input_tokens,
                         "salida":  respuesta.usage.output_tokens,
                         "total":   tokens_total},
            "error": None
        }

    except json.JSONDecodeError as e:
        return {
            "analisis": None, "dominio": dominio, "tokens": 0,
            "error": f"Claude no devolvió JSON válido: {str(e)}"
        }
    except anthropic.AuthenticationError:
        return {
            "analisis": None, "dominio": dominio, "tokens": 0,
            "error": "Clave de Anthropic inválida"
        }
    except Exception as e:
        return {
            "analisis": None, "dominio": dominio, "tokens": 0,
            "error": f"Error inesperado: {str(e)}"
        }
