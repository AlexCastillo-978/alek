"""
recon/runner.py
───────────────
ORQUESTADOR — El cerebro del Módulo 1

Este fichero es el único que necesitas llamar desde fuera.
Se encarga de:
  1. Llamar a los 4 módulos de recolección en orden
  2. Combinar todos sus resultados en un único JSON
  3. Calcular una puntuación de riesgo global
  4. Guardar el resultado en un fichero para usarlo después

¿Por qué un orquestador?
  Porque cada módulo hace UNA sola cosa (principio de responsabilidad
  única). El orquestador los coordina sin que cada módulo necesite
  saber que los demás existen. Esto hace el código más fácil de
  mantener y de ampliar.

Uso:
  python runner.py --dominio ejemplo.es
  python runner.py --dominio ejemplo.es --salida resultado.json
"""

import json
import argparse
import datetime
import sys
import os

# Añadimos el directorio raíz al path para poder importar config.py
# Esto es necesario porque runner.py está dentro de la carpeta recon/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon.crtsh          import obtener_subdominios
from recon.headers        import analizar_headers
from recon.netlas_client  import obtener_info_host
from recon.hibp           import verificar_filtraciones_dominio
from threat_intel.analyzer import enriquecer_con_inteligencia


def calcular_riesgo_global(resultados: dict) -> dict:
    """
    Calcula una puntuación de riesgo global (0-100) basada en todos
    los hallazgos, y determina el nivel: CRÍTICO, ALTO, MEDIO, BAJO.

    La lógica de puntuación es deliberada:
      - Puertos críticos expuestos: impacto muy alto (penalización grande)
      - Cabeceras de seguridad ausentes: impacto medio
      - Filtraciones de datos: impacto según cantidad
      - Subdominios de riesgo: impacto bajo (más superficie ≠ más riesgo directo)
    """

    puntuacion = 100  # Empezamos con puntuación perfecta y vamos restando

    # ── Penalización por puertos críticos ─────────────────────────────────
    puertos_criticos = resultados["puertos"].get("puertos_criticos", [])
    puntuacion -= len(puertos_criticos) * 20  # Cada puerto crítico = -20 puntos

    # ── Penalización por cabeceras ausentes ───────────────────────────────
    cabeceras_ausentes = resultados["headers"].get("ausentes", [])
    for cabecera in cabeceras_ausentes:
        if cabecera["severidad"] == "ALTA":
            puntuacion -= 8
        elif cabecera["severidad"] == "MEDIA":
            puntuacion -= 4
        else:
            puntuacion -= 2

    # ── Penalización por filtraciones ─────────────────────────────────────
    nivel_filtracion = resultados["filtraciones"].get("nivel_riesgo", "NINGUNO")
    penalizacion_filtración = {
        "ALTO": 25, "MEDIO": 15, "BAJO": 5, "NINGUNO": 0, "DESCONOCIDO": 0
    }
    puntuacion -= penalizacion_filtración.get(nivel_filtracion, 0)

    # ── Penalización por subdominios sensibles expuestos ─────────────────
    # Subdominios de administración que no deberían ser públicos
    SUBDOMINIOS_SENSIBLES = {
        "cpanel", "whm", "webmail", "webdisk", "mail", "ftp",
        "admin", "administrador", "panel", "dev", "staging",
        "test", "backup", "old", "beta", "api", "intranet"
    }
    subdominios = resultados["subdominios"].get("subdominios", [])
    sensibles_encontrados = []
    for sub in subdominios:
        prefijo = sub.split(".")[0].lower()
        if prefijo in SUBDOMINIOS_SENSIBLES:
            sensibles_encontrados.append(sub)

    # Cada subdominio sensible resta 8 puntos (máximo -24)
    puntuacion -= min(len(sensibles_encontrados) * 8, 24)

    # ── Sin HTTPS es crítico ──────────────────────────────────────────────
    if not resultados["headers"].get("https", True):
        puntuacion -= 30

    # Aseguramos que la puntuación esté entre 0 y 100
    puntuacion = max(0, min(100, puntuacion))

    # Guardamos los subdominios sensibles para que la IA los mencione
    resultados["subdominios"]["sensibles"] = sensibles_encontrados

    # Determinamos el nivel de riesgo cualitativo
    if puntuacion >= 80:
        nivel = "BAJO"
        color = "verde"
    elif puntuacion >= 60:
        nivel = "MEDIO"
        color = "amarillo"
    elif puntuacion >= 40:
        nivel = "ALTO"
        color = "naranja"
    else:
        nivel = "CRÍTICO"
        color = "rojo"

    return {
        "puntuacion": puntuacion,
        "nivel": nivel,
        "color": color
    }


def ejecutar_recon(dominio: str, verbose: bool = True) -> dict:
    """
    Función principal. Ejecuta el reconocimiento completo de un dominio.

    Parámetros:
        dominio (str):   El dominio a analizar
        verbose (bool):  Si True, imprime el progreso en consola

    Retorna:
        dict con todos los resultados estructurados
    """

    # Limpiamos el dominio: eliminamos http://, https://, y barras finales
    dominio = dominio.lower()
    dominio = dominio.replace("https://", "").replace("http://", "")
    dominio = dominio.strip("/").strip()

    if verbose:
        print(f"\n{'═'*55}")
        print(f"  ALEK — Análisis de superficie de ataque")
        print(f"{'═'*55}")
        print(f"  Dominio: {dominio}")
        print(f"  Fecha:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═'*55}\n")

    resultados = {
        "meta": {
            "dominio": dominio,
            "fecha_analisis": datetime.datetime.now().isoformat(),
            "version_modulo": "1.0.0"
        }
    }

    # ── Fuente 1: Subdominios ─────────────────────────────────────────────
    if verbose:
        print("  [1/5] Consultando subdominios en crt.sh... ", end="", flush=True)
    resultados["subdominios"] = obtener_subdominios(dominio)
    if verbose:
        total = resultados["subdominios"]["total"]
        estado = f"[OK] {total} subdominios encontrados" if not resultados["subdominios"]["error"] else f"[ERROR] {resultados['subdominios']['error']}"
        print(estado)

    # ── Fuente 2: Cabeceras HTTP ──────────────────────────────────────────
    if verbose:
        print("  [2/5] Analizando cabeceras HTTP de seguridad... ", end="", flush=True)
    resultados["headers"] = analizar_headers(dominio)
    if verbose:
        puntuacion = resultados["headers"]["puntuacion"]
        estado = f"[OK] Puntuacion: {puntuacion}/100" if not resultados["headers"]["error"] else f"[ERROR] {resultados['headers']['error']}"
        print(estado)

    # ── Fuente 3: Shodan ──────────────────────────────────────────────────
    if verbose:
        print("  [3/5] Consultando puertos expuestos en Netlas... ", end="", flush=True)
    resultados["puertos"] = obtener_info_host(dominio)
    if verbose:
        puertos = resultados["puertos"]["puertos_abiertos"]
        criticos = resultados["puertos"]["puertos_criticos"]
        if resultados["puertos"]["error"] and "no configurada" in resultados["puertos"]["error"]:
            print("[AVISO] Sin API key (modo limitado)")
        else:
            print(f"[OK] {len(puertos)} puertos | {len(criticos)} criticos")

    # ── Fuente 4: HIBP ────────────────────────────────────────────────────
    if verbose:
        print("  [4/5] Verificando filtraciones en Have I Been Pwned... ", end="", flush=True)
    resultados["filtraciones"] = verificar_filtraciones_dominio(dominio)
    if verbose:
        total = resultados["filtraciones"]["total"]
        if resultados["filtraciones"]["error"] and "no configurada" in resultados["filtraciones"]["error"]:
            print("[AVISO] Sin API key (modo limitado)")
        else:
            print(f"[OK] {total} filtracion(es) encontrada(s)")

    # ── Fuente 5: Threat Intelligence ────────────────────────────────────
    if verbose:
        print("  [5/5] Consultando inteligencia de amenazas... ", end="", flush=True)
    resultados["threat_intel"] = enriquecer_con_inteligencia(dominio, resultados, verbose=False)
    if verbose:
        nivel = resultados["threat_intel"]["nivel_amenaza"]
        print(f"[OK] Nivel de amenaza: {nivel}")

    # ── Cálculo de riesgo global ──────────────────────────────────────────
    resultados["riesgo_global"] = calcular_riesgo_global(resultados)

    if verbose:
        riesgo = resultados["riesgo_global"]
        print(f"\n{'─'*55}")
        print(f"  RESULTADO: {riesgo['nivel']} (puntuación: {riesgo['puntuacion']}/100)")
        print(f"{'─'*55}\n")

    return resultados


def main():
    """
    Punto de entrada cuando ejecutamos el script desde la terminal.
    Gestiona los argumentos de línea de comandos.
    """
    parser = argparse.ArgumentParser(
        description="Alek — Análisis de superficie de ataque",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python runner.py --dominio ejemplo.es
  python runner.py --dominio ejemplo.es --salida informe.json
  python runner.py --dominio ejemplo.es --silencioso
        """
    )
    parser.add_argument(
        "--dominio", "-d",
        required=True,
        help="Dominio a analizar (ej: empresa.es)"
    )
    parser.add_argument(
        "--salida", "-o",
        default=None,
        help="Fichero JSON donde guardar el resultado (opcional)"
    )
    parser.add_argument(
        "--silencioso", "-s",
        action="store_true",
        help="No mostrar progreso, solo el JSON final"
    )

    args = parser.parse_args()

    # Ejecutamos el análisis
    resultado = ejecutar_recon(
        dominio=args.dominio,
        verbose=not args.silencioso
    )

    # Guardamos en fichero si se especificó
    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, ensure_ascii=False, indent=2)
        print(f"  Resultado guardado en: {args.salida}")
    else:
        # Si no se especifica fichero, mostramos el JSON en consola
        print(json.dumps(resultado, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
