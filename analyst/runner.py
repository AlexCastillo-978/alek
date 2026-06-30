"""
analyst/runner.py
─────────────────
Orquestador del Módulo 2 — uso desde línea de comandos.

Uso:
  python analyst/runner.py --dominio elpais.com
  python analyst/runner.py --dominio elpais.com --salida informe.txt
  python analyst/runner.py --json resultado.json
"""

import json
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyst.analyzer import generar_informe
from recon.runner     import ejecutar_recon


def formatear_informe(dominio: str, resultado: dict) -> str:
    """Convierte el dict del análisis en texto legible para consola y fichero."""
    analisis   = resultado.get("analisis", {})
    tokens     = resultado.get("tokens", {})
    separador  = "═" * 55

    lineas = [
        f"\n{separador}",
        f"  INFORME DE SEGURIDAD — {dominio.upper()}",
        f"{separador}\n",
    ]

    punt = analisis.get("puntuacion", {})
    lineas.append(f"Puntuación: {punt.get('valor', '—')}/100 — {punt.get('nivel', '—')}")
    lineas.append(f"{punt.get('explicacion', '')}\n")

    resumen = analisis.get("resumen_ejecutivo", "")
    if resumen:
        lineas += ["RESUMEN EJECUTIVO", "─" * 40, resumen, ""]

    hallazgos = analisis.get("hallazgos", [])
    if hallazgos:
        lineas += ["HALLAZGOS", "─" * 40]
        for h in hallazgos:
            lineas += [
                f"\n[{h.get('severidad', '—')}] {h.get('titulo', '')}",
                f"Qué es:   {h.get('que_es', '')}",
                f"Riesgo:   {h.get('riesgo', '')}",
                f"Solución: {h.get('solucion', '')}",
            ]

    recs = analisis.get("recomendaciones", [])
    if recs:
        lineas += ["", "RECOMENDACIONES", "─" * 40]
        for i, r in enumerate(recs, 1):
            lineas.append(f"{i}. {r}")

    pasos = analisis.get("proximos_pasos", [])
    if pasos:
        lineas += ["", "PRÓXIMOS PASOS", "─" * 40]
        for i, p in enumerate(pasos, 1):
            lineas.append(f"{i}. {p}")

    total_tokens = tokens.get("total", 0) if isinstance(tokens, dict) else 0
    lineas += [
        f"\n{separador}",
        f"  Tokens consumidos: {total_tokens}",
        f"{separador}\n",
    ]
    return "\n".join(lineas)


def main():
    parser = argparse.ArgumentParser(
        description="Alek — Análisis con IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python analyst/runner.py --dominio elpais.com
  python analyst/runner.py --dominio elpais.com --salida informe.txt
  python analyst/runner.py --json resultado.json
        """
    )
    parser.add_argument("--dominio", "-d", help="Dominio a analizar")
    parser.add_argument("--json",    "-j", help="JSON del Módulo 1 ya guardado")
    parser.add_argument("--salida",  "-o", help="Guardar informe en fichero .txt")
    args = parser.parse_args()

    if not args.dominio and not args.json:
        parser.print_help()
        sys.exit(1)

    # Datos del Módulo 1
    if args.json:
        print(f"\n  Cargando datos desde {args.json}...")
        with open(args.json, "r", encoding="utf-8") as f:
            datos_recon = json.load(f)
        dominio = datos_recon["meta"]["dominio"]
    else:
        dominio     = args.dominio
        datos_recon = ejecutar_recon(dominio, verbose=True)

    # Análisis IA
    resultado = generar_informe(dominio, datos_recon, verbose=True)

    if resultado.get("error"):
        print(f"\n  [ERROR] {resultado['error']}")
        sys.exit(1)

    texto = formatear_informe(dominio, resultado)
    print(texto)

    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            f.write(texto)
        print(f"  Guardado en: {args.salida}")


if __name__ == "__main__":
    main()
