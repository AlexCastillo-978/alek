"""
threat_intel/runner.py
──────────────────────
Punto de entrada del Módulo 5. Puede usarse solo o junto al pipeline completo.

Uso:
  # Análisis TIP completo sobre un dominio:
  python threat_intel/runner.py --dominio aytorionansa.com

  # Usar datos de un escaneo previo:
  python threat_intel/runner.py --json resultado.json
"""

import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon.runner          import ejecutar_recon
from threat_intel.analyzer import ejecutar_analisis_tip


def main():
    parser = argparse.ArgumentParser(
        description="Alek — Threat Intelligence"
    )
    parser.add_argument("--dominio", "-d", help="Dominio a analizar")
    parser.add_argument("--json",    "-j", help="JSON del Módulo 1 ya existente")
    parser.add_argument("--salida",  "-o", help="Guardar resultado en fichero JSON")
    args = parser.parse_args()

    if not args.dominio and not args.json:
        parser.print_help()
        sys.exit(1)

    # Obtenemos datos del Módulo 1
    if args.json:
        with open(args.json, "r", encoding="utf-8") as f:
            datos_recon = json.load(f)
        dominio = datos_recon["meta"]["dominio"]
    else:
        dominio     = args.dominio
        datos_recon = ejecutar_recon(dominio, verbose=True)

    # Ejecutamos el análisis TIP
    print(f"\n  {'═'*50}")
    print(f"  MÓDULO 5 — Threat Intelligence")
    print(f"  {'═'*50}")

    resultado_tip = ejecutar_analisis_tip(dominio, datos_recon, verbose=True)

    # Mostramos el análisis
    analisis = resultado_tip.get("analisis_ia", {})
    if analisis:
        print(f"\n  {'─'*50}")
        print(f"  NIVEL DE AMENAZA: {analisis.get('nivel_amenaza_contextual','—')}")
        print(f"  {'─'*50}")
        print(f"\n  {analisis.get('resumen_inteligencia','')}")

        amenazas = analisis.get("amenazas_activas", [])
        if amenazas:
            print(f"\n  Amenazas activas detectadas:")
            for a in amenazas:
                print(f"  · [{a['relevancia']}] {a['tipo']}: {a['descripcion']}")

        cves = analisis.get("vulnerabilidades_criticas", [])
        if cves:
            print(f"\n  Vulnerabilidades críticas:")
            for c in cves:
                print(f"  · {c['cve_id']} ({c['software']}): {c['impacto']}")

        print(f"\n  Recomendación urgente:")
        print(f"  → {analisis.get('recomendacion_urgente','')}")
        print(f"\n  {'═'*50}\n")

    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            json.dump({"dominio": dominio, "tip": resultado_tip}, f,
                      ensure_ascii=False, indent=2)
        print(f"  Resultado guardado en: {args.salida}")


if __name__ == "__main__":
    main()
