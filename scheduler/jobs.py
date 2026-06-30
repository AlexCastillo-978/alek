"""
scheduler/jobs.py
─────────────────
Jobs del Módulo 4 — ahora integra el Módulo 5 (Threat Intelligence).

Pipeline correcto:
  1. Recon Engine    → datos brutos
  2. Threat Intel    → enriquecimiento con OTX + CVEs
  3. AI Analyst      → informe con todos los datos
  4. Alertas         → email si hay cambios o amenazas nuevas
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from recon.runner          import ejecutar_recon
from threat_intel.analyzer import ejecutar_analisis_tip
from analyst.analyzer      import generar_informe
from scheduler.database    import (guardar_resultado, obtener_ultimo_resultado,
                                   listar_clientes)
from scheduler.alertas     import enviar_alerta_cambios, enviar_resumen_semanal


def analizar_cliente(cliente: dict, forzar_email: bool = False):
    dominio    = cliente["dominio"]
    email      = cliente["email"]
    cliente_id = cliente["id"]

    print(f"\n  {'─'*45}")
    print(f"  Analizando: {dominio}")
    print(f"  {'─'*45}")

    # ── 1. Recon ──────────────────────────────────────────────────────────
    datos = ejecutar_recon(dominio, verbose=True)

    # ── 2. Threat Intelligence ────────────────────────────────────────────
    print("  [TI] Ejecutando análisis de amenazas...")
    ti = ejecutar_analisis_tip(dominio, datos, verbose=True)
    datos["threat_intel"] = ti  # lo inyectamos en los datos para que la IA lo vea

    # ── 3. Análisis IA ────────────────────────────────────────────────────
    resultado_ia = generar_informe(dominio, datos, verbose=True)

    if resultado_ia.get("error"):
        print(f"  [ERROR] IA: {resultado_ia['error']}")
        return

    analisis   = resultado_ia["analisis"]
    hallazgos  = analisis.get("hallazgos", [])
    puntuacion = analisis.get("puntuacion", {}).get("valor",
                 datos.get("riesgo_global", {}).get("puntuacion", 0))
    nivel      = analisis.get("puntuacion", {}).get("nivel",
                 datos.get("riesgo_global", {}).get("nivel", "DESCONOCIDO"))

    # ── 4. Guardar historial ──────────────────────────────────────────────
    guardar_resultado(cliente_id, dominio, puntuacion, nivel, hallazgos, datos)

    # ── 5. Comparar y alertar ─────────────────────────────────────────────
    anterior = obtener_ultimo_resultado(dominio)
    cambios  = {}

    if anterior:
        diferencia = anterior["puntuacion"] - puntuacion
        if diferencia >= 10:
            cambios["nueva_puntuacion_menor"]  = True
            cambios["diferencia_puntuacion"]   = diferencia
            cambios["puntuacion_anterior"]     = anterior["puntuacion"]

        subs_actuales   = set(datos.get("subdominios", {}).get("sensibles", []))
        subs_anteriores = set()
        nuevos_subs = subs_actuales - subs_anteriores
        if nuevos_subs:
            cambios["nuevos_subdominios"] = list(nuevos_subs)

    # Alerta si el nivel de amenaza TI es alto
    nivel_ti = ti.get("nivel_amenaza", "BAJO")
    if nivel_ti in ["CRÍTICO", "ALTO"]:
        cambios["amenaza_tip"] = nivel_ti

    hay_cambios = bool(cambios)

    if hay_cambios:
        print(f"  [ALERTA] Cambios detectados — enviando notificacion por email...")
        enviar_alerta_cambios(dominio, email, puntuacion, nivel, hallazgos, cambios)
    elif forzar_email:
        print(f"  [EMAIL] Enviando resumen semanal...")
        enviar_resumen_semanal(dominio, email, puntuacion, nivel, hallazgos)
    else:
        print(f"  [OK] Sin cambios significativos — email no enviado")

    print(f"  [OK] Completado: {puntuacion}/100 ({nivel}) · TI: {nivel_ti}")


def ejecutar_todos_los_clientes(forzar_email: bool = False):
    clientes = listar_clientes(solo_activos=True)
    if not clientes:
        print("  No hay clientes activos.")
        return

    print(f"\n  {'═'*45}")
    print(f"  ALEK — Análisis automatizado")
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Clientes activos: {len(clientes)}")
    print(f"  {'═'*45}")

    for cliente in clientes:
        try:
            analizar_cliente(cliente, forzar_email=forzar_email)
        except Exception as e:
            print(f"  [ERROR] {cliente['dominio']}: {type(e).__name__} — {str(e)}")

    print(f"\n  {'═'*45}")
    print(f"  Análisis completado para {len(clientes)} cliente(s)")
    print(f"  {'═'*45}\n")
