"""
threat_intel/analyzer.py
────────────────────────
Módulo 5 — Orquestador de inteligencia de amenazas.

Exporta dos nombres para compatibilidad:
  - enriquecer_con_inteligencia(): nombre interno descriptivo
  - ejecutar_analisis_tip():       alias usado por dashboard y scheduler
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel.otx_client import analizar_ip, analizar_dominio
from threat_intel.cve_client import buscar_cves


def enriquecer_con_inteligencia(dominio: str, datos_recon: dict,
                                verbose: bool = True) -> dict:
    """
    Enriquece los datos del Módulo 1 con inteligencia de amenazas
    de AlienVault OTX y NVD/CVE.
    """
    if verbose:
        print("\n  [TI] Consultando inteligencia de amenazas...")

    ips      = datos_recon.get("puertos", {}).get("ips", [])
    ip       = ips[0] if ips else ""
    servidor = datos_recon.get("headers", {}).get("servidor", "")

    # A: Reputación IP
    if verbose:
        print(f"  [TI] Reputación de IP {ip or 'desconocida'}... ", end="", flush=True)
    ip_rep = analizar_ip(ip)
    if verbose:
        print(f"[OK] {ip_rep['reputacion']} ({ip_rep['pulsos']} pulsos)")

    # B: Reputación dominio
    if verbose:
        print(f"  [TI] Reputación del dominio... ", end="", flush=True)
    dom_rep = analizar_dominio(dominio)
    if verbose:
        print(f"[OK] {dom_rep['reputacion']} ({dom_rep['pulsos']} pulsos)")

    # C: CVEs del servidor
    if verbose:
        print(f"  [TI] CVEs para '{servidor or 'desconocido'}'... ", end="", flush=True)
    cves = buscar_cves(servidor)
    if verbose:
        print(f"[OK] {cves['total']} CVEs ({cves['criticos']} criticos)")

    # Nivel de amenaza global
    puntos = 0
    if ip_rep["reputacion"]  == "MALICIOSA":    puntos += 40
    elif ip_rep["reputacion"] == "SOSPECHOSA":  puntos += 20
    if dom_rep["reputacion"] == "MALICIOSA":    puntos += 30
    elif dom_rep["reputacion"] == "SOSPECHOSA": puntos += 15
    puntos += cves["criticos"] * 15
    puntos += cves["altos"]    * 8

    if puntos >= 50:   nivel = "CRÍTICO"
    elif puntos >= 30: nivel = "ALTO"
    elif puntos >= 10: nivel = "MEDIO"
    else:              nivel = "BAJO"

    # Resumen narrativo
    partes = []
    if ip_rep["reputacion"] in ["MALICIOSA", "SOSPECHOSA"]:
        partes.append(
            f"La IP {ip} aparece en {ip_rep['pulsos']} informe(s) de "
            f"amenazas activas en AlienVault OTX ({ip_rep['reputacion'].lower()})."
        )
    else:
        partes.append(f"La IP {ip or 'desconocida'} no aparece en feeds de amenazas conocidos.")

    if cves["total"] > 0:
        partes.append(
            f"El servidor ({servidor}) tiene {cves['total']} CVE(s) publicado(s) "
            f"en los últimos 90 días: {cves['criticos']} crítico(s) y {cves['altos']} alto(s)."
        )
    elif servidor:
        partes.append(f"No se encontraron CVEs críticos recientes para {servidor}.")

    return {
        "ip_reputacion":      ip_rep,
        "dominio_reputacion": dom_rep,
        "cves":               cves,
        "nivel_amenaza":      nivel,
        "resumen":            " ".join(partes),
        "error":              None
    }


# Alias público — usado por dashboard, scheduler y runner TIP
ejecutar_analisis_tip = enriquecer_con_inteligencia
