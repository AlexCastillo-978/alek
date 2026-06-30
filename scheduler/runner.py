"""
scheduler/runner.py
───────────────────
Punto de entrada del Módulo 4. Gestiona clientes y arranca el scheduler.

Comandos disponibles:

  # Añadir un cliente:
  python scheduler/runner.py --añadir --dominio elpais.com --email cliente@email.com --nombre "El País"

  # Listar clientes registrados:
  python scheduler/runner.py --listar

  # Analizar todos los clientes ahora mismo (prueba):
  python scheduler/runner.py --ejecutar-ahora

  # Analizar todos y forzar envío de email:
  python scheduler/runner.py --ejecutar-ahora --email-forzado

  # Arrancar el scheduler automático (corre indefinidamente):
  python scheduler/runner.py --arrancar
"""

import sys
import os
import argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scheduler.database import inicializar_db, añadir_cliente, listar_clientes
from scheduler.jobs     import ejecutar_todos_los_clientes, analizar_cliente


def arrancar_scheduler():
    """
    Arranca el scheduler que ejecuta análisis automáticamente.
    Corre indefinidamente hasta que lo paras con Ctrl+C.
    """
    from apscheduler.schedulers.blocking import BlockingScheduler
    from apscheduler.triggers.cron      import CronTrigger

    scheduler = BlockingScheduler(timezone="Europe/Madrid")

    # Ejecutar todos los lunes a las 8:00 con email de resumen
    scheduler.add_job(
        func=lambda: ejecutar_todos_los_clientes(forzar_email=True),
        trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
        id="analisis_semanal",
        name="Análisis semanal de todos los clientes",
        replace_existing=True
    )

    print(f"\n  {'═'*50}")
    print(f"  ALEK — Scheduler activo")
    print(f"  Analisis automatico: todos los lunes a las 8:00")
    print(f"  Clientes monitorizados: {len(listar_clientes())}")
    print(f"  Ctrl+C para detener")
    print(f"  {'═'*50}\n")

    try:
        scheduler.start()
    except KeyboardInterrupt:
        print("\n  Scheduler detenido.")


def main():
    parser = argparse.ArgumentParser(
        description="Alek — Scheduler de analisis automatizado",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python scheduler/runner.py --añadir --dominio elpais.com --email yo@email.com
  python scheduler/runner.py --listar
  python scheduler/runner.py --ejecutar-ahora
  python scheduler/runner.py --ejecutar-ahora --email-forzado
  python scheduler/runner.py --arrancar
        """
    )

    parser.add_argument("--añadir",        action="store_true", help="Añadir nuevo cliente")
    parser.add_argument("--dominio",  "-d", help="Dominio del cliente")
    parser.add_argument("--email",    "-e", help="Email del cliente")
    parser.add_argument("--nombre",   "-n", help="Nombre del cliente", default="")
    parser.add_argument("--listar",         action="store_true", help="Listar clientes")
    parser.add_argument("--ejecutar-ahora", action="store_true", help="Ejecutar análisis ahora")
    parser.add_argument("--email-forzado",  action="store_true", help="Forzar envío de email")
    parser.add_argument("--arrancar",       action="store_true", help="Arrancar scheduler automático")

    args = parser.parse_args()

    # Siempre inicializamos la base de datos primero
    inicializar_db()

    if args.añadir:
        if not args.dominio or not args.email:
            print("  [ERROR] Necesitas especificar --dominio y --email")
            sys.exit(1)
        añadir_cliente(args.dominio, args.email, args.nombre)

    elif args.listar:
        clientes = listar_clientes(solo_activos=False)
        if not clientes:
            print("  No hay clientes registrados.")
        else:
            print(f"\n  {'─'*55}")
            print(f"  {'ID':<4} {'DOMINIO':<30} {'EMAIL':<25} {'ACTIVO'}")
            print(f"  {'─'*55}")
            for c in clientes:
                activo = "SI" if c["activo"] else "NO"
                print(f"  {c['id']:<4} {c['dominio']:<30} {c['email']:<25} {activo}")
            print(f"  {'─'*55}\n")

    elif args.ejecutar_ahora:
        ejecutar_todos_los_clientes(forzar_email=args.email_forzado)

    elif args.arrancar:
        arrancar_scheduler()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
