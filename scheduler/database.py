"""
scheduler/database.py
─────────────────────
Base de datos SQLite para guardar clientes y resultados históricos.

¿Qué es SQLite?
  Una base de datos que vive en un único fichero en tu ordenador.
  No necesitas instalar nada extra. Python la incluye de serie.
  Perfecta para el MVP: cuando tengas 50+ clientes migras a PostgreSQL.

¿Qué guardamos?
  - Tabla "clientes": los dominios que monitorizamos y a quién reportar
  - Tabla "resultados": cada análisis histórico con su puntuación y hallazgos
  - Tabla "alertas": registro de emails enviados

¿Por qué guardar el historial?
  Para poder comparar: "este mes aparecieron 2 subdominios nuevos que
  el mes pasado no estaban". Eso es el valor del servicio recurrente.
"""

import sqlite3
import json
import os
from datetime import datetime

# El fichero de base de datos se crea en la raíz del proyecto
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon_data.db")


def conectar() -> sqlite3.Connection:
    """Abre una conexión a la base de datos."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    return conn


def inicializar_db():
    """
    Crea las tablas si no existen.
    Se llama una vez al arrancar el scheduler.
    """
    conn = conectar()
    cursor = conn.cursor()

    # Tabla de clientes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clientes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            dominio       TEXT UNIQUE NOT NULL,
            email         TEXT NOT NULL,
            nombre        TEXT,
            activo        INTEGER DEFAULT 1,
            frecuencia    TEXT DEFAULT 'semanal',
            fecha_alta    TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de resultados históricos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS resultados (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id      INTEGER REFERENCES clientes(id),
            dominio         TEXT NOT NULL,
            fecha           TEXT DEFAULT CURRENT_TIMESTAMP,
            puntuacion      INTEGER,
            nivel           TEXT,
            hallazgos_json  TEXT,
            datos_json      TEXT
        )
    """)

    # Tabla de alertas enviadas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id  INTEGER REFERENCES clientes(id),
            dominio     TEXT NOT NULL,
            fecha       TEXT DEFAULT CURRENT_TIMESTAMP,
            tipo        TEXT,
            detalle     TEXT,
            enviada     INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    print(f"  Base de datos inicializada en: {DB_PATH}")


def añadir_cliente(dominio: str, email: str, nombre: str = "", frecuencia: str = "semanal") -> int:
    """
    Añade un cliente a la base de datos.
    Retorna el ID del cliente creado.
    """
    conn = conectar()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO clientes (dominio, email, nombre, frecuencia)
            VALUES (?, ?, ?, ?)
        """, (dominio.lower(), email, nombre, frecuencia))
        conn.commit()
        cliente_id = cursor.lastrowid
        print(f"  [OK] Cliente registrado: {dominio} ({email}) — ID: {cliente_id}")
        return cliente_id
    except sqlite3.IntegrityError:
        print(f"  [AVISO] El dominio {dominio} ya existe en la base de datos")
        cursor.execute("SELECT id FROM clientes WHERE dominio = ?", (dominio,))
        return cursor.fetchone()["id"]
    finally:
        conn.close()


def listar_clientes(solo_activos: bool = True) -> list:
    """Devuelve la lista de clientes registrados."""
    conn = conectar()
    cursor = conn.cursor()
    if solo_activos:
        cursor.execute("SELECT * FROM clientes WHERE activo = 1")
    else:
        cursor.execute("SELECT * FROM clientes")
    clientes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return clientes


def guardar_resultado(cliente_id: int, dominio: str, puntuacion: int,
                      nivel: str, hallazgos: list, datos_completos: dict) -> int:
    """Guarda el resultado de un análisis en el historial."""
    conn = conectar()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO resultados (cliente_id, dominio, puntuacion, nivel, hallazgos_json, datos_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        cliente_id, dominio, puntuacion, nivel,
        json.dumps(hallazgos, ensure_ascii=False),
        json.dumps(datos_completos, ensure_ascii=False)
    ))
    conn.commit()
    resultado_id = cursor.lastrowid
    conn.close()
    return resultado_id


def obtener_ultimo_resultado(dominio: str) -> dict | None:
    """
    Devuelve el resultado más reciente de un dominio.
    Útil para comparar con el análisis actual y detectar cambios.
    """
    conn = conectar()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM resultados
        WHERE dominio = ?
        ORDER BY fecha DESC
        LIMIT 1 OFFSET 1
    """, (dominio,))
    row = cursor.fetchone()
    conn.close()
    if row:
        resultado = dict(row)
        resultado["hallazgos"] = json.loads(resultado["hallazgos_json"])
        return resultado
    return None


def obtener_historial(dominio: str, limite: int = 10) -> list:
    """Devuelve el historial de análisis de un dominio."""
    conn = conectar()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fecha, puntuacion, nivel FROM resultados
        WHERE dominio = ?
        ORDER BY fecha DESC
        LIMIT ?
    """, (dominio, limite))
    historial = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return historial
