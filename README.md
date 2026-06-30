# Alek — Inteligencia de superficie de ataque

Plataforma de análisis automatizado de seguridad perimetral. Combina recopilación de datos de fuentes públicas, inteligencia de amenazas en tiempo real y análisis asistido por IA para generar informes estructurados sobre la superficie de ataque de cualquier dominio.

---

## Módulos

| Módulo | Descripción |
|--------|-------------|
| **Recon Engine** | Subdominios (crt.sh), cabeceras HTTP, puertos (Netlas), filtraciones (HIBP) |
| **AI Analyst** | Análisis con Claude: hallazgos, severidades, recomendaciones |
| **Dashboard** | Panel Streamlit con login, visualizaciones Plotly, exportación |
| **Scheduler** | Monitorización continua + alertas por email automáticas |
| **Threat Intel** | Reputación IP/dominio (OTX), CVEs recientes (NVD) |

---

## Instalación

```bash
# 1. Clona el repositorio
git clone <tu-repo> alek && cd alek

# 2. Crea y activa un entorno virtual (recomendado)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Instala dependencias
pip install -r requirements.txt

# 4. Configura las claves
cp .env.example .env
# Edita .env con tu editor y rellena las claves de API
```

---

## Claves de API necesarias

| Variable | Servicio | Dónde obtenerla |
|----------|----------|-----------------|
| `ANTHROPIC_API_KEY` | Claude (IA) | console.anthropic.com |
| `NETLAS_API_KEY` | Netlas (puertos/IPs) | app.netlas.io |
| `HIBP_API_KEY` | Have I Been Pwned | haveibeenpwned.com/API |
| `OTX_API_KEY` | AlienVault OTX | otx.alienvault.com |
| `ALERT_EMAIL_ORIGEN` | Gmail remitente | Tu cuenta Gmail |
| `ALERT_EMAIL_PASSWORD` | Contraseña de app Gmail | myaccount.google.com → Seguridad → Contraseñas de app |
| `DASHBOARD_USERNAME` | Acceso al panel | Elige tú (ej: `admin`) |
| `DASHBOARD_PASSWORD` | Acceso al panel | Elige tú (cámbialo antes de cualquier demo) |

---

## Uso

### Dashboard (demo con cliente)
```bash
streamlit run dashboard/app.py
```
Abre el navegador en `http://localhost:8501`. Introduce usuario y contraseña del `.env`.

### Scheduler (monitorización continua)
```bash
# Registrar un cliente
python scheduler/runner.py --añadir --dominio ejemplo.com --email cliente@empresa.com --nombre "Empresa S.A."

# Listar clientes registrados
python scheduler/runner.py --listar

# Ejecutar análisis ahora (prueba)
python scheduler/runner.py --ejecutar-ahora

# Ejecutar y forzar envío de email
python scheduler/runner.py --ejecutar-ahora --email-forzado

# Arrancar el scheduler automático (lunes 8:00)
python scheduler/runner.py --arrancar
```

---

## Seguridad

- El fichero `.env` está en `.gitignore` y **nunca debe subirse al repositorio**.
- El dashboard está protegido con login. Cambia `DASHBOARD_PASSWORD` antes de cualquier demo.
- La comparación de credenciales usa `hmac.compare_digest` para evitar timing attacks.

---

## Estructura del proyecto

```
alek/
├── assets/              Logos e iconos de marca
├── analyst/             Módulo IA (Claude)
├── dashboard/           Panel Streamlit
├── recon/               Motor de reconocimiento
├── scheduler/           Automatización y alertas
├── threat_intel/        Inteligencia de amenazas
├── config.py            Configuración centralizada
├── .env                 Claves (no versionar)
├── .env.example         Plantilla de claves (versionable)
└── requirements.txt
```
