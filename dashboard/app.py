"""
dashboard/app.py
Alek — Panel de inteligencia de superficie de ataque.

Como ejecutarlo:
  streamlit run dashboard/app.py
"""

import sys, os, json, hmac, base64, csv, io, unicodedata
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import plotly.graph_objects as go

from dotenv import load_dotenv
load_dotenv()

DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")

ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
LOGO_ICON  = os.path.join(ASSETS_DIR, "alek_icon_header.png")
FAVICON    = os.path.join(ASSETS_DIR, "alek_favicon.png")

st.set_page_config(
    page_title="Alek — Inteligencia de superficie de ataque",
    page_icon=FAVICON if os.path.exists(FAVICON) else None,
    layout="wide",
)

COLOR_BG         = "#04060F"
COLOR_BG_PANEL   = "#0B0F1D"
COLOR_BORDER     = "#1B2236"
COLOR_ACCENT     = "#E8EAF0"
COLOR_MUTED      = "#7E879C"
COLOR_TEXT       = "#E6E9F2"

SEV_COLORS = {
    "CRITICO": "#C0392B",
    "ALTO":    "#B8841C",
    "MEDIO":   "#3A6FB0",
    "BAJO":    "#3C8A5C",
    "INFORMATIVO": "#7E879C",
}

st.markdown(f"""
<style>
.stApp {{ background-color: {COLOR_BG}; color: {COLOR_TEXT}; }}
#MainMenu, footer, header, .stDeployButton {{ visibility: hidden; }}
.header-box {{
    background: linear-gradient(135deg, {COLOR_BG}, {COLOR_BG_PANEL});
    border: 1px solid {COLOR_BORDER}; border-radius: 12px;
    padding: 1.5rem 2rem; margin-bottom: 1.5rem;
    display: flex; align-items: center; gap: 1.1rem;
}}
.header-title {{ font-size:1.6rem; font-weight:700; color:{COLOR_ACCENT}; margin:0; letter-spacing:.04em; }}
.header-sub   {{ font-size:0.85rem; color:{COLOR_MUTED}; margin:0.2rem 0 0; }}
.metric-card {{
    background:{COLOR_BG_PANEL}; border:1px solid {COLOR_BORDER};
    border-radius:10px; padding:1.1rem 1.25rem; text-align:center;
}}
.metric-label {{ font-size:0.7rem; color:{COLOR_MUTED}; text-transform:uppercase; letter-spacing:.08em; margin-bottom:.4rem; }}
.metric-value {{ font-size:1.9rem; font-weight:700; margin:0; }}
.finding-card {{
    background:{COLOR_BG_PANEL}; border-radius:10px;
    padding:1rem 1.25rem; margin-bottom:.6rem; border-left:4px solid;
}}
.finding-title   {{ font-size:.95rem; font-weight:600; margin-bottom:.4rem; }}
.finding-section {{ font-size:.8rem; color:{COLOR_MUTED}; margin:.25rem 0 0; line-height:1.55; }}
.finding-section strong {{ color:{COLOR_TEXT}; }}
.sev-CRITICO {{ border-color:{SEV_COLORS['CRITICO']}; }}
.sev-ALTO    {{ border-color:{SEV_COLORS['ALTO']}; }}
.sev-MEDIO   {{ border-color:{SEV_COLORS['MEDIO']}; }}
.sev-BAJO    {{ border-color:{SEV_COLORS['BAJO']}; }}
.sev-INFORMATIVO {{ border-color:{SEV_COLORS['INFORMATIVO']}; }}
.badge {{ padding:2px 9px; border-radius:20px; font-size:11px; font-weight:600; }}
.badge-CRITICO {{ background:{SEV_COLORS['CRITICO']}; color:#fff; }}
.badge-ALTO    {{ background:{SEV_COLORS['ALTO']}; color:#1a1300; }}
.badge-MEDIO   {{ background:{SEV_COLORS['MEDIO']}; color:#fff; }}
.badge-BAJO    {{ background:{SEV_COLORS['BAJO']}; color:#06130b; }}
.badge-INFORMATIVO {{ background:{SEV_COLORS['INFORMATIVO']}; color:#fff; }}
.info-box {{
    background:{COLOR_BG_PANEL}; border:1px solid {COLOR_BORDER};
    border-radius:10px; padding:1.25rem 1.5rem;
    font-size:.875rem; line-height:1.8; color:{COLOR_TEXT};
}}
.rec-item {{
    background:{COLOR_BG_PANEL}; border:1px solid {COLOR_BORDER}; border-radius:8px;
    padding:.75rem 1rem; margin-bottom:.5rem;
    font-size:.875rem; color:{COLOR_TEXT}; line-height:1.5;
}}
.alek-error-box {{
    background:{COLOR_BG_PANEL}; border:1px solid {SEV_COLORS['CRITICO']};
    border-radius:10px; padding:1.25rem 1.5rem; color:{COLOR_TEXT}; font-size:.9rem;
}}
</style>
""", unsafe_allow_html=True)


# Autenticacion

def _credenciales_validas(usuario: str, contrasena: str) -> bool:
    return (hmac.compare_digest(usuario.strip(), DASHBOARD_USERNAME) and
            hmac.compare_digest(contrasena, DASHBOARD_PASSWORD))


def render_login():
    logo_html = ""
    if os.path.exists(LOGO_ICON):
        with open(LOGO_ICON, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        logo_html = (
            f'<img src="data:image/png;base64,{b64}" '
            f'width="90" style="display:block;margin:0 auto 1rem">'
        )

    st.markdown(f"""
    <div style="text-align:center; margin-bottom:1.5rem; padding-top:5vh">
        {logo_html}
        <p style="font-size:1.75rem;font-weight:700;color:{COLOR_ACCENT};
           letter-spacing:.1em;margin:0">ALEK</p>
        <p style="font-size:.85rem;color:{COLOR_MUTED};margin:.4rem 0 0">
           OSINT y escaneo de superficie de ataque</p>
    </div>
    """, unsafe_allow_html=True)

    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD:
        st.error("Define DASHBOARD_USERNAME y DASHBOARD_PASSWORD en el fichero .env")
        return

    _, col, _ = st.columns([1, 1.4, 1])
    with col:
        with st.form("login_form"):
            usuario    = st.text_input("Usuario")
            contrasena = st.text_input("Contrasena", type="password")
            enviado    = st.form_submit_button("Acceder", use_container_width=True, type="primary")

    if enviado:
        if _credenciales_validas(usuario, contrasena):
            st.session_state["autenticado"] = True
            st.rerun()
        else:
            st.error("Usuario o contrasena incorrectos.")


if "autenticado" not in st.session_state:
    st.session_state["autenticado"] = False

if "filtro_severidad" not in st.session_state:
    st.session_state["filtro_severidad"] = None

if not st.session_state["autenticado"]:
    render_login()
    st.stop()

from recon.runner          import ejecutar_recon
from analyst.analyzer      import generar_informe
from threat_intel.analyzer import ejecutar_analisis_tip


# Helpers

def normalizar_severidad(valor: str) -> str:
    """
    Normaliza cualquier variante de severidad ("CRÍTICO", "crítico",
    "Critico"...) a la clave interna que usa el dashboard: CRITICO,
    ALTO, MEDIO, BAJO o INFORMATIVO (siempre sin tilde y en mayúsculas).

    Bug corregido: la IA devuelve "CRÍTICO" (con tilde), pero SEV_COLORS
    y el resto del dashboard usaban "CRITICO" (sin tilde). Al no coincidir,
    los hallazgos críticos nunca se contaban en el donut de severidad ni
    recibían su color/estilo correcto en las tarjetas de hallazgo.
    """
    if not valor:
        return "BAJO"
    sin_tildes = unicodedata.normalize("NFKD", valor).encode("ascii", "ignore").decode("ascii")
    return sin_tildes.strip().upper()

def color_nivel(nivel: str) -> str:
    return SEV_COLORS.get(normalizar_severidad(nivel), COLOR_MUTED)

def color_puntuacion(p: int) -> str:
    # Bandas alineadas con calcular_riesgo_global() en recon/runner.py
    # (antes 60-79 se pintaba como "ALTO" cuando el nivel real es "MEDIO").
    if p >= 80: return SEV_COLORS["BAJO"]
    if p >= 60: return SEV_COLORS["MEDIO"]
    if p >= 40: return SEV_COLORS["ALTO"]
    return SEV_COLORS["CRITICO"]

def gauge(puntuacion: int, nivel: str) -> go.Figure:
    color = color_puntuacion(puntuacion)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=puntuacion,
        number={"font":{"size":46,"color":color,"family":"monospace"},"suffix":"/100"},
        gauge={
            "axis":{"range":[0,100],"tickcolor":COLOR_MUTED,
                    "tickfont":{"color":COLOR_MUTED,"size":11}},
            "bar":{"color":color,"thickness":0.25},
            "bgcolor":COLOR_BG_PANEL,"bordercolor":COLOR_BORDER,
            "steps":[
                {"range":[0,40],"color":"#160707"},
                {"range":[40,60],"color":"#161106"},
                {"range":[60,100],"color":"#081209"},
            ],
            "threshold":{"line":{"color":color,"width":3},
                         "thickness":0.8,"value":puntuacion}
        }
    ))
    fig.update_layout(paper_bgcolor=COLOR_BG, plot_bgcolor=COLOR_BG,
                      height=240, margin=dict(l=20,r=20,t=10,b=5))
    return fig

def bars_cabeceras(presentes, ausentes) -> go.Figure:
    items  = [(c["alias"],1,SEV_COLORS["BAJO"],"Configurada") for c in presentes] + \
             [(c["alias"],0,SEV_COLORS["CRITICO"],"Ausente")  for c in ausentes]
    fig = go.Figure(go.Bar(
        x=[i[1] for i in items], y=[i[0] for i in items],
        orientation="h", marker_color=[i[2] for i in items],
        text=[i[3] for i in items], textposition="inside",
        textfont={"size":12,"color":"#fff"},
        hovertemplate="%{y}: %{text}<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=COLOR_BG_PANEL, plot_bgcolor=COLOR_BG_PANEL,
        height=260, margin=dict(l=10,r=10,t=10,b=10),
        xaxis={"visible":False,"range":[0,1.4]},
        yaxis={"tickfont":{"color":COLOR_TEXT,"size":12},"gridcolor":COLOR_BORDER},
        showlegend=False
    )
    return fig

def donut_severidades(hallazgos: list) -> go.Figure:
    conteo = {"CRITICO":0,"ALTO":0,"MEDIO":0,"BAJO":0,"INFORMATIVO":0}
    for h in hallazgos:
        sev = normalizar_severidad(h.get("severidad","BAJO"))
        if sev in conteo: conteo[sev] += 1
    labels = [k for k,v in conteo.items() if v > 0]
    values = [conteo[k] for k in labels]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.6,
        marker_colors=[color_nivel(k) for k in labels],
        textinfo="label+value",
        textfont={"size":12,"color":COLOR_TEXT},
        # customdata lleva la clave de severidad "limpia" para poder
        # filtrar los hallazgos al hacer click en una porción del donut.
        customdata=labels,
    ))
    fig.update_layout(
        paper_bgcolor=COLOR_BG_PANEL, plot_bgcolor=COLOR_BG_PANEL,
        height=240, margin=dict(l=10,r=10,t=10,b=10), showlegend=False
    )
    return fig

def render_hallazgo(h: dict):
    sev_mostrada = h.get("severidad","BAJO").upper()
    sev = normalizar_severidad(sev_mostrada)
    st.markdown(f"""
    <div class="finding-card sev-{sev}">
        <div class="finding-title">
            <span class="badge badge-{sev}">{sev_mostrada}</span>&nbsp;&nbsp;{h.get('titulo','')}
        </div>
        <div class="finding-section"><strong>Que es:</strong> {h.get('que_es','')}</div>
        <div class="finding-section"><strong>Riesgo:</strong> {h.get('riesgo','')}</div>
        <div class="finding-section"><strong>Solucion:</strong> {h.get('solucion','')}</div>
    </div>""", unsafe_allow_html=True)

def render_threat_intel(ti: dict):
    if not ti or ti.get("error"):
        return
    nivel  = ti.get("nivel_amenaza", "BAJO")
    ip_rep = ti.get("ip_reputacion", {})
    cves   = ti.get("cves", {})
    st.markdown("---")
    st.markdown("### Inteligencia de amenazas")
    resumen = ti.get("resumen","")
    if resumen:
        st.info(resumen)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Nivel de amenaza</div>
            <div class="metric-value" style="color:{color_nivel(nivel)}">{nivel}</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        rep = ip_rep.get("reputacion","LIMPIA")
        color_rep = {"MALICIOSA":SEV_COLORS["CRITICO"],"SOSPECHOSA":SEV_COLORS["ALTO"],
                     "LIMPIA":SEV_COLORS["BAJO"]}.get(rep,COLOR_MUTED)
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Reputacion IP</div>
            <div class="metric-value" style="color:{color_rep};font-size:1.2rem">{rep}</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        total_cves = cves.get("total",0)
        criticos   = cves.get("criticos",0)
        color_cve  = SEV_COLORS["CRITICO"] if criticos > 0 else SEV_COLORS["ALTO"] if total_cves > 0 else SEV_COLORS["BAJO"]
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">CVEs recientes</div>
            <div class="metric-value" style="color:{color_cve}">{total_cves}</div>
        </div>""", unsafe_allow_html=True)
    if cves.get("cves"):
        st.markdown("<br><b>Vulnerabilidades criticas del servidor</b>", unsafe_allow_html=True)
        for cve in cves["cves"]:
            cvss = cve.get("cvss", 0)
            sev  = "CRITICO" if cvss >= 9 else "ALTO"
            st.markdown(f"""
            <div class="finding-card sev-{sev}">
                <div class="finding-title">
                    <span class="badge badge-{sev}">CVSS {cvss}</span>
                    &nbsp;&nbsp;{cve.get('id','')}
                    <span style="color:{COLOR_MUTED};font-size:11px;margin-left:8px">
                        {cve.get('fecha','')}
                    </span>
                </div>
                <div class="finding-section">{cve.get('descripcion','')[:250]}</div>
            </div>""", unsafe_allow_html=True)

def render_error_amigable(titulo: str, detalle: str = ""):
    st.markdown(f"""
    <div class="alek-error-box">
        <b>{titulo}</b><br>
        El analisis no se ha podido completar. Puede deberse a una incidencia temporal.
        Vuelve a intentarlo en unos minutos.
        {f'<br><br><span style="color:{COLOR_MUTED};font-size:.78rem">Ref: {detalle}</span>' if detalle else ''}
    </div>""", unsafe_allow_html=True)


# Cabecera

logo_b64_header = ""
if os.path.exists(LOGO_ICON):
    with open(LOGO_ICON, "rb") as f:
        logo_b64_header = base64.b64encode(f.read()).decode()

logo_img_header = (
    f'<img src="data:image/png;base64,{logo_b64_header}" width="46" '
    f'style="vertical-align:middle;margin-right:.75rem">'
    if logo_b64_header else ""
)

header_cols = st.columns([10, 1.4])
with header_cols[0]:
    st.markdown(f"""
    <div class="header-box">
        {logo_img_header}
        <div>
            <p class="header-title">ALEK</p>
            <p class="header-sub">OSINT y escaneo de superficie de ataque · Analisis automatizado asistido por IA</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
with header_cols[1]:
    if st.button("Cerrar sesion", use_container_width=True):
        st.session_state["autenticado"] = False
        st.rerun()

st.markdown("<br>", unsafe_allow_html=True)

c1, c2 = st.columns([5, 1])
with c1:
    dominio_input = st.text_input("Dominio", placeholder="ejemplo.com",
                                  label_visibility="collapsed")
with c2:
    analizar = st.button("Analizar", use_container_width=True, type="primary")

st.divider()

if analizar and dominio_input:
    dominio = dominio_input.replace("https://","").replace("http://","").strip("/").strip().lower()
    datos = None
    ti = {}
    resultado = {}
    error_fatal = None
    # Al lanzar un nuevo análisis, limpiamos cualquier filtro de severidad
    # que hubiera quedado activo del análisis anterior.
    st.session_state["filtro_severidad"] = None

    with st.status(f"Analizando {dominio}...", expanded=True) as status:
        try:
            st.write("Recopilando datos de fuentes publicas...")
            datos = ejecutar_recon(dominio, verbose=False)
        except Exception as e:
            error_fatal = ("No se han podido recopilar los datos del dominio.", str(e))

        if not error_fatal:
            try:
                st.write("Consultando inteligencia de amenazas...")
                ti = ejecutar_analisis_tip(dominio, datos, verbose=False)
                if ti is None:
                    ti = {}
                datos["threat_intel"] = ti
            except Exception:
                ti = {"error": True}

        if not error_fatal:
            try:
                st.write("Generando analisis con IA...")
                resultado = generar_informe(dominio, datos, verbose=False)
            except Exception as e:
                error_fatal = ("No se ha podido generar el analisis con IA.", str(e))

        if error_fatal:
            status.update(label="Analisis incompleto", state="error")
        else:
            status.update(label="Analisis completado", state="complete")

    if error_fatal:
        render_error_amigable(error_fatal[0], error_fatal[1])
    else:
        st.session_state.update({
            "datos": datos, "resultado": resultado,
            "dominio": dominio, "threat_intel": ti
        })

if "datos" in st.session_state:
    datos     = st.session_state["datos"]
    resultado = st.session_state["resultado"]
    dominio   = st.session_state["dominio"]
    ti        = st.session_state.get("threat_intel", {})

    analisis   = resultado.get("analisis") or {}
    headers    = datos.get("headers", {})
    puertos    = datos.get("puertos", {})
    subs       = datos.get("subdominios", {})
    filtr      = datos.get("filtraciones", {})
    riesgo_d   = datos.get("riesgo_global", {})

    hallazgos  = analisis.get("hallazgos", [])
    punt_ia    = analisis.get("puntuacion", {})
    puntuacion = punt_ia.get("valor", riesgo_d.get("puntuacion", 0))
    nivel      = punt_ia.get("nivel", riesgo_d.get("nivel", ""))

    if resultado.get("error"):
        render_error_amigable("El analisis con IA no se ha podido completar.", resultado.get("error",""))
        st.stop()

    st.markdown(f"### `{dominio}` — Analisis de superficie de ataque")

    m1,m2,m3,m4,m5 = st.columns(5)
    metricas = [
        ("Puntuacion", str(puntuacion), color_puntuacion(puntuacion)),
        ("Nivel",      nivel,           color_nivel(nivel)),
        ("Hallazgos",  str(len(hallazgos)), SEV_COLORS["ALTO"]),
        ("Cabeceras ausentes", str(len(headers.get("ausentes",[]))), SEV_COLORS["ALTO"]),
        ("Filtraciones", str(filtr.get("total",0)),
         SEV_COLORS["CRITICO"] if filtr.get("total",0) > 0 else SEV_COLORS["BAJO"]),
    ]
    for col,(label,val,color) in zip([m1,m2,m3,m4,m5], metricas):
        with col:
            st.markdown(f"""<div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{color}">{val}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    resumen = analisis.get("resumen_ejecutivo","")
    if resumen:
        st.info(f"**Resumen ejecutivo:** {resumen}")

    st.markdown("<br>", unsafe_allow_html=True)

    g1,g2,g3 = st.columns(3)
    with g1:
        st.markdown("**Puntuacion global**")
        st.plotly_chart(gauge(puntuacion, nivel), use_container_width=True,
                        config={"displayModeBar":False})
    with g2:
        st.markdown("**Cabeceras HTTP**")
        presentes = headers.get("presentes",[])
        ausentes  = headers.get("ausentes", [])
        if presentes or ausentes:
            st.plotly_chart(bars_cabeceras(presentes,ausentes),
                            use_container_width=True, config={"displayModeBar":False})
        elif headers.get("error"):
            st.caption(f"Sin datos de cabeceras ({headers['error']})")
        else:
            st.caption("Sin datos de cabeceras")
    with g3:
        st.markdown("**Hallazgos por severidad**")
        if hallazgos:
            evento_donut = st.plotly_chart(
                donut_severidades(hallazgos),
                use_container_width=True,
                config={"displayModeBar": False},
                on_select="rerun",
                selection_mode="points",
                key="donut_severidad",
            )
            puntos_sel = (evento_donut.get("selection", {}) or {}).get("points", [])
            if puntos_sel:
                severidad_click = puntos_sel[0].get("customdata")
                if isinstance(severidad_click, (list, tuple)):
                    severidad_click = severidad_click[0] if severidad_click else None
                if not severidad_click:
                    severidad_click = puntos_sel[0].get("label")
                if severidad_click:
                    st.session_state["filtro_severidad"] = normalizar_severidad(severidad_click)
            if st.session_state.get("filtro_severidad"):
                fc1, fc2 = st.columns([3, 1])
                with fc1:
                    st.caption(
                        f"Filtrando hallazgos: **{st.session_state['filtro_severidad']}** "
                        "(click de nuevo en el donut o pulsa el boton para ver todos)"
                    )
                with fc2:
                    if st.button("Ver todos", key="quitar_filtro_severidad", use_container_width=True):
                        st.session_state["filtro_severidad"] = None
                        st.rerun()
        else:
            st.caption("Sin hallazgos")

    st.markdown("<br>", unsafe_allow_html=True)

    col_hall, col_info = st.columns([3,2])
    with col_hall:
        st.markdown("**Hallazgos detectados**")
        filtro_sev = st.session_state.get("filtro_severidad")
        hallazgos_mostrados = (
            [h for h in hallazgos if normalizar_severidad(h.get("severidad","BAJO")) == filtro_sev]
            if filtro_sev else hallazgos
        )
        if hallazgos_mostrados:
            for h in hallazgos_mostrados:
                render_hallazgo(h)
        elif filtro_sev:
            st.info(f"No hay hallazgos de severidad {filtro_sev}.")
        else:
            st.success("No se detectaron hallazgos.")

    with col_info:
        st.markdown("**Informacion del servidor**")
        ips_str     = ", ".join(puertos.get("ips",[])) or "Sin datos"
        puertos_str = str(puertos.get("puertos_abiertos",[])) \
                      if puertos.get("puertos_abiertos") else "Sin datos"
        st.markdown(f"""<div class="info-box">
            <b>URL analizada</b><br>
            <span style="color:{COLOR_MUTED}">{headers.get('url_analizada', dominio)}</span><br><br>
            <b>Servidor revelado</b><br>
            <span style="color:{SEV_COLORS['ALTO']}">{headers.get('servidor','No revelado')}</span><br><br>
            <b>HTTPS activo</b><br>
            <span>{'Si' if headers.get('https') else 'No'}</span><br><br>
            <b>IPs detectadas</b><br>
            <span style="color:{COLOR_MUTED}">{ips_str}</span><br><br>
            <b>Puertos abiertos</b><br>
            <span style="color:{COLOR_MUTED}">{puertos_str}</span>
        </div>""", unsafe_allow_html=True)

        lista_subs = subs.get("subdominios",[])
        if lista_subs:
            st.markdown("<br><b>Subdominios activos</b>", unsafe_allow_html=True)
            for s in lista_subs[:8]:
                st.markdown(f"`{s}`")
            if len(lista_subs) > 8:
                st.caption(f"... y {len(lista_subs)-8} mas")

    st.markdown("<br>", unsafe_allow_html=True)

    render_threat_intel(ti)

    st.markdown("<br>", unsafe_allow_html=True)

    recs  = analisis.get("recomendaciones",[])
    pasos = analisis.get("proximos_pasos",[])
    if recs or pasos:
        r1,r2 = st.columns(2)
        with r1:
            st.markdown("**Recomendaciones prioritarias**")
            for i, rec in enumerate(recs, 1):
                st.markdown(f"""
                <div class="rec-item">
                    <span style="color:{COLOR_MUTED};font-size:.7rem;text-transform:uppercase;
                    letter-spacing:.06em;font-weight:600;display:block;margin-bottom:.25rem">
                        Accion {i}
                    </span>{rec}
                </div>""", unsafe_allow_html=True)
        with r2:
            st.markdown("**Proximos pasos**")
            for i, paso in enumerate(pasos, 1):
                st.markdown(f"""
                <div class="rec-item">
                    <span style="color:{COLOR_MUTED};font-size:.7rem;text-transform:uppercase;
                    letter-spacing:.06em;font-weight:600;display:block;margin-bottom:.25rem">
                        Paso {i}
                    </span>{paso}
                </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("**Exportar**")
    e1,e2 = st.columns(2)
    with e1:
        json_export = json.dumps(
            {"dominio": dominio, "analisis": analisis,
             "threat_intel": ti, "datos_recon": datos},
            ensure_ascii=False, indent=2
        )
        st.download_button("Descargar JSON completo", data=json_export,
                           file_name=f"alek_{dominio.replace('.','_')}.json",
                           mime="application/json", use_container_width=True)
    with e2:
        # Informe en CSV en vez de .txt — a peticion de un usuario experimentado,
        # para poder abrirlo y filtrarlo directamente en Excel/Sheets.
        buffer_csv = io.StringIO()
        escritor = csv.writer(buffer_csv)
        escritor.writerow(["Seccion", "Severidad", "Titulo", "Detalle"])
        escritor.writerow(["Resumen", nivel, "Puntuacion global", f"{puntuacion}/100"])
        if resumen:
            escritor.writerow(["Resumen", "", "Resumen ejecutivo", resumen])
        for h in hallazgos:
            detalle = (
                f"Que es: {h.get('que_es','')} | "
                f"Riesgo: {h.get('riesgo','')} | "
                f"Solucion: {h.get('solucion','')}"
            )
            escritor.writerow(["Hallazgo", h.get("severidad",""), h.get("titulo",""), detalle])
        if ti.get("resumen"):
            escritor.writerow(["Inteligencia de amenazas", ti.get("nivel_amenaza",""),
                               "Resumen", ti["resumen"]])
        for i, rec in enumerate(recs, 1):
            escritor.writerow(["Recomendacion", "", f"Accion {i}", rec])
        for i, paso in enumerate(pasos, 1):
            escritor.writerow(["Proximo paso", "", f"Paso {i}", paso])

        st.download_button("Descargar informe .csv",
                           data=buffer_csv.getvalue(),
                           file_name=f"informe_{dominio.replace('.','_')}.csv",
                           mime="text/csv", use_container_width=True)

else:
    logo_espera = ""
    if logo_b64_header:
        logo_espera = f'<img src="data:image/png;base64,{logo_b64_header}" width="64" style="margin-bottom:1rem;opacity:.7">'

    st.markdown(f"""
    <div style="text-align:center;padding:4rem 2rem;color:{COLOR_MUTED}">
        {logo_espera}
        <div style="font-size:1.15rem;font-weight:500;color:{COLOR_TEXT};margin-bottom:.5rem">
            Introduce un dominio y pulsa Analizar
        </div>
        <div style="font-size:.875rem">El analisis completo tarda entre 30 y 60 segundos</div>
    </div>""", unsafe_allow_html=True)
