"""
dashboard/app.py
────────────────
Módulo 3 — Dashboard visual completo con Threat Intelligence.

Cómo ejecutarlo:
  streamlit run dashboard/app.py
"""

import sys, os, json, hmac, base64
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

# ── Configuración ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Alek — Inteligencia de superficie de ataque",
    page_icon=FAVICON if os.path.exists(FAVICON) else None,
    layout="wide",
)

# ── Autenticación ──────────────────────────────────────────────────────────

def _credenciales_validas(usuario: str, contrasena: str) -> bool:
    return (hmac.compare_digest(usuario.strip(), DASHBOARD_USERNAME) and
            hmac.compare_digest(contrasena, DASHBOARD_PASSWORD))


def render_login():
    # Logo en base64 incrustado directamente en HTML para centrado perfecto
    logo_html = ""
    if os.path.exists(LOGO_ICON):
        with open(LOGO_ICON, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        logo_html = (
            f'<img src="data:image/png;base64,{b64}" '
            f'width="90" style="display:block;margin:0 auto 1rem">'
        )

    st.markdown(f"""
    <div style="text-align:center; margin-bottom:1.5rem">
        {logo_html}
        <p style="font-size:1.75rem;font-weight:700;color:#E8EAF0;
           letter-spacing:.1em;margin:0">ALEK</p>
        <p style="font-size:.85rem;color:#7E879C;margin:.4rem 0 0">
           Inteligencia de superficie de ataque</p>
    </div>
    """, unsafe_allow_html=True)

    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD:
        st.error("Define DASHBOARD_USERNAME y DASHBOARD_PASSWORD en el fichero .env")
        return

    _, col, _ = st.columns([1, 1.4, 1])
    with col:
        with st.form("login_form"):
            usuario    = st.text_input("Usuario")
            contrasena = st.text_input("Contraseña", type="password")
            enviado    = st.form_submit_button("Acceder", use_container_width=True, type="primary")

    if enviado:
        if _credenciales_validas(usuario, contrasena):
            st.session_state["autenticado"] = True
            st.rerun()
        else:
            st.error("Usuario o contraseña incorrectos.")


if "autenticado" not in st.session_state:
    st.session_state["autenticado"] = False

if not st.session_state["autenticado"]:
    render_login()
    st.stop()

# A partir de aquí el usuario está autenticado
from recon.runner          import ejecutar_recon
from analyst.analyzer      import generar_informe
from threat_intel.analyzer import ejecutar_analisis_tip


st.markdown("""
<style>
.stApp { background-color: #0D1117; color: #E6EDF3; }
.header-box {
    background: linear-gradient(135deg, #0D1117, #161B22);
    border: 1px solid #1D9E75; border-radius: 12px;
    padding: 1.75rem 2rem; margin-bottom: 1.5rem;
}
.header-title { font-size:1.8rem; font-weight:700; color:#1D9E75; margin:0; }
.header-sub   { font-size:0.9rem; color:#8B949E; margin:0.3rem 0 0; }
.metric-card {
    background:#161B22; border:1px solid #21262D;
    border-radius:10px; padding:1.1rem 1.25rem; text-align:center;
}
.metric-label { font-size:0.7rem; color:#8B949E; text-transform:uppercase;
                letter-spacing:.08em; margin-bottom:.4rem; }
.metric-value { font-size:1.9rem; font-weight:700; margin:0; }
.finding-card {
    background:#161B22; border-radius:10px;
    padding:1rem 1.25rem; margin-bottom:.6rem; border-left:4px solid;
}
.finding-title   { font-size:.95rem; font-weight:600; margin-bottom:.4rem; }
.finding-section { font-size:.8rem; color:#8B949E; margin:.25rem 0 0; line-height:1.55; }
.finding-section strong { color:#C9D1D9; }
.sev-CRÍTICO, .sev-CRITICO { border-color:#DA3633; }
.sev-ALTO    { border-color:#D29922; }
.sev-MEDIO   { border-color:#388BFD; }
.sev-BAJO    { border-color:#3FB950; }
.sev-INFORMATIVO { border-color:#8B949E; }
.badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:600; }
.badge-CRÍTICO, .badge-CRITICO { background:#DA3633; color:#fff; }
.badge-ALTO    { background:#D29922; color:#000; }
.badge-MEDIO   { background:#388BFD; color:#fff; }
.badge-BAJO    { background:#3FB950; color:#000; }
.badge-INFORMATIVO { background:#8B949E; color:#fff; }
.info-box {
    background:#161B22; border:1px solid #21262D;
    border-radius:10px; padding:1.25rem 1.5rem;
    font-size:.875rem; line-height:1.8; color:#C9D1D9;
}
.rec-item {
    background:#161B22; border:1px solid #21262D; border-radius:8px;
    padding:.75rem 1rem; margin-bottom:.5rem;
    font-size:.875rem; color:#C9D1D9; line-height:1.5;
}
</style>
""", unsafe_allow_html=True)

# ── Helpers ───────────────────────────────────────────────────────────────

def color_nivel(nivel: str) -> str:
    return {"CRÍTICO":"#DA3633","ALTO":"#D29922",
            "MEDIO":"#388BFD","BAJO":"#3FB950"}.get(nivel.upper(), "#8B949E")

def color_puntuacion(p: int) -> str:
    if p >= 80: return "#3FB950"
    if p >= 60: return "#D29922"
    if p >= 40: return "#388BFD"
    return "#DA3633"

def gauge(puntuacion: int, nivel: str) -> go.Figure:
    color = color_puntuacion(puntuacion)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=puntuacion,
        number={"font":{"size":46,"color":color,"family":"monospace"},"suffix":"/100"},
        gauge={
            "axis":{"range":[0,100],"tickcolor":"#8B949E",
                    "tickfont":{"color":"#8B949E","size":11}},
            "bar":{"color":color,"thickness":0.25},
            "bgcolor":"#161B22","bordercolor":"#21262D",
            "steps":[
                {"range":[0,40],"color":"#180808"},
                {"range":[40,60],"color":"#181400"},
                {"range":[60,100],"color":"#081808"},
            ],
            "threshold":{"line":{"color":color,"width":3},
                         "thickness":0.8,"value":puntuacion}
        }
    ))
    fig.update_layout(paper_bgcolor="#0D1117", plot_bgcolor="#0D1117",
                      height=240, margin=dict(l=20,r=20,t=10,b=5))
    return fig

def bars_cabeceras(presentes, ausentes) -> go.Figure:
    items  = [(c["alias"],1,"#3FB950","✓ Configurada") for c in presentes] + \
             [(c["alias"],0,"#DA3633","✗ Ausente")     for c in ausentes]
    fig = go.Figure(go.Bar(
        x=[i[1] for i in items], y=[i[0] for i in items],
        orientation="h", marker_color=[i[2] for i in items],
        text=[i[3] for i in items], textposition="inside",
        textfont={"size":12,"color":"#fff"},
        hovertemplate="%{y}: %{text}<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor="#161B22", plot_bgcolor="#161B22",
        height=260, margin=dict(l=10,r=10,t=10,b=10),
        xaxis={"visible":False,"range":[0,1.4]},
        yaxis={"tickfont":{"color":"#C9D1D9","size":12},"gridcolor":"#21262D"},
        showlegend=False
    )
    return fig

def donut_severidades(hallazgos: list) -> go.Figure:
    conteo = {"CRÍTICO":0,"ALTO":0,"MEDIO":0,"BAJO":0,"INFORMATIVO":0}
    for h in hallazgos:
        sev = h.get("severidad","BAJO").upper()
        if sev in conteo: conteo[sev] += 1
    labels = [k for k,v in conteo.items() if v > 0]
    values = [conteo[k] for k in labels]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.6,
        marker_colors=[color_nivel(k) for k in labels],
        textinfo="label+value",
        textfont={"size":12,"color":"#E6EDF3"},
    ))
    fig.update_layout(
        paper_bgcolor="#161B22", plot_bgcolor="#161B22",
        height=240, margin=dict(l=10,r=10,t=10,b=10), showlegend=False
    )
    return fig

def render_hallazgo(h: dict):
    sev = h.get("severidad","BAJO").upper()
    st.markdown(f"""
    <div class="finding-card sev-{sev}">
        <div class="finding-title">
            <span class="badge badge-{sev}">{sev}</span>&nbsp;&nbsp;{h.get('titulo','')}
        </div>
        <div class="finding-section"><strong>Qué es:</strong> {h.get('que_es','')}</div>
        <div class="finding-section"><strong>Riesgo:</strong> {h.get('riesgo','')}</div>
        <div class="finding-section"><strong>Solución:</strong> {h.get('solucion','')}</div>
    </div>""", unsafe_allow_html=True)

# Bug 2 corregido: render_threat_intel definida ANTES de ser llamada
def render_threat_intel(ti: dict):
    """Renderiza la sección de inteligencia de amenazas."""
    if not ti or ti.get("error"):
        return

    nivel  = ti.get("nivel_amenaza", "BAJO")
    ip_rep = ti.get("ip_reputacion", {})
    cves   = ti.get("cves", {})

    st.markdown("---")
    st.markdown("### 🌐 Inteligencia de amenazas")
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
        color_rep = {"MALICIOSA":"#DA3633","SOSPECHOSA":"#D29922",
                     "LIMPIA":"#3FB950"}.get(rep,"#8B949E")
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Reputación IP</div>
            <div class="metric-value" style="color:{color_rep};font-size:1.2rem">{rep}</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        total_cves = cves.get("total",0)
        criticos   = cves.get("criticos",0)
        color_cve  = "#DA3633" if criticos > 0 else "#D29922" if total_cves > 0 else "#3FB950"
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">CVEs recientes</div>
            <div class="metric-value" style="color:{color_cve}">{total_cves}</div>
        </div>""", unsafe_allow_html=True)

    if cves.get("cves"):
        st.markdown("<br><b>Vulnerabilidades críticas del servidor</b>",
                    unsafe_allow_html=True)
        for cve in cves["cves"]:
            cvss = cve.get("cvss", 0)
            sev  = "CRÍTICO" if cvss >= 9 else "ALTO"
            st.markdown(f"""
            <div class="finding-card sev-{sev}">
                <div class="finding-title">
                    <span class="badge badge-{sev}">CVSS {cvss}</span>
                    &nbsp;&nbsp;{cve.get('id','')}
                    <span style="color:#8B949E;font-size:11px;margin-left:8px">
                        {cve.get('fecha','')}
                    </span>
                </div>
                <div class="finding-section">{cve.get('descripcion','')[:250]}</div>
            </div>""", unsafe_allow_html=True)

# ── Cabecera ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="header-box">
    <p class="header-title">🛡️ Recon Platform</p>
    <p class="header-sub">Análisis automatizado de superficie de ataque · Powered by Claude AI</p>
</div>
""", unsafe_allow_html=True)

# ── Input ─────────────────────────────────────────────────────────────────
c1, c2 = st.columns([5, 1])
with c1:
    dominio_input = st.text_input("Dominio", placeholder="elpais.com · incibe.es ...",
                                  label_visibility="collapsed")
with c2:
    analizar = st.button("🔍 Analizar", use_container_width=True, type="primary")

st.divider()

# ── Análisis ──────────────────────────────────────────────────────────────
if analizar and dominio_input:
    dominio = dominio_input.replace("https://","").replace("http://","").strip("/").strip().lower()

    with st.status(f"Analizando {dominio}...", expanded=True) as status:
        st.write("🔎 Recopilando datos de fuentes públicas...")
        datos = ejecutar_recon(dominio, verbose=False)

        st.write("🌐 Consultando inteligencia de amenazas...")
        ti = ejecutar_analisis_tip(dominio, datos, verbose=False)
        datos["threat_intel"] = ti

        st.write("🤖 Generando análisis con Claude AI...")
        resultado = generar_informe(dominio, datos, verbose=False)
        status.update(label="✅ Análisis completado", state="complete")

    st.session_state.update({
        "datos": datos, "resultado": resultado,
        "dominio": dominio, "threat_intel": ti
    })

# ── Dashboard ─────────────────────────────────────────────────────────────
if "datos" in st.session_state:
    datos     = st.session_state["datos"]
    resultado = st.session_state["resultado"]
    dominio   = st.session_state["dominio"]
    ti        = st.session_state.get("threat_intel", {})  # Bug 7: desde session_state

    analisis   = resultado.get("analisis") or {}
    headers    = datos.get("headers", {})
    puertos    = datos.get("puertos", {})
    subs       = datos.get("subdominios", {})
    filtr      = datos.get("filtraciones", {})
    riesgo_d   = datos.get("riesgo_global", {})

    hallazgos  = analisis.get("hallazgos", [])
    punt_ia    = analisis.get("puntuacion", {})
    puntuacion = punt_ia.get("valor", riesgo_d.get("puntuacion", 0))
    nivel      = punt_ia.get("nivel", riesgo_d.get("nivel", "—"))

    if resultado.get("error"):
        st.error(f"Error en análisis IA: {resultado['error']}")
        st.stop()

    st.markdown(f"### `{dominio}` — Análisis de superficie de ataque")

    # Métricas
    m1,m2,m3,m4,m5 = st.columns(5)
    metricas = [
        ("Puntuación", str(puntuacion), color_puntuacion(puntuacion)),
        ("Nivel",      nivel,           color_nivel(nivel)),
        ("Hallazgos",  str(len(hallazgos)), "#D29922"),
        ("Cabeceras ausentes", str(len(headers.get("ausentes",[]))), "#D29922"),
        ("Filtraciones", str(filtr.get("total",0)),
         "#DA3633" if filtr.get("total",0) > 0 else "#3FB950"),
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

    # Gráficos
    g1,g2,g3 = st.columns(3)
    with g1:
        st.markdown("**Puntuación global**")
        st.plotly_chart(gauge(puntuacion, nivel), use_container_width=True,
                        config={"displayModeBar":False})
    with g2:
        st.markdown("**Cabeceras HTTP**")
        presentes = headers.get("presentes",[])
        ausentes  = headers.get("ausentes", [])
        if presentes or ausentes:
            st.plotly_chart(bars_cabeceras(presentes,ausentes),
                            use_container_width=True, config={"displayModeBar":False})
        else:
            st.caption("Sin datos de cabeceras")
    with g3:
        st.markdown("**Hallazgos por severidad**")
        if hallazgos:
            st.plotly_chart(donut_severidades(hallazgos),
                            use_container_width=True, config={"displayModeBar":False})
        else:
            st.caption("Sin hallazgos")

    st.markdown("<br>", unsafe_allow_html=True)

    # Hallazgos + Info servidor
    col_hall, col_info = st.columns([3,2])
    with col_hall:
        st.markdown("**Hallazgos detectados**")
        if hallazgos:
            for h in hallazgos:
                render_hallazgo(h)
        else:
            st.success("No se detectaron hallazgos.")

    with col_info:
        st.markdown("**Información del servidor**")
        ips_str     = ", ".join(puertos.get("ips",[])) or "Sin datos"
        puertos_str = str(puertos.get("puertos_abiertos",[])) \
                      if puertos.get("puertos_abiertos") else "Sin datos"
        st.markdown(f"""<div class="info-box">
            <b>URL analizada</b><br>
            <span style="color:#8B949E">{headers.get('url_analizada', dominio)}</span><br><br>
            <b>Servidor revelado</b><br>
            <span style="color:#D29922">{headers.get('servidor','No revelado')}</span><br><br>
            <b>HTTPS activo</b><br>
            <span>{'✅ Sí' if headers.get('https') else '❌ No'}</span><br><br>
            <b>IPs detectadas</b><br>
            <span style="color:#8B949E">{ips_str}</span><br><br>
            <b>Puertos abiertos</b><br>
            <span style="color:#8B949E">{puertos_str}</span>
        </div>""", unsafe_allow_html=True)

        lista_subs = subs.get("subdominios",[])
        if lista_subs:
            st.markdown("<br><b>Subdominios activos</b>", unsafe_allow_html=True)
            for s in lista_subs[:8]:
                st.markdown(f"`{s}`")
            if len(lista_subs) > 8:
                st.caption(f"... y {len(lista_subs)-8} más")

    st.markdown("<br>", unsafe_allow_html=True)

    # Threat Intelligence — Bug 2 corregido: función ya definida arriba
    render_threat_intel(ti)

    st.markdown("<br>", unsafe_allow_html=True)

    # Recomendaciones
    recs  = analisis.get("recomendaciones",[])
    pasos = analisis.get("proximos_pasos",[])
    if recs or pasos:
        r1,r2 = st.columns(2)
        with r1:
            st.markdown("**Recomendaciones prioritarias**")
            for i,rec in enumerate(recs,1):
                st.markdown(f'<div class="rec-item">**{i}.** {rec}</div>',
                            unsafe_allow_html=True)
        with r2:
            st.markdown("**Próximos pasos**")
            for i,paso in enumerate(pasos,1):
                st.markdown(f'<div class="rec-item">**{i}.** {paso}</div>',
                            unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Exportar
    st.markdown("**Exportar**")
    e1,e2 = st.columns(2)
    with e1:
        json_export = json.dumps(
            {"dominio": dominio, "analisis": analisis,
             "threat_intel": ti, "datos_recon": datos},
            ensure_ascii=False, indent=2
        )
        st.download_button("⬇️ Descargar JSON completo", data=json_export,
                           file_name=f"recon_{dominio.replace('.','_')}.json",
                           mime="application/json", use_container_width=True)
    with e2:
        lineas = [f"INFORME — {dominio.upper()}", "="*55, "",
                  f"Puntuación: {puntuacion}/100 — {nivel}",
                  f"\nResumen: {resumen}\n",
                  "HALLAZGOS", "-"*40]
        for h in hallazgos:
            lineas += [f"\n[{h['severidad']}] {h['titulo']}",
                       f"Qué es: {h['que_es']}",
                       f"Riesgo: {h['riesgo']}",
                       f"Solución: {h['solucion']}"]
        if ti.get("resumen"):
            lineas += ["", "INTELIGENCIA DE AMENAZAS", "-"*40,
                       ti["resumen"]]
        for i,r in enumerate(recs,1):
            lineas.append(f"{i}. {r}")
        st.download_button("⬇️ Descargar informe .txt",
                           data="\n".join(lineas),
                           file_name=f"informe_{dominio.replace('.','_')}.txt",
                           mime="text/plain", use_container_width=True)

else:
    st.markdown("""
    <div style="text-align:center;padding:4rem 2rem;color:#8B949E">
        <div style="font-size:3.5rem;margin-bottom:1rem">🛡️</div>
        <div style="font-size:1.15rem;font-weight:500;color:#C9D1D9;margin-bottom:.5rem">
            Introduce un dominio y pulsa Analizar
        </div>
        <div style="font-size:.875rem">El análisis completo tarda entre 30 y 60 segundos</div>
    </div>""", unsafe_allow_html=True)
