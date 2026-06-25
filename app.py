import threading
import time
from typing import Dict, List

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from database import Database
from simulator import SimulationManager

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="RADIUS CPE Simulator",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
    .log-box {
        background: #0e1117;
        border: 1px solid #2d3548;
        border-radius: 8px;
        padding: 12px;
        max-height: 420px;
        overflow-y: auto;
        font-family: 'Courier New', monospace;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# ── Singletons ────────────────────────────────────────────────────────────────
db = Database()

if "mgr" not in st.session_state:
    st.session_state.mgr = SimulationManager(db)

mgr: SimulationManager = st.session_state.mgr

# ── Title ─────────────────────────────────────────────────────────────────────
st.title("RADIUS CPE Simulator")
st.caption("Simule autenticações RADIUS de CPEs reais através de proxies SOCKS5")

tabs = st.tabs([
    "Servidor RADIUS",
    "Proxies",
    "Simulações",
    "Dashboard",
])

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — RADIUS Server
# ═════════════════════════════════════════════════════════════════════════════
with tabs[0]:
    st.header("⚙️ Configuração do Servidor RADIUS")
    col_form, col_list = st.columns([1, 2], gap="large")

    with col_form:
        st.subheader("Novo Servidor")
        with st.form("frm_server", clear_on_submit=True):
            name     = st.text_input("Nome *", placeholder="Servidor Principal")
            ip       = st.text_input("IP *", placeholder="192.168.1.1")
            c1, c2   = st.columns(2)
            auth_p   = c1.number_input("Porta Auth", 1, 65535, 1812)
            acct_p   = c2.number_input("Porta Acct", 1, 65535, 1813)
            if st.form_submit_button("➕ Adicionar", width="stretch", type="primary"):
                if name and ip:
                    db.add_server(name, ip, int(auth_p), int(acct_p))
                    st.success(f"Servidor **{name}** adicionado!")
                    st.rerun()
                else:
                    st.error("Preencha nome e IP.")

    with col_list:
        st.subheader("Servidores Cadastrados")
        servers = db.get_servers()
        if servers:
            for s in servers:
                with st.container(border=True):
                    ci, cd = st.columns([5, 1])
                    with ci:
                        st.markdown(f"**{s['name']}**")
                        st.caption(
                            f"🌐 `{s['ip']}` &nbsp;|&nbsp; "
                            f"Auth: `{s['auth_port']}` &nbsp;|&nbsp; "
                            f"Acct: `{s['acct_port']}`"
                        )
                    with cd:
                        if st.button("🗑️", key=f"del_srv_{s['id']}"):
                            db.delete_server(s["id"])
                            st.rerun()
        else:
            st.info("Nenhum servidor cadastrado.")

# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — Proxies
# ═════════════════════════════════════════════════════════════════════════════
with tabs[1]:
    st.header("Gerenciamento de Proxies")

    # ── Controles superiores ──────────────────────────────────────────────────
    col_load, col_test, col_info = st.columns([1.5, 1.5, 1], gap="large")

    # ── Carregar lista ────────────────────────────────────────────────────────
    with col_load:
        st.subheader("Carregar Lista")
        url = st.text_input(
            "URL do JSON",
            value=(
                "https://raw.githubusercontent.com/"
                "ClearProxy/checked-proxy-list/main/socks5/json/all.json"
            ),
            key="proxy_url",
        )
        if st.button("Carregar Lista", width="stretch", type="primary"):
            with st.spinner("Baixando lista de proxies…"):
                try:
                    r = requests.get(url, timeout=30)
                    r.raise_for_status()
                    n = db.upsert_proxies(r.json())
                    st.success(f"{n} proxies carregados!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao carregar: {e}")

    # ── Testar proxies ────────────────────────────────────────────────────────
    with col_test:
        st.subheader("🔍 Testar Proxies")

        c_w, c_t = st.columns(2)
        max_workers = c_w.number_input(
            "Threads", min_value=5, max_value=200, value=50, step=5,
            help="Conexões simultâneas durante o teste",
        )
        test_timeout = c_t.number_input(
            "Timeout (s)", min_value=2, max_value=30, value=8,
            help="Tempo máximo de espera por proxy",
        )

        total_proxies = db.proxy_count()
        st.caption(f"**{total_proxies:,}** proxies disponíveis para teste")

        btn_test = st.button(
            "⚡ Testar Todos os Proxies",
            width="stretch",
            disabled=(total_proxies == 0),
            type="primary",
        )

    # ── Info / Limpar ─────────────────────────────────────────────────────────
    with col_info:
        st.subheader("Base de Dados")
        st.metric("Total de Proxies", f"{total_proxies:,}")
        st.caption("Países distintos")
        st.metric(
            label="Países",
            value=len(db.proxy_countries()),
        )
        if st.button("Limpar Todos", width="stretch"):
            db.clear_proxies()
            st.rerun()

    st.divider()

    # ── Execução do teste ─────────────────────────────────────────────────────
    if btn_test:
        from proxy_tester import test_single_proxy

        proxies_to_test = db.get_all_proxies()
        total = len(proxies_to_test)

        if not proxies_to_test:
            st.warning("Nenhum proxy para testar.")
        else:
            st.info(
                f"  Iniciando teste de **{total}** proxies  "
                f"({max_workers} threads | timeout {test_timeout}s)…"
            )

            # ── UI de progresso ───────────────────────────────────────────────
            prog_bar   = st.progress(0.0, text="Aguardando…")
            stat_cont  = st.container()

            with stat_cont:
                m1, m2, m3, m4 = st.columns(4)
                alive_ph   = m1.empty()
                dead_ph    = m2.empty()
                remain_ph  = m3.empty()
                speed_ph   = m4.empty()

            log_ph = st.empty()

            # ── Variáveis de controle ─────────────────────────────────────────
            alive_ids:   List[int]   = []
            dead_ids:    List[int]   = []
            latencies:   List[float] = []
            completed    = [0]
            lock         = threading.Lock()
            sem          = threading.Semaphore(int(max_workers))

            recent_logs: List[str] = []

            def _worker(proxy: Dict):
                with sem:
                    res = test_single_proxy(
                        proxy["ip"], proxy["port"], int(test_timeout))
                with lock:
                    if res["alive"]:
                        alive_ids.append(proxy["id"])
                        latencies.append(res["latency_ms"])
                        db.update_proxy_speed(proxy["id"], res["latency_ms"])
                        recent_logs.insert(
                            0,
                            f"{proxy['ip']}:{proxy['port']} "
                            f"— {res['latency_ms']} ms "
                            f"({proxy.get('country_code','??')})",
                        )
                    else:
                        dead_ids.append(proxy["id"])
                        recent_logs.insert(
                            0,
                            f"{proxy['ip']}:{proxy['port']} "
                            f"— {(res['error'] or 'timeout')[:60]}",
                        )
                    # mantém só os últimos 60 logs
                    if len(recent_logs) > 60:
                        recent_logs.pop()
                    completed[0] += 1

            threads = [
                threading.Thread(target=_worker, args=(p,), daemon=True)
                for p in proxies_to_test
            ]

            for t in threads:
                t.start()

            # ── Loop de atualização da UI ─────────────────────────────────────
            REFRESH_EVERY = max(1, total // 200)   # atualiza ~200 vezes no máximo

            while any(t.is_alive() for t in threads):
                done     = completed[0]
                n_alive  = len(alive_ids)
                n_dead   = len(dead_ids)
                n_remain = total - done
                avg_lat  = (
                    f"{sum(latencies)/len(latencies):.0f} ms"
                    if latencies else "—"
                )

                if done % REFRESH_EVERY == 0 or n_remain == 0:
                    pct  = done / total if total else 0
                    text = (
                        f"Testando… {done}/{total}  "
                        f"✅ {n_alive} ativos  ❌ {n_dead} inativos"
                    )
                    prog_bar.progress(min(pct, 1.0), text=text)
                    alive_ph.metric("✅ Ativos",    n_alive)
                    dead_ph.metric("❌ Inativos",  n_dead)
                    remain_ph.metric("⏳ Restantes", n_remain)
                    speed_ph.metric("⚡ Lat. Média", avg_lat)

                    # log box
                    lines = "".join(
                        f'<div style="margin-bottom:2px">{l}</div>'
                        for l in recent_logs[:30]
                    )
                    log_ph.markdown(
                        f'<div class="log-box">{lines}</div>',
                        unsafe_allow_html=True,
                    )

                time.sleep(0.3)

            # ── Finaliza ──────────────────────────────────────────────────────
            for t in threads:
                t.join()

            prog_bar.progress(1.0, text="✅ Teste concluído!")

            # Remove proxies inativos
            if dead_ids:
                db.delete_proxies_by_ids(dead_ids)

            avg_lat_final = (
                f"{sum(latencies)/len(latencies):.0f} ms"
                if latencies else "N/A"
            )

            st.success(
                f"🎉 Teste finalizado!  "
                f"**{len(alive_ids)}** ativos mantidos  |  "
                f"**{len(dead_ids)}** inativos removidos  |  "
                f"Latência média: **{avg_lat_final}**"
            )
            time.sleep(0.8)
            st.rerun()

    # ── Distribuição por país ─────────────────────────────────────────────────
    st.subheader("Distribuição por País")
    country_data = db.proxy_by_country()
    if country_data:
        df = pd.DataFrame(country_data)
        df.columns = ["País", "Código", "Quantidade"]

        c_chart, c_table = st.columns(2)
        with c_chart:
            fig = px.pie(
                df.head(15), values="Quantidade", names="País",
                title="Top 15 Países", hole=0.35,
                color_discrete_sequence=px.colors.qualitative.Set3,
            )
            fig.update_layout(
                height=380, showlegend=True,
                margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig, width="stretch")

        with c_table:
            st.dataframe(
                df, width="stretch",
                height=380, hide_index=True,
            )
    else:
        st.info("Carregue a lista de proxies primeiro.")

# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — Simulations
# ═════════════════════════════════════════════════════════════════════════════
with tabs[2]:
    st.header("  Gerenciamento de Simulações")

    servers = db.get_servers()
    if not servers:
        st.warning("⚠️ Cadastre um servidor RADIUS antes de criar simulações.")
    else:
        # ── New Simulation ────────────────────────────────────────────────────
        with st.expander("➕  Nova Simulação", expanded=False):
            with st.form("frm_sim", clear_on_submit=False):
                st.subheader("Configurar Simulação de CPEs")

                c1, c2 = st.columns(2, gap="large")

                with c1:
                    sim_name = st.text_input("Nome da Simulação *",
                                             placeholder="Teste Carga 01")
                    srv_map  = {f"{s['name']} ({s['ip']})": s["id"] for s in servers}
                    sel_srv  = st.selectbox("Servidor RADIUS *", list(srv_map))
                    secret   = st.text_input("Secret RADIUS *", type="password")
                    u_prefix = st.text_input(
                        "Prefixo de Usuário *", placeholder="testuser",
                        help="Gera: testuser_001, testuser_002 …"
                    )

                with c2:
                    interim  = st.number_input(
                        "Intervalo Interim-Update (s)", 30, 3600, 300,
                        help="Intervalo entre pacotes Accounting-Interim-Update"
                    )
                    use_term = st.checkbox("Definir tempo de encerramento automático")
                    term_time = None
                    if use_term:
                        term_time = st.number_input(
                            "Tempo de Encerramento (s)", 60, 86400, 3600)

                    st.markdown("##### Protocolos LCP (Access-Request)")
                    st.caption(
                        "Selecione um ou mais protocolos. Se mais de um for marcado, "
                        "cada CPE sorteia aleatoriamente qual usar."
                    )
                    lcp_pap      = st.checkbox("PAP",       value=True,  key="lcp_pap")
                    lcp_chap     = st.checkbox("CHAP",      value=False, key="lcp_chap")
                    lcp_mschapv2 = st.checkbox("MS-CHAPv2", value=False, key="lcp_mschapv2")
                    lcp_eap      = st.checkbox("EAP",       value=False, key="lcp_eap")

                    st.markdown("##### Seleção de Proxies (CPEs)")
                    countries = db.proxy_countries()
                    selected_countries = []
                    if countries:
                        selected_countries = st.multiselect(
                            "Filtrar por Países (Opcional)", countries,
                            help="Selecione países para filtrar a lista de proxies"
                        )
                    
                    proxies_list = db.get_proxies(selected_countries or None, limit=1000)
                    if proxies_list:
                        proxy_options = {
                            f"{p['ip']}:{p['port']} ({p['country_code'] or 'XX'} - {p['speed_ms'] or 0:.0f}ms)": p
                            for p in proxies_list
                        }
                        selected_labels = st.multiselect(
                            "Selecionar Proxies *",
                            options=list(proxy_options.keys()),
                            default=list(proxy_options.keys())[:10] if len(proxy_options) >= 10 else list(proxy_options.keys()),
                            help="Selecione os proxies individuais para simular como CPEs"
                        )
                        preview = [proxy_options[lbl] for lbl in selected_labels]
                        st.caption(f"🔍 {len(preview)} proxy(s) selecionado(s)")
                        
                        n_cpes = st.number_input(
                            "Quantidade de CPEs *",
                            min_value=1, max_value=1000,
                            value=10,
                            step=1,
                            help="Número total de CPEs a simular. Se maior que a quantidade de proxies, os proxies serão distribuídos aleatoriamente."
                        )
                    else:
                        st.warning("Nenhum proxy disponível. Carregue proxies na aba 'Proxies' primeiro.")
                        preview = []
                        n_cpes = 0

                submitted = st.form_submit_button(
                    "  Criar Simulação", width="stretch", type="primary")

                if submitted:
                    # --- Validação dos LCPs ---
                    selected_lcps = []
                    if lcp_pap:      selected_lcps.append("PAP")
                    if lcp_chap:     selected_lcps.append("CHAP")
                    if lcp_mschapv2: selected_lcps.append("MS-CHAPv2")
                    if lcp_eap:      selected_lcps.append("EAP")

                    if not all([sim_name, secret, u_prefix]):
                        st.error("Preencha todos os campos obrigatórios.")
                    elif not selected_lcps:
                        st.error("Selecione ao menos um protocolo LCP.")
                    elif not preview:
                        st.error("Nenhum proxy selecionado.")
                    elif n_cpes <= 0:
                        st.error("Quantidade de CPEs deve ser maior que zero.")
                    else:
                        sid = db.create_simulation(
                            sim_name, srv_map[sel_srv], secret,
                            int(interim),
                            int(term_time) if term_time else None,
                            ",".join(selected_lcps),
                        )
                        import secrets
                        import random
                        for i in range(n_cpes):
                            p = random.choice(preview)
                            cpe_password = secrets.token_urlsafe(8)
                            db.add_cpe(sid, p["ip"], p["port"],
                                       f"{u_prefix}_{i+1:03d}", cpe_password)
                        st.success(
                            f"✅ Simulação **{sim_name}** criada com "
                            f"{n_cpes} CPE(s) usando {len(preview)} proxy(s)! "
                            f"LCPs: **{', '.join(selected_lcps)}**"
                        )
                        time.sleep(0.4)
                        st.rerun()

        st.divider()
        st.subheader("Simulações Cadastradas")

        simulations = db.get_simulations()
        if not simulations:
            st.info("Nenhuma simulação cadastrada.")
        else:
            for sim in simulations:
                stats    = db.cpe_stats(sim["id"])
                running  = mgr.is_running(sim["id"])
                active_n = mgr.active_count(sim["id"])

                badge = {
                    "created":  "🟡",
                    "running":  "🟢",
                    "stopped":  "🔴",
                    "finished": "✅",
                }.get(sim["status"], "⚪")

                with st.container(border=True):
                    ci, cs1, cs2, cbt = st.columns([3, 1, 1, 2], gap="small")

                    with ci:
                        st.markdown(f"### {badge} {sim['name']}")
                        srv = db.get_server(sim["radius_server_id"])
                        lcp_display = sim.get("lcp_protocols") or "PAP"
                        st.caption(
                            f"**Servidor:** {srv['name']} ({srv['ip']})  |  "
                            f"**Interim:** {sim['interim_update_interval']}s  |  "
                            f"**LCPs:** {lcp_display}  |  "
                            f"**Encerramento:** "
                            f"{sim['termination_time']}s" if sim["termination_time"]
                            else "contínuo"
                        )

                    with cs1:
                        st.metric("CPEs", f"{active_n}/{stats.get('total', 0)}",
                                  delta="ativos" if active_n else None)
                    with cs2:
                        st.metric("Status", sim["status"].upper())

                    with cbt:
                        st.write("")  # spacing
                        if not running and sim["status"] != "finished":
                            if st.button("▶️ Iniciar", key=f"start_{sim['id']}",
                                         width="stretch", type="primary"):
                                mgr.start(sim["id"])
                                st.toast("Simulação iniciada!", icon="🚀")
                                time.sleep(0.5)
                                st.rerun()
                        if running:
                            if st.button("⏹️ Parar", key=f"stop_{sim['id']}",
                                         width="stretch"):
                                mgr.stop(sim["id"])
                                st.toast("Simulação parada.", icon="🛑")
                                time.sleep(0.5)
                                st.rerun()
                        if st.button("🗑️ Excluir", key=f"del_sim_{sim['id']}",
                                     width="stretch"):
                            mgr.stop(sim["id"])
                            db.delete_simulation(sim["id"])
                            st.rerun()

# ═════════════════════════════════════════════════════════════════════════════
# TAB 4 — Dashboard
# ═════════════════════════════════════════════════════════════════════════════
with tabs[3]:
    st.header("Dashboard")

    # Auto-refresh control
    c_ctrl, c_filter = st.columns([1, 3])
    with c_ctrl:
        auto_ref = st.checkbox("⟳ Auto-refresh (5s)")
        if auto_ref:
            st_autorefresh(interval=5000, key="dash_refresh")
        if st.button("🔄 Atualizar agora", width="stretch"):
            st.rerun()

    with c_filter:
        sims = db.get_simulations()
        sim_opts = {"— Todas —": None}
        sim_opts.update({s["name"]: s["id"] for s in sims})
        sel_name = st.selectbox("Filtrar por Simulação", list(sim_opts))
        sel_sid  = sim_opts[sel_name]

    # ── Metric cards ──────────────────────────────────────────────────────────
    gs = db.overall_stats(sel_sid)
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("🔵 Total",       gs.get("total",         0))
    m2.metric("🟢 Ativos",      gs.get("active",        0))
    m3.metric("✅ Finalizados", gs.get("finished",      0))
    m4.metric("❌ Falhas",      gs.get("failed",        0))
    m5.metric("🚫 Rejeitados",  gs.get("rejected",      0))

    st.divider()

    # ── CPE table + packet chart ──────────────────────────────────────────────
    col_tbl, col_chart = st.columns([3, 2], gap="large")

    with col_tbl:
        st.subheader("Status das Sessões")
        rows = db.cpe_details(sel_sid)
        if rows:
            df = pd.DataFrame(rows)
            icons = {
                "active": "🟢", "pending": "🟡", "authenticating": "🔵",
                "failed": "🔴", "rejected": "🚫", "finished": "✅",
            }
            df["status"] = df["status"].apply(lambda x: f"{icons.get(x,'⚪')} {x}")
            
            def format_bytes(b):
                if pd.isna(b) or b is None or b == 0:
                    return "0 B"
                b = float(b)
                for unit in ["B", "KB", "MB", "GB", "TB"]:
                    if b < 1024.0:
                        return f"{b:.1f} {unit}"
                    b /= 1024.0
                return f"{b:.1f} PB"

            df["upload"] = df["upload_bytes"].apply(format_bytes)
            df["download"] = df["download_bytes"].apply(format_bytes)

            display_cols = {
                "username":        "Usuário",
                "proxy_ip":        "Proxy / NAS-IP",
                "status":          "Status",
                "lcp_protocol":    "LCP",
                "session_id":      "Session-ID",
                "framed_ip":       "Framed-IP",
                "started_at":      "Início",
                "upload":          "Upload Acumulado",
                "download":        "Download Acumulado",
                "last_update_at":  "Último Update",
                "ended_at":        "Fim",
            }
            st.dataframe(
                df[[c for c in display_cols if c in df.columns]].rename(
                    columns=display_cols),
                use_container_width=True,
                height=380,
                hide_index=True,
                column_config={
                    "Usuário": st.column_config.TextColumn(width=140),
                    "Proxy / NAS-IP": st.column_config.TextColumn(width=160),
                    "Status": st.column_config.TextColumn(width=120),
                    "LCP": st.column_config.TextColumn(width=100),
                    "Session-ID": st.column_config.TextColumn(width=110),
                    "Framed-IP": st.column_config.TextColumn(width=130),
                    "Início": st.column_config.TextColumn(width=160),
                    "Upload Acumulado": st.column_config.TextColumn(width=140),
                    "Download Acumulado": st.column_config.TextColumn(width=140),
                    "Último Update": st.column_config.TextColumn(width=160),
                    "Fim": st.column_config.TextColumn(width=160),
                }
            )
        else:
            st.info("Nenhuma sessão registrada.")

    with col_chart:
        st.subheader("Pacotes RADIUS Enviados")
        pkt_data = db.packet_stats(sel_sid)
        if pkt_data:
            df_p = pd.DataFrame(pkt_data)
            df_p.columns = ["Tipo", "Quantidade"]
            color_map = {
                "Access-Request":     "#636EFA",
                "Access-Accept":      "#00CC96",
                "Access-Reject":      "#EF553B",
                "Accounting-Start":   "#AB63FA",
                "Accounting-Interim": "#FFA15A",
                "Accounting-Stop":    "#19D3F3",
                "Session-End":        "#FF6692",
            }
            fig = px.bar(
                df_p, x="Tipo", y="Quantidade",
                color="Tipo", color_discrete_map=color_map,
                title="Distribuição de Pacotes",
            )
            fig.update_layout(
                height=380, showlegend=False,
                margin=dict(t=40, b=40, l=0, r=0),
                xaxis_tickangle=-30,
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("Aguardando dados de pacotes…")

    st.divider()

    # ── Logs ──────────────────────────────────────────────────────────────────
    st.subheader("Logs em Tempo Real")

    lc1, lc2, lc3 = st.columns([2, 2, 1])
    with lc1:
        lvl_filter = st.selectbox("Nível", ["Todos", "INFO", "WARN", "ERROR"])
    with lc2:
        log_limit = st.select_slider("Últimas entradas",
                                     options=[50, 100, 200, 500, 1000], value=200)
    with lc3:
        st.write("")
        if st.button("🧹 Limpar Logs", width="stretch"):
            db.clear_logs(sel_sid)
            st.rerun()

    lvl = None if lvl_filter == "Todos" else lvl_filter
    logs = db.get_logs(sel_sid, lvl, log_limit)

    if logs:
        color_map_log = {"INFO": "#00d4aa", "WARN": "#ffaa00", "ERROR": "#ff4b4b"}
        icon_map_log  = {"INFO": "ℹ️",      "WARN": "⚠️",      "ERROR": "❌"}

        html = '<div class="log-box">'
        for log in logs:
            color = color_map_log.get(log["level"], "#aaaaaa")
            icon  = icon_map_log.get(log["level"],  "📝")
            ptype = f'<span style="color:#888;margin:0 6px">[{log["packet_type"]}]</span>' \
                    if log.get("packet_type") else ""
            html += (
                f'<div style="color:{color};margin-bottom:3px">'
                f'<span style="color:#555">{log["timestamp"]}</span> '
                f'{icon} {ptype}'
                f'<span style="color:#ccc">{log["message"]}</span>'
                f'</div>'
            )
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)
    else:
        st.info("Nenhum log encontrado para os filtros selecionados.")