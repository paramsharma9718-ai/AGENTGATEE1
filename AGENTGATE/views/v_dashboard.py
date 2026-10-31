"""Security Overview Dashboard View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
High-performance, dark-cybersecurity telemetry dashboard with Plotly charts and live metrics.
"""

import html as html_module
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from storage.approval_service import default_approval_service
from storage.document_service import default_document_service
from storage.hash_chain_audit import default_hash_chain_logger
from views.theme import (
    classification_badge,
    decision_badge,
    empty_state,
    integrity_banner,
    kpi_card,
    page_header,
    section_header,
    status_badge,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_dashboard(current_user: dict):
    # 1. Page Header
    page_header(
        icon="🛡️",
        title="Security Overview",
        subtitle="Real-time telemetry, authorization metrics, and cryptographic integrity from the AGENTGATE Security Gateway.",
    )

    # 2. Fetch live metrics from trusted services
    docs = default_document_service.list_documents()
    events = default_hash_chain_logger.get_events(limit=500)
    pending_count = default_approval_service.count_pending()
    integrity = default_hash_chain_logger.verify_chain_integrity()

    total_events = len(events)
    allowed_count = sum(1 for e in events if "ALLOW" in str(e["decision"]).upper())
    blocked_count = sum(1 for e in events if "BLOCK" in str(e["decision"]).upper())
    approval_count = sum(1 for e in events if "APPROVAL" in str(e["decision"]).upper())

    # 3. KPI Metrics Row (Responsive 5-card layout)
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(
            kpi_card(
                icon="⚡",
                label="Total Decisions",
                value=total_events,
                variant="purple",
                sub="Gateway evaluations",
                delay=1,
            ),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            kpi_card(
                icon="✓",
                label="Allowed Actions",
                value=allowed_count,
                variant="emerald",
                sub="Authorized operations",
                delay=2,
            ),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            kpi_card(
                icon="✕",
                label="Blocked Threats",
                value=blocked_count,
                variant="red",
                sub="Neutralized exploits",
                delay=3,
            ),
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            kpi_card(
                icon="⏳",
                label="Pending Review",
                value=pending_count,
                variant="amber",
                sub="Awaiting admin approval",
                delay=4,
            ),
            unsafe_allow_html=True,
        )
    with c5:
        st.markdown(
            kpi_card(
                icon="📁",
                label="Secure Documents",
                value=len(docs),
                variant="blue",
                sub="Registered in vault",
                delay=5,
            ),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # 4. Cryptographic Hash Chain Status
    head_hash = integrity.get("head_hash", "")
    short_hash = (head_hash[:20] + "...") if head_hash else "GENESIS"
    if integrity["is_valid"]:
        st.markdown(
            f"""
            <div class="ag-integrity-banner ag-integrity-ok">
                <div class="ag-integrity-icon">🔒</div>
                <div class="ag-integrity-text" style="flex:1;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4 style="color:#51FAAA; margin:0;">Cryptographic Hash Chain Intact</h4>
                        <span style="font-size:0.75rem; color:#777D9B; font-family:monospace;">HEAD: {short_hash}</span>
                    </div>
                    <p>All {integrity['total_events']} audit events mathematically verified via SHA-256 tamper-evident chaining. Zero modifications detected.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="ag-integrity-banner ag-integrity-fail">
                <div class="ag-integrity-icon">🚨</div>
                <div class="ag-integrity-text" style="flex:1;">
                    <h4 style="color:#FF6B6B; margin:0;">SECURITY ALERT: AUDIT TAMPERING DETECTED!</h4>
                    <p>{_esc(integrity['error_message'])}</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 5. Visualizations Row
    section_header("📊", "Security Intelligence & Operations Breakdown")
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown(
            """
            <div style="font-size:0.85rem; font-weight:600; color:#A6ABC5; margin-bottom:8px;">
                AUTHORIZATION DECISIONS DISTRIBUTION
            </div>
            """,
            unsafe_allow_html=True,
        )
        if total_events > 0:
            dec_data = pd.DataFrame([
                {"Decision": "ALLOW", "Count": allowed_count},
                {"Decision": "BLOCK", "Count": blocked_count},
                {"Decision": "REQUIRE APPROVAL", "Count": approval_count},
            ])
            dec_data = dec_data[dec_data["Count"] > 0]

            color_map = {
                "ALLOW": "#51FAAA",
                "BLOCK": "#FF6B6B",
                "REQUIRE APPROVAL": "#FFB347",
            }

            fig1 = px.pie(
                dec_data,
                values="Count",
                names="Decision",
                hole=0.68,
                color="Decision",
                color_discrete_map=color_map,
            )
            fig1.update_traces(
                textposition="inside",
                textinfo="percent+label",
                marker=dict(line=dict(color="#0C0E1D", width=2)),
                hoverinfo="label+value+percent",
            )
            fig1.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#E2E8F0", "family": "Inter, sans-serif"},
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.25,
                    xanchor="center",
                    x=0.5,
                    font=dict(size=11, color="#A6ABC5"),
                ),
                margin=dict(l=10, r=10, t=10, b=30),
                height=280,
                annotations=[
                    dict(
                        text=f"<b>{total_events}</b><br><span style='font-size:10px; color:#777D9B;'>TOTAL</span>",
                        x=0.5,
                        y=0.5,
                        font_size=18,
                        showarrow=False,
                        font_color="#EAECFF",
                    )
                ],
            )
            st.plotly_chart(fig1, use_container_width=True)
        else:
            empty_state("📊", "No Audit Events Recorded", "Execute actions in the AI Playground or Attack Simulator to generate telemetry.")

    with col_chart2:
        st.markdown(
            """
            <div style="font-size:0.85rem; font-weight:600; color:#A6ABC5; margin-bottom:8px;">
                OPERATIONS ACTIVITY DISTRIBUTION
            </div>
            """,
            unsafe_allow_html=True,
        )
        if total_events > 0:
            ops_counts = {}
            for e in events:
                op = e["operation"]
                ops_counts[op] = ops_counts.get(op, 0) + 1

            ops_df = pd.DataFrame(list(ops_counts.items()), columns=["Operation", "Count"])
            ops_df = ops_df.sort_values(by="Count", ascending=True)

            fig2 = px.bar(
                ops_df,
                x="Count",
                y="Operation",
                orientation="h",
                color="Operation",
                color_discrete_sequence=["#8B7CFF", "#51FAAA", "#60A5FA", "#FF81FF", "#FFB347"],
            )
            fig2.update_traces(
                marker=dict(line=dict(color="rgba(139, 124, 255, 0.2)", width=1)),
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#E2E8F0", "family": "Inter, sans-serif"},
                showlegend=False,
                margin=dict(l=10, r=10, t=10, b=20),
                height=280,
                xaxis=dict(
                    gridcolor="rgba(139, 124, 255, 0.08)",
                    zerolinecolor="rgba(139, 124, 255, 0.15)",
                    tickfont=dict(color="#777D9B"),
                ),
                yaxis=dict(
                    showgrid=False,
                    tickfont=dict(color="#A6ABC5", size=11),
                ),
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            empty_state("⚡", "No Operations Recorded", "No tool or gateway operations have been evaluated yet.")

    # 6. Real-Time Security Activity Feed
    section_header("📡", "Real-Time Security Activity Stream")
    recent = events[:10]
    if recent:
        feed_rows = []
        for r in recent:
            feed_rows.append({
                "Timestamp": r["timestamp"][:19].replace("T", " "),
                "User ID": r["user_id"],
                "Operation": r["operation"],
                "Resource": r["resource_id"],
                "Decision": r["decision"],
                "Risk Level": r["risk_level"],
                "Status": r["status"],
                "SHA-256 Digest": (r.get("event_hash") or "N/A")[:18] + "...",
            })
        st.dataframe(pd.DataFrame(feed_rows), use_container_width=True, hide_index=True)
    else:
        empty_state("📡", "No Activity Records Available", "Historical audit entries will appear here in real-time as actions occur.")
