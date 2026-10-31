"""Security Overview Dashboard View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from storage.approval_service import default_approval_service
from storage.document_service import default_document_service
from storage.hash_chain_audit import default_hash_chain_logger
from views.theme import classification_badge, decision_badge


def render_dashboard(current_user: dict):
    # Page Header
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">🛡️ Security Overview Dashboard</div>
            <div class="ag-section-subtext">Real-time telemetry and monitoring from the AGENTGATE Independent Security Gateway.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Fetch live metrics
    docs = default_document_service.list_documents()
    events = default_hash_chain_logger.get_events(limit=500)
    pending_count = default_approval_service.count_pending()
    integrity = default_hash_chain_logger.verify_chain_integrity()

    total_events = len(events)
    allowed_count = sum(1 for e in events if "ALLOW" in e["decision"])
    blocked_count = sum(1 for e in events if "BLOCK" in e["decision"])
    approval_count = sum(1 for e in events if "APPROVAL" in e["decision"])

    # 2. Key Metrics Row — Glass stat cards via HTML
    st.markdown(
        f"""
        <div class="ag-fade-in" style="display:grid; grid-template-columns: repeat(5, 1fr); gap:14px; margin-bottom:24px;">
            <div class="ag-stat-card">
                <div class="ag-stat-value">{len(docs)}</div>
                <div class="ag-stat-label">📄 Documents</div>
            </div>
            <div class="ag-stat-card">
                <div class="ag-stat-value">{total_events}</div>
                <div class="ag-stat-label">⚡ Decisions</div>
            </div>
            <div class="ag-stat-card">
                <div class="ag-stat-value">{allowed_count}</div>
                <div class="ag-stat-label">✅ Allowed</div>
            </div>
            <div class="ag-stat-card">
                <div class="ag-stat-value">{blocked_count}</div>
                <div class="ag-stat-label">🚫 Blocked</div>
            </div>
            <div class="ag-stat-card">
                <div class="ag-stat-value">{pending_count}</div>
                <div class="ag-stat-label">⏳ Pending</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # 3. Cryptographic Chain Status Banner — Glass card
    if integrity["is_valid"]:
        st.markdown(
            f"""
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-green">
                    <div style="display:flex; align-items:center; gap:12px; margin-bottom:8px;">
                        <span class="ag-status-dot ag-status-dot-green"></span>
                        <span style="font-size:1.1rem; font-weight:700; color:#10B981;">Cryptographic Hash Chain Intact</span>
                    </div>
                    <p style="color:#CBD5E1; margin:0; font-size:0.92rem;">All <strong style="color:#FFFFFF;">{integrity['total_events']}</strong> audit events verified via SHA-256 tamper-evident chaining. Zero tampering detected.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-red">
                    <div style="display:flex; align-items:center; gap:12px; margin-bottom:8px;">
                        <span class="ag-status-dot ag-status-dot-red"></span>
                        <span style="font-size:1.1rem; font-weight:700; color:#EF4444;">🚨 SECURITY ALERT: AUDIT TAMPERING DETECTED!</span>
                    </div>
                    <p style="color:#F87171; margin:0;">{integrity['error_message']}</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 4. Visualizations Row — Glass card wrappers
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown(
            '<div class="ag-fade-in"><div class="ag-card" style="padding:16px;">',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<h4 style="margin:0 0 8px 0; font-size:1rem; color:#E2E8F0;">📊 Authorization Decisions</h4>',
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
                "ALLOW": "#10B981",
                "BLOCK": "#EF4444",
                "REQUIRE APPROVAL": "#F59E0B",
            }

            fig1 = px.pie(
                dec_data,
                values="Count",
                names="Decision",
                hole=0.6,
                color="Decision",
                color_discrete_map=color_map,
            )
            fig1.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#E2E8F0"},
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                margin=dict(l=20, r=20, t=20, b=20),
            )
            st.plotly_chart(fig1, width="stretch")
        else:
            st.info("No audit events recorded yet.")
        st.markdown("</div></div>", unsafe_allow_html=True)

    with col_chart2:
        st.markdown(
            '<div class="ag-fade-in"><div class="ag-card" style="padding:16px;">',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<h4 style="margin:0 0 8px 0; font-size:1rem; color:#E2E8F0;">⚡ Operations Breakdown</h4>',
            unsafe_allow_html=True,
        )
        if total_events > 0:
            ops_counts = {}
            for e in events:
                op = e["operation"]
                ops_counts[op] = ops_counts.get(op, 0) + 1

            ops_df = pd.DataFrame(list(ops_counts.items()), columns=["Operation", "Count"])
            fig2 = px.bar(
                ops_df,
                x="Operation",
                y="Count",
                color="Operation",
                color_discrete_sequence=["#3B82F6", "#8B5CF6", "#EC4899", "#10B981"],
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#E2E8F0"},
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=20),
            )
            st.plotly_chart(fig2, width="stretch")
        else:
            st.info("No operation activity recorded yet.")
        st.markdown("</div></div>", unsafe_allow_html=True)

    st.markdown("---")

    # 5. Live Activity Stream (Recent Events)
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-card" style="padding:18px 22px 10px 22px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span class="ag-status-dot ag-status-dot-green"></span>
                    <span style="font-size:1.05rem; font-weight:700; color:#E2E8F0;">📡 Real-Time Security Activity Feed</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    recent = events[:8]
    if recent:
        feed_rows = []
        for r in recent:
            feed_rows.append({
                "Timestamp": r["timestamp"][:19].replace("T", " "),
                "User": r["user_id"],
                "Operation": r["operation"],
                "Resource": r["resource_id"],
                "Decision": r["decision"],
                "Risk": r["risk_level"],
                "Status": r["status"],
                "Event Hash": (r.get("event_hash") or "N/A")[:16] + "...",
            })
        st.dataframe(pd.DataFrame(feed_rows), width="stretch", hide_index=True)
    else:
        st.write("No recent security events.")
