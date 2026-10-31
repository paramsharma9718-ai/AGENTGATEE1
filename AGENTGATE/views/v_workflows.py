"""Workflow Manager View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Persistent multi-step AI agent pipelines backed by SQLite with stateful gateway authorization.
"""

import html as html_module
import json
from pathlib import Path
import sqlite3
import pandas as pd
import streamlit as st

from agent.action_proposer import ActionProposer
from agent.workflow_manager import default_workflow_manager
from storage.audit_logger import default_audit_logger
from views.theme import (
    decision_badge,
    empty_state,
    kpi_card,
    page_header,
    section_header,
    status_badge,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_workflows(current_user: dict):
    # 1. Page Header
    page_header(
        icon="🔄",
        title="Multi-Step Workflow Manager",
        subtitle="Construct, persist, and orchestrate resilient multi-step AI agent execution pipelines backed by SQLite with stateful gateway authorization re-evaluated at every step.",
    )

    db_path = Path(__file__).resolve().parent.parent / "data" / "agentgate.db"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM workflows ORDER BY updated_at DESC").fetchall()

    total_wf = len(rows)
    completed_wf = sum(1 for r in rows if r["status"] == "COMPLETED")
    suspended_wf = sum(1 for r in rows if r["status"] == "SUSPENDED")

    # 2. Pipeline KPIs
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(kpi_card("🔄", "Total Pipelines", total_wf, "purple", "Persisted in SQLite", delay=1), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("✓", "Completed", completed_wf, "emerald", "Successfully executed", delay=2), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card("⏸️", "Suspended / Held", suspended_wf, "amber", "Awaiting resumption", delay=3), unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    tab_create, tab_manage = st.tabs(["⚡ Pipeline Designer & Execution", "📋 Persisted Pipelines Ledger"])

    # -------------------------------------------------------------
    # TAB 1: PIPELINE DESIGNER
    # -------------------------------------------------------------
    with tab_create:
        section_header("⚡", "Multi-Step Autonomous Tool Pipeline")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.88rem;'>Compose and execute chained operations across protected tools. "
            "The Execution Gateway inspects permissions independently before every individual step:</p>",
            unsafe_allow_html=True,
        )

        # Visual Pipeline Architecture
        st.markdown(
            """
            <div style="
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
                padding: 18px 24px;
                background: linear-gradient(135deg, rgba(25,27,50,0.85) 0%, rgba(17,20,38,0.7) 100%);
                border: 1px solid rgba(139,124,255,0.15);
                border-radius: 14px;
                margin-bottom: 20px;
                overflow-x: auto;
            ">
                <div style="flex:1; text-align:center; padding:10px; background:rgba(96,165,250,0.06); border:1px solid rgba(96,165,250,0.2); border-radius:10px;">
                    <div style="font-size:1.3rem; margin-bottom:4px;">📖</div>
                    <div style="font-size:0.75rem; color:#60A5FA; font-weight:700;">STEP 1: INGESTION</div>
                    <div style="font-size:0.85rem; color:#F5F6FF; font-weight:600;">Read DOC-001</div>
                    <div style="font-size:0.7rem; color:#777D9B;">Clearance: PUBLIC</div>
                </div>
                <div style="color:#8B7CFF; font-size:1.4rem; font-weight:bold;">→</div>
                <div style="flex:1; text-align:center; padding:10px; background:rgba(139,124,255,0.06); border:1px solid rgba(139,124,255,0.2); border-radius:10px;">
                    <div style="font-size:1.3rem; margin-bottom:4px;">📊</div>
                    <div style="font-size:0.75rem; color:#A78BFA; font-weight:700;">STEP 2: SYNTHESIS</div>
                    <div style="font-size:0.85rem; color:#F5F6FF; font-weight:600;">Save Derived Report</div>
                    <div style="font-size:0.7rem; color:#777D9B;">Label Inheritance Applied</div>
                </div>
                <div style="color:#8B7CFF; font-size:1.4rem; font-weight:bold;">→</div>
                <div style="flex:1; text-align:center; padding:10px; background:rgba(81,250,170,0.06); border:1px solid rgba(81,250,170,0.2); border-radius:10px;">
                    <div style="font-size:1.3rem; margin-bottom:4px;">📬</div>
                    <div style="font-size:0.75rem; color:#51FAAA; font-weight:700;">STEP 3: DISPATCH</div>
                    <div style="font-size:0.85rem; color:#F5F6FF; font-weight:600;">Deliver to Recipient</div>
                    <div style="font-size:0.7rem; color:#777D9B;">Whitelist Policy Check</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_exec, col_sus = st.columns(2)

        with col_exec:
            if st.button("🚀 Create & Execute Pipeline Now", use_container_width=True):
                with st.spinner("Submitting multi-step pipeline through ExecutionGateway..."):
                    p1 = ActionProposer.propose_read(current_user["user_id"], "DOC-001")
                    p2 = ActionProposer.propose_save_report(
                        current_user["user_id"],
                        f"WF-REP-{pd.Timestamp.now().strftime('%M%S')}",
                        "Automated Pipeline Summary",
                        "Summary content derived from DOC-001",
                        ["DOC-001"],
                    )
                    p3 = ActionProposer.propose_send_report(
                        current_user["user_id"],
                        p2.resource_id,
                        "USER-101",
                    )

                    wf = default_workflow_manager.create_workflow(current_user["user_id"], [p1, p2, p3])
                    res_wf = default_workflow_manager.resume_workflow(wf.workflow_id)

                st.markdown(
                    f"""
                    <div class="ag-card ag-card-glow-green" style="margin-top:14px;">
                        <h4 style="color:#51FAAA; margin:0 0 6px 0;">✓ Pipeline Completed Successfully</h4>
                        <div style="font-size:0.85rem; color:#A6ABC5;">
                            <b>Pipeline ID:</b> <code>{_esc(res_wf.workflow_id)}</code> &nbsp;|&nbsp;
                            <b>Status:</b> <span style="color:#51FAAA; font-weight:bold;">{_esc(res_wf.status.value)}</span> &nbsp;|&nbsp;
                            <b>Steps Completed:</b> {res_wf.current_step_index} of {len(res_wf.steps)}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.rerun()

        with col_sus:
            if st.button("⏸️ Create & Suspend (Simulate Failure / Restart)", use_container_width=True):
                p1 = ActionProposer.propose_read(current_user["user_id"], "DOC-001")
                p2 = ActionProposer.propose_save_report(
                    current_user["user_id"],
                    f"WF-SUS-{pd.Timestamp.now().strftime('%M%S')}",
                    "Suspended Pipeline Report",
                    "Content before suspension",
                    ["DOC-001"],
                )
                p3 = ActionProposer.propose_send_report(
                    current_user["user_id"],
                    p2.resource_id,
                    "USER-101",
                )

                wf = default_workflow_manager.create_workflow(current_user["user_id"], [p1, p2, p3])
                default_workflow_manager.suspend_workflow(wf.workflow_id)

                st.markdown(
                    f"""
                    <div class="ag-card ag-card-glow-amber" style="margin-top:14px;">
                        <h4 style="color:#FFB347; margin:0 0 6px 0;">⏸️ Pipeline Suspended & Persisted</h4>
                        <div style="font-size:0.85rem; color:#A6ABC5;">
                            Pipeline <code>{_esc(wf.workflow_id)}</code> paused at step 0. State safely serialized in SQLite.
                            Go to the 'Persisted Pipelines Ledger' tab to resume execution.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.rerun()

    # -------------------------------------------------------------
    # TAB 2: PERSISTED WORKFLOWS LEDGER
    # -------------------------------------------------------------
    with tab_manage:
        section_header("📋", "Persisted SQLite Workflow Ledger")

        if not rows:
            empty_state("🔄", "No Persisted Workflows", "Create and run a pipeline to view state history.")
            return

        w_table = []
        for r in rows:
            w_table.append({
                "Pipeline ID": r["workflow_id"],
                "Owner": r["user_id"],
                "Status": r["status"],
                "Completed Steps": r["current_step_index"],
                "Last Updated": r["updated_at"][:19].replace("T", " "),
            })
        st.dataframe(pd.DataFrame(w_table), use_container_width=True, hide_index=True)

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        section_header("⏯️", "Resume Suspended Pipeline")

        wf_ids = [r["workflow_id"] for r in rows if r["status"] == "SUSPENDED"]
        if wf_ids:
            sel_wf = st.selectbox("Select Suspended Pipeline to Resume:", wf_ids)
            if st.button(f"▶️ Resume Execution for '{sel_wf}'", use_container_width=True):
                with st.spinner("Resuming workflow and re-evaluating security policies at each step..."):
                    resumed = default_workflow_manager.resume_workflow(sel_wf)

                st.success(f"✓ Pipeline `{sel_wf}` resumed! Current Status: `{resumed.status.value}`")
                st.rerun()
        else:
            st.info("No workflows are currently in SUSPENDED state.")
