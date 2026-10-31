"""Workflow Manager View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import json
import sqlite3
from pathlib import Path
import pandas as pd
import streamlit as st

from agent.action_proposer import ActionProposer
from agent.workflow_manager import default_workflow_manager
from storage.audit_logger import default_audit_logger
from views.theme import decision_badge


def render_workflows(current_user: dict):
    # Page Header with animated entrance
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">🔄 Multi-Step Workflow Manager</div>
            <div class="ag-section-subtext">Persistent multi-step AI Agent execution pipelines backed by SQLite with checkpointing and atomic policy re-validation.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_create, tab_manage = st.tabs(["⚡ Create & Run Pipeline", "📋 Persisted Workflows"])

    with tab_create:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 8px 0; color: #60A5FA;">🚀 Multi-Step Agent Execution Pipeline</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        This test pipeline chains 3 sequential operations through the <strong>ExecutionGateway</strong>.
                        Every step must satisfy policy validation independently. If suspended mid-pipeline, state is checkpointed in SQLite.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Visual pipeline flow cards
        st.markdown(
            """
            <div class="ag-fade-in" style="display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 12px; align-items: center; margin-bottom: 24px;">
                <div class="ag-card" style="padding: 16px; margin: 0; border-top: 3px solid #3B82F6;">
                    <div style="font-size: 0.75rem; color: #60A5FA; font-weight: 700; text-transform: uppercase;">Step 01 &bull; Read</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC; margin: 4px 0;">DOC-001</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">Target: PUBLIC document</div>
                    <span class="ag-badge ag-badge-public" style="margin-top: 8px;">PUBLIC</span>
                </div>
                <div class="ag-pipeline-arrow">➔</div>
                <div class="ag-card" style="padding: 16px; margin: 0; border-top: 3px solid #8B5CF6;">
                    <div style="font-size: 0.75rem; color: #A78BFA; font-weight: 700; text-transform: uppercase;">Step 02 &bull; Generate</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC; margin: 4px 0;">WF-REP-AUTO</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">Derived analytics report</div>
                    <span class="ag-badge ag-badge-internal" style="margin-top: 8px;">SAVE_REPORT</span>
                </div>
                <div class="ag-pipeline-arrow">➔</div>
                <div class="ag-card" style="padding: 16px; margin: 0; border-top: 3px solid #10B981;">
                    <div style="font-size: 0.75rem; color: #34D399; font-weight: 700; text-transform: uppercase;">Step 03 &bull; Deliver</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC; margin: 4px 0;">USER-101</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">Recipient: Cleared User</div>
                    <span class="ag-badge ag-badge-allow" style="margin-top: 8px;">SEND_REPORT</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_exec, col_sus = st.columns(2)

        with col_exec:
            if st.button("🚀 Create & Execute Pipeline Now", width="stretch"):
                with st.spinner("Executing pipeline through ExecutionGateway..."):
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
                    <div class="ag-fade-in" style="margin-top: 16px;">
                        <div class="ag-card ag-card-glow-green">
                            <h4 style="color:#10B981; margin:0 0 8px 0;">✅ Pipeline Successfully Executed</h4>
                            <p style="margin: 0; color: #E2E8F0;">
                                <strong>Workflow ID:</strong> <code>{res_wf.workflow_id}</code> &nbsp;|&nbsp;
                                <strong>Status:</strong> <span class="ag-badge ag-badge-allow">{res_wf.status.value}</span> &nbsp;|&nbsp;
                                <strong>Completed Steps:</strong> {res_wf.current_step_index} of {len(res_wf.steps)}
                            </p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.rerun()

        with col_sus:
            if st.button("⏸️ Create & Suspend (Test Checkpoint & Resume)", width="stretch"):
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
                    <div class="ag-fade-in" style="margin-top: 16px;">
                        <div class="ag-card ag-card-glow-amber">
                            <h4 style="color:#F59E0B; margin:0 0 8px 0;">⏸️ Workflow State Suspended</h4>
                            <p style="margin: 0; color: #E2E8F0;">
                                Workflow <code>{wf.workflow_id}</code> checkpointed at step 0 in SQLite.
                                Switch to the <strong>Persisted Workflows</strong> tab to inspect and resume it.
                            </p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.rerun()

    with tab_manage:
        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <h4 style="color: #F8FAFC; margin: 0 0 4px 0;">Persisted SQLite Pipeline Registry</h4>
                <p style="color: #CBD5E1; font-size: 0.85rem; margin: 0;">State checkpoints loaded directly from local SQLite database.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        db_path = Path(__file__).resolve().parent.parent / "data" / "agentgate.db"
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM workflows ORDER BY updated_at DESC").fetchall()

        if not rows:
            st.info("No workflows found in database.")
            return

        w_table = []
        for r in rows:
            w_table.append({
                "Workflow ID": r["workflow_id"],
                "Owner": r["user_id"],
                "Status": r["status"],
                "Current Step": r["current_step_index"],
                "Updated At": r["updated_at"][:19].replace("T", " "),
            })

        st.dataframe(pd.DataFrame(w_table), width="stretch", hide_index=True)

        st.markdown("---")

        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 12px;">
                <h4 style="color: #60A5FA; margin: 0 0 4px 0;">⏯️ Resume Suspended Workflow</h4>
                <p style="color: #CBD5E1; font-size: 0.85rem; margin: 0;">Re-evaluates security policies at each step upon resumption to guarantee no temporal policy bypass.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        wf_ids = [r["workflow_id"] for r in rows if r["status"] == "SUSPENDED"]
        if wf_ids:
            sel_wf = st.selectbox("Select Suspended Workflow to Resume:", wf_ids)
            if st.button(f"▶️ Resume Workflow '{sel_wf}'", width="stretch"):
                with st.spinner("Resuming workflow and re-evaluating security policies at each step..."):
                    resumed = default_workflow_manager.resume_workflow(sel_wf)

                st.markdown(
                    f"""
                    <div class="ag-fade-in">
                        <div class="ag-card ag-card-glow-green">
                            <h4 style="color:#10B981; margin:0 0 6px 0;">✅ Workflow Resumed & Completed</h4>
                            <p style="margin: 0; color: #E2E8F0;">
                                Workflow <code>{sel_wf}</code> transitioned to <span class="ag-badge ag-badge-allow">{resumed.status.value}</span>.
                            </p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.rerun()
        else:
            st.markdown(
                """
                <div class="ag-card" style="padding: 14px; text-align: center; color: #CBD5E1;">
                    No workflows are currently in <code>SUSPENDED</code> state.
                </div>
                """,
                unsafe_allow_html=True,
            )
