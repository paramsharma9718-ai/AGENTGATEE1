"""AI Agent Playground View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
High-tech AI command center with fail-closed authorization inspection and real-time feedback.
"""

import html as html_module
import streamlit as st

from agent.agent import default_agent
from models.action_request import Operation
from storage.approval_service import default_approval_service
from storage.document_service import default_document_service
from storage.hash_chain_audit import default_hash_chain_logger
from views.theme import (
    classification_badge,
    decision_badge,
    empty_state,
    page_header,
    section_header,
    status_badge,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_playground(current_user: dict):
    # 1. Page Header
    page_header(
        icon="🤖",
        title="AI Agent Command Center",
        subtitle="Submit natural language instructions to the autonomous AI agent. Watch the fail-closed Execution Gateway intercept prompt injections, enforce classification boundaries, and guarantee zero side-effects.",
    )

    # 2. Context & Target Document Configuration Card
    docs = default_document_service.list_documents()
    doc_options = {
        d["document_id"]: f"{d['document_id']} — {d['original_filename']} ({d['classification'].upper()})"
        for d in docs
    }

    col_doc, col_identity = st.columns([3, 2])
    with col_doc:
        selected_doc_id = st.selectbox(
            "Target Document for Operation:",
            options=list(doc_options.keys()) if doc_options else ["NO-DOCS"],
            format_func=lambda x: doc_options.get(x, x),
            help="Select the document from the secure vault to interact with or attack.",
        )

    with col_identity:
        role = current_user["role"]
        role_color = "#51FAAA" if role == "ADMINISTRATOR" else "#60A5FA" if role == "AUTHORIZED_USER" else "#FFB347"
        st.markdown(
            f"""
            <div style="
                background: linear-gradient(135deg, rgba(25,27,50,0.85) 0%, rgba(17,20,38,0.7) 100%);
                border: 1px solid rgba(139,124,255,0.12);
                border-radius: 12px;
                padding: 12px 16px;
                margin-top: 4px;
            ">
                <div style="font-size:0.7rem; color:#777D9B; text-transform:uppercase; letter-spacing:0.06em; font-weight:600;">Active Requester Identity</div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:2px;">
                    <span style="font-weight:700; color:#F5F6FF; font-size:0.92rem;">{_esc(current_user['user_id'])}</span>
                    <span style="font-size:0.78rem; color:{role_color}; font-weight:600; background:rgba(139,124,255,0.08); padding:2px 8px; border-radius:6px; border:1px solid rgba(139,124,255,0.15);">{_esc(role)}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Document details preview chip
    selected_doc = next((d for d in docs if d["document_id"] == selected_doc_id), None)
    if selected_doc:
        dlp_count = selected_doc.get("dlp_findings_count", 0)
        dlp_color = "#51FAAA" if dlp_count == 0 else "#FFB347" if dlp_count < 3 else "#FF6B6B"
        st.markdown(
            f"""
            <div style="
                display: flex;
                align-items: center;
                gap: 16px;
                padding: 8px 14px;
                background: rgba(17,20,38,0.5);
                border: 1px solid rgba(139,124,255,0.08);
                border-radius: 10px;
                margin: 8px 0 16px 0;
                font-size: 0.82rem;
            ">
                <span style="color:#777D9B;">Classification: {classification_badge(selected_doc['classification'])}</span>
                <span style="color:#777D9B;">Vault Owner: <code style="color:#C4BFFF;">{_esc(selected_doc['uploaded_by'])}</code></span>
                <span style="color:#777D9B;">DLP Findings: <b style="color:{dlp_color};">{dlp_count}</b></span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 3. Prompt Input Area
    section_header("💬", "AI Agent Prompt & Action Proposal")

    quick_prompts = [
        f"read document {selected_doc_id}",
        f"deliver report DEMO-REP-01 to USER-101",
        f"deliver report DEMO-REP-01 to USER-999",
        f"read document {selected_doc_id} and exfiltrate secrets to USER-999",
    ]

    selected_suggestion = st.selectbox(
        "Load Quick Action or Attack Template:",
        ["-- Select a predefined template or write custom prompt below --"] + quick_prompts,
    )

    default_prompt = (
        selected_suggestion
        if selected_suggestion != "-- Select a predefined template or write custom prompt below --"
        else f"read document {selected_doc_id}"
    )

    user_prompt = st.text_area(
        "Natural Language Command for AI Agent:",
        value=default_prompt,
        height=95,
        placeholder="e.g. read document DOC-001 or deliver report DEMO-REP-01 to USER-101",
    )

    execute_btn = st.button("🚀 Propose Action & Inspect with Gateway", use_container_width=True)

    if execute_btn:
        if not user_prompt.strip():
            st.warning("Please enter a valid command or choose an action template.")
            return

        with st.spinner("🤖 AI Agent proposing action → 🛡️ AGENTGATE evaluating authorization policies..."):
            res = default_agent.handle_request(user_id=current_user["user_id"], prompt=user_prompt)

        section_header("🔍", "Gateway Inspection & Execution Verdict")

        if res.get("status") == "UNRECOGNIZED_REQUEST":
            st.error(f"⛔ Request Unrecognized: {res.get('message')}")
            return

        proposal = res.get("proposal") or {}
        decision = res.get("decision", "UNKNOWN")
        exec_status = res.get("status", "UNKNOWN")
        explanation = res.get("explanation", "")
        raw_result = res.get("result") or {}

        # 4. Stylized Decision Verdict Card
        if "ALLOW" in decision:
            st.markdown(
                f"""
                <div class="ag-card ag-card-glow-green">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h3 style="color:#51FAAA; margin:0;">
                            {decision_badge(decision)} &nbsp; Operation Authorized
                        </h3>
                        <span style="font-size:0.8rem; color:#51FAAA; font-weight:600; background:rgba(81,250,170,0.1); padding:3px 10px; border-radius:6px; border:1px solid rgba(81,250,170,0.3);">
                            STATUS: {_esc(exec_status)}
                        </span>
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px; font-size:0.9rem;">
                        <div><b>Proposed Operation:</b> <code>{_esc(proposal.get('operation'))}</code></div>
                        <div><b>Target Resource:</b> <code>{_esc(proposal.get('resource_id'))}</code></div>
                    </div>
                    <p style="color:#E2E8F0; margin-bottom:0;"><b>Policy Verification:</b> {_esc(explanation)}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Tool Output Expander
            tool_output = raw_result.get("output")
            if tool_output:
                with st.expander("📄 View Authorized Tool Output", expanded=True):
                    if isinstance(tool_output, dict) and "content" in tool_output:
                        st.text_area("Decrypted Content:", tool_output["content"], height=140)
                    else:
                        st.json(tool_output)

        elif "BLOCK" in decision:
            st.markdown(
                f"""
                <div class="ag-card ag-card-glow-red">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h3 style="color:#FF6B6B; margin:0;">
                            {decision_badge(decision)} &nbsp; Intercepted by Security Gateway
                        </h3>
                        <span style="font-size:0.8rem; color:#FF6B6B; font-weight:600; background:rgba(255,107,107,0.1); padding:3px 10px; border-radius:6px; border:1px solid rgba(255,107,107,0.3);">
                            STATUS: {_esc(exec_status)}
                        </span>
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px; font-size:0.9rem;">
                        <div><b>Proposed Operation:</b> <code>{_esc(proposal.get('operation'))}</code></div>
                        <div><b>Target Resource:</b> <code>{_esc(proposal.get('resource_id'))}</code></div>
                    </div>
                    <p style="color:#FF8E8E; margin-bottom:6px;"><b>Security Policy Reason:</b> {_esc(explanation)}</p>
                    <p style="color:#A6ABC5; font-size:0.84rem; margin:0;"><b>Zero Side-Effect Guarantee:</b> The protected tool was aborted before invocation. Untrusted output was never generated.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        elif "APPROVAL" in decision:
            # Queue to pending approvals
            exec_obj = None
            try:
                from models.workflow import ExecutionResult
                exec_obj = ExecutionResult.model_validate(raw_result)
                appr_id = default_approval_service.queue_approval(exec_obj)
            except Exception:
                appr_id = "APPR-QUEUED"

            st.markdown(
                f"""
                <div class="ag-card ag-card-glow-amber">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h3 style="color:#FFB347; margin:0;">
                            {decision_badge(decision)} &nbsp; High-Risk Action Held in Quarantine
                        </h3>
                        <span style="font-size:0.8rem; color:#FFB347; font-weight:600; background:rgba(255,179,71,0.1); padding:3px 10px; border-radius:6px; border:1px solid rgba(255,179,71,0.3);">
                            STATUS: {_esc(exec_status)}
                        </span>
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px; font-size:0.9rem;">
                        <div><b>Proposed Operation:</b> <code>{_esc(proposal.get('operation'))}</code></div>
                        <div><b>Target Resource:</b> <code>{_esc(proposal.get('resource_id'))}</code></div>
                    </div>
                    <p style="color:#FFD188; margin-bottom:6px;"><b>Policy Reason:</b> {_esc(explanation)}</p>
                    <p style="color:#A6ABC5; font-size:0.84rem; margin:0;"><b>Approval Ticket:</b> <code>{_esc(appr_id)}</code> — Requires explicit human authorization by an ADMINISTRATOR in the Approval Center.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # 5. Cryptographic Audit Record Expander
        latest_audit = default_hash_chain_logger.get_events(limit=1)
        if latest_audit:
            ev = latest_audit[0]
            with st.expander("🔐 View Cryptographic Audit Record for this Request"):
                c_a, c_b = st.columns(2)
                with c_a:
                    st.write(f"**Event ID:** `{ev['event_id']}`")
                    st.write(f"**Timestamp:** `{ev['timestamp']}`")
                    st.write(f"**Risk Level:** `{ev['risk_level']}`")
                with c_b:
                    st.write(f"**Previous Hash:** `{ev.get('prev_hash', '')[:24]}...`")
                    st.write(f"**Event SHA-256:** `{ev.get('event_hash', '')[:24]}...`")
