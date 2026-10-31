"""Approval Center View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Human-in-the-loop authorization center for reviewing quarantined high-risk actions.
"""

import html as html_module
import pandas as pd
import streamlit as st

from storage.approval_service import default_approval_service
from tools.mock_inbox import default_mock_inbox
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


def render_approvals(current_user: dict):
    # 1. Page Header
    page_header(
        icon="🛡️",
        title="Human Approval & Quarantine Center",
        subtitle="Review, authorize, or reject high-risk AI operations held in REQUIRE_APPROVAL state. Cryptographically signs approvals with administrator identity and provenance.",
    )

    is_admin = current_user.get("role") == "ADMINISTRATOR"

    # 2. Permission Banner if non-admin
    if not is_admin:
        st.markdown(
            f"""
            <div class="ag-card ag-card-glow-amber" style="padding:14px 18px; margin-bottom:16px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="font-size:1.3rem;">⚠️</span>
                    <div>
                        <b style="color:#FFB347;">Read-Only Mode:</b> Current Identity <code>{_esc(current_user['username'])}</code> has role <code>{_esc(current_user['role'])}</code>.
                        <span style="color:#A6ABC5; font-size:0.85rem;">Only users with <b>ADMINISTRATOR</b> clearance can approve or reject pending requests. Switch identity in the 'Identity & Access' menu to exercise approval authority.</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    pending_list = default_approval_service.list_pending("PENDING")
    all_apprs = default_approval_service.list_pending("ALL")

    # 3. Queue KPIs
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(kpi_card("⏳", "Pending Review", len(pending_list), "amber", "Operations in quarantine", delay=1), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("📜", "Historical Tickets", len(all_apprs), "purple", "Total processed", delay=2), unsafe_allow_html=True)
    with c3:
        auth_val = "AUTHORIZED" if is_admin else "READ-ONLY"
        st.markdown(kpi_card("👤", "Your Authority", auth_val, "emerald" if is_admin else "amber", f"Role: {current_user['role']}", delay=3), unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    tab_pending, tab_history, tab_test = st.tabs([
        f"⏳ Active Pending Queue ({len(pending_list)})",
        "📜 Historical Approvals Log",
        "🧪 Trigger Test Request",
    ])

    # -------------------------------------------------------------
    # TAB 1: PENDING QUEUE
    # -------------------------------------------------------------
    with tab_pending:
        section_header("⏳", "Operations Awaiting Human Clearance")

        if not pending_list:
            empty_state("✅", "Quarantine Queue Clear", "No AI agent operations are currently awaiting human review.")
        else:
            for req in pending_list:
                with st.container():
                    st.markdown(
                        f"""
                        <div class="ag-card ag-card-glow-amber">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                                <h4 style="color:#FFB347; margin:0;">
                                    Ticket: <code>{_esc(req['approval_id'])}</code>
                                </h4>
                                <span class="ag-badge ag-badge-restricted">RISK: {_esc(req['risk_level'])}</span>
                            </div>
                            <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; font-size:0.85rem; color:#A6ABC5; margin-bottom:10px;">
                                <div><b>Requester:</b> <code>{_esc(req['user_id'])}</code></div>
                                <div><b>Operation:</b> <code>{_esc(req['operation'])}</code></div>
                                <div><b>Target Resource:</b> <code>{_esc(req['resource_id'])}</code></div>
                            </div>
                            <p style="color:#FFD188; font-size:0.88rem; margin-bottom:8px;">
                                <b>Flagged Reason:</b> {_esc(req['explanation'])}
                            </p>
                            <div style="font-size:0.75rem; color:#777D9B;">
                                <b>Submitted At:</b> {req['created_at'][:19].replace('T', ' ')}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    col_appr, col_rej = st.columns([1, 1])

                    with col_appr:
                        if st.button(
                            f"✅ Sign & Approve ({req['approval_id']})",
                            key=f"appr_{req['approval_id']}",
                            disabled=not is_admin,
                            use_container_width=True,
                        ):
                            with st.spinner("Submitting cryptographic approval signature to gateway..."):
                                ok, msg, out = default_approval_service.approve_request(
                                    approval_id=req["approval_id"],
                                    approver_user_id=current_user["user_id"],
                                    approver_role=current_user["role"],
                                )
                            if ok:
                                st.success(f"✓ {msg}")
                                st.rerun()
                            else:
                                st.error(f"Approval failed: {msg}")

                    with col_rej:
                        if st.button(
                            f"❌ Reject & Abort ({req['approval_id']})",
                            key=f"rej_{req['approval_id']}",
                            disabled=not is_admin,
                            use_container_width=True,
                        ):
                            with st.spinner("Recording rejection in tamper-evident audit chain..."):
                                ok, msg = default_approval_service.reject_request(
                                    approval_id=req["approval_id"],
                                    approver_user_id=current_user["user_id"],
                                    approver_role=current_user["role"],
                                    reason="Rejected during administrator security review",
                                )
                            if ok:
                                st.info(f"✓ {msg}")
                                st.rerun()
                            else:
                                st.error(f"Rejection failed: {msg}")

                    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # TAB 2: HISTORICAL LOG
    # -------------------------------------------------------------
    with tab_history:
        section_header("📜", "Historical Approval & Rejection Ledger")
        if all_apprs:
            hist_rows = []
            for a in all_apprs:
                hist_rows.append({
                    "Approval ID": a["approval_id"],
                    "Status": a["status"],
                    "User ID": a["user_id"],
                    "Operation": a["operation"],
                    "Resource": a["resource_id"],
                    "Risk Level": a["risk_level"],
                    "Resolved By": a.get("resolved_by") or "-",
                    "Resolved At": (a.get("resolved_at") or "")[:19].replace("T", " ") or "-",
                })
            st.dataframe(pd.DataFrame(hist_rows), use_container_width=True, hide_index=True)
        else:
            empty_state("📜", "No Historical Records", "No approvals or rejections have been logged yet.")

    # -------------------------------------------------------------
    # TAB 3: TRIGGER TEST REQUEST
    # -------------------------------------------------------------
    with tab_test:
        section_header("🧪", "Generate Test High-Risk Quarantine Request")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.88rem;'>According to <code>security_policies.json</code>, when an authorized user attempts "
            "to deliver a <code>CONFIDENTIAL</code> report (such as <code>DEMO-REP-01</code>), the policy engine places it in "
            "<code>REQUIRE_APPROVAL</code> state and holds delivery until explicitly authorized by an Administrator.</p>",
            unsafe_allow_html=True,
        )

        if st.button("🧪 Generate Pending Approval Event", use_container_width=True):
            with st.spinner("Dispatching confidential report via MockInbox to trigger policy quarantine..."):
                res = default_mock_inbox.deliver_report(
                    user_id="USER-101",
                    report_id="DEMO-REP-01",
                    recipient_id="USER-101",
                )
                appr_id = default_approval_service.queue_approval(res)

            st.success(f"Generated pending approval ticket: `{appr_id}`! Switch to the Active Pending Queue tab to review.")
            st.rerun()
