"""Approval Center View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import pandas as pd
import streamlit as st

from storage.approval_service import default_approval_service
from tools.mock_inbox import default_mock_inbox
from views.theme import decision_badge


def render_approvals(current_user: dict):
    # Page Header
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">🛡️ Human Approval Center</div>
            <div class="ag-section-subtext">Review and authorize high-risk operations held in <code>REQUIRE_APPROVAL</code> state by AGENTGATE.
            Only users with <code>ADMINISTRATOR</code> clearance can grant approval.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    is_admin = current_user.get("role") == "ADMINISTRATOR"
    if not is_admin:
        st.warning(
            f"⚠️ Current Identity `{current_user['username']}` has role `{current_user['role']}` (Read-Only in Approval Center). "
            f"Switch to an `ADMINISTRATOR` identity (e.g. `admin` / `param`) to approve or reject pending requests."
        )

    tab_pending, tab_history, tab_test = st.tabs([
        "⏳ Active Pending Queue",
        "📜 Historical Approvals Log",
        "🧪 Trigger Test Approval Request",
    ])

    with tab_pending:
        pending_list = default_approval_service.list_pending("PENDING")

        if not pending_list:
            st.markdown(
                """
                <div class="ag-fade-in">
                    <div class="ag-card ag-card-glow-green" style="padding:16px 20px;">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="ag-status-dot ag-status-dot-green"></span>
                            <span style="color:#10B981; font-weight:700;">All Clear — No requests currently awaiting human approval.</span>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="ag-fade-in">
                    <div class="ag-card" style="padding:14px 20px 10px 20px;">
                        <h4 style="margin:0; color:#E2E8F0;">📋 Requests Requiring Review ({len(pending_list)})</h4>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            for req in pending_list:
                with st.container():
                    st.markdown(
                        f"""
                        <div class="ag-fade-in">
                            <div class="ag-card ag-card-glow-amber">
                                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:10px;">
                                    <h4 style="margin:0;">Ticket: <code>{req['approval_id']}</code></h4>
                                    <span class="ag-threat-badge ag-threat-critical">Risk: {req['risk_level']}</span>
                                </div>
                                <p><b>Requester:</b> <code>{req['user_id']}</code> &nbsp;|&nbsp; <b>Operation:</b> <code>{req['operation']}</code> &nbsp;|&nbsp; <b>Target Resource:</b> <code>{req['resource_id']}</code> &nbsp;|&nbsp; <b>Recipient:</b> <code>{req.get('recipient_id') or 'N/A'}</code></p>
                                <p><b>Gateway Flag Reason:</b> {req['explanation']}</p>
                                <p style="color:#CBD5E1; font-size:0.85rem;"><b>Created At:</b> <code>{req['created_at'][:19].replace('T', ' ')}</code></p>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    col_appr, col_rej = st.columns([1, 1])

                    with col_appr:
                        if st.button(f"✅ Approve & Execute ({req['approval_id']})", key=f"appr_{req['approval_id']}", disabled=not is_admin, width="stretch"):
                            with st.spinner("Submitting administrator cryptographic approval..."):
                                ok, msg, out = default_approval_service.approve_request(
                                    approval_id=req["approval_id"],
                                    approver_user_id=current_user["user_id"],
                                    approver_role=current_user["role"],
                                )
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(f"Approval failed: {msg}")

                    with col_rej:
                        if st.button(f"❌ Reject ({req['approval_id']})", key=f"rej_{req['approval_id']}", disabled=not is_admin, width="stretch"):
                            with st.spinner("Recording rejection in audit chain..."):
                                ok, msg = default_approval_service.reject_request(
                                    approval_id=req["approval_id"],
                                    approver_user_id=current_user["user_id"],
                                    approver_role=current_user["role"],
                                    reason="Rejected during administrator security review",
                                )
                            if ok:
                                st.info(msg)
                                st.rerun()
                            else:
                                st.error(f"Rejection failed: {msg}")

    with tab_history:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card" style="padding:14px 20px 10px 20px;">
                    <h4 style="margin:0; color:#E2E8F0;">📜 Historical Approvals & Rejections</h4>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        all_apprs = default_approval_service.list_pending("ALL")
        if all_apprs:
            hist_rows = []
            for a in all_apprs:
                hist_rows.append({
                    "Approval ID": a["approval_id"],
                    "Status": a["status"],
                    "User": a["user_id"],
                    "Operation": a["operation"],
                    "Resource": a["resource_id"],
                    "Risk": a["risk_level"],
                    "Resolved By": a.get("resolved_by") or "-",
                    "Resolved At": (a.get("resolved_at") or "")[:19].replace("T", " ") or "-",
                })
            st.dataframe(pd.DataFrame(hist_rows), width="stretch", hide_index=True)
        else:
            st.write("No historical approval records.")

    with tab_test:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="padding:16px 20px;">
                    <h4 style="margin-top:0; color:#60A5FA;">🧪 Generate Test Operation Needing Approval</h4>
                    <p style="color:#CBD5E1; font-size:0.9rem;">According to <code>security_policies.json</code>, when <code>USER-101</code> attempts to deliver
                    <code>DEMO-REP-01</code> (<code>CONFIDENTIAL</code>), the gateway marks it as <code>REQUIRE_APPROVAL</code>
                    and blocks premature delivery until an administrator reviews it.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("Generate Pending Approval Event", width="stretch"):
            with st.spinner("Triggering confidential delivery through MockInbox..."):
                res = default_mock_inbox.deliver_report(
                    user_id="USER-101",
                    report_id="DEMO-REP-01",
                    recipient_id="USER-101",
                )
                appr_id = default_approval_service.queue_approval(res)

            st.success(f"Generated pending approval ticket: `{appr_id}`! Switch to the **Active Pending Queue** tab to approve it.")
            st.rerun()
