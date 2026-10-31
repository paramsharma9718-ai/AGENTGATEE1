"""Policy Monitoring View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import json
from pathlib import Path
import pandas as pd
import streamlit as st


def render_policies(current_user: dict):
    # Page Header with animated entrance
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">📜 Policy Monitoring & Configuration</div>
            <div class="ag-section-subtext">Inspection of trusted Role-Based Access Control (RBAC), classification clearance boundaries, and human approval rules.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    policy_path = Path(__file__).resolve().parent.parent / "config" / "security_policies.json"
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_data = json.load(f)

    tab_matrix, tab_class, tab_approvals, tab_raw = st.tabs([
        "👥 Roles & Operations Matrix",
        "🏷️ Classification Clearance",
        "⚠️ Approval Rules & Recipients",
        "📄 Raw JSON Policy",
    ])

    with tab_matrix:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 6px 0; color: #60A5FA;">Role-Based Access Control (RBAC) Permissions</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        Specifies the precise action proposals each role is permitted to submit to the security gateway.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        roles_dict = policy_data.get("roles", {})
        all_ops = ["READ_DOCUMENT", "SAVE_REPORT", "SEND_REPORT", "ACCESS_RESOURCE", "MODIFY_CLASSIFICATION"]

        rows = []
        for role, conf in roles_dict.items():
            row = {"Role": role}
            allowed = set(conf.get("allowed_operations", []))
            for op in all_ops:
                row[op] = "✅ ALLOWED" if op in allowed else "❌ BLOCKED"
            rows.append(row)

        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

    with tab_class:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 6px 0; color: #60A5FA;">Resource Classification Clearance Boundaries</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        Multi-level security classification tiers. Users without corresponding clearance are blocked fail-closed.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        class_dict = policy_data.get("resource_classifications", {})
        c_rows = []
        for cls_name, conf in class_dict.items():
            c_rows.append({
                "Classification Tier": cls_name.upper(),
                "Authorized Roles": ", ".join(conf.get("allowed_roles", [])),
            })
        st.dataframe(pd.DataFrame(c_rows), width="stretch", hide_index=True)

    with tab_approvals:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-amber" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 6px 0; color: #F59E0B;">⚠️ Mandatory Human Approval Rules</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        High-risk operations that trigger <code>REQUIRE_APPROVAL</code> state regardless of user clearance, requiring explicit administrator sign-off.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        appr_rules = policy_data.get("approval_required", {})
        a_rows = []
        for op, tiers in appr_rules.items():
            a_rows.append({
                "Operation": op,
                "Requires Human Approval On": ", ".join([t.upper() for t in tiers]),
                "Default Risk Level": "CRITICAL",
            })
        st.dataframe(pd.DataFrame(a_rows), width="stretch", hide_index=True)

        st.markdown(
            """
            <div class="ag-fade-in" style="margin-top: 24px;">
                <h4 style="color: #60A5FA; margin-bottom: 8px;">Authorized External Report Recipients</h4>
                <p style="color: #CBD5E1; font-size: 0.85rem; margin-bottom: 12px;">Identities vetted to receive external reports through the gateway:</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        recips = policy_data.get("recipient_authorizations", {}).get("authorized_recipients", [])
        recip_html = "".join([f'<span class="ag-badge ag-badge-public" style="margin-right: 8px; margin-bottom: 8px;">👤 {r}</span>' for r in recips])
        st.markdown(f'<div class="ag-fade-in" style="display:flex; flex-wrap:wrap; gap:8px;">{recip_html}</div>', unsafe_allow_html=True)

    with tab_raw:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card" style="margin-bottom: 16px;">
                    <h4 style="margin: 0 0 4px 0; color: #F8FAFC;">Live Configuration File (<code>security_policies.json</code>)</h4>
                    <p style="color: #CBD5E1; font-size: 0.85rem; margin: 0;">Authoritative policy document loaded at gateway initialization.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.json(policy_data)
