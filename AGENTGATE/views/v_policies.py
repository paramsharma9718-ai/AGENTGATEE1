"""Policy Monitoring View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Role-Based Access Control (RBAC), classification clearance boundaries, and approval policy inspector.
"""

import html as html_module
import json
from pathlib import Path
import pandas as pd
import streamlit as st

from views.theme import (
    classification_badge,
    empty_state,
    kpi_card,
    page_header,
    section_header,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_policies(current_user: dict):
    # 1. Page Header
    page_header(
        icon="📜",
        title="Security Policy Matrix",
        subtitle="Inspection of trusted Role-Based Access Control (RBAC), multi-tier data clearance boundaries, and mandatory human approval rules configured in Module 01.",
    )

    policy_path = Path(__file__).resolve().parent.parent / "config" / "security_policies.json"
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_data = json.load(f)

    roles_dict = policy_data.get("roles", {})
    class_dict = policy_data.get("resource_classifications", {})
    appr_rules = policy_data.get("approval_required", {})
    recips = policy_data.get("recipient_authorizations", {}).get("authorized_recipients", [])

    # 2. Policy Summary KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(kpi_card("👥", "Configured Roles", len(roles_dict), "purple", "RBAC security roles", delay=1), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("🏷️", "Clearance Tiers", len(class_dict), "blue", "Sensitivity levels", delay=2), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card("⚠️", "Approval Triggers", len(appr_rules), "amber", "High-risk actions", delay=3), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card("📬", "Authorized Recipients", len(recips), "emerald", "Cleared destinations", delay=4), unsafe_allow_html=True)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    tab_matrix, tab_class, tab_approvals, tab_raw = st.tabs([
        "👥 Roles & Operations Matrix",
        "🏷️ Classification Clearance",
        "⚠️ Approval Rules & Recipients",
        "📄 Raw Policy JSON",
    ])

    with tab_matrix:
        section_header("👥", "Role-Based Access Control (RBAC) Permissions")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>Defines the baseline tool operations each role is authorized to propose via the AI agent or Execution Gateway:</p>",
            unsafe_allow_html=True,
        )

        all_ops = ["READ_DOCUMENT", "SAVE_REPORT", "SEND_REPORT", "ACCESS_RESOURCE", "MODIFY_CLASSIFICATION"]
        rows = []
        for role, conf in roles_dict.items():
            row = {"Role": role}
            allowed = set(conf.get("allowed_operations", []))
            for op in all_ops:
                row[op] = "✅ ALLOWED" if op in allowed else "❌ BLOCKED"
            rows.append(row)

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with tab_class:
        section_header("🏷️", "Resource Classification Clearance Boundaries")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>Strict Bell-LaPadula / Biba clearance rules governing which roles may read or modify data at each sensitivity tier:</p>",
            unsafe_allow_html=True,
        )

        c_rows = []
        for cls_name, conf in class_dict.items():
            c_rows.append({
                "Sensitivity Tier": cls_name.upper(),
                "Authorized Clearance Roles": ", ".join(conf.get("allowed_roles", [])),
                "Enforcement Rule": "Fail-Closed Gateway Block if role not in set",
            })
        st.dataframe(pd.DataFrame(c_rows), use_container_width=True, hide_index=True)

    with tab_approvals:
        section_header("⚠️", "Mandatory Human Approval Thresholds")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>High-risk operations that automatically trigger <code>REQUIRE_APPROVAL</code> state, quarantining the execution until an Administrator signs off:</p>",
            unsafe_allow_html=True,
        )

        a_rows = []
        for op, tiers in appr_rules.items():
            a_rows.append({
                "Operation": op,
                "Requires Human Approval On": ", ".join([t.upper() for t in tiers]),
                "Default Risk Level": "CRITICAL",
                "Resolution Authority": "ADMINISTRATOR only",
            })
        st.dataframe(pd.DataFrame(a_rows), use_container_width=True, hide_index=True)

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        section_header("📬", "Authorized External Report Recipients")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>Only identities in this whitelist are permitted destinations for report dispatch operations:</p>",
            unsafe_allow_html=True,
        )

        recip_chips = "".join([
            f'<div style="background:rgba(81,250,170,0.08); border:1px solid rgba(81,250,170,0.25); border-radius:8px; padding:8px 14px; color:#51FAAA; font-weight:600; font-size:0.85rem; display:inline-flex; align-items:center; gap:6px; margin:4px;">'
            f'<span>👤</span> <code>{_esc(r)}</code>'
            f'</div>'
            for r in recips
        ])
        st.markdown(f"<div>{recip_chips}</div>", unsafe_allow_html=True)

    with tab_raw:
        section_header("📄", "Live Configuration Artifact")
        st.markdown(
            "<p style='color:#777D9B; font-size:0.82rem;'>Source of truth: <code>config/security_policies.json</code></p>",
            unsafe_allow_html=True,
        )
        st.json(policy_data)
