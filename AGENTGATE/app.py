"""AGENTGATE — Intelligent Security Gateway for AI Agents.

Main Application Entrypoint (Module 04: Application, Database, Dashboard & Monitoring).
Developed by Param for Team AGENTGATE (Nihal, Dev, Param, Keshav).
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from auth.user_manager import default_user_manager
from storage.approval_service import default_approval_service
from views.theme import apply_theme
from views.v_approvals import render_approvals
from views.v_attacks import render_attacks
from views.v_audit import render_audit
from views.v_dashboard import render_dashboard
from views.v_documents import render_documents
from views.v_login import render_login
from views.v_policies import render_policies
from views.v_playground import render_playground
from views.v_workflows import render_workflows


def main():
    st.set_page_config(
        page_title="AGENTGATE — AI Security Gateway",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply custom dark-navy cybersecurity theme
    apply_theme()

    # Initialize current user in session state
    if "user" not in st.session_state:
        # Default active session: Param Sharma (Admin)
        admin_user = default_user_manager.authenticate_user("admin", "admin123")
        if admin_user:
            st.session_state["user"] = admin_user
        else:
            st.session_state["user"] = {
                "user_id": "USER-001",
                "username": "admin",
                "role": "ADMINISTRATOR",
                "full_name": "Param Sharma (Admin)",
            }

    current_user = st.session_state["user"]

    # -----------------------------------------------------------------
    # SIDEBAR NAVIGATION
    # -----------------------------------------------------------------
    with st.sidebar:
        # ── Logo & Brand ──
        st.markdown(
            '<div class="ag-sidebar-brand">'
            '<div class="ag-sidebar-logo">🛡️ AGENTGATE</div>'
            '<div class="ag-sidebar-subtext">AI Security Gateway & Information Control</div>'
            '<div class="ag-gateway-badge">'
            '<span class="ag-gateway-dot"></span>'
            '<span class="ag-gateway-text">FAIL-CLOSED GATEWAY ACTIVE</span>'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        # ── Gradient Divider ──
        st.markdown('<div class="ag-sidebar-divider"></div>', unsafe_allow_html=True)

        # ── Active User Profile Card ──
        role_color = "#10B981" if current_user["role"] == "ADMINISTRATOR" else "#3B82F6" if current_user["role"] == "AUTHORIZED_USER" else "#EF4444"
        role_bg = "rgba(16,185,129,0.1)" if current_user["role"] == "ADMINISTRATOR" else "rgba(59,130,246,0.1)" if current_user["role"] == "AUTHORIZED_USER" else "rgba(239,68,68,0.1)"
        role_border = "rgba(16,185,129,0.3)" if current_user["role"] == "ADMINISTRATOR" else "rgba(59,130,246,0.3)" if current_user["role"] == "AUTHORIZED_USER" else "rgba(239,68,68,0.3)"

        st.markdown(
            f'<div class="ag-user-card">'
            f'<div class="ag-user-label">AUTHENTICATED IDENTITY</div>'
            f'<div class="ag-user-name">{current_user["full_name"]}</div>'
            f'<div style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; background:{role_bg}; border:1px solid {role_border}; border-radius:999px; color:{role_color}; font-size:0.68rem; font-weight:700; letter-spacing:0.04em; font-family:\'Inter\',sans-serif;">{current_user["role"]}</div>'
            f'<div class="ag-user-id">ID: {current_user["user_id"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # ── Navigation Divider ──
        st.markdown('<div class="ag-sidebar-divider" style="margin:4px 0 12px 0;"></div>', unsafe_allow_html=True)

        # Check pending approvals count for badge
        pending_count = default_approval_service.count_pending()
        appr_label = f"⏳ Approval Center ({pending_count})" if pending_count > 0 else "⏳ Approval Center"

        # Navigation Menu
        nav_options = [
            "🛡️ Security Overview Dashboard",
            "🤖 Agent Playground",
            "📁 Document Manager",
            "🎯 Attack Simulator",
            appr_label,
            "🔄 Workflow Manager",
            "📜 Policy Monitoring",
            "🔍 Tamper-Evident Audit Explorer",
            "👤 Identity & Access (Auth)",
        ]

        selection = st.radio("Navigation:", nav_options, label_visibility="collapsed")

        # ── Bottom Divider ──
        st.markdown('<div class="ag-sidebar-divider" style="margin:16px 0 12px 0;"></div>', unsafe_allow_html=True)

        # ── Team Credits — Glass Footer ──
        st.markdown(
            '<div class="ag-team-card">'
            '<div style="font-size:0.68rem; color:#93C5FD; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:8px; font-family:\'Inter\',sans-serif;">TEAM AGENTGATE</div>'
            '<div style="font-size:0.75rem; color:#E2E8F0; line-height:1.7; font-family:\'Inter\',sans-serif;">'
            '<span style="color:#60A5FA; font-weight:600;">Param</span> — Module 04 (App & DB)<br/>'
            '<span style="color:#60A5FA; font-weight:600;">Nihal</span> — Module 03 (Gateway & Agent)<br/>'
            '<span style="color:#60A5FA; font-weight:600;">Dev & Keshav</span> — Modules 01 & 02'
            '</div>'
            '<div style="margin-top:10px; padding-top:8px; border-top:1px solid rgba(99,102,241,0.25); font-size:0.65rem; color:#CBD5E1; font-style:italic; font-family:\'Inter\',sans-serif;">Module 04: Active & Integrated</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    # -----------------------------------------------------------------
    # PAGE ROUTING
    # -----------------------------------------------------------------
    if "Security Overview Dashboard" in selection:
        render_dashboard(current_user)

    elif "Agent Playground" in selection:
        render_playground(current_user)

    elif "Document Manager" in selection:
        render_documents(current_user)

    elif "Attack Simulator" in selection:
        render_attacks(current_user)

    elif "Approval Center" in selection:
        render_approvals(current_user)

    elif "Workflow Manager" in selection:
        render_workflows(current_user)

    elif "Policy Monitoring" in selection:
        render_policies(current_user)

    elif "Audit Explorer" in selection:
        render_audit(current_user)

    elif "Identity & Access" in selection:
        render_login(current_user)


if __name__ == "__main__":
    main()
