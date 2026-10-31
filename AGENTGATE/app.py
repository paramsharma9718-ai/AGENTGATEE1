"""AGENTGATE — Intelligent Security Gateway for AI Agents.

Main Application Entrypoint (Module 04: Application, Database, Dashboard & Monitoring).
Developed by Param for Team AGENTGATE (Nihal, Dev, Param, Keshav).
"""

import html as html_module
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


def _esc(value) -> str:
    return html_module.escape(str(value))


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
        # Branding
        st.markdown(
            """
            <div style="text-align:center; padding: 10px 0 8px 0; animation: ag-fade-in 0.5s ease-out both;">
                <div style="
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    width: 52px; height: 52px;
                    background: linear-gradient(135deg, rgba(139,124,255,0.15) 0%, rgba(81,250,170,0.1) 100%);
                    border: 1px solid rgba(139,124,255,0.25);
                    border-radius: 14px;
                    font-size: 1.6rem;
                    margin-bottom: 10px;
                ">🛡️</div>
                <h1 style="
                    background: linear-gradient(135deg, #C4BFFF 0%, #51FAAA 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    font-size: 1.6rem;
                    font-weight: 800;
                    letter-spacing: -0.03em;
                    margin: 0 0 2px 0;
                    line-height: 1.2;
                ">AGENTGATE</h1>
                <p style="color: #777D9B; font-size: 0.76rem; margin: 0 0 10px 0; letter-spacing: 0.06em; text-transform: uppercase; font-weight: 500;">
                    AI Security Gateway
                </p>
                <div style="
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    padding: 4px 12px;
                    background: rgba(81,250,170,0.06);
                    border: 1px solid rgba(81,250,170,0.2);
                    border-radius: 8px;
                    font-size: 0.68rem;
                    font-weight: 600;
                    color: #51FAAA;
                    letter-spacing: 0.04em;
                ">
                    <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:#51FAAA; box-shadow: 0 0 6px rgba(81,250,170,0.5);"></span>
                    GATEWAY ACTIVE
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("---")

        # Active User Profile Card
        role = current_user["role"]
        if role == "ADMINISTRATOR":
            role_color = "#51FAAA"
            role_dot = "ag-status-dot-green"
        elif role == "AUTHORIZED_USER":
            role_color = "#60A5FA"
            role_dot = "ag-status-dot-green"
        else:
            role_color = "#FFB347"
            role_dot = "ag-status-dot-amber"

        st.markdown(
            f"""
            <div style="
                background: linear-gradient(135deg, rgba(25,27,50,0.8) 0%, rgba(17,20,38,0.6) 100%);
                border: 1px solid rgba(139,124,255,0.1);
                border-radius: 12px;
                padding: 14px 16px;
                margin-bottom: 12px;
                animation: ag-fade-in-up 0.4s ease-out both;
            ">
                <div style="font-size:0.68rem; color:#777D9B; text-transform:uppercase; letter-spacing:0.08em; font-weight:600; margin-bottom:6px;">
                    Authenticated Identity
                </div>
                <div style="font-weight:700; color:#F5F6FF; font-size:0.92rem; margin-bottom:3px;">
                    {_esc(current_user['full_name'])}
                </div>
                <div style="display:flex; align-items:center; gap:6px; font-size:0.78rem; color:{role_color}; font-weight:600;">
                    <span class="ag-status-dot {role_dot}" style="animation:none;"></span>
                    {_esc(role)} · {_esc(current_user['user_id'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Check pending approvals count for badge
        pending_count = default_approval_service.count_pending()
        appr_label = f"⏳ Approval Center ({pending_count})" if pending_count > 0 else "⏳ Approval Center"

        # Navigation Menu
        nav_options = [
            "📊 Security Overview",
            "🤖 AI Playground",
            "📁 Documents",
            "🎯 Attack Simulator",
            appr_label,
            "🔄 Workflows",
            "📜 Security Policies",
            "🔍 Audit Explorer",
            "👤 Identity & Access",
        ]

        selection = st.radio("Navigation:", nav_options, label_visibility="collapsed")

        st.markdown("---")
        st.markdown(
            """
            <div style="font-size:0.7rem; color:#555A75; line-height:1.5; padding: 0 4px;">
                <div style="font-weight:600; color:#777D9B; margin-bottom:4px;">College Team</div>
                <span style="color:#616083;">Param</span> — Module 04 · App & DB<br/>
                <span style="color:#616083;">Nihal</span> — Module 03 · Gateway<br/>
                <span style="color:#616083;">Dev & Keshav</span> — Modules 01 & 02
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -----------------------------------------------------------------
    # PAGE ROUTING
    # -----------------------------------------------------------------
    if "Security Overview" in selection:
        render_dashboard(current_user)

    elif "AI Playground" in selection:
        render_playground(current_user)

    elif "Documents" in selection:
        render_documents(current_user)

    elif "Attack Simulator" in selection:
        render_attacks(current_user)

    elif "Approval Center" in selection:
        render_approvals(current_user)

    elif "Workflows" in selection:
        render_workflows(current_user)

    elif "Security Policies" in selection:
        render_policies(current_user)

    elif "Audit Explorer" in selection:
        render_audit(current_user)

    elif "Identity & Access" in selection:
        render_login(current_user)


if __name__ == "__main__":
    main()
