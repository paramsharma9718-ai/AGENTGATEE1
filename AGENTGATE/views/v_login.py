"""User Login, Registration and Identity Management View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
PBKDF2-HMAC-SHA256 authenticated identity management and role switching for policy evaluation.
"""

import html as html_module
import pandas as pd
import streamlit as st

from auth.user_manager import default_user_manager
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


def render_login(current_user: dict):
    # 1. Page Header
    page_header(
        icon="👤",
        title="User Identity & Access Management",
        subtitle="Role-based credential management, PBKDF2 authentication, and multi-role evaluation switcher for AGENTGATE authorization policies.",
    )

    users = default_user_manager.list_users()

    # 2. Identity Summary KPIs
    role = current_user["role"]
    role_color = "emerald" if role == "ADMINISTRATOR" else "blue" if role == "AUTHORIZED_USER" else "amber"

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(kpi_card("👤", "Active Identity", current_user["username"], "purple", f"ID: {current_user['user_id']}", delay=1), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("🛡️", "Clearance Tier", role, role_color, "Current RBAC role", delay=2), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card("👥", "Total Users", len(users), "blue", "Registered in SQLite", delay=3), unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    tab_current, tab_login, tab_register, tab_directory = st.tabs([
        "🔑 Active Identity & Role Switcher",
        "🔓 User Sign In",
        "📝 Register New User",
        "👥 User Directory",
    ])

    # -------------------------------------------------------------
    # TAB 1: ACTIVE IDENTITY & ROLE SWITCHER
    # -------------------------------------------------------------
    with tab_current:
        section_header("🔑", "Active Authenticated Session")

        st.markdown(
            f"""
            <div class="ag-card ag-card-glow-blue" style="margin-bottom:18px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <h3 style="color:#60A5FA; margin:0;">
                        Active User: <code>{_esc(current_user['username'])}</code>
                    </h3>
                    <span class="ag-badge ag-badge-public">ID: {_esc(current_user['user_id'])}</span>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; font-size:0.9rem; color:#A6ABC5;">
                    <div><b>Full Name:</b> {_esc(current_user['full_name'])}</div>
                    <div><b>Clearance Role:</b> <span style="color:#60A5FA; font-weight:700;">{_esc(current_user['role'])}</span></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        section_header("⚡", "Quick Role Switcher (For Evaluation & Boundary Testing)")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>Quickly assume different identities to test how the fail-closed gateway restricts unauthorized reads and deliveries:</p>",
            unsafe_allow_html=True,
        )

        u_map = {u["username"]: u for u in users}

        c_sel, c_btn = st.columns([3, 1])
        with c_sel:
            sel_user = st.selectbox(
                "Select Identity to Simulate:",
                options=list(u_map.keys()),
                index=list(u_map.keys()).index(current_user["username"]) if current_user["username"] in u_map else 0,
                format_func=lambda x: f"{x} — {u_map[x]['full_name']} ({u_map[x]['role']})",
            )

        with c_btn:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("Switch Identity", use_container_width=True):
                st.session_state["user"] = u_map[sel_user]
                st.success(f"✓ Switched identity to {sel_user} ({u_map[sel_user]['role']})!")
                st.rerun()

    # -------------------------------------------------------------
    # TAB 2: SIGN IN
    # -------------------------------------------------------------
    with tab_login:
        section_header("🔓", "Authenticate with Credentials")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.85rem;'>Passwords verified via PBKDF2-HMAC-SHA256 with 100,000 hashing rounds:</p>",
            unsafe_allow_html=True,
        )

        col_l1, col_l2 = st.columns([1, 1])
        with col_l1:
            login_u = st.text_input("Username:", key="login_u", placeholder="e.g. admin or keshav")
        with col_l2:
            login_p = st.text_input("Password:", type="password", key="login_p", placeholder="••••••••")

        if st.button("Sign In to Session", use_container_width=True):
            user_profile = default_user_manager.authenticate_user(login_u, login_p)
            if user_profile:
                st.session_state["user"] = user_profile
                st.success(f"✓ Welcome back, {user_profile['full_name']}! Clearance: {user_profile['role']}")
                st.rerun()
            else:
                st.error("Invalid username or password.")

    # -------------------------------------------------------------
    # TAB 3: REGISTER NEW USER
    # -------------------------------------------------------------
    with tab_register:
        section_header("📝", "Register New User Account")

        c_r1, c_r2 = st.columns(2)
        with c_r1:
            reg_u = st.text_input("New Username:", key="reg_u", placeholder="e.g. auditor_01")
            reg_p = st.text_input("Password (min 6 characters):", type="password", key="reg_p", placeholder="••••••••")
            reg_p_confirm = st.text_input("Confirm Password:", type="password", key="reg_p_c", placeholder="••••••••")

        with c_r2:
            reg_fname = st.text_input("Full Name:", key="reg_fn", placeholder="e.g. Jane Doe")
            reg_role = st.selectbox(
                "Assign Role Clearance:",
                ["AUTHORIZED_USER", "RESTRICTED_USER", "ADMINISTRATOR"],
                help="ADMINISTRATOR: Full access + Approval authority. AUTHORIZED_USER: Standard docs. RESTRICTED_USER: Public docs only.",
            )

        if st.button("Create Authenticated Identity", use_container_width=True):
            if not reg_u.strip() or not reg_fname.strip():
                st.warning("Please fill in all required fields.")
            elif len(reg_p) < 6:
                st.warning("Password must be at least 6 characters.")
            elif reg_p != reg_p_confirm:
                st.error("Passwords do not match.")
            else:
                ok, msg, new_u = default_user_manager.register_user(
                    username=reg_u,
                    password=reg_p,
                    role=reg_role,
                    full_name=reg_fname,
                )
                if ok:
                    st.success(f"✓ {msg} User ID: `{new_u['user_id']}`")
                    st.session_state["user"] = new_u
                    st.rerun()
                else:
                    st.error(f"Registration failed: {msg}")

    # -------------------------------------------------------------
    # TAB 4: USER DIRECTORY
    # -------------------------------------------------------------
    with tab_directory:
        section_header("👥", "Registered Users in System Directory")
        all_u = default_user_manager.list_users()

        u_rows = []
        for u in all_u:
            u_rows.append({
                "User ID": u["user_id"],
                "Username": u["username"],
                "Full Name": u["full_name"],
                "Clearance Role": u["role"],
                "Registered At": u["created_at"][:19].replace("T", " "),
            })

        st.dataframe(pd.DataFrame(u_rows), use_container_width=True, hide_index=True)
