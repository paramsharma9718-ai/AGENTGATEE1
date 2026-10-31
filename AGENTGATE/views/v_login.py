"""User Login, Registration and Identity Management View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import pandas as pd
import streamlit as st

from auth.user_manager import default_user_manager


def render_login(current_user: dict):
    # Page Header with animated entrance
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">👤 User Identity & Access Management</div>
            <div class="ag-section-subtext">Cryptographic credential authentication, Role-Based Access Control (RBAC), and simulated identity switching for gateway policy verification.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_current, tab_login, tab_register, tab_directory = st.tabs([
        "🔑 Active Identity & Role Switcher",
        "🔓 User Sign In",
        "📝 Register New User",
        "👥 User Directory",
    ])

    with tab_current:
        role_color = "#10B981" if current_user["role"] == "ADMINISTRATOR" else "#3B82F6" if current_user["role"] == "AUTHORIZED_USER" else "#EF4444"
        glow_class = "ag-card-glow-green" if current_user["role"] == "ADMINISTRATOR" else "ag-card-glow-blue" if current_user["role"] == "AUTHORIZED_USER" else "ag-card-glow-red"

        st.markdown(
            f"""
            <div class="ag-fade-in">
                <div class="ag-card {glow_class}" style="margin-bottom: 24px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <div>
                            <span style="font-size:0.75rem; color:#CBD5E1; text-transform:uppercase; letter-spacing:0.05em; font-weight:700;">Active Gateway Session</span>
                            <h3 style="margin:2px 0 0 0; color:#F8FAFC;">{current_user['full_name']}</h3>
                        </div>
                        <span class="ag-badge" style="background:rgba(59,130,246,0.15); color:{role_color}; border:1px solid {role_color}; font-size:0.85rem; padding:6px 14px;">
                            ● {current_user['role']}
                        </span>
                    </div>
                    <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:12px; padding-top:8px; border-top:1px solid rgba(255,255,255,0.06);">
                        <div>
                            <span style="color:#CBD5E1; font-size:0.8rem; font-weight:600;">USER ID:</span>
                            <code style="color:#60A5FA; font-family:'JetBrains Mono',monospace;">{current_user['user_id']}</code>
                        </div>
                        <div>
                            <span style="color:#CBD5E1; font-size:0.8rem; font-weight:600;">USERNAME:</span>
                            <code style="color:#E2E8F0; font-family:'JetBrains Mono',monospace;">{current_user['username']}</code>
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 12px;">
                <h4 style="color:#60A5FA; margin:0 0 4px 0;">⚡ Fast Identity Simulation (For Security Evaluation)</h4>
                <p style="color:#CBD5E1; font-size:0.85rem; margin:0;">Instantly switch identities to verify authorization boundaries and fail-closed gates without logging out.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        users = default_user_manager.list_users()
        u_map = {u["username"]: u for u in users}

        c1, c2 = st.columns([2, 1])
        with c1:
            sel_user = st.selectbox(
                "Select Identity to Simulate:",
                options=list(u_map.keys()),
                index=list(u_map.keys()).index(current_user["username"]) if current_user["username"] in u_map else 0,
                format_func=lambda x: f"{x} — {u_map[x]['full_name']} ({u_map[x]['role']})",
            )

        with c2:
            st.write("")
            st.write("")
            if st.button("Switch Identity", width="stretch"):
                st.session_state["user"] = u_map[sel_user]
                st.success(f"Switched identity to {sel_user} ({u_map[sel_user]['role']})!")
                st.rerun()

    with tab_login:
        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <h4 style="color:#F8FAFC; margin:0 0 4px 0;">Sign In with Cryptographic Credentials</h4>
                <p style="color:#CBD5E1; font-size:0.85rem; margin:0;">Passwords are salted and verified with PBKDF2-HMAC-SHA256.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        login_u = st.text_input("Username:", key="login_u")
        login_p = st.text_input("Password:", type="password", key="login_p")

        if st.button("Sign In", width="stretch"):
            user_profile = default_user_manager.authenticate_user(login_u, login_p)
            if user_profile:
                st.session_state["user"] = user_profile
                st.success(f"Welcome back, {user_profile['full_name']}! Clearance: {user_profile['role']}")
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with tab_register:
        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <h4 style="color:#F8FAFC; margin:0 0 4px 0;">Register New Account</h4>
                <p style="color:#CBD5E1; font-size:0.85rem; margin:0;">Create a new user profile with assigned security role.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        reg_u = st.text_input("New Username:", key="reg_u")
        reg_p = st.text_input("Password (min 6 characters):", type="password", key="reg_p")
        reg_p_confirm = st.text_input("Confirm Password:", type="password", key="reg_p_c")
        reg_role = st.selectbox("Assign Role:", ["AUTHORIZED_USER", "RESTRICTED_USER", "ADMINISTRATOR"])
        reg_fname = st.text_input("Full Name:", key="reg_fn")

        if st.button("Create Account", width="stretch"):
            if reg_p != reg_p_confirm:
                st.error("Passwords do not match.")
            else:
                ok, msg, new_u = default_user_manager.register_user(
                    username=reg_u,
                    password=reg_p,
                    role=reg_role,
                    full_name=reg_fname,
                )
                if ok:
                    st.success(f"{msg} User ID: `{new_u['user_id']}`")
                    st.session_state["user"] = new_u
                    st.rerun()
                else:
                    st.error(msg)

    with tab_directory:
        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <h4 style="color:#F8FAFC; margin:0 0 4px 0;">Registered Users in Secure Directory</h4>
                <p style="color:#CBD5E1; font-size:0.85rem; margin:0;">Authorized accounts stored in SQLite with hashed credentials.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        all_u = default_user_manager.list_users()
        st.dataframe(pd.DataFrame(all_u), width="stretch", hide_index=True)
