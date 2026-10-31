"""Audit Explorer View with Tamper-Evident SHA-256 Hash Chaining for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Cryptographic audit verification engine and immutable blockchain-style security ledger.
"""

import html as html_module
import pandas as pd
import streamlit as st

from storage.hash_chain_audit import default_hash_chain_logger
from views.theme import (
    decision_badge,
    empty_state,
    integrity_banner,
    kpi_card,
    page_header,
    section_header,
    status_badge,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_audit(current_user: dict):
    # 1. Page Header
    page_header(
        icon="🔍",
        title="Tamper-Evident Audit Explorer",
        subtitle="Every security authorization is cryptographically sealed with a SHA-256 digest and chained to its predecessor. Any database modification, row insertion, or tampering is immediately detectable.",
    )

    integrity = default_hash_chain_logger.verify_chain_integrity()
    head_hash = integrity.get("head_hash", "")
    short_head = (head_hash[:18] + "...") if head_hash else "GENESIS"

    # 2. Cryptographic Summary KPIs
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            kpi_card(
                icon="🔒",
                label="Chain Integrity",
                value="VERIFIED" if integrity["is_valid"] else "TAMPERED",
                variant="emerald" if integrity["is_valid"] else "red",
                sub="SHA-256 hash chain status",
                delay=1,
            ),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            kpi_card(
                icon="📜",
                label="Total Sealed Events",
                value=integrity["total_events"],
                variant="purple",
                sub="Chained audit entries",
                delay=2,
            ),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            kpi_card(
                icon="🔑",
                label="Chain Head Digest",
                value=short_head,
                variant="blue",
                sub="Latest event hash",
                delay=3,
            ),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    tab_verify, tab_events, tab_demo = st.tabs([
        "🔒 Cryptographic Integrity Checker",
        "📜 Browse Audit Ledger",
        "🧪 Live Tamper-Detection Lab",
    ])

    # -------------------------------------------------------------
    # TAB 1: INTEGRITY CHECKER
    # -------------------------------------------------------------
    with tab_verify:
        section_header("🔒", "SHA-256 Hash Chain Integrity Verification Engine")
        st.markdown(
            """
            <div style="background:rgba(17,20,38,0.6); border:1px solid rgba(139,124,255,0.12); border-radius:12px; padding:14px 18px; margin-bottom:16px;">
                <p style="color:#A6ABC5; font-size:0.88rem; margin:0 0 6px 0;">
                    AGENTGATE verifies that for every historical security event <i>E<sub>i</sub></i>:
                </p>
                <div style="font-family:monospace; color:#51FAAA; font-size:0.85rem; padding:8px 12px; background:rgba(12,14,29,0.8); border-radius:8px; border:1px solid rgba(81,250,170,0.2);">
                    H(E<sub>i</sub>) = SHA-256(PrevHash<sub>i-1</sub> ‖ EventPayload<sub>i</sub>) &nbsp;&amp;&nbsp; PrevHash<sub>i</sub> = H(E<sub>i-1</sub>)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("🔐 Execute Cryptographic Chain Verification", use_container_width=True):
            with st.spinner("Traversing blockchain-style hash chain and verifying SHA-256 digests..."):
                integrity = default_hash_chain_logger.verify_chain_integrity()

            if integrity["is_valid"]:
                st.markdown(
                    f"""
                    <div class="ag-card ag-card-glow-green" style="margin-top:14px;">
                        <h3 style="color:#51FAAA; margin:0 0 8px 0;">✓ AUDIT INTEGRITY VERIFIED (Zero Tampering)</h3>
                        <p style="color:#E2E8F0; margin-bottom:6px;"><b>Total Events Traversed & Verified:</b> {integrity['total_events']}</p>
                        <p style="color:#A6ABC5; margin-bottom:6px;"><b>Head Hash (Latest SHA-256):</b> <code style="color:#51FAAA;">{_esc(integrity['head_hash'])}</code></p>
                        <p style="color:#777D9B; font-size:0.82rem; margin:0;">
                            Every cryptographic link in SQLite matches its computed digest. No unauthorized inserts, updates, or deletes have occurred.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class="ag-card ag-card-glow-red" style="margin-top:14px;">
                        <h3 style="color:#FF6B6B; margin:0 0 8px 0;">🚨 CRITICAL SECURITY ALERT: AUDIT TAMPERING DETECTED!</h3>
                        <p style="color:#FF8E8E; margin-bottom:6px;"><b>Violation Details:</b> {_esc(integrity['error_message'])}</p>
                        <p style="color:#E2E8F0; margin-bottom:6px;"><b>Tampered Event ID:</b> <code>{_esc(integrity['tampered_event_id'])}</code></p>
                        <p style="color:#A6ABC5; margin-bottom:6px;"><b>Record Index:</b> Event #{integrity['tampered_index'] + 1}</p>
                        <p style="color:#FF6B6B; font-size:0.84rem; margin:0;">
                            A database record was maliciously updated out-of-band! The hash chain has been severed.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # -------------------------------------------------------------
    # TAB 2: AUDIT RECORDS EXPLORER
    # -------------------------------------------------------------
    with tab_events:
        section_header("📜", "Search & Filter Security Audit Trail")

        c_u, c_d, c_o = st.columns(3)
        with c_u:
            filter_user = st.text_input("Filter by User ID (optional):", placeholder="e.g. USER-001")
        with c_d:
            filter_dec = st.selectbox("Filter by Decision:", ["ALL", "ALLOW", "BLOCK", "REQUIRE_APPROVAL"])
        with c_o:
            filter_op = st.selectbox("Filter by Operation:", ["ALL", "READ_DOCUMENT", "SAVE_REPORT", "SEND_REPORT", "ACCESS_RESOURCE"])

        dec_arg = None if filter_dec == "ALL" else filter_dec
        op_arg = None if filter_op == "ALL" else filter_op
        user_arg = filter_user.strip() if filter_user.strip() else None

        events = default_hash_chain_logger.get_events(
            limit=100,
            user_id=user_arg,
            decision=dec_arg,
            operation=op_arg,
        )

        st.markdown(f"<div style='font-size:0.85rem; color:#A6ABC5; margin-bottom:8px;'>Showing <b>{len(events)}</b> matching audit records:</div>", unsafe_allow_html=True)
        if events:
            rows = []
            for e in events:
                rows.append({
                    "Event ID": e["event_id"],
                    "Timestamp": e["timestamp"][:19].replace("T", " "),
                    "User": e["user_id"],
                    "Operation": e["operation"],
                    "Resource": e["resource_id"],
                    "Recipient": e.get("recipient_id") or "-",
                    "Decision": e["decision"],
                    "Risk": e["risk_level"],
                    "Status": e["status"],
                    "Prev Hash": (e.get("prev_hash") or "")[:14] + "...",
                    "SHA-256 Digest": (e.get("event_hash") or "")[:14] + "...",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            with st.expander("🔎 Deep Inspect Event Cryptographic Envelope"):
                sel_ev_id = st.selectbox("Select Event ID:", [e["event_id"] for e in events])
                sel_ev = next((e for e in events if e["event_id"] == sel_ev_id), None)
                if sel_ev:
                    st.json(sel_ev)
        else:
            empty_state("📜", "No Matching Audit Records", "No events match the specified filter criteria.")

    # -------------------------------------------------------------
    # TAB 3: TAMPER-DETECTION DEMONSTRATION
    # -------------------------------------------------------------
    with tab_demo:
        section_header("🧪", "Tamper-Detection Verification Laboratory")
        st.markdown(
            """
            <div style="background:rgba(255,179,71,0.06); border:1px solid rgba(255,179,71,0.2); border-radius:12px; padding:14px 18px; margin-bottom:16px;">
                <h4 style="color:#FFB347; margin:0 0 6px 0;">Demonstrating Cryptographic Tamper-Evidence</h4>
                <p style="color:#A6ABC5; font-size:0.86rem; margin:0;">
                    If an insider threat or attacker with direct SQLite database access alters a historical decision
                    (e.g. changing a <code>BLOCK</code> to <code>ALLOW</code>), the cryptographic hash chain breaks.
                    Use this lab to simulate such tampering and observe the instant detection.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        events = default_hash_chain_logger.get_events(limit=5)
        if not events:
            empty_state("🧪", "No Events Available", "Execute actions first to generate events to tamper with.")
            return

        target_event = events[0]
        st.markdown(
            f"<div style='font-size:0.88rem; color:#E2E8F0; margin-bottom:12px;'>"
            f"<b>Target Event for Simulation:</b> <code>{_esc(target_event['event_id'])}</code> &nbsp;|&nbsp; "
            f"<b>Current Recorded Decision:</b> {decision_badge(target_event['decision'])}"
            f"</div>",
            unsafe_allow_html=True,
        )

        col_tamp, col_fix = st.columns(2)

        with col_tamp:
            if st.button("😈 Simulate SQLite Tampering (Flip Decision)", use_container_width=True):
                new_dec = "ALLOW" if target_event["decision"] != "ALLOW" else "BLOCK"
                default_hash_chain_logger.simulate_tampering_for_demo(
                    event_id=target_event["event_id"],
                    field="decision",
                    new_value=new_dec,
                )
                st.error("Row updated in SQLite without recomputing hash! Now switch to the Cryptographic Integrity Checker tab to see the alarm trigger!")

        with col_fix:
            if st.button("🛠️ Repair Hash Chain (Re-seal Digests)", use_container_width=True):
                default_hash_chain_logger._backfill_hashes_if_needed()
                st.success("✓ Hash chain recomputed and cryptographically re-sealed!")
                st.rerun()
