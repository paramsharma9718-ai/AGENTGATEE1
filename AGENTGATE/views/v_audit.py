"""Audit Explorer View with Tamper-Evident SHA-256 Hash Chaining for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import pandas as pd
import streamlit as st

from storage.hash_chain_audit import default_hash_chain_logger
from views.theme import decision_badge


def render_audit(current_user: dict):
    # Page Header with animated entrance
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">🔍 Tamper-Evident Audit Explorer</div>
            <div class="ag-section-subtext">Cryptographically verifiable immutable audit trail using SHA-256 recursive hash chaining. Every security event is chained to prevent undetected tampering.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_verify, tab_events, tab_demo = st.tabs([
        "🔒 Cryptographic Integrity Checker",
        "📜 Audit Records Explorer",
        "🧪 Tamper-Detection Demonstration",
    ])

    # -------------------------------------------------------------
    # TAB 1: INTEGRITY CHECKER
    # -------------------------------------------------------------
    with tab_verify:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 6px 0; color: #60A5FA;">SHA-256 Recursive Hash Chain Verification</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        Verifies blockchain-style backward link property: for every record <em>E<sub>i</sub></em>,
                        <code>H(E<sub>i</sub>) = SHA-256(PrevHash &parallel; E<sub>i</sub>)</code> and
                        <code>PrevHash<sub>i</sub> = H(E<sub>i-1</sub>)</code>.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("🔐 Run Full Cryptographic Chain Verification", width="stretch"):
            with st.spinner("Traversing blockchain-style hash chain and verifying SHA-256 digests..."):
                integrity = default_hash_chain_logger.verify_chain_integrity()

            if integrity["is_valid"]:
                st.markdown(
                    f"""
                    <div class="ag-fade-in">
                        <div class="ag-card ag-card-glow-green">
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                                <span class="ag-status-dot ag-status-dot-green"></span>
                                <h3 style="color:#10B981; margin:0; font-size:1.25rem;">✅ AUDIT INTEGRITY VERIFIED (Zero Tampering)</h3>
                            </div>
                            <p style="margin:4px 0; color:#E2E8F0;"><b>Total Events Verified:</b> <span class="ag-badge ag-badge-allow">{integrity['total_events']}</span></p>
                            <p style="margin:4px 0; color:#CBD5E1;"><b>Head Hash (Latest SHA-256):</b> <code style="font-family:'JetBrains Mono',monospace; color:#60A5FA;">{integrity['head_hash']}</code></p>
                            <p style="margin:8px 0 0 0; color:#CBD5E1; font-size:0.85rem;">All historical security decisions, timestamps, and parameters match their cryptographic digests with 100% fidelity.</p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class="ag-fade-in">
                        <div class="ag-card ag-card-glow-red">
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                                <span class="ag-status-dot ag-status-dot-red"></span>
                                <h3 style="color:#EF4444; margin:0; font-size:1.25rem;">🚨 SECURITY ALERT: AUDIT TAMPERING DETECTED!</h3>
                            </div>
                            <p style="margin:4px 0; color:#F87171;"><b>Error Details:</b> {integrity['error_message']}</p>
                            <p style="margin:4px 0; color:#E2E8F0;"><b>Tampered Event ID:</b> <code>{integrity['tampered_event_id']}</code></p>
                            <p style="margin:4px 0; color:#E2E8F0;"><b>Record Index:</b> Event #{integrity['tampered_index'] + 1}</p>
                            <p style="margin:8px 0 0 0; color:#CBD5E1; font-size:0.85rem;">A historical record in the database was modified or an unauthorized record was injected!</p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # -------------------------------------------------------------
    # TAB 2: AUDIT RECORDS EXPLORER
    # -------------------------------------------------------------
    with tab_events:
        st.markdown(
            """
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <h4 style="color: #F8FAFC; margin: 0 0 4px 0;">Browse & Filter Cryptographic Audit Trail</h4>
                <p style="color: #CBD5E1; font-size: 0.85rem; margin: 0;">Query tamper-evident events by identity, decision, or operation type.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

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

        st.markdown(f"**Showing {len(events)} events:**")
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
                    "Prev Hash": (e.get("prev_hash") or "")[:12] + "...",
                    "Event Hash": (e.get("event_hash") or "")[:12] + "...",
                })
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

            with st.expander("🔎 Inspect Event Details & Raw JSON Payload"):
                sel_ev_id = st.selectbox("Select Event ID:", [e["event_id"] for e in events])
                sel_ev = next((e for e in events if e["event_id"] == sel_ev_id), None)
                if sel_ev:
                    st.json(sel_ev)
        else:
            st.info("No audit events match the selected criteria.")

    # -------------------------------------------------------------
    # TAB 3: TAMPER-DETECTION DEMONSTRATION
    # -------------------------------------------------------------
    with tab_demo:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-amber" style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 6px 0; color: #F59E0B;">🧪 Educational Demonstration: Tamper-Evident Resilience</h4>
                    <p style="color: #CBD5E1; margin: 0; font-size: 0.9rem;">
                        This live demo proves that even if an attacker with direct SQLite database access illicitly modifies
                        a recorded decision (e.g., flipping a <code>BLOCK</code> to <code>ALLOW</code>), the hash chain integrity checker immediately flags the fraud.
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        events = default_hash_chain_logger.get_events(limit=5)
        if not events:
            st.info("No events to tamper with.")
            return

        target_event = events[0]
        st.markdown(
            f"""
            <div class="ag-fade-in" style="margin-bottom: 16px;">
                <p><strong>Target Event for Simulation:</strong> <code>{target_event['event_id']}</code> &nbsp;|&nbsp;
                <strong>Current Decision:</strong> <span class="ag-badge ag-badge-{'allow' if 'ALLOW' in target_event['decision'] else 'block'}">{target_event['decision']}</span></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_tamp, col_fix = st.columns(2)

        with col_tamp:
            if st.button("😈 Simulate DB Tampering (Modify Decision to 'ALLOW')", width="stretch"):
                default_hash_chain_logger.simulate_tampering_for_demo(
                    event_id=target_event["event_id"],
                    field="decision",
                    new_value="ALLOW" if target_event["decision"] != "ALLOW" else "BLOCK",
                )
                st.error("Row updated in SQLite without updating hash! Now switch to the Cryptographic Integrity Checker tab to see the alarm trigger!")

        with col_fix:
            if st.button("🛠️ Repair Hash Chain (Re-seal Hashes)", width="stretch"):
                default_hash_chain_logger._backfill_hashes_if_needed()
                st.success("Hash chain recomputed and re-sealed!")
                st.rerun()
