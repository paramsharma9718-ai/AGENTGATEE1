"""Document Manager View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
"""

import pandas as pd
import streamlit as st

from models.document_security import Classification
from storage.document_service import default_document_service
from views.theme import classification_badge, render_pro_reader


def render_documents(current_user: dict):
    # Page Header
    st.markdown(
        """
        <div class="ag-fade-in">
            <div class="ag-section-header">📁 Document Manager & Reader</div>
            <div class="ag-section-subtext">Secure document ingestion with automated Data Loss Prevention (DLP) scanning,
            sensitivity classification, and an immersive document reading suite protected by ExecutionGateway.</div>
            <div class="ag-section-header-bar"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_reader, tab_manage, tab_upload = st.tabs([
        "📖 Document Reader",
        "📋 Registered Documents Registry",
        "📤 Upload & Inspect Document",
    ])

    docs = default_document_service.list_documents()

    # -------------------------------------------------------------
    # TAB 1: PRO DOCUMENT READER
    # -------------------------------------------------------------
    with tab_reader:
        if not docs:
            st.info("No documents currently registered in the system. Use the Upload tab to add documents.")
        else:
            doc_dict = {d["document_id"]: d for d in docs}
            doc_ids = list(doc_dict.keys())

            # Determine currently selected document
            stored_active = st.session_state.get("pro_reader_active_doc_id")
            default_index = doc_ids.index(stored_active) if stored_active in doc_ids else 0

            col_sel, col_user = st.columns([3, 1])
            with col_sel:
                selected_doc_id = st.selectbox(
                    "Select Document to Read:",
                    options=doc_ids,
                    index=default_index,
                    format_func=lambda x: f"{x} — {doc_dict[x]['original_filename']} ({doc_dict[x]['classification'].upper()})",
                    key="pro_reader_doc_selector",
                )
                st.session_state["pro_reader_active_doc_id"] = selected_doc_id

            with col_user:
                st.markdown(
                    f"""
                    <div class="ag-card" style="padding:10px 14px; margin-top:24px; margin-bottom:0;">
                        <span style="font-size:0.75rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">Active Identity</span><br>
                        <span style="font-size:0.95rem; font-weight:700; color:#60A5FA;">{current_user['user_id']}</span>
                        <span style="font-size:0.75rem; color:#A78BFA; margin-left:6px;">({current_user['role']})</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            selected_doc = doc_dict[selected_doc_id]

            # Security clearance retrieval via ExecutionGateway
            allowed, content_or_err, cls_val, decision = default_document_service.get_document_content(
                document_id=selected_doc_id,
                requesting_user_id=current_user["user_id"],
            )

            if allowed:
                render_pro_reader(
                    content=content_or_err,
                    title=selected_doc["original_filename"],
                    document_id=selected_doc["document_id"],
                    classification=selected_doc["classification"],
                    file_type=selected_doc.get("file_type", "txt"),
                    redacted_content=selected_doc.get("redacted_content"),
                    key_prefix=f"pro_read_{selected_doc_id}",
                    default_height=560,
                    clearance_note=f"GATEWAY CLEARED ({decision}) • FAIL-CLOSED ACTIVE",
                )
            else:
                # Gateway Blocked Card
                st.markdown(
                    f"""
                    <div class="ag-fade-in" style="margin-top:16px;">
                        <div class="ag-card ag-card-glow-red" style="padding:28px 32px;">
                            <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
                                <h3 style="margin:0; color:#EF4444;">⛔ Access Denied by ExecutionGateway (Module 01 Fail-Closed)</h3>
                                <span class="ag-clearance-pill-blocked">🚫 RESTRICTED CLEARANCE</span>
                            </div>
                            <div style="margin-top:16px; padding:14px 18px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3); border-radius:12px;">
                                <p style="margin:0 0 6px 0; color:#FCA5A5; font-size:1.02rem;"><b>Gateway Decision:</b> <code>{decision}</code></p>
                                <p style="margin:0; color:#E2E8F0;"><b>Security Policy Reason:</b> {content_or_err}</p>
                            </div>
                            <p style="margin-top:16px; color:#CBD5E1; font-size:0.92rem; line-height:1.6;">
                                Identity <b>{current_user['user_id']}</b> (Role: <span style="color:#A78BFA; font-weight:bold;">{current_user['role']}</span>) lacks the mandatory security clearance to access <b>{selected_doc['classification'].upper()}</b> document <code>{selected_doc_id}</code>.
                                Under AGENTGATE's Zero-Trust fail-closed architecture, the document contents were never read from disk.
                            </p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # -------------------------------------------------------------
    # TAB 2: REGISTERED DOCUMENTS REGISTRY
    # -------------------------------------------------------------
    with tab_manage:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card" style="padding:14px 20px 10px 20px;">
                    <h4 style="margin:0; color:#E2E8F0;">📋 Current Document Registry</h4>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not docs:
            st.info("No documents currently registered.")
        else:
            table_rows = []
            for d in docs:
                table_rows.append({
                    "Document ID": d["document_id"],
                    "Filename": d["original_filename"],
                    "Type": d["file_type"],
                    "Size (KB)": round(d["file_size_bytes"] / 1024, 1),
                    "Classification": d["classification"].upper(),
                    "Uploaded By": d["uploaded_by"],
                    "Date": d["upload_date"][:19].replace("T", " "),
                    "DLP Findings": d["dlp_findings_count"],
                })

            st.dataframe(pd.DataFrame(table_rows), width="stretch", hide_index=True)

            st.markdown("---")
            st.markdown(
                """
                <div class="ag-fade-in">
                    <div class="ag-card ag-card-glow-blue" style="padding:14px 20px 10px 20px;">
                        <h4 style="margin:0; color:#E2E8F0;">🔐 Document Actions (Authorized Operations)</h4>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            doc_ids = [d["document_id"] for d in docs]
            sel_doc_id = st.selectbox("Select Document for Actions:", doc_ids, key="mgmt_sel_doc")

            c_open, c_dlp, c_del = st.columns(3)

            with c_open:
                if st.button("📖 Read Document", width="stretch"):
                    st.session_state["pro_reader_active_doc_id"] = sel_doc_id
                    st.session_state["inline_read_doc_id"] = sel_doc_id

            with c_dlp:
                if st.button("🔍 View DLP Findings Report", width="stretch"):
                    cur_doc = next((d for d in docs if d["document_id"] == sel_doc_id), None)
                    if cur_doc and cur_doc.get("dlp_findings"):
                        st.write(f"**DLP Findings for `{sel_doc_id}`:**")
                        st.dataframe(pd.DataFrame(cur_doc["dlp_findings"]), width="stretch")
                    else:
                        st.info(f"Zero sensitive patterns detected in `{sel_doc_id}`.")

            with c_del:
                if st.button("🗑️ Delete Document (Admin Only)", width="stretch"):
                    del_ok, del_msg = default_document_service.delete_document(
                        document_id=sel_doc_id,
                        requesting_user_id=current_user["user_id"],
                        user_role=current_user["role"],
                    )
                    if del_ok:
                        st.success(del_msg)
                        st.rerun()
                    else:
                        st.error(f"⛔ {del_msg}")

            # If user clicked "Read Document" from registry, render below full-width
            if st.session_state.get("inline_read_doc_id") == sel_doc_id:
                cur_doc = next((d for d in docs if d["document_id"] == sel_doc_id), None)
                if cur_doc:
                    allowed, content_or_err, cls_val, decision = default_document_service.get_document_content(
                        document_id=sel_doc_id,
                        requesting_user_id=current_user["user_id"],
                    )
                    if allowed:
                        st.markdown("#### 📖 Full-Width Reader")
                        render_pro_reader(
                            content=content_or_err,
                            title=cur_doc["original_filename"],
                            document_id=cur_doc["document_id"],
                            classification=cur_doc["classification"],
                            file_type=cur_doc.get("file_type", "txt"),
                            redacted_content=cur_doc.get("redacted_content"),
                            key_prefix=f"inline_reader_{sel_doc_id}",
                            default_height=520,
                            clearance_note=f"GATEWAY CLEARED ({decision})",
                        )
                    else:
                        st.error(f"⛔ {content_or_err}")

    # -------------------------------------------------------------
    # TAB 3: UPLOAD & DLP SCAN
    # -------------------------------------------------------------
    with tab_upload:
        st.markdown(
            """
            <div class="ag-fade-in">
                <div class="ag-card ag-card-glow-blue" style="padding:16px 20px; margin-bottom:16px;">
                    <h4 style="margin:0 0 6px 0; color:#E2E8F0;">Upload Document (PDF, DOCX, TXT)</h4>
                    <p style="color:#CBD5E1; margin:0; font-size:0.88rem;">Uploaded documents are stored in secure isolated storage and scanned via <strong style="color:#60A5FA;">Module 02 DLP Engine</strong> to automatically detect credentials, API keys, PII, and financial data.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_f, col_meta = st.columns([2, 1])

        with col_f:
            st.markdown(
                '<div class="ag-drop-zone" style="margin-bottom:8px;"><span style="color:#CBD5E1; font-size:0.88rem; font-weight:500;">📎 Drop file below or browse</span></div>',
                unsafe_allow_html=True,
            )
            uploaded_file = st.file_uploader("Select Document File:", type=["txt", "pdf", "docx"], label_visibility="collapsed")

        with col_meta:
            doc_desc = st.text_input("Document Description:", placeholder="e.g. Q4 Financial projections")
            class_choice = st.selectbox(
                "Classification Mode:",
                ["AUTO (Scan via Module 02 DLP)", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
            )

        if st.button("🔒 Ingest, Scan & Classify Document", width="stretch"):
            if not uploaded_file:
                st.warning("Please select a file to upload.")
                return

            file_bytes = uploaded_file.read()
            override_cls = None
            if class_choice != "AUTO (Scan via Module 02 DLP)":
                override_cls = Classification(class_choice.lower())

            with st.spinner("Extracting content and running Module 02 DLP regex and keyword engine..."):
                success, msg, res_dict = default_document_service.upload_document(
                    filename=uploaded_file.name,
                    file_bytes=file_bytes,
                    uploaded_by=current_user["user_id"],
                    user_role=current_user["role"],
                    description=doc_desc,
                    override_classification=override_cls,
                )

            if success:
                st.success(msg)
                st.markdown(
                    f"""
                    <div class="ag-fade-in">
                        <div class="ag-card ag-card-glow-green" style="padding:14px 18px;">
                            <p style="margin:4px 0;"><b>Document ID:</b> <code>{res_dict['document_id']}</code></p>
                            <p style="margin:4px 0;"><b>Assigned Classification:</b> {classification_badge(res_dict['classification'])}</p>
                            <p style="margin:4px 0;"><b>Suggested by DLP:</b> {classification_badge(res_dict['suggested_classification'])}</p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                findings = res_dict.get("dlp_findings", [])
                if findings:
                    st.markdown(
                        f"""
                        <div class="ag-fade-in">
                            <div class="ag-card ag-card-glow-amber" style="padding:14px 18px;">
                                <h4 style="margin:0 0 8px 0; color:#FBBF24;">⚠️ {len(findings)} Sensitive Data Patterns Detected by DLP</h4>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    findings_df = pd.DataFrame(findings)
                    st.dataframe(findings_df[["category", "severity", "confidence", "line", "redacted"]], width="stretch")
                    if res_dict.get("redacted_content"):
                        with st.expander("🛡️ View DLP-Sanitized Redacted Text Preview"):
                            st.code(res_dict["redacted_content"], language="text")
                else:
                    st.info("✅ No sensitive PII, financial, or credential patterns detected.")

                st.session_state["pro_reader_active_doc_id"] = res_dict["document_id"]
                st.info("💡 You can now switch to the **📖 Document Reader** tab to view your document with custom typography and themes!")
            else:
                st.error(f"Upload failed: {msg}")
