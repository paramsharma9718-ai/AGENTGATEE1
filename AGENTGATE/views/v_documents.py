"""Document Manager View for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Secure document vault with automated DLP content scanning, sensitivity tagging, and gateway authorization.
"""

import html as html_module
import pandas as pd
import streamlit as st

from models.document_security import Classification
from storage.document_service import default_document_service
from views.theme import (
    classification_badge,
    decision_badge,
    empty_state,
    kpi_card,
    page_header,
    section_header,
    status_badge,
)


def _esc(value) -> str:
    return html_module.escape(str(value))


def render_documents(current_user: dict):
    # 1. Page Header
    page_header(
        icon="📁",
        title="Document Vault & DLP Scanner",
        subtitle="Secure document ingestion with automated Data Loss Prevention (DLP) pattern inspection, clearance classification, and cryptographic authorization boundaries.",
    )

    docs = default_document_service.list_documents()

    # 2. Vault KPI Summary Cards
    c1, c2, c3, c4 = st.columns(4)
    total_docs = len(docs)
    total_dlp = sum(d.get("dlp_findings_count", 0) for d in docs)
    conf_docs = sum(1 for d in docs if str(d.get("classification")).upper() in ("CONFIDENTIAL", "RESTRICTED"))
    pub_docs = sum(1 for d in docs if str(d.get("classification")).upper() == "PUBLIC")

    with c1:
        st.markdown(kpi_card("📁", "Total Documents", total_docs, "purple", "Vault documents", delay=1), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("🌐", "Public Documents", pub_docs, "blue", "Accessible by all roles", delay=2), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card("🔒", "High-Sensitivity", conf_docs, "amber", "Confidential / Restricted", delay=3), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card("⚠️", "DLP Findings", total_dlp, "red" if total_dlp > 0 else "emerald", "Sensitive patterns flagged", delay=4), unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    tab_manage, tab_upload = st.tabs(["📋 Document Registry & Actions", "📤 Upload & Scan Document"])

    # -------------------------------------------------------------
    # TAB 1: REGISTERED DOCUMENTS & OPERATIONS
    # -------------------------------------------------------------
    with tab_manage:
        section_header("📋", "Registered Documents in Secure Vault")

        if not docs:
            empty_state("📁", "No Documents Found in Vault", "Use the 'Upload & Scan Document' tab to ingest and classify files.")
            return

        table_rows = []
        for d in docs:
            table_rows.append({
                "Document ID": d["document_id"],
                "Filename": d["original_filename"],
                "Type": d["file_type"].upper(),
                "Size (KB)": round(d["file_size_bytes"] / 1024, 1),
                "Classification": d["classification"].upper(),
                "Uploaded By": d["uploaded_by"],
                "Registered At": d["upload_date"][:19].replace("T", " "),
                "DLP Findings": d["dlp_findings_count"],
            })

        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        section_header("🔐", "Authorized Document Operations")

        doc_ids = [d["document_id"] for d in docs]
        sel_doc_id = st.selectbox("Select Target Document for Operation:", doc_ids)

        c_view, c_dlp, c_del = st.columns(3)

        with c_view:
            if st.button("📖 Read Content (Gateway Authorization)", use_container_width=True):
                with st.spinner("Submitting READ_DOCUMENT to ExecutionGateway..."):
                    allowed, content_or_err, cls_val, decision = default_document_service.get_document_content(
                        document_id=sel_doc_id,
                        requesting_user_id=current_user["user_id"],
                    )

                if allowed:
                    st.markdown(
                        f"""
                        <div class="ag-card ag-card-glow-green" style="margin-top:10px;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <h4 style="color:#51FAAA; margin:0;">✓ Access Granted ({_esc(decision)})</h4>
                                <span>{classification_badge(cls_val)}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.text_area("Authorized Document Content:", content_or_err, height=200)
                else:
                    st.markdown(
                        f"""
                        <div class="ag-card ag-card-glow-red" style="margin-top:10px;">
                            <h4 style="color:#FF6B6B; margin:0 0 6px 0;">⛔ Access Denied ({_esc(decision)})</h4>
                            <p style="color:#FF8E8E; margin:0;">{_esc(content_or_err)}</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        with c_dlp:
            if st.button("🔍 View DLP Findings Report", use_container_width=True):
                cur_doc = next((d for d in docs if d["document_id"] == sel_doc_id), None)
                if cur_doc and cur_doc.get("dlp_findings"):
                    st.markdown(
                        f"""
                        <div class="ag-card ag-card-glow-amber" style="margin-top:10px;">
                            <h4 style="color:#FFB347; margin:0 0 4px 0;">⚠️ Sensitive Data Findings for {_esc(sel_doc_id)}</h4>
                            <p><b>{len(cur_doc['dlp_findings'])}</b> sensitive pattern(s) identified by the Module 02 DLP Engine.</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.dataframe(pd.DataFrame(cur_doc["dlp_findings"]), use_container_width=True)
                else:
                    st.markdown(
                        f"""
                        <div class="ag-card ag-card-glow-green" style="margin-top:10px;">
                            <h4 style="color:#51FAAA; margin:0;">✓ Zero DLP Violations</h4>
                            <p>No sensitive credentials, PII, or financial patterns detected in <code>{_esc(sel_doc_id)}</code>.</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        with c_del:
            if st.button("🗑️ Delete Document (Admin Only)", use_container_width=True):
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

    # -------------------------------------------------------------
    # TAB 2: UPLOAD & DLP SCAN
    # -------------------------------------------------------------
    with tab_upload:
        section_header("📤", "Ingest New Document into Secure Vault")
        st.markdown(
            "<p style='color:#A6ABC5; font-size:0.88rem;'>Files are stored in isolated vault storage and inspected by the <b>Module 02 DLP Engine</b> "
            "using entropy calculation, regular expressions, and keyword heuristics for automated classification.</p>",
            unsafe_allow_html=True,
        )

        col_f, col_meta = st.columns([3, 2])

        with col_f:
            uploaded_file = st.file_uploader("Select Document to Ingest:", type=["txt", "pdf", "docx"])

        with col_meta:
            doc_desc = st.text_input("Document Description:", placeholder="e.g. Q4 Financial projections")
            class_choice = st.selectbox(
                "Classification Assignment:",
                ["AUTO (Scan via Module 02 DLP)", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
                help="AUTO uses the DLP engine's sensitivity heuristic. Manual selection overrides subject to admin role.",
            )

        if st.button("🔒 Ingest, Scan & Classify Document", use_container_width=True):
            if not uploaded_file:
                st.warning("Please select a valid document file.")
                return

            file_bytes = uploaded_file.read()
            override_cls = None
            if class_choice != "AUTO (Scan via Module 02 DLP)":
                override_cls = Classification(class_choice.lower())

            with st.spinner("Executing Module 02 DLP regex and keyword classification scan..."):
                success, msg, res_dict = default_document_service.upload_document(
                    filename=uploaded_file.name,
                    file_bytes=file_bytes,
                    uploaded_by=current_user["user_id"],
                    user_role=current_user["role"],
                    description=doc_desc,
                    override_classification=override_cls,
                )

            if success:
                st.markdown(
                    f"""
                    <div class="ag-card ag-card-glow-green" style="margin-top:12px;">
                        <h4 style="color:#51FAAA; margin:0 0 6px 0;">✓ Document Ingestion Successful</h4>
                        <p style="color:#E2E8F0; margin-bottom:8px;">{_esc(msg)}</p>
                        <div style="display:flex; gap:16px; font-size:0.85rem; color:#A6ABC5;">
                            <span><b>Vault ID:</b> <code>{_esc(res_dict['document_id'])}</code></span>
                            <span><b>Assigned Label:</b> {classification_badge(res_dict['classification'])}</span>
                            <span><b>DLP Recommendation:</b> {classification_badge(res_dict['suggested_classification'])}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                findings = res_dict.get("dlp_findings", [])
                if findings:
                    st.warning(f"⚠️ {len(findings)} Sensitive Data Pattern(s) Identified by DLP:")
                    findings_df = pd.DataFrame(findings)
                    st.dataframe(findings_df[["category", "severity", "confidence", "line", "redacted"]], use_container_width=True)
                else:
                    st.info("✅ Clean Scan: No credentials, tokens, or PII detected.")
            else:
                st.error(f"Ingestion failed: {msg}")
