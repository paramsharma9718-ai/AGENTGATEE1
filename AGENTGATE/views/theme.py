"""Theme, Styling and Visual Components for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Theme: Premium Cybersecurity Dark — Midnight Navy, Purple & Emerald Glow
"""

import html as html_module
import streamlit as st


# ---------------------------------------------------------------------------
# Color Tokens
# ---------------------------------------------------------------------------
COLORS = {
    # Backgrounds
    "bg_primary": "#0C0E1D",
    "bg_secondary": "#111426",
    "bg_elevated": "#171A2E",
    "bg_card": "#191B32",
    "bg_card_hover": "#1E2040",
    "bg_sidebar": "#0A0C1A",
    # Purple / Indigo
    "purple_primary": "#616083",
    "purple_deep": "#211F36",
    "purple_accent": "#8B7CFF",
    "purple_soft": "#A78BFA",
    "magenta_soft": "#FF81FF",
    # Emerald / Green
    "emerald": "#51FAAA",
    "emerald_secondary": "#23D9A1",
    "emerald_dark": "#102B27",
    "emerald_muted": "#10B981",
    # Text
    "text_primary": "#F5F6FF",
    "text_secondary": "#A6ABC5",
    "text_muted": "#777D9B",
    "text_heading": "#EAECFF",
    # Borders
    "border_subtle": "rgba(139, 124, 255, 0.12)",
    "border_card": "rgba(139, 124, 255, 0.15)",
    "border_hover": "rgba(139, 124, 255, 0.35)",
    # Decision semantics
    "allow": "#51FAAA",
    "allow_bg": "rgba(81, 250, 170, 0.08)",
    "allow_border": "rgba(81, 250, 170, 0.3)",
    "block": "#FF6B6B",
    "block_bg": "rgba(255, 107, 107, 0.08)",
    "block_border": "rgba(255, 107, 107, 0.3)",
    "approval": "#FFB347",
    "approval_bg": "rgba(255, 179, 71, 0.08)",
    "approval_border": "rgba(255, 179, 71, 0.3)",
    "pending": "#8B7CFF",
    "pending_bg": "rgba(139, 124, 255, 0.08)",
    "pending_border": "rgba(139, 124, 255, 0.3)",
    # Classification
    "cls_public": "#60A5FA",
    "cls_internal": "#A78BFA",
    "cls_confidential": "#FFB347",
    "cls_restricted": "#FF6B6B",
}


def _esc(value) -> str:
    """Safely escape a value for embedding in HTML."""
    return html_module.escape(str(value))


def apply_theme():
    """Inject comprehensive premium dark cybersecurity theme CSS."""
    st.markdown(
        """
        <style>
            /* ============================================================
               GOOGLE FONTS — Inter
               ============================================================ */
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

            /* ============================================================
               KEYFRAME ANIMATIONS
               ============================================================ */
            @keyframes ag-fade-in-up {
                from { opacity: 0; transform: translateY(18px); }
                to   { opacity: 1; transform: translateY(0); }
            }
            @keyframes ag-fade-in {
                from { opacity: 0; }
                to   { opacity: 1; }
            }
            @keyframes ag-slide-in-left {
                from { opacity: 0; transform: translateX(-16px); }
                to   { opacity: 1; transform: translateX(0); }
            }
            @keyframes ag-pulse-glow {
                0%, 100% { box-shadow: 0 0 8px rgba(81, 250, 170, 0.15); }
                50%      { box-shadow: 0 0 20px rgba(81, 250, 170, 0.3); }
            }
            @keyframes ag-shimmer {
                0%   { background-position: -200% 0; }
                100% { background-position: 200% 0; }
            }
            @keyframes ag-border-glow {
                0%, 100% { border-color: rgba(139, 124, 255, 0.15); }
                50%      { border-color: rgba(139, 124, 255, 0.35); }
            }

            @media (prefers-reduced-motion: reduce) {
                *, *::before, *::after {
                    animation-duration: 0.01ms !important;
                    animation-iteration-count: 1 !important;
                    transition-duration: 0.01ms !important;
                }
            }

            /* ============================================================
               BASE APPLICATION
               ============================================================ */
            .stApp {
                background: linear-gradient(165deg, #0C0E1D 0%, #0E1025 40%, #10112A 100%) !important;
                color: #F5F6FF;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            }
            .stApp::before {
                content: '';
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background:
                    radial-gradient(ellipse 800px 600px at 15% 10%, rgba(139, 124, 255, 0.04) 0%, transparent 70%),
                    radial-gradient(ellipse 600px 500px at 85% 80%, rgba(81, 250, 170, 0.03) 0%, transparent 70%);
                pointer-events: none;
                z-index: 0;
            }

            /* ============================================================
               TYPOGRAPHY
               ============================================================ */
            h1 {
                color: #EAECFF !important;
                font-weight: 800 !important;
                letter-spacing: -0.03em;
                font-size: 1.85rem !important;
            }
            h2 {
                color: #EAECFF !important;
                font-weight: 700 !important;
                letter-spacing: -0.02em;
                font-size: 1.5rem !important;
            }
            h3 {
                color: #E0E2F5 !important;
                font-weight: 600 !important;
                letter-spacing: -0.01em;
                font-size: 1.2rem !important;
            }
            h4 {
                color: #D0D3E8 !important;
                font-weight: 600 !important;
                font-size: 1.05rem !important;
            }
            p, li, span, div {
                line-height: 1.6;
            }

            /* ============================================================
               SIDEBAR
               ============================================================ */
            [data-testid="stSidebar"] {
                background: linear-gradient(180deg, #0A0C1A 0%, #0D0F22 100%) !important;
                border-right: 1px solid rgba(139, 124, 255, 0.1) !important;
            }
            [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
                color: #A6ABC5;
            }
            /* Sidebar radio nav styling */
            [data-testid="stSidebar"] .stRadio > label {
                display: none !important;
            }
            [data-testid="stSidebar"] .stRadio > div {
                gap: 2px !important;
            }
            [data-testid="stSidebar"] .stRadio > div > label {
                background: transparent !important;
                border: 1px solid transparent !important;
                border-radius: 10px !important;
                padding: 9px 14px !important;
                margin: 1px 0 !important;
                color: #A6ABC5 !important;
                font-weight: 500 !important;
                font-size: 0.88rem !important;
                cursor: pointer !important;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
            }
            [data-testid="stSidebar"] .stRadio > div > label:hover {
                background: rgba(139, 124, 255, 0.08) !important;
                border-color: rgba(139, 124, 255, 0.15) !important;
                color: #D0D3E8 !important;
            }
            [data-testid="stSidebar"] .stRadio > div > label[data-checked="true"],
            [data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
                background: linear-gradient(135deg, rgba(81, 250, 170, 0.1) 0%, rgba(139, 124, 255, 0.08) 100%) !important;
                border-color: rgba(81, 250, 170, 0.3) !important;
                color: #51FAAA !important;
                font-weight: 600 !important;
                box-shadow: 0 0 12px rgba(81, 250, 170, 0.08) !important;
            }
            [data-testid="stSidebar"] hr {
                border-color: rgba(139, 124, 255, 0.1) !important;
                margin: 12px 0 !important;
            }

            /* ============================================================
               MAIN CONTENT AREA
               ============================================================ */
            .stMainBlockContainer, [data-testid="stAppViewBlockContainer"] {
                padding-top: 2rem !important;
            }
            section[data-testid="stMain"] {
                background: transparent !important;
            }
            hr {
                border-color: rgba(139, 124, 255, 0.08) !important;
            }

            /* ============================================================
               CUSTOM CARD SYSTEM
               ============================================================ */
            .ag-card {
                background: linear-gradient(135deg, rgba(25, 27, 50, 0.95) 0%, rgba(23, 26, 46, 0.9) 100%);
                border: 1px solid rgba(139, 124, 255, 0.12);
                border-radius: 16px;
                padding: 22px 24px;
                margin-bottom: 16px;
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(139, 124, 255, 0.05);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                animation: ag-fade-in-up 0.45s ease-out both;
                position: relative;
                overflow: hidden;
            }
            .ag-card::before {
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0;
                height: 1px;
                background: linear-gradient(90deg, transparent, rgba(139, 124, 255, 0.2), transparent);
            }
            .ag-card:hover {
                border-color: rgba(139, 124, 255, 0.25);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(139, 124, 255, 0.06);
                transform: translateY(-2px);
            }
            .ag-card h3 { margin: 0 0 8px 0; }
            .ag-card p { color: #A6ABC5; margin: 4px 0; font-size: 0.92rem; }
            .ag-card code {
                background: rgba(139, 124, 255, 0.1);
                border: 1px solid rgba(139, 124, 255, 0.15);
                border-radius: 6px;
                padding: 2px 8px;
                font-size: 0.82rem;
                color: #C4BFFF;
            }

            /* Card glow variants */
            .ag-card-glow-green {
                border-left: 3px solid #51FAAA;
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), inset 0 0 30px rgba(81, 250, 170, 0.03);
            }
            .ag-card-glow-red {
                border-left: 3px solid #FF6B6B;
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), inset 0 0 30px rgba(255, 107, 107, 0.03);
            }
            .ag-card-glow-amber {
                border-left: 3px solid #FFB347;
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), inset 0 0 30px rgba(255, 179, 71, 0.03);
            }
            .ag-card-glow-blue {
                border-left: 3px solid #60A5FA;
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), inset 0 0 30px rgba(96, 165, 250, 0.03);
            }
            .ag-card-glow-purple {
                border-left: 3px solid #8B7CFF;
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), inset 0 0 30px rgba(139, 124, 255, 0.03);
            }

            /* ============================================================
               KPI / METRIC CARDS
               ============================================================ */
            .ag-kpi {
                background: linear-gradient(135deg, rgba(25, 27, 50, 0.95) 0%, rgba(23, 26, 46, 0.85) 100%);
                border: 1px solid rgba(139, 124, 255, 0.12);
                border-radius: 16px;
                padding: 20px 22px;
                text-align: left;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            .ag-kpi::before {
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0;
                height: 1px;
                background: linear-gradient(90deg, transparent, rgba(139, 124, 255, 0.15), transparent);
            }
            .ag-kpi:hover {
                border-color: rgba(139, 124, 255, 0.25);
                transform: translateY(-3px);
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
            }
            .ag-kpi-icon {
                font-size: 1.6rem;
                margin-bottom: 8px;
                display: inline-block;
            }
            .ag-kpi-label {
                font-size: 0.76rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #777D9B;
                margin-bottom: 6px;
            }
            .ag-kpi-value {
                font-size: 2rem;
                font-weight: 800;
                letter-spacing: -0.02em;
                line-height: 1.1;
                margin-bottom: 4px;
            }
            .ag-kpi-sub {
                font-size: 0.78rem;
                color: #777D9B;
            }

            /* KPI color variants */
            .ag-kpi-emerald .ag-kpi-value { color: #51FAAA; }
            .ag-kpi-emerald { border-bottom: 2px solid rgba(81, 250, 170, 0.3); }
            .ag-kpi-emerald:hover { box-shadow: 0 8px 30px rgba(0,0,0,0.35), 0 0 15px rgba(81, 250, 170, 0.06); }

            .ag-kpi-red .ag-kpi-value { color: #FF6B6B; }
            .ag-kpi-red { border-bottom: 2px solid rgba(255, 107, 107, 0.3); }
            .ag-kpi-red:hover { box-shadow: 0 8px 30px rgba(0,0,0,0.35), 0 0 15px rgba(255, 107, 107, 0.06); }

            .ag-kpi-amber .ag-kpi-value { color: #FFB347; }
            .ag-kpi-amber { border-bottom: 2px solid rgba(255, 179, 71, 0.3); }

            .ag-kpi-purple .ag-kpi-value { color: #A78BFA; }
            .ag-kpi-purple { border-bottom: 2px solid rgba(139, 124, 255, 0.3); }

            .ag-kpi-blue .ag-kpi-value { color: #60A5FA; }
            .ag-kpi-blue { border-bottom: 2px solid rgba(96, 165, 250, 0.3); }

            /* ============================================================
               BADGES
               ============================================================ */
            .ag-badge {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                padding: 4px 12px;
                border-radius: 8px;
                font-size: 0.72rem;
                font-weight: 700;
                letter-spacing: 0.06em;
                text-transform: uppercase;
                white-space: nowrap;
                transition: all 0.2s ease;
            }
            .ag-badge-allow {
                background: rgba(81, 250, 170, 0.1);
                color: #51FAAA;
                border: 1px solid rgba(81, 250, 170, 0.25);
            }
            .ag-badge-block {
                background: rgba(255, 107, 107, 0.1);
                color: #FF6B6B;
                border: 1px solid rgba(255, 107, 107, 0.25);
            }
            .ag-badge-approval {
                background: rgba(255, 179, 71, 0.1);
                color: #FFB347;
                border: 1px solid rgba(255, 179, 71, 0.25);
            }
            .ag-badge-pending {
                background: rgba(139, 124, 255, 0.1);
                color: #A78BFA;
                border: 1px solid rgba(139, 124, 255, 0.25);
            }
            .ag-badge-success {
                background: rgba(81, 250, 170, 0.1);
                color: #51FAAA;
                border: 1px solid rgba(81, 250, 170, 0.25);
            }

            /* Classification badges */
            .ag-badge-public {
                background: rgba(96, 165, 250, 0.1);
                color: #60A5FA;
                border: 1px solid rgba(96, 165, 250, 0.25);
            }
            .ag-badge-internal {
                background: rgba(167, 139, 250, 0.1);
                color: #A78BFA;
                border: 1px solid rgba(167, 139, 250, 0.25);
            }
            .ag-badge-confidential {
                background: rgba(255, 179, 71, 0.1);
                color: #FFB347;
                border: 1px solid rgba(255, 179, 71, 0.25);
            }
            .ag-badge-restricted {
                background: rgba(255, 107, 107, 0.12);
                color: #FF6B6B;
                border: 1px solid rgba(255, 107, 107, 0.3);
            }

            /* ============================================================
               BUTTONS
               ============================================================ */
            .stButton > button {
                background: linear-gradient(135deg, #8B7CFF 0%, #6C5CE7 100%) !important;
                color: #FFFFFF !important;
                border: none !important;
                border-radius: 12px !important;
                padding: 10px 22px !important;
                font-weight: 600 !important;
                font-size: 0.88rem !important;
                letter-spacing: 0.01em;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
                box-shadow: 0 2px 12px rgba(139, 124, 255, 0.2) !important;
            }
            .stButton > button:hover {
                transform: translateY(-2px) !important;
                box-shadow: 0 6px 24px rgba(139, 124, 255, 0.35) !important;
                background: linear-gradient(135deg, #9D8FFF 0%, #7C6CF7 100%) !important;
            }
            .stButton > button:active {
                transform: translateY(0) !important;
            }
            .stButton > button:disabled {
                opacity: 0.4 !important;
                cursor: not-allowed !important;
                transform: none !important;
                box-shadow: none !important;
            }

            /* ============================================================
               FORM INPUTS
               ============================================================ */
            .stTextInput > div > div > input,
            .stTextArea > div > div > textarea,
            .stSelectbox > div > div > div {
                background-color: #111426 !important;
                border: 1px solid rgba(139, 124, 255, 0.15) !important;
                border-radius: 10px !important;
                color: #F5F6FF !important;
                transition: border-color 0.25s ease !important;
            }
            .stTextInput > div > div > input:focus,
            .stTextArea > div > div > textarea:focus {
                border-color: rgba(139, 124, 255, 0.4) !important;
                box-shadow: 0 0 0 2px rgba(139, 124, 255, 0.1) !important;
            }

            /* ============================================================
               METRICS (Streamlit native)
               ============================================================ */
            [data-testid="stMetricValue"] {
                color: #A78BFA !important;
                font-size: 2rem !important;
                font-weight: 800 !important;
            }
            [data-testid="stMetricLabel"] {
                color: #777D9B !important;
            }

            /* ============================================================
               DATAFRAMES / TABLES
               ============================================================ */
            .stDataFrame {
                border-radius: 12px !important;
                overflow: hidden !important;
            }
            [data-testid="stDataFrameResizable"] {
                border: 1px solid rgba(139, 124, 255, 0.12) !important;
                border-radius: 12px !important;
            }

            /* ============================================================
               TABS
               ============================================================ */
            .stTabs [data-baseweb="tab-list"] {
                gap: 4px;
                background: rgba(17, 20, 38, 0.6);
                border-radius: 12px;
                padding: 4px;
                border: 1px solid rgba(139, 124, 255, 0.08);
            }
            .stTabs [data-baseweb="tab"] {
                border-radius: 10px !important;
                padding: 8px 18px !important;
                color: #777D9B !important;
                font-weight: 500 !important;
                font-size: 0.85rem !important;
                transition: all 0.25s ease !important;
            }
            .stTabs [data-baseweb="tab"]:hover {
                color: #A6ABC5 !important;
                background: rgba(139, 124, 255, 0.06) !important;
            }
            .stTabs [aria-selected="true"] {
                background: rgba(139, 124, 255, 0.12) !important;
                color: #C4BFFF !important;
                font-weight: 600 !important;
            }
            .stTabs [data-baseweb="tab-highlight"] {
                background-color: #8B7CFF !important;
            }
            .stTabs [data-baseweb="tab-border"] {
                display: none;
            }

            /* ============================================================
               EXPANDERS
               ============================================================ */
            .streamlit-expanderHeader {
                background: rgba(17, 20, 38, 0.5) !important;
                border: 1px solid rgba(139, 124, 255, 0.1) !important;
                border-radius: 12px !important;
                color: #A6ABC5 !important;
                font-weight: 500 !important;
            }

            /* ============================================================
               ALERTS (st.success, st.error, st.warning, st.info)
               ============================================================ */
            .stAlert {
                border-radius: 12px !important;
                border: 1px solid rgba(139, 124, 255, 0.1) !important;
            }
            [data-testid="stNotification"] {
                border-radius: 12px !important;
            }

            /* ============================================================
               FILE UPLOADER
               ============================================================ */
            [data-testid="stFileUploader"] {
                border-radius: 12px !important;
            }
            [data-testid="stFileUploader"] section {
                border: 2px dashed rgba(139, 124, 255, 0.2) !important;
                border-radius: 12px !important;
                background: rgba(17, 20, 38, 0.4) !important;
                transition: all 0.3s ease !important;
            }
            [data-testid="stFileUploader"] section:hover {
                border-color: rgba(139, 124, 255, 0.4) !important;
                background: rgba(17, 20, 38, 0.6) !important;
            }

            /* ============================================================
               SPINNER
               ============================================================ */
            .stSpinner > div {
                border-top-color: #8B7CFF !important;
            }

            /* ============================================================
               PAGE HEADER COMPONENT
               ============================================================ */
            .ag-page-header {
                padding: 8px 0 24px 0;
                animation: ag-fade-in-up 0.5s ease-out both;
            }
            .ag-page-header h2 {
                margin: 0 0 6px 0;
                font-size: 1.6rem !important;
            }
            .ag-page-header p {
                color: #777D9B;
                font-size: 0.92rem;
                margin: 0;
                max-width: 700px;
            }

            /* ============================================================
               SECTION HEADER
               ============================================================ */
            .ag-section-header {
                display: flex;
                align-items: center;
                gap: 10px;
                margin: 24px 0 16px 0;
                padding-bottom: 10px;
                border-bottom: 1px solid rgba(139, 124, 255, 0.08);
                animation: ag-fade-in 0.4s ease-out both;
            }
            .ag-section-header h4 {
                margin: 0 !important;
                font-size: 1.05rem !important;
            }
            .ag-section-header .ag-section-icon {
                font-size: 1.15rem;
            }

            /* ============================================================
               EMPTY STATE
               ============================================================ */
            .ag-empty-state {
                text-align: center;
                padding: 40px 20px;
                color: #777D9B;
                animation: ag-fade-in 0.5s ease-out both;
            }
            .ag-empty-state .ag-empty-icon {
                font-size: 2.5rem;
                margin-bottom: 12px;
                opacity: 0.5;
            }
            .ag-empty-state .ag-empty-title {
                font-size: 1.05rem;
                font-weight: 600;
                color: #A6ABC5;
                margin-bottom: 6px;
            }
            .ag-empty-state .ag-empty-desc {
                font-size: 0.85rem;
                max-width: 400px;
                margin: 0 auto;
            }

            /* ============================================================
               STATUS INDICATOR
               ============================================================ */
            .ag-status-dot {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                margin-right: 6px;
                animation: ag-pulse-glow 2.5s ease-in-out infinite;
            }
            .ag-status-dot-green { background: #51FAAA; box-shadow: 0 0 6px rgba(81,250,170,0.4); }
            .ag-status-dot-red { background: #FF6B6B; box-shadow: 0 0 6px rgba(255,107,107,0.4); }
            .ag-status-dot-amber { background: #FFB347; box-shadow: 0 0 6px rgba(255,179,71,0.4); }

            /* ============================================================
               SCROLLBAR
               ============================================================ */
            ::-webkit-scrollbar { width: 6px; height: 6px; }
            ::-webkit-scrollbar-track { background: #0C0E1D; }
            ::-webkit-scrollbar-thumb {
                background: rgba(139, 124, 255, 0.2);
                border-radius: 3px;
            }
            ::-webkit-scrollbar-thumb:hover { background: rgba(139, 124, 255, 0.35); }

            /* ============================================================
               ANIMATION DELAYS FOR STAGGERED ENTRANCE
               ============================================================ */
            .ag-delay-1 { animation-delay: 0.08s; }
            .ag-delay-2 { animation-delay: 0.16s; }
            .ag-delay-3 { animation-delay: 0.24s; }
            .ag-delay-4 { animation-delay: 0.32s; }
            .ag-delay-5 { animation-delay: 0.40s; }
            .ag-delay-6 { animation-delay: 0.48s; }

            /* ============================================================
               EVENT ROW (for audit/activity feeds)
               ============================================================ */
            .ag-event-row {
                display: flex;
                align-items: center;
                gap: 14px;
                padding: 12px 16px;
                border-radius: 10px;
                background: rgba(17, 20, 38, 0.4);
                border: 1px solid rgba(139, 124, 255, 0.06);
                margin-bottom: 6px;
                transition: all 0.2s ease;
                animation: ag-fade-in-up 0.4s ease-out both;
                font-size: 0.88rem;
            }
            .ag-event-row:hover {
                background: rgba(17, 20, 38, 0.7);
                border-color: rgba(139, 124, 255, 0.12);
            }
            .ag-event-time {
                color: #777D9B;
                font-size: 0.78rem;
                white-space: nowrap;
                min-width: 130px;
                font-variant-numeric: tabular-nums;
            }
            .ag-event-user {
                color: #A6ABC5;
                font-weight: 500;
                min-width: 80px;
            }
            .ag-event-op {
                color: #C4BFFF;
                font-weight: 600;
                font-size: 0.8rem;
                min-width: 110px;
            }
            .ag-event-resource {
                color: #A6ABC5;
                font-size: 0.82rem;
                flex: 1;
            }

            /* ============================================================
               INTEGRITY BANNER
               ============================================================ */
            .ag-integrity-banner {
                display: flex;
                align-items: center;
                gap: 14px;
                padding: 14px 20px;
                border-radius: 14px;
                animation: ag-fade-in-up 0.5s ease-out both;
            }
            .ag-integrity-ok {
                background: linear-gradient(135deg, rgba(81, 250, 170, 0.06) 0%, rgba(35, 217, 161, 0.03) 100%);
                border: 1px solid rgba(81, 250, 170, 0.2);
            }
            .ag-integrity-fail {
                background: linear-gradient(135deg, rgba(255, 107, 107, 0.06) 0%, rgba(239, 68, 68, 0.03) 100%);
                border: 1px solid rgba(255, 107, 107, 0.2);
            }
            .ag-integrity-icon { font-size: 1.5rem; }
            .ag-integrity-text h4 { margin: 0 0 2px 0 !important; font-size: 0.95rem !important; }
            .ag-integrity-text p { margin: 0; font-size: 0.82rem; color: #A6ABC5; }

        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Reusable HTML Component Helpers
# ---------------------------------------------------------------------------

def page_header(icon: str, title: str, subtitle: str) -> None:
    """Render a consistent page header with animation."""
    st.markdown(
        f"""
        <div class="ag-page-header">
            <h2>{icon} {_esc(title)}</h2>
            <p>{_esc(subtitle)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(icon: str, title: str) -> None:
    """Render a section divider with icon and title."""
    st.markdown(
        f"""
        <div class="ag-section-header">
            <span class="ag-section-icon">{icon}</span>
            <h4>{_esc(title)}</h4>
        </div>
        """,
        unsafe_allow_html=True,
    )


def kpi_card(icon: str, label: str, value, variant: str = "purple", sub: str = "", delay: int = 0) -> str:
    """Return HTML for a KPI metric card. Caller wraps in st.markdown(..., unsafe_allow_html=True)."""
    delay_cls = f"ag-delay-{delay}" if delay else ""
    return f"""
    <div class="ag-kpi ag-kpi-{_esc(variant)} {delay_cls}" style="animation: ag-fade-in-up 0.45s ease-out both;">
        <div class="ag-kpi-icon">{icon}</div>
        <div class="ag-kpi-label">{_esc(label)}</div>
        <div class="ag-kpi-value">{_esc(str(value))}</div>
        <div class="ag-kpi-sub">{_esc(sub)}</div>
    </div>
    """


def empty_state(icon: str, title: str, description: str) -> None:
    """Render a styled empty-state placeholder."""
    st.markdown(
        f"""
        <div class="ag-empty-state">
            <div class="ag-empty-icon">{icon}</div>
            <div class="ag-empty-title">{_esc(title)}</div>
            <div class="ag-empty-desc">{_esc(description)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def integrity_banner(is_valid: bool, total_events: int, head_hash: str = "", error_msg: str = "") -> None:
    """Render the SHA-256 chain integrity banner."""
    if is_valid:
        st.markdown(
            f"""
            <div class="ag-integrity-banner ag-integrity-ok">
                <div class="ag-integrity-icon">🔒</div>
                <div class="ag-integrity-text">
                    <h4 style="color:#51FAAA;">Cryptographic Hash Chain Intact</h4>
                    <p>All {_esc(str(total_events))} audit events verified via SHA-256 tamper-evident chaining. Zero tampering detected.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="ag-integrity-banner ag-integrity-fail">
                <div class="ag-integrity-icon">🚨</div>
                <div class="ag-integrity-text">
                    <h4 style="color:#FF6B6B;">SECURITY ALERT: AUDIT TAMPERING DETECTED</h4>
                    <p>{_esc(error_msg)}</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def decision_badge(decision: str) -> str:
    """Return an HTML badge for an authorization decision."""
    dec = str(decision).upper()
    if "ALLOW" in dec:
        return f'<span class="ag-badge ag-badge-allow">● {_esc(dec)}</span>'
    elif "BLOCK" in dec:
        return f'<span class="ag-badge ag-badge-block">✕ {_esc(dec)}</span>'
    elif "APPROVAL" in dec:
        return f'<span class="ag-badge ag-badge-approval">⏳ {_esc(dec)}</span>'
    elif "PENDING" in dec:
        return f'<span class="ag-badge ag-badge-pending">◌ {_esc(dec)}</span>'
    return f'<span class="ag-badge">{_esc(dec)}</span>'


def classification_badge(classification: str) -> str:
    """Return an HTML badge for a document classification level."""
    cls = str(classification).upper()
    if "PUBLIC" in cls:
        return f'<span class="ag-badge ag-badge-public">◈ {_esc(cls)}</span>'
    elif "INTERNAL" in cls:
        return f'<span class="ag-badge ag-badge-internal">◈ {_esc(cls)}</span>'
    elif "CONFIDENTIAL" in cls:
        return f'<span class="ag-badge ag-badge-confidential">◈ {_esc(cls)}</span>'
    elif "RESTRICTED" in cls:
        return f'<span class="ag-badge ag-badge-restricted">◈ {_esc(cls)}</span>'
    return f'<span class="ag-badge">◈ {_esc(cls)}</span>'


def status_badge(status: str) -> str:
    """Return an HTML badge for a general status value."""
    s = str(status).upper()
    if s in ("SUCCESS", "COMPLETED"):
        return f'<span class="ag-badge ag-badge-success">✓ {_esc(s)}</span>'
    elif s in ("BLOCKED", "FAILED", "ERROR"):
        return f'<span class="ag-badge ag-badge-block">✕ {_esc(s)}</span>'
    elif s in ("PENDING", "PENDING_APPROVAL", "SUSPENDED"):
        return f'<span class="ag-badge ag-badge-pending">◌ {_esc(s)}</span>'
    elif s in ("RUNNING", "IN_PROGRESS"):
        return f'<span class="ag-badge ag-badge-approval">▸ {_esc(s)}</span>'
    return f'<span class="ag-badge">{_esc(s)}</span>'


def event_row(timestamp: str, user: str, operation: str, resource: str, decision_html: str, delay: int = 0) -> str:
    """Return HTML for a single event row in an activity feed."""
    delay_cls = f"ag-delay-{delay}" if delay else ""
    return f"""
    <div class="ag-event-row {delay_cls}">
        <span class="ag-event-time">{_esc(timestamp)}</span>
        <span class="ag-event-user">{_esc(user)}</span>
        <span class="ag-event-op">{_esc(operation)}</span>
        <span class="ag-event-resource">{_esc(resource)}</span>
        <span>{decision_html}</span>
    </div>
    """
