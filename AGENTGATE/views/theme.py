"""Theme, Styling and Visual Components for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)
Theme: Cyber Dark Navy & Blue/Purple Accent
"""

import html
import re
import streamlit as st


def apply_theme():
    """Inject custom CSS for modern dark-navy cybersecurity aesthetic."""
    st.markdown(
        """
        <style>
            /* ============================================================
               GOOGLE FONTS
               ============================================================ */
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

            /* ============================================================
               KEYFRAME ANIMATIONS
               ============================================================ */

            /* Animated gradient mesh background */
            @keyframes gradientShift {
                0%   { background-position: 0% 0%; }
                25%  { background-position: 100% 0%; }
                50%  { background-position: 100% 100%; }
                75%  { background-position: 0% 100%; }
                100% { background-position: 0% 0%; }
            }

            /* Fade-in from below */
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(24px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            /* Slide in from left */
            @keyframes slideInLeft {
                from {
                    opacity: 0;
                    transform: translateX(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }

            /* Pulse for status indicators */
            @keyframes pulse {
                0%, 100% { opacity: 1; transform: scale(1); }
                50%      { opacity: 0.6; transform: scale(1.15); }
            }

            /* Shimmer sweep for loading / highlights */
            @keyframes shimmer {
                0%   { background-position: -200% center; }
                100% { background-position: 200% center; }
            }

            /* Glow pulse for card borders on hover */
            @keyframes glowPulse {
                0%, 100% { box-shadow: 0 0 15px rgba(59, 130, 246, 0.15); }
                50%      { box-shadow: 0 0 30px rgba(99, 102, 241, 0.35); }
            }

            /* Breathing glow for logo */
            @keyframes breatheGlow {
                0%, 100% { text-shadow: 0 0 20px rgba(96, 165, 250, 0.4), 0 0 40px rgba(99, 102, 241, 0.15); }
                50%      { text-shadow: 0 0 30px rgba(96, 165, 250, 0.7), 0 0 60px rgba(99, 102, 241, 0.3); }
            }

            /* Gradient text shimmer */
            @keyframes textShimmer {
                0%   { background-position: 0% 50%; }
                50%  { background-position: 100% 50%; }
                100% { background-position: 0% 50%; }
            }

            /* ============================================================
               MAIN APP BACKGROUND — Animated Gradient Mesh
               ============================================================ */
            .stApp {
                background: linear-gradient(
                    135deg,
                    #030712 0%,
                    #0A0E1A 15%,
                    #0F0B2E 30%,
                    #0A0E1A 45%,
                    #071222 60%,
                    #100B28 75%,
                    #030712 100%
                );
                background-size: 400% 400%;
                animation: gradientShift 25s ease infinite;
                color: #F1F5F9;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            }

            /* ============================================================
               HIGH-CONTRAST TYPOGRAPHY BASE
               ============================================================ */
            h1, h2, h3, h4, h5, h6 {
                color: #FFFFFF !important;
                font-weight: 700;
                letter-spacing: -0.02em;
                font-family: 'Inter', sans-serif !important;
            }

            p, span, div, li {
                color: #E2E8F0;
            }

            strong, b {
                color: #FFFFFF !important;
                font-weight: 700 !important;
            }

            code {
                font-family: 'JetBrains Mono', monospace !important;
                color: #93C5FD !important;
                background: rgba(15, 23, 42, 0.85) !important;
                padding: 2px 7px !important;
                border-radius: 6px !important;
                border: 1px solid rgba(99, 102, 241, 0.25) !important;
                font-size: 0.88em !important;
            }

            pre, .stCodeBlock {
                font-family: 'JetBrains Mono', monospace !important;
            }

            /* Ensure text inside cards is always bright & legible */
            .ag-card p {
                color: #CBD5E1 !important;
                line-height: 1.6;
            }
            .ag-card strong, .ag-card b {
                color: #FFFFFF !important;
            }

            /* ============================================================
               MAIN CONTENT FADE-IN
               ============================================================ */
            .main .block-container {
                animation: fadeInUp 0.6s ease-out both;
            }

            /* ============================================================
               SIDEBAR — Glass Panel
               ============================================================ */
            [data-testid="stSidebar"] {
                background: rgba(10, 14, 26, 0.85) !important;
                backdrop-filter: blur(24px) saturate(1.4);
                -webkit-backdrop-filter: blur(24px) saturate(1.4);
                border-right: 1px solid rgba(99, 102, 241, 0.15) !important;
                box-shadow: 4px 0 30px rgba(0, 0, 0, 0.4);
            }

            [data-testid="stSidebar"] > div:first-child {
                animation: slideInLeft 0.5s ease-out both;
            }

            /* Sidebar radio / nav items */
            [data-testid="stSidebar"] .stRadio > div {
                gap: 4px !important;
            }

            [data-testid="stSidebar"] .stRadio label {
                background: rgba(15, 23, 42, 0.5) !important;
                border: 1px solid rgba(51, 65, 85, 0.35) !important;
                border-radius: 12px !important;
                padding: 10px 14px !important;
                margin: 0 !important;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                cursor: pointer;
            }

            [data-testid="stSidebar"] .stRadio label p,
            [data-testid="stSidebar"] .stRadio label span,
            .stRadio label p,
            .stRadio label span {
                color: #F1F5F9 !important;
                font-weight: 500 !important;
                font-size: 0.88rem !important;
            }

            [data-testid="stSidebar"] .stRadio label:hover {
                background: rgba(59, 130, 246, 0.15) !important;
                border-color: rgba(59, 130, 246, 0.45) !important;
                transform: translateX(4px);
                box-shadow: 0 0 20px rgba(59, 130, 246, 0.15);
            }

            [data-testid="stSidebar"] .stRadio label:hover p,
            [data-testid="stSidebar"] .stRadio label:hover span {
                color: #FFFFFF !important;
            }

            [data-testid="stSidebar"] .stRadio label[data-checked="true"],
            [data-testid="stSidebar"] .stRadio label:has(input:checked) {
                background: rgba(59, 130, 246, 0.2) !important;
                border-color: rgba(59, 130, 246, 0.6) !important;
                border-left: 3px solid #60A5FA !important;
                box-shadow: 0 0 25px rgba(59, 130, 246, 0.2),
                            inset 0 0 15px rgba(59, 130, 246, 0.08);
            }

            [data-testid="stSidebar"] .stRadio label[data-checked="true"] p,
            [data-testid="stSidebar"] .stRadio label:has(input:checked) p {
                color: #93C5FD !important;
                font-weight: 700 !important;
            }

            /* ============================================================
               GLASSMORPHISM CARDS
               ============================================================ */
            .ag-card {
                background: rgba(15, 23, 42, 0.6);
                backdrop-filter: blur(20px) saturate(1.3);
                -webkit-backdrop-filter: blur(20px) saturate(1.3);
                border: 1px solid rgba(99, 102, 241, 0.12);
                border-radius: 16px;
                padding: 22px;
                margin-bottom: 16px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3),
                            inset 0 1px 0 rgba(255, 255, 255, 0.04);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                animation: fadeInUp 0.5s ease-out both;
            }

            .ag-card:hover {
                transform: translateY(-2px) scale(1.01);
                border-color: rgba(99, 102, 241, 0.25);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4),
                            0 0 30px rgba(99, 102, 241, 0.1),
                            inset 0 1px 0 rgba(255, 255, 255, 0.06);
                animation: glowPulse 2s ease-in-out infinite;
            }

            /* Card glow accent variants */
            .ag-card-glow-blue {
                border-left: 3px solid #3B82F6;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3),
                            -4px 0 20px rgba(59, 130, 246, 0.08);
            }
            .ag-card-glow-green {
                border-left: 3px solid #10B981;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3),
                            -4px 0 20px rgba(16, 185, 129, 0.08);
            }
            .ag-card-glow-red {
                border-left: 3px solid #EF4444;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3),
                            -4px 0 20px rgba(239, 68, 68, 0.08);
            }
            .ag-card-glow-amber {
                border-left: 3px solid #F59E0B;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3),
                            -4px 0 20px rgba(245, 158, 11, 0.08);
            }

            /* ============================================================
               PILL BADGES — Glassmorphism
               ============================================================ */
            .ag-badge {
                display: inline-block;
                padding: 5px 14px;
                border-radius: 999px;
                font-size: 0.72rem;
                font-weight: 700;
                letter-spacing: 0.06em;
                text-transform: uppercase;
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                transition: all 0.3s ease;
                font-family: 'Inter', sans-serif;
            }

            .ag-badge-allow {
                background: rgba(16, 185, 129, 0.12);
                color: #34D399;
                border: 1px solid rgba(16, 185, 129, 0.35);
                box-shadow: 0 0 12px rgba(16, 185, 129, 0.15);
            }
            .ag-badge-block {
                background: rgba(239, 68, 68, 0.12);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.35);
                box-shadow: 0 0 12px rgba(239, 68, 68, 0.15);
            }
            .ag-badge-approval {
                background: rgba(245, 158, 11, 0.12);
                color: #FBBF24;
                border: 1px solid rgba(245, 158, 11, 0.35);
                box-shadow: 0 0 12px rgba(245, 158, 11, 0.15);
            }

            .ag-badge-public {
                background: rgba(59, 130, 246, 0.12);
                color: #60A5FA;
                border: 1px solid rgba(59, 130, 246, 0.35);
                box-shadow: 0 0 12px rgba(59, 130, 246, 0.12);
            }
            .ag-badge-internal {
                background: rgba(139, 92, 246, 0.12);
                color: #A78BFA;
                border: 1px solid rgba(139, 92, 246, 0.35);
                box-shadow: 0 0 12px rgba(139, 92, 246, 0.12);
            }
            .ag-badge-confidential {
                background: rgba(245, 158, 11, 0.12);
                color: #FBBF24;
                border: 1px solid rgba(245, 158, 11, 0.35);
                box-shadow: 0 0 12px rgba(245, 158, 11, 0.12);
            }
            .ag-badge-restricted {
                background: rgba(239, 68, 68, 0.15);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.4);
                box-shadow: 0 0 14px rgba(239, 68, 68, 0.15);
            }

            /* ============================================================
               BUTTONS — Gradient + Shimmer
               ============================================================ */
            .stButton>button {
                background: linear-gradient(135deg, #2563EB 0%, #7C3AED 50%, #4F46E5 100%);
                background-size: 200% 200%;
                color: white !important;
                border: none !important;
                border-radius: 12px;
                padding: 10px 22px;
                font-weight: 600;
                font-family: 'Inter', sans-serif;
                letter-spacing: 0.01em;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 4px 15px rgba(59, 130, 246, 0.2),
                            0 0 0 1px rgba(99, 102, 241, 0.15);
                position: relative;
                overflow: hidden;
            }

            .stButton>button::before {
                content: '';
                position: absolute;
                top: 0; left: -100%; right: 0; bottom: 0;
                width: 300%;
                background: linear-gradient(
                    90deg,
                    transparent 0%,
                    rgba(255,255,255,0.08) 50%,
                    transparent 100%
                );
                animation: shimmer 3s ease-in-out infinite;
            }

            .stButton>button:hover {
                transform: translateY(-2px) scale(1.02);
                box-shadow: 0 8px 25px rgba(59, 130, 246, 0.35),
                            0 0 40px rgba(99, 102, 241, 0.15),
                            0 0 0 1px rgba(99, 102, 241, 0.3);
                background-position: 100% 0%;
            }

            .stButton>button:active {
                transform: translateY(0) scale(0.99);
            }

            /* ============================================================
               METRICS — Gradient Text
               ============================================================ */
            [data-testid="stMetricValue"] {
                background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 50%, #818CF8 100%);
                background-size: 200% 200%;
                animation: textShimmer 4s ease infinite;
                -webkit-background-clip: text !important;
                -webkit-text-fill-color: transparent !important;
                background-clip: text !important;
                font-size: 2.1rem !important;
                font-weight: 800 !important;
                font-family: 'Inter', sans-serif !important;
            }

            [data-testid="stMetricDelta"] {
                font-family: 'Inter', sans-serif !important;
                font-weight: 600 !important;
            }

            /* Metric containers */
            [data-testid="stMetric"] {
                background: rgba(15, 23, 42, 0.5);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid rgba(99, 102, 241, 0.1);
                border-radius: 16px;
                padding: 18px;
                transition: all 0.3s ease;
            }

            [data-testid="stMetric"]:hover {
                border-color: rgba(99, 102, 241, 0.25);
                box-shadow: 0 0 20px rgba(99, 102, 241, 0.08);
            }

            /* ============================================================
               TABS — Glass Style
               ============================================================ */
            .stTabs [data-baseweb="tab-list"] {
                gap: 4px;
                background: rgba(15, 23, 42, 0.5);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border-radius: 16px;
                padding: 5px;
                border: 1px solid rgba(51, 65, 85, 0.3);
            }

            .stTabs [data-baseweb="tab"] {
                border-radius: 12px;
                padding: 10px 20px;
                font-weight: 600;
                font-family: 'Inter', sans-serif;
                color: #CBD5E1;
                transition: all 0.3s ease;
                border: none !important;
                background: transparent;
            }

            .stTabs [data-baseweb="tab"]:hover {
                color: #FFFFFF;
                background: rgba(59, 130, 246, 0.15);
            }

            .stTabs [aria-selected="true"] {
                background: rgba(59, 130, 246, 0.22) !important;
                color: #93C5FD !important;
                font-weight: 700 !important;
                border: 1px solid rgba(59, 130, 246, 0.45) !important;
                box-shadow: 0 0 15px rgba(59, 130, 246, 0.15);
            }

            .stTabs [data-baseweb="tab-highlight"] {
                background: transparent !important;
            }

            .stTabs [data-baseweb="tab-border"] {
                display: none !important;
            }

            /* ============================================================
               DATAFRAMES / TABLES — Glass
               ============================================================ */
            [data-testid="stDataFrame"],
            .stDataFrame {
                border-radius: 16px !important;
                overflow: hidden;
                border: 1px solid rgba(51, 65, 85, 0.3) !important;
            }

            [data-testid="stDataFrame"] > div {
                border-radius: 16px !important;
            }

            /* ============================================================
               TEXT INPUTS & FORM CONTROLS — High Contrast Glass
               ============================================================ */
            label, [data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p {
                color: #F1F5F9 !important;
                font-weight: 600 !important;
                font-size: 0.88rem !important;
                font-family: 'Inter', sans-serif !important;
            }

            .stTextInput input,
            .stTextArea textarea {
                background: #0F172A !important;
                color: #F8FAFC !important;
                border: 1px solid rgba(99, 102, 241, 0.35) !important;
                border-radius: 12px !important;
                font-size: 0.92rem !important;
                font-family: 'Inter', sans-serif !important;
            }

            .stTextInput input::placeholder,
            .stTextArea textarea::placeholder {
                color: #94A3B8 !important;
            }

            .stTextInput input:focus,
            .stTextArea textarea:focus {
                border-color: #3B82F6 !important;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25) !important;
                color: #FFFFFF !important;
            }

            /* Selectbox container */
            .stSelectbox [data-baseweb="select"] > div {
                background: #0F172A !important;
                color: #F8FAFC !important;
                border: 1px solid rgba(99, 102, 241, 0.35) !important;
                border-radius: 12px !important;
            }

            .stSelectbox [data-baseweb="select"] span {
                color: #F8FAFC !important;
                font-weight: 500 !important;
            }

            .stSelectbox svg {
                fill: #CBD5E1 !important;
            }

            /* BaseWeb Dropdown Menu / Popover (CRITICAL FOR SELECTBOX OPTIONS) */
            [data-baseweb="popover"],
            [data-baseweb="popover"] > div,
            [data-baseweb="menu"],
            ul[role="listbox"] {
                background: #0F172A !important;
                border: 1px solid rgba(99, 102, 241, 0.4) !important;
                border-radius: 12px !important;
                box-shadow: 0 12px 36px rgba(0, 0, 0, 0.7) !important;
            }

            li[role="option"] {
                background: transparent !important;
                color: #F1F5F9 !important;
                padding: 10px 14px !important;
            }

            li[role="option"]:hover,
            li[role="option"][aria-selected="true"] {
                background: rgba(59, 130, 246, 0.25) !important;
                color: #FFFFFF !important;
            }

            li[role="option"] span,
            li[role="option"] div,
            li[role="option"] p {
                color: #F1F5F9 !important;
            }

            /* ============================================================
               EXPANDERS — High Contrast Glass
               ============================================================ */
            [data-testid="stExpander"],
            details {
                background: rgba(15, 23, 42, 0.65) !important;
                border: 1px solid rgba(99, 102, 241, 0.25) !important;
                border-radius: 14px !important;
                margin-bottom: 12px !important;
            }

            [data-testid="stExpander"] summary,
            details summary {
                color: #F8FAFC !important;
                font-weight: 600 !important;
                padding: 12px 16px !important;
            }

            [data-testid="stExpander"] summary p,
            [data-testid="stExpander"] summary span,
            [data-testid="stExpander"] summary div {
                color: #F8FAFC !important;
                font-weight: 600 !important;
            }

            [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
                color: #E2E8F0 !important;
                padding: 16px !important;
                background: rgba(10, 14, 26, 0.4) !important;
                border-radius: 0 0 14px 14px !important;
            }

            /* Code blocks */
            .stCodeBlock,
            .stCodeBlock pre,
            [data-testid="stCodeBlock"],
            [data-testid="stCodeBlock"] pre {
                background: #060913 !important;
                border: 1px solid rgba(99, 102, 241, 0.3) !important;
                border-radius: 12px !important;
            }

            .stCodeBlock code,
            .stCodeBlock span,
            [data-testid="stCodeBlock"] code {
                color: #E2E8F0 !important;
                background: transparent !important;
                border: none !important;
            }

            /* ============================================================
               CUSTOM SCROLLBAR
               ============================================================ */
            ::-webkit-scrollbar {
                width: 6px;
                height: 6px;
            }
            ::-webkit-scrollbar-track {
                background: rgba(15, 23, 42, 0.3);
                border-radius: 10px;
            }
            ::-webkit-scrollbar-thumb {
                background: rgba(99, 102, 241, 0.25);
                border-radius: 10px;
                transition: background 0.3s ease;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: rgba(99, 102, 241, 0.45);
            }

            /* ============================================================
               CONTAINERS / COLUMNS — Glass
               ============================================================ */
            [data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"] {
                gap: 16px;
            }

            /* ============================================================
               DIVIDERS
               ============================================================ */
            hr {
                border: none !important;
                height: 1px !important;
                background: linear-gradient(90deg,
                    transparent 0%,
                    rgba(99, 102, 241, 0.25) 50%,
                    transparent 100%
                ) !important;
                margin: 20px 0 !important;
            }

            /* ============================================================
               MULTISELECT TAGS
               ============================================================ */
            .stMultiSelect [data-baseweb="tag"] {
                background: rgba(59, 130, 246, 0.15) !important;
                border: 1px solid rgba(59, 130, 246, 0.3) !important;
                border-radius: 999px !important;
                color: #60A5FA !important;
            }

            /* ============================================================
               PROGRESS BARS
               ============================================================ */
            .stProgress > div > div > div {
                background: linear-gradient(90deg, #3B82F6 0%, #8B5CF6 100%) !important;
                border-radius: 999px;
            }

            /* ============================================================
               ALERTS / NOTIFICATIONS — High Contrast
               ============================================================ */
            .stAlert {
                background: rgba(15, 23, 42, 0.85) !important;
                backdrop-filter: blur(14px) !important;
                border-radius: 14px !important;
                border: 1px solid rgba(99, 102, 241, 0.35) !important;
                color: #F8FAFC !important;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3) !important;
            }

            .stAlert p,
            .stAlert span,
            .stAlert div,
            .stAlert strong,
            .stAlert b {
                color: #F8FAFC !important;
                font-size: 0.92rem !important;
                line-height: 1.55 !important;
            }

            /* Info alert */
            [data-testid="stAlert"]:has([data-testid="stNotificationContentInfo"]),
            div[data-testid="stAlert"]:has(svg[data-testid="stNotificationIconInfo"]) {
                background: rgba(15, 33, 64, 0.85) !important;
                border: 1px solid rgba(59, 130, 246, 0.6) !important;
            }
            [data-testid="stAlert"] [data-testid="stNotificationContentInfo"] p,
            [data-testid="stAlert"] [data-testid="stNotificationContentInfo"] * {
                color: #BFDBFE !important;
            }

            /* Success alert */
            [data-testid="stAlert"]:has([data-testid="stNotificationContentSuccess"]),
            div[data-testid="stAlert"]:has(svg[data-testid="stNotificationIconSuccess"]) {
                background: rgba(6, 46, 32, 0.85) !important;
                border: 1px solid rgba(16, 185, 129, 0.6) !important;
            }
            [data-testid="stAlert"] [data-testid="stNotificationContentSuccess"] p,
            [data-testid="stAlert"] [data-testid="stNotificationContentSuccess"] * {
                color: #A7F3D0 !important;
            }

            /* Warning alert */
            [data-testid="stAlert"]:has([data-testid="stNotificationContentWarning"]),
            div[data-testid="stAlert"]:has(svg[data-testid="stNotificationIconWarning"]) {
                background: rgba(56, 34, 6, 0.85) !important;
                border: 1px solid rgba(245, 158, 11, 0.6) !important;
            }
            [data-testid="stAlert"] [data-testid="stNotificationContentWarning"] p,
            [data-testid="stAlert"] [data-testid="stNotificationContentWarning"] * {
                color: #FDE68A !important;
            }

            /* Error alert */
            [data-testid="stAlert"]:has([data-testid="stNotificationContentError"]),
            div[data-testid="stAlert"]:has(svg[data-testid="stNotificationIconError"]) {
                background: rgba(64, 15, 15, 0.85) !important;
                border: 1px solid rgba(239, 68, 68, 0.6) !important;
            }
            [data-testid="stAlert"] [data-testid="stNotificationContentError"] p,
            [data-testid="stAlert"] [data-testid="stNotificationContentError"] * {
                color: #FECACA !important;
            }

            /* ============================================================
               GENERAL TRANSITIONS on interactive elements
               ============================================================ */
            a, button, input, select, textarea,
            [role="tab"], [role="button"] {
                transition: all 0.3s ease !important;
            }

            /* ============================================================
               UTILITY CLASSES
               ============================================================ */
            .ag-glass-panel {
                background: rgba(15, 23, 42, 0.6);
                backdrop-filter: blur(20px) saturate(1.3);
                -webkit-backdrop-filter: blur(20px) saturate(1.3);
                border: 1px solid rgba(99, 102, 241, 0.1);
                border-radius: 20px;
                padding: 24px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
            }

            .ag-gradient-text {
                background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 50%, #F472B6 100%);
                background-size: 200% 200%;
                animation: textShimmer 4s ease infinite;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .ag-shimmer-line {
                height: 2px;
                background: linear-gradient(90deg,
                    transparent 0%,
                    rgba(99, 102, 241, 0.5) 50%,
                    transparent 100%
                );
                background-size: 200% 100%;
                animation: shimmer 2s ease-in-out infinite;
                border-radius: 999px;
            }

            .ag-pulse-dot {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #10B981;
                animation: pulse 2s ease-in-out infinite;
                box-shadow: 0 0 8px rgba(16, 185, 129, 0.5);
            }

            .ag-pulse-dot-red {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #EF4444;
                animation: pulse 2s ease-in-out infinite;
                box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
            }

            .ag-fade-in {
                animation: fadeInUp 0.6s ease-out both;
            }

            .ag-section-header {
                font-size: 1.75rem;
                font-weight: 800;
                color: #F8FAFC;
                margin-bottom: 4px;
                font-family: 'Inter', sans-serif;
                letter-spacing: -0.02em;
            }

            .ag-section-subtext {
                color: #CBD5E1;
                font-size: 0.92rem;
                line-height: 1.6;
                margin-bottom: 20px;
            }

            .ag-section-header-bar {
                height: 3px;
                width: 80px;
                border-radius: 999px;
                background: linear-gradient(90deg, #3B82F6, #8B5CF6, #EC4899);
                margin-bottom: 24px;
            }

            .ag-stat-card {
                background: rgba(15, 23, 42, 0.55);
                backdrop-filter: blur(16px) saturate(1.3);
                -webkit-backdrop-filter: blur(16px) saturate(1.3);
                border: 1px solid rgba(99, 102, 241, 0.1);
                border-radius: 16px;
                padding: 20px 18px;
                text-align: center;
                transition: all 0.3s ease;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            }

            .ag-stat-card:hover {
                border-color: rgba(99, 102, 241, 0.3);
                transform: translateY(-3px);
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3),
                            0 0 20px rgba(99, 102, 241, 0.08);
            }

            .ag-stat-value {
                font-size: 2.2rem;
                font-weight: 800;
                background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 50%, #818CF8 100%);
                background-size: 200% 200%;
                animation: textShimmer 4s ease infinite;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 4px;
                font-family: 'Inter', sans-serif;
            }

            .ag-stat-label {
                font-size: 0.82rem;
                color: #CBD5E1;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                font-family: 'Inter', sans-serif;
            }

            .ag-status-dot {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                animation: pulse 2s ease-in-out infinite;
                margin-right: 8px;
                vertical-align: middle;
            }

            .ag-status-dot-green {
                background: #10B981;
                box-shadow: 0 0 10px rgba(16, 185, 129, 0.6);
            }

            .ag-status-dot-red {
                background: #EF4444;
                box-shadow: 0 0 10px rgba(239, 68, 68, 0.6);
            }

            .ag-threat-badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 999px;
                font-size: 0.68rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                font-family: 'Inter', sans-serif;
            }

            .ag-threat-critical {
                background: rgba(239, 68, 68, 0.15);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.4);
            }

            .ag-threat-high {
                background: rgba(245, 158, 11, 0.15);
                color: #FBBF24;
                border: 1px solid rgba(245, 158, 11, 0.4);
            }

            .ag-drop-zone {
                border: 2px dashed rgba(99, 102, 241, 0.3);
                border-radius: 16px;
                padding: 24px;
                background: rgba(15, 23, 42, 0.3);
                text-align: center;
                transition: all 0.3s ease;
            }

            .ag-drop-zone:hover {
                border-color: rgba(99, 102, 241, 0.5);
                background: rgba(59, 130, 246, 0.04);
            }

            .ag-pipeline-arrow {
                display: flex;
                align-items: center;
                justify-content: center;
                color: #94A3B8;
                font-size: 1.8rem;
                padding: 0 4px;
            }

            /* ============================================================
               SIDEBAR BRAND & COMPONENT CLASSES
               ============================================================ */
            .ag-sidebar-brand {
                text-align: center;
                padding: 16px 8px 12px 8px;
            }
            .ag-sidebar-logo {
                font-size: 1.9rem;
                font-weight: 900;
                letter-spacing: -0.03em;
                background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 40%, #818CF8 70%, #60A5FA 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: textShimmer 5s ease infinite, breatheGlow 3s ease-in-out infinite;
                font-family: 'Inter', sans-serif;
                line-height: 1.2;
            }
            .ag-sidebar-subtext {
                color: #CBD5E1;
                font-size: 0.76rem;
                margin: 4px 0 10px 0;
                font-weight: 400;
                letter-spacing: 0.02em;
                font-family: 'Inter', sans-serif;
            }
            .ag-gateway-badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 6px 14px;
                background: rgba(16, 185, 129, 0.08);
                border: 1px solid rgba(16, 185, 129, 0.25);
                border-radius: 999px;
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
            }
            .ag-gateway-dot {
                display: inline-block;
                width: 7px;
                height: 7px;
                border-radius: 50%;
                background: #10B981;
                animation: pulse 2s ease-in-out infinite;
                box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
            }
            .ag-gateway-text {
                color: #34D399;
                font-size: 0.66rem;
                font-weight: 700;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                font-family: 'Inter', sans-serif;
            }
            .ag-sidebar-divider {
                height: 1px;
                background: linear-gradient(90deg, transparent 0%, rgba(99,102,241,0.3) 50%, transparent 100%);
                margin: 12px 0 16px 0;
            }
            .ag-user-card {
                background: rgba(15, 23, 42, 0.5);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border: 1px solid rgba(99, 102, 241, 0.12);
                border-radius: 14px;
                padding: 14px;
                margin-bottom: 14px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            }
            .ag-user-label {
                font-size: 0.65rem;
                color: #CBD5E1;
                font-weight: 600;
                letter-spacing: 0.1em;
                text-transform: uppercase;
                margin-bottom: 6px;
                font-family: 'Inter', sans-serif;
            }
            .ag-user-name {
                font-weight: 700;
                color: #F1F5F9;
                font-size: 0.95rem;
                margin-bottom: 8px;
                font-family: 'Inter', sans-serif;
            }
            .ag-user-id {
                font-size: 0.72rem;
                color: #93C5FD;
                margin-top: 8px;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 500;
            }
            .ag-team-card {
                background: rgba(15, 23, 42, 0.4);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid rgba(99, 102, 241, 0.2);
                border-radius: 12px;
                padding: 14px;
                margin-top: 4px;
            }

            /* ============================================================
               PRO READER SUITE STYLES
               ============================================================ */
            @import url('https://fonts.googleapis.com/css2?family=Merriweather:ital,wght@0,300;0,400;0,700;1,300;1,400&display=swap');

            .ag-pro-reader-card {
                background: rgba(15, 23, 42, 0.75);
                backdrop-filter: blur(24px) saturate(1.3);
                -webkit-backdrop-filter: blur(24px) saturate(1.3);
                border: 1px solid rgba(99, 102, 241, 0.28);
                border-radius: 20px;
                overflow: hidden;
                box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5), 0 0 35px rgba(99, 102, 241, 0.12);
                margin-top: 14px;
                margin-bottom: 24px;
            }

            .ag-reader-header-bar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
                gap: 14px;
                padding: 18px 26px;
                background: linear-gradient(90deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.95) 100%);
                border-bottom: 1px solid rgba(99, 102, 241, 0.22);
            }

            .ag-reader-title-group {
                display: flex;
                align-items: center;
                gap: 12px;
                flex-wrap: wrap;
            }

            .ag-reader-doc-title {
                font-size: 1.2rem;
                font-weight: 800;
                color: #FFFFFF !important;
                margin: 0;
                letter-spacing: -0.01em;
            }

            .ag-reader-stats-bar {
                display: flex;
                align-items: center;
                gap: 18px;
                padding: 10px 26px;
                background: rgba(10, 14, 26, 0.65);
                border-bottom: 1px solid rgba(51, 65, 85, 0.35);
                font-size: 0.82rem;
                color: #CBD5E1;
                flex-wrap: wrap;
            }

            .ag-reader-stat-item {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                color: #CBD5E1;
            }

            .ag-reader-stat-item strong {
                color: #60A5FA !important;
            }

            /* Theme containers */
            .ag-reader-body-obsidian {
                background: #090D16 !important;
                color: #F1F5F9 !important;
            }

            .ag-reader-body-navy {
                background: #060E22 !important;
                color: #E2E8F0 !important;
            }

            .ag-reader-body-sepia {
                background: #1C1610 !important;
                color: #F5E8D3 !important;
            }

            .ag-reader-body-matrix {
                background: #03100B !important;
                color: #6EE7B7 !important;
            }

            .ag-reader-body-paper {
                background: #F8FAFC !important;
                color: #0F172A !important;
            }

            .ag-reader-body-paper h1,
            .ag-reader-body-paper h2,
            .ag-reader-body-paper h3,
            .ag-reader-body-paper h4,
            .ag-reader-body-paper strong,
            .ag-reader-body-paper b {
                color: #0F172A !important;
            }

            .ag-reader-body-paper p,
            .ag-reader-body-paper li,
            .ag-reader-body-paper span,
            .ag-reader-body-paper div {
                color: #1E293B !important;
            }

            .ag-reader-body-paper code {
                background: #E2E8F0 !important;
                color: #0F172A !important;
                border-color: #CBD5E1 !important;
            }

            /* Reader typography */
            .ag-reader-font-sans {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
            }

            .ag-reader-font-serif {
                font-family: 'Merriweather', 'Georgia', 'Cambria', serif !important;
            }

            .ag-reader-font-mono {
                font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace !important;
            }

            .ag-pro-reader-content {
                padding: 34px 44px;
                overflow-y: auto;
                transition: all 0.25s ease;
                white-space: pre-wrap;
                word-break: break-word;
            }

            .ag-pro-reader-content::-webkit-scrollbar {
                width: 8px;
            }
            .ag-pro-reader-content::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.25);
            }
            .ag-pro-reader-content::-webkit-scrollbar-thumb {
                background: rgba(99, 102, 241, 0.35);
                border-radius: 4px;
            }
            .ag-pro-reader-content::-webkit-scrollbar-thumb:hover {
                background: rgba(99, 102, 241, 0.65);
            }

            /* Line numbered view */
            .ag-code-reader-table {
                width: 100%;
                border-collapse: collapse;
                font-family: 'JetBrains Mono', monospace;
            }
            .ag-code-line-num {
                user-select: none;
                width: 52px;
                text-align: right;
                padding-right: 18px;
                color: #64748B;
                border-right: 1px solid rgba(255, 255, 255, 0.12);
                vertical-align: top;
            }
            .ag-code-line-text {
                padding-left: 18px;
                vertical-align: top;
                white-space: pre-wrap;
                word-break: break-word;
            }

            /* Reader toolbar container */
            .ag-reader-toolbar-box {
                background: rgba(15, 23, 42, 0.7);
                border: 1px solid rgba(99, 102, 241, 0.2);
                border-radius: 14px;
                padding: 12px 18px;
                margin-top: 10px;
                margin-bottom: 14px;
            }

            .ag-reader-highlight {
                background: rgba(245, 158, 11, 0.35);
                color: #FDE68A !important;
                padding: 2px 4px;
                border-radius: 4px;
                font-weight: 700;
                border: 1px solid rgba(245, 158, 11, 0.6);
            }

            .ag-clearance-pill {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 4px 12px;
                background: rgba(16, 185, 129, 0.15);
                border: 1px solid rgba(16, 185, 129, 0.35);
                border-radius: 999px;
                font-size: 0.72rem;
                font-weight: 700;
                color: #34D399;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }

            .ag-clearance-pill-blocked {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 4px 12px;
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid rgba(239, 68, 68, 0.35);
                border-radius: 999px;
                font-size: 0.72rem;
                font-weight: 700;
                color: #F87171;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }

        </style>
        """,
        unsafe_allow_html=True,
    )


def decision_badge(decision: str) -> str:
    dec = str(decision).upper()
    if "ALLOW" in dec:
        return f'<span class="ag-badge ag-badge-allow">● {dec}</span>'
    elif "BLOCK" in dec:
        return f'<span class="ag-badge ag-badge-block">✕ {dec}</span>'
    elif "APPROVAL" in dec:
        return f'<span class="ag-badge ag-badge-approval">⚠ {dec}</span>'
    return f'<span class="ag-badge">{dec}</span>'


def classification_badge(classification: str) -> str:
    cls = str(classification).upper()
    if "PUBLIC" in cls:
        return f'<span class="ag-badge ag-badge-public">{cls}</span>'
    elif "INTERNAL" in cls:
        return f'<span class="ag-badge ag-badge-internal">{cls}</span>'
    elif "CONFIDENTIAL" in cls:
        return f'<span class="ag-badge ag-badge-confidential">{cls}</span>'
    elif "RESTRICTED" in cls:
        return f'<span class="ag-badge ag-badge-restricted">{cls}</span>'
    return f'<span class="ag-badge">{cls}</span>'


def render_pro_reader(
    content: str,
    title: str = "Document Content",
    document_id: str = "",
    classification: str = "INTERNAL",
    file_type: str = "txt",
    redacted_content: str | None = None,
    key_prefix: str = "pro_reader",
    default_height: int = 540,
    show_header: bool = True,
    clearance_note: str = "VERIFIED SECURE READ • GATEWAY CLEARED",
):
    """Render a professional, full-width document reading suite.
    
    Includes reader themes, typography switches, font sizing, line spacing,
    line numbering, search highlighting, reading telemetry, and DLP comparison.
    """
    if not content:
        st.info("No content to display in reader.")
        return

    # Calculate reading telemetry
    words = len(content.split())
    chars = len(content)
    lines_list = content.splitlines() or [""]
    lines_count = len(lines_list)
    reading_time_mins = max(1, round(words / 200))

    # Controls Bar
    with st.expander("⚙️ Reader Typography & Display Settings", expanded=False):
        c_th, c_font, c_sz, c_sp, c_mod, c_ht = st.columns(6)
        with c_th:
            theme_choice = st.selectbox(
                "Palette:",
                ["🌑 Obsidian Dark", "🌌 Midnight Navy", "📜 Warm Sepia", "⚡ Cyber Matrix", "☀️ Clean Paper"],
                key=f"{key_prefix}_theme",
            )
        with c_font:
            font_choice = st.selectbox(
                "Typeface:",
                ["Modern Sans", "Editorial Serif", "Hacker Mono"],
                key=f"{key_prefix}_font",
            )
        with c_sz:
            size_choice = st.selectbox(
                "Font Size:",
                ["14px", "16px", "18px", "20px", "22px"],
                index=2,
                key=f"{key_prefix}_size",
            )
        with c_sp:
            spacing_choice = st.selectbox(
                "Line Height:",
                ["1.5 (Standard)", "1.8 (Comfort)", "2.2 (Relaxed)"],
                index=1,
                key=f"{key_prefix}_spacing",
            )
        with c_mod:
            available_modes = ["📖 Formatted Text", "🔢 Line Numbers", "🔍 Find in Text"]
            if redacted_content:
                available_modes.append("🛡️ DLP Redaction Diff")
            mode_choice = st.selectbox(
                "Reader Mode:",
                available_modes,
                key=f"{key_prefix}_mode",
            )
        with c_ht:
            height_choice = st.selectbox(
                "Height:",
                ["520px", "750px", "Auto Height"],
                key=f"{key_prefix}_height",
            )

    # Search bar if in search mode
    search_query = ""
    if mode_choice == "🔍 Find in Text":
        c_srch, c_clr = st.columns([4, 1])
        with c_srch:
            search_query = st.text_input("Type keyword to find & highlight:", key=f"{key_prefix}_search_input")
        with c_clr:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            if search_query:
                st.caption(f"Matches: **{len(re.findall(re.escape(search_query), content, flags=re.IGNORECASE))}**")

    # Map settings to CSS classes
    theme_map = {
        "🌑 Obsidian Dark": "ag-reader-body-obsidian",
        "🌌 Midnight Navy": "ag-reader-body-navy",
        "📜 Warm Sepia": "ag-reader-body-sepia",
        "⚡ Cyber Matrix": "ag-reader-body-matrix",
        "☀️ Clean Paper": "ag-reader-body-paper",
    }
    font_map = {
        "Modern Sans": "ag-reader-font-sans",
        "Editorial Serif": "ag-reader-font-serif",
        "Hacker Mono": "ag-reader-font-mono",
    }
    spacing_map = {
        "1.5 (Standard)": "1.5",
        "1.8 (Comfort)": "1.8",
        "2.2 (Relaxed)": "2.2",
    }
    height_map = {
        "520px": "520px",
        "750px": "750px",
        "Auto Height": "none",
    }

    body_theme_cls = theme_map.get(theme_choice, "ag-reader-body-obsidian")
    body_font_cls = font_map.get(font_choice, "ag-reader-font-sans")
    font_size_val = size_choice
    line_spacing_val = spacing_map.get(spacing_choice, "1.8")
    max_height_val = height_map.get(height_choice, "520px")

    # Render Pro Reader Card Container
    card_html = f"""
    <div class="ag-fade-in">
        <div class="ag-pro-reader-card">
            <!-- Header Bar -->
            <div class="ag-reader-header-bar">
                <div class="ag-reader-title-group">
                    <span class="ag-reader-doc-title">📄 {html.escape(title)}</span>
                    {f'<code>{html.escape(document_id)}</code>' if document_id else ''}
                    {classification_badge(classification)}
                    <span style="font-size:0.75rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">.{html.escape(file_type)}</span>
                </div>
                <div>
                    <span class="ag-clearance-pill">🔒 {html.escape(clearance_note)}</span>
                </div>
            </div>
            <!-- Telemetry Stats Bar -->
            <div class="ag-reader-stats-bar">
                <span class="ag-reader-stat-item">⏱️ Reading Time: <strong>~{reading_time_mins} min</strong></span>
                <span style="color:#475569;">|</span>
                <span class="ag-reader-stat-item">📝 Words: <strong>{words:,}</strong></span>
                <span style="color:#475569;">|</span>
                <span class="ag-reader-stat-item">🔤 Characters: <strong>{chars:,}</strong></span>
                <span style="color:#475569;">|</span>
                <span class="ag-reader-stat-item">📄 Lines: <strong>{lines_count:,}</strong></span>
                <span style="color:#475569;">|</span>
                <span class="ag-reader-stat-item">🎨 Theme: <span style="color:#CBD5E1;">{theme_choice}</span></span>
                <span style="color:#475569;">|</span>
                <span class="ag-reader-stat-item">🖋️ Typeface: <span style="color:#CBD5E1;">{font_choice} ({font_size_val})</span></span>
            </div>
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)

    # Render Content Body based on selected Mode
    if mode_choice == "🔢 Line Numbers":
        table_rows = []
        for idx, line in enumerate(lines_list, start=1):
            escaped_line = html.escape(line)
            if search_query:
                escaped_query = html.escape(search_query)
                pattern = re.compile(re.escape(escaped_query), re.IGNORECASE)
                escaped_line = pattern.sub(r'<mark class="ag-reader-highlight">\g<0></mark>', escaped_line)
            table_rows.append(
                f'<tr><td class="ag-code-line-num">{idx}</td><td class="ag-code-line-text">{escaped_line if escaped_line else "&nbsp;"}</td></tr>'
            )
        lines_html = "".join(table_rows)
        body_markup = f"""
        <div class="{body_theme_cls} {body_font_cls} ag-pro-reader-content" style="max-height:{max_height_val}; font-size:{font_size_val}; line-height:{line_spacing_val};">
            <table class="ag-code-reader-table">
                {lines_html}
            </table>
        </div>
        """
        st.markdown(body_markup, unsafe_allow_html=True)

    elif mode_choice == "🛡️ DLP Redaction Diff" and redacted_content:
        col_orig, col_redacted = st.columns(2)
        with col_orig:
            st.markdown("##### 📄 Original Cleartext (Cleared Identity)")
            st.markdown(
                f"""
                <div class="{body_theme_cls} {body_font_cls} ag-pro-reader-content" style="max-height:{max_height_val}; font-size:{font_size_val}; line-height:{line_spacing_val}; border-radius:12px;">
                    {html.escape(content)}
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_redacted:
            st.markdown("##### 🛡️ DLP-Sanitized Redacted Stream")
            st.markdown(
                f"""
                <div class="{body_theme_cls} {body_font_cls} ag-pro-reader-content" style="max-height:{max_height_val}; font-size:{font_size_val}; line-height:{line_spacing_val}; border-radius:12px;">
                    {html.escape(redacted_content)}
                </div>
                """,
                unsafe_allow_html=True,
            )

    else:
        # Formatted / Clean Text / Highlight mode
        escaped_content = html.escape(content)
        if search_query:
            escaped_query = html.escape(search_query)
            pattern = re.compile(re.escape(escaped_query), re.IGNORECASE)
            escaped_content = pattern.sub(r'<mark class="ag-reader-highlight">\g<0></mark>', escaped_content)

        body_markup = f"""
        <div class="{body_theme_cls} {body_font_cls} ag-pro-reader-content" style="max-height:{max_height_val}; font-size:{font_size_val}; line-height:{line_spacing_val}; border-radius:0 0 20px 20px;">
{escaped_content}
        </div>
        """
        st.markdown(body_markup, unsafe_allow_html=True)

    # Reader Quick Utility Actions
    col_act1, col_act2 = st.columns([1, 4])
    with col_act1:
        st.download_button(
            label="💾 Download Document (.txt)",
            data=content,
            file_name=f"{document_id or 'document'}.txt",
            mime="text/plain",
            key=f"{key_prefix}_download",
        )
    with col_act2:
        with st.expander("📋 Copy Raw Text to Clipboard"):
            st.code(content, language="text")
