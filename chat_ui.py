# chat_ui.py
import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="Spikers",
    page_icon="◆",
    layout="wide",
    initial_sidebar_state="expanded"   # Force sidebar open
)

# -------------------------------------------------------------------
# CUSTOM CSS — Gradient hero + Claude/Gemini polish
# -------------------------------------------------------------------
st.markdown("""
<style>
    /* Hide Streamlit chrome.
       NOTE: do NOT hide the whole <header>. It contains the arrow that re-opens a
       collapsed sidebar. We only make it transparent and hide the toolbar/menu. */
    header[data-testid="stHeader"] {background: transparent !important;}
    [data-testid="stToolbar"] {visibility: hidden;}
    [data-testid="stAppDeployButton"] {display: none;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none;}

    /* Always show the button that re-opens a collapsed sidebar.
       The test id differs between Streamlit versions, so all three are listed. */
    [data-testid="stExpandSidebarButton"],
    [data-testid="stSidebarCollapsedControl"],
    [data-testid="collapsedControl"] {
        visibility: visible !important;
        display: flex !important;
    }

    /* Main container */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 6rem;
        max-width: 52rem;
    }

    /* ---------- HERO / FLASH PAGE ---------- */
    .hero-wrap {
        position: relative;
        text-align: center;
        padding: 4.5rem 2rem 3rem 2rem;
        margin: 2rem auto 2.5rem auto;
        border-radius: 16px;
        overflow: hidden;
        /* Maroon → Deep Purple gradient from your palette */
        background: linear-gradient(
            135deg,
            #46000D 0%,
            #5E0009 25%,
            #720137 50%,
            #590054 75%,
            #42002E 100%
        );
        box-shadow: 0 8px 32px rgba(70, 0, 13, 0.45);
    }

    /* Soft abstract glow overlays */
    .hero-wrap::before {
        content: "";
        position: absolute;
        top: -40%;
        left: -20%;
        width: 70%;
        height: 140%;
        background: radial-gradient(ellipse, rgba(114, 1, 55, 0.55) 0%, transparent 70%);
        pointer-events: none;
    }
    .hero-wrap::after {
        content: "";
        position: absolute;
        bottom: -30%;
        right: -15%;
        width: 60%;
        height: 120%;
        background: radial-gradient(ellipse, rgba(89, 0, 84, 0.5) 0%, transparent 70%);
        pointer-events: none;
    }

    .hero-title {
        position: relative;
        z-index: 2;
        font-size: 3.2rem;
        font-weight: 600;
        color: #ffffff;
        letter-spacing: -1.5px;
        margin: 0 0 0.6rem 0;
        text-shadow: 0 2px 20px rgba(0,0,0,0.35);
    }
    .hero-sub {
        position: relative;
        z-index: 2;
        font-size: 1.25rem;
        font-weight: 400;
        color: rgba(255,255,255,0.78);
        margin: 0;
    }

    /* ---------- SECURITY NOTICE ---------- */
    .security-suggestion {
        background: rgba(114, 1, 55, 0.12);
        border-left: 3px solid #720137;
        padding: 12px 16px;
        border-radius: 6px;
        font-size: 0.84rem;
        color: #d0d0d0;
        margin-top: 14px;
        line-height: 1.45;
    }

    /* ---------- SIDEBAR ---------- */
    [data-testid="stSidebar"] {
        background-color: #141414;
        border-right: 1px solid #2a2a2a;
    }
    [data-testid="stSidebar"] .stButton button {
        background: transparent;
        border: 1px solid #333;
        color: #e0e0e0;
        font-weight: 500;
        border-radius: 8px;
        transition: all 0.15s ease;
    }
    [data-testid="stSidebar"] .stButton button:hover {
        border-color: #720137;
        background: rgba(114, 1, 55, 0.15);
        color: #fff;
    }

    /* Chat input polish */
    .stChatInput {
        border-color: #333 !important;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# STATE
# -------------------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

# -------------------------------------------------------------------
# LEFT SIDEBAR
# -------------------------------------------------------------------
with st.sidebar:
    st.markdown("## Spikers")
    st.caption("Enterprise AI Gateway")

    if st.button("New Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.markdown("---")
    st.markdown(
        "<p style='color:#666; font-size:0.72rem; font-weight:600; "
        "letter-spacing:0.06em; margin-bottom:0.4rem;'>RECENT</p>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='color:#999; font-size:0.85rem; margin:0.25rem 0;'>Database migration plan</p>"
        "<p style='color:#999; font-size:0.85rem; margin:0.25rem 0;'>Q3 Financial Summary</p>"
        "<p style='color:#999; font-size:0.85rem; margin:0.25rem 0;'>Code review: auth.py</p>",
        unsafe_allow_html=True
    )

    st.markdown("<br>" * 6, unsafe_allow_html=True)
    st.markdown(
        "<p style='color:#666; font-size:0.72rem; font-weight:600; "
        "letter-spacing:0.06em;'>SESSION</p>",
        unsafe_allow_html=True
    )
    user_id = st.selectbox(
        "Active Role",
        ["user_general", "user_hr", "user_finance", "user_admin", "user_devops"],
        label_visibility="collapsed"
    )
    st.caption("Role used for access-controlled RAG")

# -------------------------------------------------------------------
# MAIN AREA — Flash page OR conversation
# -------------------------------------------------------------------
if not st.session_state.messages:
    # ---------- FLASH / HERO PAGE ----------
    st.markdown("""
        <div class="hero-wrap">
            <div class="hero-title">Spikers</div>
            <div class="hero-sub">Hi there! What can I help you with today?</div>
        </div>
    """, unsafe_allow_html=True)

else:
    # ---------- CHAT HISTORY ----------
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            if msg["role"] == "assistant" and msg.get("meta"):
                col_text, col_sec = st.columns([7.5, 2.5])

                with col_text:
                    st.write(msg["content"])

                    if msg["meta"].get("flagged"):
                        st.markdown("""
                        <div class="security-suggestion">
                            <strong>Security Notice:</strong> Sensitive credentials were detected
                            in your prompt and automatically masked before reaching the cloud model.
                            <br><em>Suggestion: Avoid pasting raw API keys, PAN, Aadhaar, or passwords
                            directly into chat interfaces.</em>
                        </div>
                        """, unsafe_allow_html=True)

                with col_sec:
                    meta = msg["meta"]
                    risk = meta.get("risk_level", "CLEAN")
                    label = f"● {risk}"
                    with st.popover(label):
                        st.markdown("**Gateway Trace**")
                        for action in meta.get("actions_taken", []):
                            st.caption(f"• {action}")
                        st.caption(f"Route: {meta.get('llm_used', '—')}")
                        st.caption(f"Input Risk: {meta.get('risk_score_input', 0)}")
            else:
                st.write(msg["content"])

# -------------------------------------------------------------------
# BOTTOM INPUT
# -------------------------------------------------------------------
with st.expander("Attach document or image"):
    uploaded_file = st.file_uploader(
        "Upload",
        type=["png", "jpg", "jpeg", "pdf", "txt", "csv"],
        label_visibility="collapsed"
    )

prompt = st.chat_input("Ask Spikers anything...")

# -------------------------------------------------------------------
# REQUEST HANDLING
# -------------------------------------------------------------------
if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt, "meta": None})
    st.rerun()

if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
    latest_msg = st.session_state.messages[-1]["content"]

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            try:
                if uploaded_file is not None:
                    files = {
                        "file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)
                    }
                    data = {"user_id": user_id, "prompt": latest_msg}
                    response = requests.post(
                        f"{API_URL}/chat/multimodal", data=data, files=files, timeout=90
                    )
                else:
                    payload = {"user_id": user_id, "message": latest_msg}
                    response = requests.post(
                        f"{API_URL}/chat", json=payload, timeout=90
                    )

                if response.status_code == 200:
                    data = response.json()
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": data.get("response", ""),
                        "meta": data
                    })
                    st.rerun()
                else:
                    st.error(f"Gateway error {response.status_code}: {response.text[:300]}")

            except requests.exceptions.ConnectionError:
                st.error("Cannot reach Spikers Gateway. Is the server running on port 8000?")
            except Exception as e:
                st.error(f"Unexpected error: {e}")