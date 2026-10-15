"""
user_app.py - Spikers Secure AI Assistant  (END-USER interface)
Owner: Bhoomi

Run:  streamlit run user_app.py --server.port 8501

This is what employees see. It deliberately shows NO scores, findings or policy
internals - those live in the admin console (admin_app.py). Everything goes through
GatewayClient, which talks to the live gateway API or falls back to demo mode.
"""
import html
import os
import uuid

import streamlit as st

from gateway.client import GatewayClient
from ui import helpers as H

st.set_page_config(page_title="Spikers · AI Assistant", page_icon="🛡️",
                   layout="centered", initial_sidebar_state="expanded")

with open(os.path.join(os.path.dirname(__file__), "assets", "user.css"), encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

USER_AVATAR, AI_AVATAR = ":material/person:", ":material/auto_awesome:"


@st.cache_resource
def get_client() -> GatewayClient:
    return GatewayClient()


client = get_client()

# ───────────────────────────── state ─────────────────────────────
if "user_id" not in st.session_state:
    st.session_state.user_id = "user_general"
if "store" not in st.session_state:
    st.session_state.store = {}

uid = st.session_state.user_id
user_name, user_role = H.DEMO_USERS[uid]
S = st.session_state.store.setdefault(uid, {"chats": {}, "order": [], "active": None})


def new_chat() -> None:
    cid = uuid.uuid4().hex[:8]
    S["chats"][cid] = {"title": "New chat", "messages": []}
    S["order"].insert(0, cid)
    S["active"] = cid


if S["active"] not in S["chats"]:
    new_chat()
chat = S["chats"][S["active"]]

# ───────────────────────────── sidebar ─────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="brand-chip">🛡</div>
      <div><div class="brand-name">Spikers</div><div class="brand-sub">Secure AI Assistant</div></div>
    </div>""", unsafe_allow_html=True)

    if st.button("＋  New chat", key="new_chat"):
        if chat["messages"]:          # don't stack empty chats
            new_chat()
        st.rerun()

    recent = [c for c in S["order"] if S["chats"][c]["messages"]][:10]
    if recent:
        st.markdown('<div class="side-label">Recent</div>', unsafe_allow_html=True)
    for cid in recent:
        prefix = "active_" if cid == S["active"] else "chat_"
        if st.button(S["chats"][cid]["title"], key=prefix + cid):
            S["active"] = cid
            st.rerun()

    st.markdown('<div class="side-label">Sample prompts</div>', unsafe_allow_html=True)
    for i, (label, text) in enumerate(H.SAMPLE_PROMPTS):
        if st.button(label, key=f"sample_{i}"):
            st.session_state.pending = text
            st.rerun()

    st.markdown('<div class="side-label">Signed in as</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="acct">
      <div class="acct-av">{html.escape(H.initials(user_name))}</div>
      <div><div class="acct-name">{html.escape(user_name)}</div>
           <div class="acct-role">{html.escape(user_role)}</div></div>
    </div>""", unsafe_allow_html=True)
    st.selectbox(
        "Demo account", list(H.DEMO_USERS), key="user_id", label_visibility="collapsed",
        format_func=lambda u: f"{H.DEMO_USERS[u][0]} · {H.DEMO_USERS[u][1]}",
    )


# ───────────────────────────── helpers ─────────────────────────────
def read_input():
    try:
        v = st.chat_input("Message Spikers…", accept_file=True,
                          file_type=[e.lstrip(".") for e in H.SUPPORTED_UPLOADS])
    except TypeError:                       # older Streamlit without file upload in chat_input
        v = st.chat_input("Message Spikers…")
    if v is None:
        return None, []
    if isinstance(v, str):
        return v, []
    text = getattr(v, "text", None)
    files = getattr(v, "files", None)
    if text is None and isinstance(v, dict):
        text, files = v.get("text", ""), v.get("files", [])
    return text or "", list(files or [])


def blocked_card(text: str) -> None:
    body = html.escape(text).replace("\n", "<br>")
    st.markdown(f'<div class="blocked"><div class="blocked-t">⛔ Request blocked</div>{body}</div>',
                unsafe_allow_html=True)


def chip(status: str) -> None:
    c = H.chip_for(status)
    if c:
        st.markdown(f'<span class="chip {c[0]}">{c[1]}</span>', unsafe_allow_html=True)


def render_message(m: dict) -> None:
    if m["role"] == "user":
        with st.chat_message("user", avatar=USER_AVATAR):
            st.markdown(H.safe_md(m["content"]))
            for fname in m.get("attachments", []):
                st.markdown(f'<span class="file-chip">📎 {html.escape(fname)}</span>', unsafe_allow_html=True)
    else:
        with st.chat_message("assistant", avatar=AI_AVATAR):
            if m["status"] == "BLOCKED":
                blocked_card(m["content"])
            else:
                st.markdown(H.safe_md(m["content"]))
            chip(m["status"])


def welcome() -> None:
    st.markdown(f"""
    <div class="hero">
      <div class="hero-hi">{H.greeting()}, {html.escape(user_name.split()[0])}</div>
      <h1>How can I help you today?</h1>
      <p>Ask about company policies, finance, holidays and more. You can also attach a file.</p>
    </div>""", unsafe_allow_html=True)
    cols = st.columns(2)
    for i, (icon, title, text) in enumerate(H.SUGGESTIONS):
        with cols[i % 2]:
            if st.button(f"{icon}  {title}\n\n{text}", key=f"sugg_{i}"):
                st.session_state.pending = text
                st.rerun()


# ───────────────────────────── main ─────────────────────────────
prompt, files = read_input()
pending = st.session_state.pop("pending", None)
if pending and not (prompt or files):
    prompt, files = pending, []

st.markdown(f"""
<div class="topbar"><span class="tb-title">{html.escape(chat['title'])}</span>
<span class="tb-pill"><span class="tb-dot"></span>Company knowledge connected</span></div>
""", unsafe_allow_html=True)

has_input = bool((prompt or "").strip() or files)
if not chat["messages"] and not has_input:
    welcome()

for m in chat["messages"]:
    render_message(m)

if has_input:
    attachments, errors = [], []
    for f in files:
        try:
            text, _ = H.read_attachment(f.name, f.getvalue())
            attachments.append((f.name, text))
        except ValueError as e:
            errors.append(str(e))

    typed = (prompt or "").strip() or "Please review the attached file."
    shown = H.display_text(typed)            # never keep raw sensitive values in the session
    user_msg = {"role": "user", "content": shown, "attachments": [n for n, _ in attachments]}
    chat["messages"].append(user_msg)
    if chat["title"] == "New chat":
        chat["title"] = H.make_title(shown)
    render_message(user_msg)
    for e in errors:
        st.warning(e, icon="⚠️")

    with st.chat_message("assistant", avatar=AI_AVATAR):
        try:
            with st.spinner("Thinking…"):
                result = client.chat(uid, H.build_message(typed, attachments), session_id=S["active"])
            status, reply = result["status"], result["response"]
        except Exception as exc:               # never show stack traces to employees
            print(f"[user_app] gateway error: {exc!r}")
            status, reply = "ERROR", "Sorry, something went wrong on our side. Please try again."
        if status == "BLOCKED":
            blocked_card(reply)
        else:
            st.write_stream(H.stream_words(H.safe_md(reply)))
        chip(status)

    chat["messages"].append({"role": "assistant", "content": reply, "status": status})
    st.rerun()
