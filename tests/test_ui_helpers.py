"""Run: python -m pytest tests/test_ui_helpers.py -v"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ui import helpers as H  # noqa: E402


def test_initials_and_greeting():
    assert H.initials("Priya Nair") == "PN" and H.initials("") == "?"
    assert H.greeting(8) == "Good morning" and H.greeting(13) == "Good afternoon" and H.greeting(20) == "Good evening"


def test_dollar_signs_are_escaped_so_they_never_render_as_latex():
    assert H.safe_md("Revenue $4.2M, cash $1.2M") == "Revenue \\$4.2M, cash \\$1.2M"


def test_history_text_never_keeps_raw_sensitive_values():
    shown = H.display_text("PAN ABCPK1234F and phone 9876543210")
    assert "ABCPK1234F" not in shown and "9876543210" not in shown
    assert "[PAN_REDACTED]" in shown


def test_clean_text_is_unchanged():
    assert H.display_text("When is Diwali?") == "When is Diwali?"


def test_titles():
    assert H.make_title("   ") == "New chat"
    assert H.make_title("short") == "short"
    t = H.make_title("x" * 100)
    assert len(t) == 34 and t.endswith("…")


def test_attachment_reading_and_limits():
    text, trunc = H.read_attachment("notes.TXT", b"hello")
    assert text == "hello" and trunc is False
    text, trunc = H.read_attachment("big.csv", b"a" * 9000)
    assert len(text) == H.MAX_ATTACHMENT_CHARS and trunc is True
    with pytest.raises(ValueError):
        H.read_attachment("virus.exe", b"MZ")


def test_build_message_includes_file_content():
    m = H.build_message("Summarise", [("a.txt", "secret stuff")])
    assert m.startswith("Summarise") and "Attached file: a.txt" in m and "secret stuff" in m


def test_chips_only_for_masked_and_restricted():
    assert H.chip_for("MASKED") and H.chip_for("RESTRICTED")
    assert H.chip_for("SAFE") is None and H.chip_for("BLOCKED") is None


def test_stream_words_reassembles_text_exactly():
    text = "Line one\n\nLine two  with   spaces"
    assert "".join(H.stream_words(text, delay=0)) == text


def test_every_demo_user_has_a_name_and_role():
    assert set(H.DEMO_USERS) >= {"user_general", "user_hr", "user_finance", "user_devops", "user_cfo", "user_admin"}
