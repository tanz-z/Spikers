"""Run: python -m pytest tests/test_rag_engine.py -v"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.rag_engine import AccessControlledRAG  # noqa: E402


@pytest.fixture(scope="module")
def rag(tmp_path_factory):
    # Temp directory: tests never touch your real data/chroma_db.
    return AccessControlledRAG(persist_dir=str(tmp_path_factory.mktemp("chroma")))


def titles(docs):
    return [d["title"] for d in docs]


def test_unprivileged_user_is_denied_hr_salaries(rag):
    r = rag.query("What are the employee salaries?", "user_general")
    assert any("HR Employee" in t for t in titles(r["denied_docs"]))
    assert not any("HR Employee" in t for t in titles(r["allowed_docs"]))
    assert r["access_violation"] is True
    assert "18,50,000" not in r["context"] and "9876" not in r["context"]


def test_hr_user_gets_hr_records(rag):
    r = rag.query("What are the employee salaries?", "user_hr")
    assert any("HR Employee" in t for t in titles(r["allowed_docs"]))
    assert "18,50,000" in r["context"]


def test_harmless_question_is_not_a_violation(rag):
    """The original bug: every query flagged an access violation."""
    r = rag.query("When is Diwali and how many holidays do we get?", "user_general")
    assert any("Holiday" in t for t in titles(r["allowed_docs"]))
    assert r["access_violation"] is False


def test_irrelevant_question_gives_empty_context(rag):
    r = rag.query("How do I bake a chocolate cake?", "user_general")
    assert r["context"] == ""
    assert r["allowed_docs"] == [] and r["access_violation"] is False


def test_blank_query_gives_empty_context(rag):
    r = rag.query("   ", "user_hr")
    assert r["context"] == "" and r["access_violation"] is False


def test_credentials_never_reach_context_for_other_roles(rag):
    r = rag.query("What is the AWS production password?", "user_general")
    assert "AKIA" not in r["context"] and "AdminP@ss" not in r["context"]
    assert r["access_violation"] is True


def test_anonymous_cannot_read_internal_docs(rag):
    r = rag.query("employee conduct policy remote work VPN", "anonymous")
    assert not any("Conduct" in t for t in titles(r["allowed_docs"]))
    assert any("Conduct" in t for t in titles(r["denied_docs"]))


def test_authenticated_user_can_read_internal_docs(rag):
    r = rag.query("employee conduct policy remote work VPN", "user_general")
    assert any("Conduct" in t for t in titles(r["allowed_docs"]))