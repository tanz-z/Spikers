"""
gateway/rag_engine.py - Access-Controlled RAG Engine (ChromaDB)
Owner: Bhoomi

Interface contract (Tanya's pipeline.py calls this):
    query(query_text, user_id, n_results=3) -> {
        "context": str,            # "" when nothing relevant AND allowed
        "allowed_docs": [...],     # relevant docs the user may read
        "denied_docs": [...],      # relevant docs the user may NOT read
        "access_violation": bool,  # True only if a RELEVANT doc was denied
        ...
    }

Design notes
- Cosine space: similarity = 1 - distance, so the score is meaningful.
- Relevance cutoff: documents below MIN_SIMILARITY are ignored entirely.
  Without it every query returns every document and every non-privileged
  user is flagged for an "access violation" on every request.
- Access control is enforced BEFORE any text reaches the LLM: denied
  documents never contribute to `context`.
"""

import json
import os
from typing import Any, Dict, List, Optional

import chromadb

try:  # pick up RAG_MIN_SIMILARITY from .env if present
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "chroma_db")

# v2 = cosine distance. (v1 used Chroma's default L2 and cannot be converted.)
COLLECTION_NAME = "security_gateway_docs_v2"

# Tune with `python -m gateway.rag_engine` (prints similarity for every doc).
DEFAULT_MIN_SIMILARITY = 0.25

_UNAUTHENTICATED = {"", "anonymous", "none", "null"}


class AccessControlledRAG:
    """RAG vector store with document-level access control."""

    SEED_DOCUMENTS = [
        {
            "id": "doc_hr_01",
            "title": "HR Employee Records & Salaries 2024",
            "content": "CONFIDENTIAL HR DATA: Employee Salary List 2024. Rahul Sharma: ₹18,50,000. Priya Verma (PAN: ABCPV1234K, Aadhaar: 9876 5432 1098): ₹22,00,000. Performance appraisal ratings: High Performers list attached.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_hr", "user_admin"],
            "department": "HR",
        },
        {
            "id": "doc_fin_01",
            "title": "Q3 Financial Performance & Revenue Report",
            "content": "CONFIDENTIAL FINANCE REPORT: Q3 Gross Revenue: $4.2M, Net Profit Margin: 18.5%. Cash reserves stand at $1.2M. Projected M&A target budget: $850,000 reserved for Q4 acquisition.",
            "classification": "CONFIDENTIAL",
            "allowed_users": ["user_cfo", "user_finance", "user_admin"],
            "department": "Finance",
        },
        {
            "id": "doc_devops_01",
            "title": "Cloud Infrastructure & AWS Secrets Guide",
            "content": "DEVOPS SECRETS: AWS Primary Production Cluster in us-east-1. Master API Key: AKIAIOSFODNN7EXAMPLE. Master DB Admin Password: AdminP@ssw0rd2024! SSH access via bastion host 192.168.1.105.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_devops", "user_admin"],
            "department": "DevOps",
        },
        {
            "id": "doc_pub_01",
            "title": "Company Holiday Calendar 2024",
            "content": "PUBLIC INFO: Official Company Holidays 2024. New Year Day: Jan 1, Independence Day: Aug 15, Diwali: Nov 1, Christmas: Dec 25. Standard PTO allowance: 21 days per year.",
            "classification": "PUBLIC",
            "allowed_users": ["ALL"],
            "department": "General",
        },
        {
            "id": "doc_gen_01",
            "title": "General Employee Conduct Policy",
            "content": "INTERNAL POLICY: All employees must complete annual security awareness training. Remote work permitted 2 days per week. Use of corporate VPN is mandatory on public Wi-Fi.",
            "classification": "INTERNAL",
            "allowed_users": ["ALL_AUTHENTICATED"],
            "department": "HR",
        },
        {
            "id": "doc_project_nexus",
            "title": "Project Nexus - Secret M&A Strategy",
            "content": "RESTRICTED STRATEGY: Project Nexus acquisition plan for competitor FinTech Corp. Acquisition price target: $15M. Expected closing date: December 2024.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_cfo", "user_admin"],
            "department": "Executive",
        },
    ]

    def __init__(self, persist_dir: str = DATA_DIR, min_similarity: Optional[float] = None):
        os.makedirs(persist_dir, exist_ok=True)
        self.min_similarity = float(
            min_similarity
            if min_similarity is not None
            else os.getenv("RAG_MIN_SIMILARITY", DEFAULT_MIN_SIMILARITY)
        )
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        if self.collection.count() == 0:
            self._seed_database()

    # ───────────────────────────── seeding ─────────────────────────────
    def _seed_database(self) -> None:
        self.collection.add(
            ids=[d["id"] for d in self.SEED_DOCUMENTS],
            # Title is embedded with the content so title-style queries match.
            documents=[f'{d["title"]}. {d["content"]}' for d in self.SEED_DOCUMENTS],
            metadatas=[
                {
                    "title": d["title"],
                    "content": d["content"],
                    "classification": d["classification"],
                    "allowed_users": json.dumps(d["allowed_users"]),
                    "department": d["department"],
                }
                for d in self.SEED_DOCUMENTS
            ],
        )
        print(f"[RAG] Seeded {len(self.SEED_DOCUMENTS)} documents into '{COLLECTION_NAME}'")

    # ─────────────────────────── access control ───────────────────────────
    @staticmethod
    def _user_has_access(user_id: Optional[str], allowed_users_json: str) -> bool:
        try:
            allowed = json.loads(allowed_users_json)
        except Exception:
            return False  # fail closed

        uid = (user_id or "").strip()
        if "ALL" in allowed:
            return True
        if "ALL_AUTHENTICATED" in allowed and uid.lower() not in _UNAUTHENTICATED:
            return True
        return uid in allowed

    # ─────────────────────────────── query ───────────────────────────────
    def query(
        self,
        query_text: str,
        user_id: str = "user_general",
        n_results: int = 3,
        min_similarity: Optional[float] = None,
    ) -> Dict[str, Any]:
        threshold = self.min_similarity if min_similarity is None else float(min_similarity)
        total = self.collection.count()

        if not query_text or not query_text.strip() or total == 0:
            return self._result([], [], [], 0, threshold)

        fetch_limit = min(max(n_results * 3, 10), total)
        res = self.collection.query(
            query_texts=[query_text],
            n_results=fetch_limit,
            include=["metadatas", "distances"],
        )

        ids = res["ids"][0]
        metas = res["metadatas"][0]
        dists = res["distances"][0]

        allowed: List[Dict[str, Any]] = []
        denied: List[Dict[str, Any]] = []
        parts: List[str] = []

        for doc_id, meta, dist in zip(ids, metas, dists):
            similarity = round(1.0 - float(dist), 4)
            if similarity < threshold:
                continue  # not relevant to this question -> ignore completely

            info = {
                "id": doc_id,
                "title": meta.get("title", "Untitled"),
                "classification": meta.get("classification", "UNKNOWN"),
                "department": meta.get("department", "General"),
                "score": similarity,
            }

            if self._user_has_access(user_id, meta.get("allowed_users", "[]")):
                if len(allowed) < n_results:
                    allowed.append(info)
                    parts.append(
                        f"--- Document: {info['title']} ({info['classification']}) ---\n"
                        f"{meta.get('content', '')}"
                    )
            else:
                denied.append(info)

        return self._result(allowed, denied, parts, len(ids), threshold)

    @staticmethod
    def _result(allowed, denied, parts, examined, threshold) -> Dict[str, Any]:
        return {
            "context": "\n\n".join(parts),  # "" when nothing allowed + relevant
            "allowed_docs": allowed,
            "denied_docs": denied,
            "access_violation": len(denied) > 0,
            "total_candidates_examined": examined,
            "min_similarity": threshold,
        }


# ───────────────── calibration helper: python -m gateway.rag_engine ─────────────────
if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        rag = AccessControlledRAG(persist_dir=os.path.join(tmp, "c"))
        print(f"\nThreshold in use: {rag.min_similarity}\n")

        probes = [
            ("What are the employee salaries?", "user_general"),
            ("When is Diwali and how many holidays do we get?", "user_general"),
            ("What is the AWS production password?", "user_general"),
            ("Tell me about the company acquisition plans", "user_general"),
            ("How do I bake a chocolate cake?", "user_general"),
            ("What is Python?", "user_general"),
        ]
        for q, user in probes:
            r = rag.query(q, user, n_results=10, min_similarity=-1.0)  # show everything
            rows = [(d["score"], "ALLOW", d["title"]) for d in r["allowed_docs"]] + \
                   [(d["score"], "DENY ", d["title"]) for d in r["denied_docs"]]
            print(f'Q: "{q}"  (as {user})')
            for score, verdict, title in sorted(rows, reverse=True):
                mark = "  <-- kept" if score >= rag.min_similarity else ""
                print(f"   {score:6.3f}  {verdict}  {title}{mark}")
            print()