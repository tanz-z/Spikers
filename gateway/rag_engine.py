"""
gateway/rag_engine.py - Access-Controlled RAG Engine using ChromaDB
Owner: Bhoomi

Features:
- Role/User-based access control filtering (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
- Over-fetching strategy (fetches 3x candidates, filters by permission)
- Realistic seed documents for HR, Finance, DevOps, Legal, and Public domain
- Detailed access violation logging (returns denied docs for UI warnings)
"""

import os
import json
import chromadb
from typing import List, Dict, Any, Optional

# Path where persistent vector database will be stored
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "chroma_db")


class AccessControlledRAG:
    """RAG vector store with fine-grained access control."""

    # Realistic Seed Documents
    SEED_DOCUMENTS = [
        {
            "id": "doc_hr_01",
            "title": "HR Employee Records & Salaries 2024",
            "content": "CONFIDENTIAL HR DATA: Employee Salary List 2024. Rahul Sharma: ₹18,50,000. Priya Verma (PAN: ABCPV1234K, Aadhaar: 9876 5432 1098): ₹22,00,000. Performance appraisal ratings: High Performers list attached.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_hr", "user_admin"],
            "department": "HR"
        },
        {
            "id": "doc_fin_01",
            "title": "Q3 Financial Performance & Revenue Report",
            "content": "CONFIDENTIAL FINANCE REPORT: Q3 Gross Revenue: $4.2M, Net Profit Margin: 18.5%. Cash reserves stand at $1.2M. Projected M&A target budget: $850,000 reserved for Q4 acquisition.",
            "classification": "CONFIDENTIAL",
            "allowed_users": ["user_cfo", "user_finance", "user_admin"],
            "department": "Finance"
        },
        {
            "id": "doc_devops_01",
            "title": "Cloud Infrastructure & AWS Secrets Guide",
            "content": "DEVOPS SECRETS: AWS Primary Production Cluster in us-east-1. Master API Key: AKIAIOSFODNN7EXAMPLE. Master DB Admin Password: AdminP@ssw0rd2024! SSH access via bastion host 192.168.1.105.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_devops", "user_admin"],
            "department": "DevOps"
        },
        {
            "id": "doc_pub_01",
            "title": "Company Holiday Calendar 2024",
            "content": "PUBLIC INFO: Official Company Holidays 2024. New Year Day: Jan 1, Independence Day: Aug 15, Diwali: Nov 1, Christmas: Dec 25. Standard PTO allowance: 21 days per year.",
            "classification": "PUBLIC",
            "allowed_users": ["ALL"],  # Accessible to everyone
            "department": "General"
        },
        {
            "id": "doc_gen_01",
            "title": "General Employee Conduct Policy",
            "content": "INTERNAL POLICY: All employees must complete annual security awareness training. Remote work permitted 2 days per week. Use of corporate VPN is mandatory on public Wi-Fi.",
            "classification": "INTERNAL",
            "allowed_users": ["ALL_AUTHENTICATED"],  # Accessible to any valid user
            "department": "HR"
        },
        {
            "id": "doc_project_nexus",
            "title": "Project Nexus - Secret M&A Strategy",
            "content": "RESTRICTED STRATEGY: Project Nexus acquisition plan for competitor FinTech Corp. Acquisition price target: $15M. Expected closing date: December 2024.",
            "classification": "RESTRICTED",
            "allowed_users": ["user_cfo", "user_admin"],
            "department": "Executive"
        }
    ]

    def __init__(self, persist_dir: str = DATA_DIR):
        """Initialize ChromaDB collection and seed default documents."""
        os.makedirs(persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="security_gateway_docs",
            metadata={"description": "Access-controlled knowledge base"}
        )
        
        # Seed documents if empty
        if self.collection.count() == 0:
            self._seed_database()

    def _seed_database(self):
        """Seed the ChromaDB database with demo documents."""
        ids = [doc["id"] for doc in self.SEED_DOCUMENTS]
        documents = [doc["content"] for doc in self.SEED_DOCUMENTS]
        metadatas = [
            {
                "title": doc["title"],
                "classification": doc["classification"],
                "allowed_users": json.dumps(doc["allowed_users"]),
                "department": doc["department"]
            }
            for doc in self.SEED_DOCUMENTS
        ]
        
        self.collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )
        print(f"✅ RAG Engine: Successfully seeded {len(ids)} documents into ChromaDB!")

    def _user_has_access(self, user_id: str, allowed_users_json: str) -> bool:
        """Check if user is authorized to read document based on permission array."""
        try:
            allowed_users = json.loads(allowed_users_json)
        except Exception:
            return False

        # Access rules:
        # 1. "ALL" means public access
        # 2. "ALL_AUTHENTICATED" means any non-anonymous user
        # 3. Specific user ID matching (e.g., "user_hr", "user_admin")
        if "ALL" in allowed_users:
            return True
        if "ALL_AUTHENTICATED" in allowed_users and user_id != "anonymous":
            return True
        if user_id in allowed_users:
            return True

        return False

    def query(self, query_text: str, user_id: str = "user_general", n_results: int = 3) -> Dict[str, Any]:
        """
        Query RAG with Access Control Filtering.
        Uses Over-Fetching (fetches 3x candidates, filters by user rights).
        """
        # Over-fetch candidate results (fetch 3x requested)
        fetch_limit = min(n_results * 3, self.collection.count())
        
        results = self.collection.query(
            query_texts=[query_text],
            n_results=fetch_limit
        )

        allowed_docs = []
        denied_docs = []
        context_parts = []

        if results and results["documents"] and results["documents"][0]:
            docs = results["documents"][0]
            metas = results["metadatas"][0]
            ids = results["ids"][0]
            distances = results["distances"][0] if "distances" in results else [0.0] * len(docs)

            for doc_id, doc_text, metadata, dist in zip(ids, docs, metas, distances):
                allowed_users_json = metadata.get("allowed_users", "[]")
                
                doc_info = {
                    "id": doc_id,
                    "title": metadata.get("title", "Untitled"),
                    "classification": metadata.get("classification", "UNKNOWN"),
                    "department": metadata.get("department", "General"),
                    "score": round(1.0 - dist, 4) if dist else 1.0
                }

                if self._user_has_access(user_id, allowed_users_json):
                    if len(allowed_docs) < n_results:
                        allowed_docs.append(doc_info)
                        context_parts.append(f"--- Document: {doc_info['title']} ({doc_info['classification']}) ---\n{doc_text}")
                else:
                    denied_docs.append(doc_info)

        combined_context = "\n\n".join(context_parts) if context_parts else "No relevant allowed documents found."
        access_violation = len(denied_docs) > 0

        return {
            "context": combined_context,
            "allowed_docs": allowed_docs,
            "denied_docs": denied_docs,
            "access_violation": access_violation,
            "total_candidates_examined": len(results["documents"][0]) if results and results["documents"] else 0
        }


# ─── QUICK TEST / VERIFICATION ───
if __name__ == "__main__":
    rag = AccessControlledRAG()

    print("\n--- TEST 1: General User asking about salaries ---")
    res1 = rag.query("What are the employee salaries?", user_id="user_general")
    print(f"Allowed Docs: {[d['title'] for d in res1['allowed_docs']]}")
    print(f"Denied Docs:  {[d['title'] for d in res1['denied_docs']]}")
    print(f"Access Violation Triggered? {res1['access_violation']}")

    print("\n--- TEST 2: HR User asking about salaries ---")
    res2 = rag.query("What are the employee salaries?", user_id="user_hr")
    print(f"Allowed Docs: {[d['title'] for d in res2['allowed_docs']]}")
    print(f"Denied Docs:  {[d['title'] for d in res2['denied_docs']]}")
    print(f"Access Violation Triggered? {res2['access_violation']}")