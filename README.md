#  AI Security Gateway & Tamper-Proof Audit Ledger

An enterprise security reverse proxy and compliance engine for Large Language Models. It provides multi-modal input/output sanitization, prompt injection defense, role-based access control (RBAC), and RAG knowledge boundary enforcement. It supports hybrid LLM routing across local inference (**Ollama: `qwen2.5:7b`**) and cloud reasoning (**Google Gemini**), while logging all transactions to an HMAC-keyed, SHA-256 tamper-evident cryptographic ledger.

---

## Architecture Overview

```
                        [End-User / Client UI]
                                   │  (Prompt / PDF / Image + RBAC Headers)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AI Security Gateway (FastAPI)                      │
│                                                                         │
│   ├── Ingress Inspection: prompt_inspector.py & multimodal_inspector.py │
│   │   └── Presidio PII Masking, Secret Regex, Document/Image Extraction │
│   │                                                                     │
│   ├── Policy & Clearance: policy_engine.py & risk_scorer.py             │
│   │   └── Role clearance enforcement (Guest, Analyst, Admin)            │
│   │                                                                     │
│   ├── Knowledge Boundary: rag_engine.py                                 │
│   │   └── ChromaDB context retrieval bounded by tenant permissions      │
│   │                                                                     │
│   └── Verification & Forensics: hash_chain.py & integrity.py            │
│       └── Cryptographic HMAC-SHA256 append-only ledger entry            │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │      llm_router.py          │
                    ▼                             ▼
       [Local: Ollama (qwen2.5:7b)]    [Cloud: Google Gemini]
                    │                             │
                    └──────────────┬──────────────┘
                                   │  (Raw LLM Generation)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AI Security Gateway (FastAPI)                      │
│   ├── Egress Leakage Scrubbing & De-anonymization Mapping               │
│   └── Cryptographic Egress Ledger Signature                             │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
        [chat_ui.py / user_app.py]  &  [dashboard.py / SecOps View]
```

---

## Key Features

* **Hybrid Model Routing:** Dynamic dispatch between self-hosted local models via **Ollama (`qwen2.5:7b`)** for air-gapped workloads and **Google Gemini** for complex cloud completions.
* **Multimodal Data Scrubbing:** Ingests and sanitizes text, images (OCR scanning via Pillow), and documents (`pypdf`/`pymupdf`) to strip PII and internal credentials before LLM dispatch.
* **Cryptographic Tamper-Proof Ledger:** SHA-256 hash-chain with HMAC signing for every transaction. Any unauthorized row modification or deletion breaks the chain and triggers immediate SecOps alarms.
* **Security Operations & User UI:**
  * **User Application:** `chat_ui.py` / `user_app.py` for interacting with the protected LLM with role-based document uploads.
  * **SecOps Dashboard:** `dashboard.py` / `dashboardlogs.py` for real-time ledger health auditing, block diagnostics, and live intrusion alerts.

---

## Directory Structure

```
Cybercup/
├── .streamlit/
│   └── config.toml             # Streamlit UI theme and server configuration
├── assets/                     # Architecture diagrams and media assets
├── data/                       # ChromaDB persistent store & audit_log.db
├── gateway/                    # Core Security Proxy Engine
│   ├── client.py               # Gateway HTTP client interfaces
│   ├── hash_chain.py           # HMAC-SHA256 hash-chain ledger implementation
│   ├── integrity.py            # Audit chain verification & tamper forensics
│   ├── llm_router.py           # Provider router (Ollama qwen2.5:7b vs Gemini)
│   ├── models.py               # Pydantic schemas and request/response models
│   ├── multimodal_inspector.py # Image OCR & document content extraction
│   ├── pipeline.py             # Ingress/egress sanitization orchestrator
│   ├── policy_engine.py        # RBAC and tenant authorization policies
│   ├── prompt_inspector.py     # Presidio NLP & regex PII sanitizers
│   ├── rag_engine.py           # ChromaDB vector store retriever
│   └── risk_scorer.py          # Threat heuristics & prompt injection scoring
├── scripts/                    # Maintenance & utility scripts
├── tests/                      # Automated test suites (hash chain, RAG, etc.)
├── ui/
│   └── helpers.py              # Shared rendering and session helpers
├── .env                        # Local environment variables & secrets
├── chat_ui.py                  # End-user chat interface
├── user_app.py                 # Multi-role user workspace
├── dashboard.py                # SecOps security & tamper auditing dashboard
├── dashboardlogs.py            # Log inspection tool
├── demo.py                     # Demo scenario runner
├── main.py                     # FastAPI application entry point
├── requirements.txt            # Python dependencies
└── README.md
```

---

## Setup & Installation

### Prerequisites

1. **Python 3.10+**
2. **Ollama:** Installed and running locally ([ollama.com](https://ollama.com/))
3. **Google Gemini API Key:** Accessible via [Google AI Studio](https://aistudio.google.com/)

---

### 1. Pull the Local Model

Ensure the Ollama daemon is running, then pull `qwen2.5:7b`:

```bash
ollama run qwen2.5:7b
```

---

### 2. Virtual Environment Setup

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3. Install Dependencies & NLP Models

```powershell
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

---

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```ini
# Google Gemini
GEMINI_API_KEY=your_gemini_api_key_here

# Local Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b

# Gateway Settings
GATEWAY_SECRET_KEY=your_secure_hmac_signing_key_here
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=8000

# Audit Ledger
AUDIT_DB_PATH=data/audit_log.db
```

---

## Running the System

Open separate terminal tabs (with `.venv` active) to run each service:

### 1. Start the Gateway Proxy (FastAPI)
```powershell
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive API Docs (Swagger): `http://127.0.0.1:8000/docs`

### 2. Launch the SecOps Audit Dashboard
```powershell
streamlit run dashboard.py --server.port 8501
```
* SecOps Dashboard: `http://localhost:8501`

### 3. Launch the End-User Chat Client
```powershell
streamlit run chat_ui.py --server.port 8502
```
* Chat Application: `http://localhost:8502`

*(Alternatively, run `streamlit run user_app.py` depending on the desired interface).*

---

## Cryptographic Hash-Chain Verification

The ledger computes an HMAC-SHA256 signature chaining each record to its predecessor:

$$
\text{Hash}_n = \text{HMAC-SHA256}(\text{SecretKey}, \text{Payload}_n \mathbin{\Vert} \text{Hash}_{n-1})
$$

### Run Automated Tests
```powershell
pytest tests/
```

### Manual Integrity Verification
Run the verification check to validate the database:
```powershell
python -m gateway.integrity
```

---

## Demo Scenarios

1. **PII Masking & Anonymization:**
   Enter: *"My name is Jane Doe, SSN 123-45-6789. Summarize my profile."*  
   **Result:** The gateway intercepts the payload, masks values to `<PERSON_1>` and `<US_SSN_1>`, and sends only anonymized data to the LLM backend.

2. **RBAC Clearance Enforcement:**
   Switch active role to `Guest` in the user app and ask for internal corporate financials.  
   **Result:** `policy_engine.py` halts evaluation, emits an access denial, and logs the blocked transaction.

3. **Tamper Forensics:**
   Edit a past log row in `data/audit_log.db` using an SQLite editor. Navigate to the **SecOps Dashboard** and refresh. The status switches to **TAMPER DETECTED**, highlighting the exact record ID where the hash chain diverged.
