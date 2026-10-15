# main.py
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from gateway.models import ChatRequest, ChatResponse
from gateway.pipeline import GatewayPipeline

app = FastAPI(
    title="🛡️ AI Security Gateway",
    description="Enterprise API Gateway to prevent data leakage and prompt injection in LLM workflows.",
    version="1.0.0"
)

# Enable CORS for Streamlit / React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate the pipeline
gateway = GatewayPipeline()

# Middleware to record processing latency
@app.middleware("http")
async def add_latency_header(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    response.headers["X-Gateway-Latency-Ms"] = str(duration_ms)
    return response

# -------------------------------------------------------------------
# API ENDPOINTS
# -------------------------------------------------------------------

@app.get("/")
async def root():
    return {"message": "🛡️ AI Security Gateway is running live!", "docs": "/docs"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "gateway": "active",
        "version": "1.0.0"
    }

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    """Main Chat Endpoint: Passes user input through security inspection and LLM router."""
    try:
        return await gateway.process(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gateway Error: {str(e)}")

@app.get("/audit/logs")
async def get_audit_logs(limit: int = 50):
    return gateway.audit.get_logs(limit=limit)

@app.get("/audit/stats")
async def get_audit_stats():
    return gateway.audit.get_stats()

@app.get("/audit/verify")
async def verify_hash_chain():
    return gateway.audit.verify_chain()

@app.get("/policies")
async def get_policies():
    return gateway.policy.get_all_policies()

@app.put("/policies/{policy_name}")
async def update_policy(policy_name: str, action: str):
    valid_actions = ["block", "redact", "mask", "warn", "allow"]
    if action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Action must be one of {valid_actions}")
    gateway.policy.update_policy(policy_name, action)
    return {"status": "success", "policy": policy_name, "new_action": action}

# Run standalone
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)