# # main.py
# import time
# from fastapi import FastAPI, HTTPException, UploadFile, File, Form
# from fastapi.middleware.cors import CORSMiddleware
# from typing import Optional

# from gateway.models import ChatRequest, ChatResponse
# from gateway.pipeline import GatewayPipeline
# from gateway.multimodal_inspector import MultimodalInspector

# app = FastAPI(
#     title="🛡️ AI Security Gateway",
#     description="Enterprise API Gateway with Multimodal (Text, Image, PDF) Data Leakage & Prompt Injection Protection.",
#     version="1.0.0"
# )

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# gateway = GatewayPipeline()
# multimodal_inspector = MultimodalInspector()

# @app.middleware("http")
# async def add_latency_header(request, call_next):
#     start_time = time.time()
#     response = await call_next(request)
#     duration_ms = round((time.time() - start_time) * 1000, 2)
#     response.headers["X-Gateway-Latency-Ms"] = str(duration_ms)
#     return response

# @app.get("/")
# async def root():
#     return {"message": "🛡️ Multimodal AI Security Gateway is active!", "docs": "/docs"}

# @app.get("/health")
# async def health_check():
#     return {"status": "healthy", "gateway": "active", "multimodal": "enabled"}

# # 1. Standard Text Endpoint
# @app.post("/chat", response_model=ChatResponse)
# async def chat_endpoint(request: ChatRequest):
#     """Text-only Chat Endpoint"""
#     try:
#         return await gateway.process(request)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Gateway Error: {str(e)}")

# # 🖼️📄 2. NEW: Multimodal File Upload Endpoint (Images, PDFs, Screenshots, Documents)
# @app.post("/chat/multimodal", response_model=ChatResponse)
# async def chat_multimodal_endpoint(
#     user_id: str = Form(...),
#     prompt: Optional[str] = Form(""),
#     file: UploadFile = File(...)
# ):
#     """
#     Multimodal Chat Endpoint: Accepts images (screenshots, Aadhaar/PAN photos) or documents (PDFs, code files),
#     extracts content, scans for PII/secrets/injections, and processes through the gateway pipeline.
#     """
#     try:
#         file_bytes = await file.read()
#         extracted_text, file_meta = await multimodal_inspector.inspect_file(file_bytes, file.filename)
        
#         # Combine user prompt with extracted file content
#         combined_message = f"User Prompt: {prompt}\n\n[ATTACHED FILE: {file.filename}]\n{extracted_text}"
        
#         # Process combined content through your existing security pipeline!
#         chat_request = ChatRequest(user_id=user_id, message=combined_message)
#         response = await gateway.process(chat_request)
        
#         # Inject file inspection details into response actions
#         response.actions_taken.insert(0, f"FILE_INSPECTED: {file.filename} ({file_meta['file_type']})")
#         if file_meta.get("visual_pii_detected"):
#             response.actions_taken.insert(1, "VISUAL_SECURITY_FLAG: Sensitive credentials/ID detected inside uploaded image")
            
#         return response

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Multimodal Processing Error: {str(e)}")

# @app.get("/audit/logs")
# async def get_audit_logs(limit: int = 50):
#     return gateway.audit.get_logs(limit=limit)

# @app.get("/audit/stats")
# async def get_audit_stats():
#     return gateway.audit.get_stats()

# @app.get("/audit/verify")
# async def verify_hash_chain():
#     return gateway.audit.verify_chain()

# @app.get("/policies")
# async def get_policies():
#     return gateway.policy.get_all_policies()

# @app.put("/policies/{policy_name}")
# async def update_policy(policy_name: str, action: str):
#     gateway.policy.update_policy(policy_name, action)
#     return {"status": "success", "policy": policy_name, "new_action": action}

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)



# main.py
import re
import time
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from gateway.models import ChatRequest, ChatResponse
from gateway.pipeline import GatewayPipeline
from gateway.multimodal_inspector import MultimodalInspector
from dashboardlogs import router as dash_router, log_request   # NEW: Spikers dashboard

app = FastAPI(
    title="🛡️ AI Security Gateway",
    description="Enterprise API Gateway with Multimodal (Text, Image, PDF) Data Leakage & Prompt Injection Protection.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dash_router)   # NEW: serves /dashboard and /api/dash/*

gateway = GatewayPipeline()
multimodal_inspector = MultimodalInspector()

# NEW ---------------------------------------------------------------
# Turns a gateway response into a dashboard log row. Findings are read from entries in
# response.actions_taken that look like "INJECTION/ML_CLASSIFIER: score 0.50".
# Logging can never break a chat request.
_FIND = re.compile(r"\b(PII|SECRET|INJECTION)/([A-Z_]+)(?::\s*score\s*([0-9.]+))?")


def _log(user_id, text, response, source, t0):
    try:
        actions = [str(a) for a in (getattr(response, "actions_taken", None) or [])]
        findings = [{"type": m[0], "subtype": m[1], "confidence": float(m[2] or 0.8)}
                    for a in actions for m in _FIND.findall(a)]
        joined = " ".join(actions).lower()
        if str(getattr(response, "llm_used", "")).upper() == "BLOCKED" or "request blocked" in joined:
            action = "block"
        elif any(k in joined for k in ("mask", "redact", "sanitiz")):
            action = "mask"
        else:
            action = "allow"
        log_request(user_id, [(source, text, findings)], action,
                    risk_level=getattr(response, "risk_level", ""),
                    risk_score=getattr(response, "risk_score_input", 0) or 0,
                    llm_used=getattr(response, "llm_used", ""),
                    latency_ms=round((time.perf_counter() - t0) * 1000))
    except Exception as e:
        print(f"dashboard log failed: {e}")
# -------------------------------------------------------------------

@app.middleware("http")
async def add_latency_header(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    response.headers["X-Gateway-Latency-Ms"] = str(duration_ms)
    return response

@app.get("/")
async def root():
    return {"message": "🛡️ Multimodal AI Security Gateway is active!", "docs": "/docs", "dashboard": "/dashboard"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "gateway": "active", "multimodal": "enabled"}

# 1. Standard Text Endpoint
@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    """Text-only Chat Endpoint"""
    try:
        t0 = time.perf_counter()
        response = await gateway.process(request)
        _log(request.user_id, request.message, response, "prompt", t0)   # NEW
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gateway Error: {str(e)}")

# 🖼️📄 2. Multimodal File Upload Endpoint (Images, PDFs, Screenshots, Documents)
@app.post("/chat/multimodal", response_model=ChatResponse)
async def chat_multimodal_endpoint(
    user_id: str = Form(...),
    prompt: Optional[str] = Form(""),
    file: UploadFile = File(...)
):
    """
    Multimodal Chat Endpoint: Accepts images (screenshots, Aadhaar/PAN photos) or documents (PDFs, code files),
    extracts content, scans for PII/secrets/injections, and processes through the gateway pipeline.
    """
    try:
        t0 = time.perf_counter()
        file_bytes = await file.read()
        extracted_text, file_meta = await multimodal_inspector.inspect_file(file_bytes, file.filename)

        # Combine user prompt with extracted file content
        combined_message = f"User Prompt: {prompt}\n\n[ATTACHED FILE: {file.filename}]\n{extracted_text}"

        # Process combined content through your existing security pipeline!
        chat_request = ChatRequest(user_id=user_id, message=combined_message)
        response = await gateway.process(chat_request)

        # Inject file inspection details into response actions
        response.actions_taken.insert(0, f"FILE_INSPECTED: {file.filename} ({file_meta['file_type']})")
        if file_meta.get("visual_pii_detected"):
            response.actions_taken.insert(1, "VISUAL_SECURITY_FLAG: Sensitive credentials/ID detected inside uploaded image")

        # "combined" because prompt and file text are scanned as one string (see note on splitting them)
        _log(user_id, combined_message, response, "combined", t0)   # NEW
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Multimodal Processing Error: {str(e)}")

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
    gateway.policy.update_policy(policy_name, action)
    return {"status": "success", "policy": policy_name, "new_action": action}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)