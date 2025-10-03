from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .detector import analyze
from .config import get_settings
from .schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(
    title="PhishGuard AI",
    description="Heuristic AI-powered phishing detection service.",
    version="0.1.0",
)

app.state.settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["analysis"])
def analyze_endpoint(payload: AnalyzeRequest) -> AnalyzeResponse:
    try:
        result = analyze(payload.url, payload.html)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise HTTPException(status_code=400, detail=f"Analysis failed: {exc}") from exc

    return AnalyzeResponse(**result)
