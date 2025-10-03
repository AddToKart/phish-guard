from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, description="URL to inspect for phishing indicators.")
    html: Optional[str] = Field(
        default=None,
        description="Optional HTML or text content of the page/email for additional signals.",
        max_length=200_000,
    )

    @field_validator("url", mode="before")
    @classmethod
    def normalize_scheme(cls, value: str) -> str:
        lowered = value.strip()
        if not lowered:
            raise ValueError("URL cannot be empty")
        if not lowered.startswith(("http://", "https://")):
            lowered = f"https://{lowered}"
        return lowered


class RiskSignal(BaseModel):
    feature: str
    message: str
    impact: float
    evidence: Optional[str]


class FeatureVectorItem(BaseModel):
    name: str
    value: float
    weight: float
    impact: float
    description: str
    evidence: Optional[str]


class AnalyzeResponse(BaseModel):
    normalizedUrl: HttpUrl
    score: float = Field(..., ge=0, le=1)
    verdict: str = Field(..., description="phishing | suspicious | legitimate")
    confidence: float = Field(..., ge=0, le=1)
    signals: list[RiskSignal]
    featureVector: list[FeatureVectorItem]
    recommendations: list[str]
