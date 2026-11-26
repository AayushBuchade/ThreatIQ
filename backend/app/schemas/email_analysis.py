"""Request and response models for PHISHGUARD email analysis."""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(default="", max_length=998)
    sender: str = Field(default="", max_length=320)
    body: str = Field(..., min_length=1, max_length=200_000)
    record: bool = False

    @field_validator("body")
    @classmethod
    def body_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Email body is empty")
        return value


class SuspiciousUrl(BaseModel):
    """Defanged URL already present in the message. Not fetched."""

    defanged: str
    reason: str


class TokenContribution(BaseModel):
    token: str
    tfidf: float
    weight: float
    contribution: float
    method: str = "tfidf_linear_weight"


class EmailAnalysisResponse(BaseModel):
    prediction: str
    predicted_class: int
    phishing_probability: float
    model_version: str
    model_name: str
    sklearn_version: str
    artifact_sha256: str
    token_contributions: list[TokenContribution]
    suspicious_urls: list[SuspiciousUrl] = Field(default_factory=list)
    attribution_note: str
    recorded: bool
    duplicate: bool
    event_id: Optional[str] = None
    record_error: Optional[str] = None
