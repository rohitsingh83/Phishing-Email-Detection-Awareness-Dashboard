"""
Pydantic Schemas for Request Validation and Typed API Responses
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., example="security-alert@account-verify.invalid.test", description="Sender email address")
    subject: str = Field(..., example="URGENT: Verify Your Account Immediately", description="Email subject line")
    body: str = Field(..., example="Please verify your password immediately to avoid suspension.", description="Raw email text body")
    urls: Optional[str] = Field(default="", example="http://198.51.100.10/verify-account", description="Space-separated URLs or extracted links")
    attachment_name: Optional[str] = Field(default="", example="Invoice_2026.pdf.exe", description="Filename of attachment if present")


class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., example="http://198.51.100.10/verify-login", description="URL string to analyze statically")


class IndicatorItem(BaseModel):
    category: str
    severity: str
    title: str
    description: str


class ScoreBreakdownItem(BaseModel):
    factor: str
    points: int


class EmailAnalysisResponse(BaseModel):
    analysis_id: Optional[int] = None
    hybrid_risk_score: int
    classification: str
    risk_level: str
    rule_engine: Dict[str, Any]
    machine_learning: Dict[str, Any]
    indicators: List[Dict[str, Any]]
    recommendations: List[str]
    sender_analysis: Dict[str, Any]
    url_analysis: Dict[str, Any]
    attachment_analysis: Dict[str, Any]
    features: Dict[str, Any]


class DashboardStatsResponse(BaseModel):
    total_analyzed: int
    likely_phishing: int
    suspicious: int
    low_risk: int
    average_risk_score: float
    phishing_vs_legitimate: Optional[Dict[str, int]] = None
    distribution: Dict[str, int]
    top_indicators: List[Dict[str, Any]]
    top_keywords: Optional[List[Dict[str, Any]]] = None
    recent_trend: List[Dict[str, Any]]
