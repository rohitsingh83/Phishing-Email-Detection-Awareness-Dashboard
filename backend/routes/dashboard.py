"""
Dashboard Metrics and Telemetry Endpoints
"""

from fastapi import APIRouter
from backend.models.schemas import DashboardStatsResponse
from backend.database import get_dashboard_stats

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_stats():
    """
    Returns aggregated KPI metrics, risk distributions, and recent detection history.
    """
    return get_dashboard_stats()


@router.get("/indicators")
def get_top_indicators():
    """
    Returns the most frequently detected phishing indicators for dashboard charts.
    """
    stats = get_dashboard_stats()
    return {"indicators": stats.get("top_indicators", [])}
