"""
Analysis History Endpoints
Provides search, filtering, and detail inspection for past forensic assessments.
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from backend.database import get_all_analyses, get_analysis_by_id, delete_analysis

router = APIRouter(prefix="/api/analyses", tags=["History"])


@router.get("")
def list_analyses(
    classification: Optional[str] = Query(None, description="Filter by classification status"),
    search: Optional[str] = Query(None, description="Search subject or sender domain"),
    sort_by: str = Query("created_at", description="Sort field: created_at, risk_score, subject"),
    order: str = Query("DESC", description="Sort order: ASC or DESC"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """
    Lists recorded email analysis metadata with filtering and search.
    """
    records = get_all_analyses(
        classification_filter=classification,
        search_query=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        offset=offset
    )
    return {"total": len(records), "analyses": records}


@router.get("/{analysis_id}")
def get_analysis_detail(analysis_id: int):
    """
    Retrieves full forensic details, indicators, and URL analysis for an entry.
    """
    record = get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found.")
    return record


@router.delete("/{analysis_id}")
def remove_analysis(analysis_id: int):
    """
    Deletes an analysis record and its cascaded indicators from the database.
    """
    success = delete_analysis(analysis_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found.")
    return {"status": "success", "message": f"Analysis ID {analysis_id} deleted successfully."}
