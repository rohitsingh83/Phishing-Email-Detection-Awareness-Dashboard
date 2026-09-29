"""
Email and URL Analysis API Endpoints
"""

import email
from email import policy
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File
from backend.models.schemas import EmailAnalysisRequest, EmailAnalysisResponse, UrlAnalysisRequest
from backend.services.hybrid_detector import run_hybrid_analysis
from backend.services.url_analyzer import analyze_single_url
from backend.utils.preprocessor import extract_domain, extract_urls
from backend.database import save_analysis_record

router = APIRouter(prefix="/api", tags=["Analysis"])


@router.post("/analyze", response_model=EmailAnalysisResponse)
def analyze_email_endpoint(payload: EmailAnalysisRequest):
    """
    Ingests email data, extracts forensic indicators, evaluates rules + ML,
    computes hybrid score, logs to database, and returns explainable findings.
    """
    try:
        # Run Hybrid Detection Engine
        result = run_hybrid_analysis(
            sender=payload.sender,
            subject=payload.subject,
            body=payload.body,
            urls=payload.urls or "",
            attachment_name=payload.attachment_name or ""
        )

        # Extract domain for metadata tracking
        sender_domain = extract_domain(payload.sender)

        # Persist to database audit trail
        analysis_id = save_analysis_record(result, sender_domain=sender_domain, subject=payload.subject)
        result["analysis_id"] = analysis_id

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@router.post("/analyze/url")
def analyze_url_endpoint(payload: UrlAnalysisRequest):
    """
    Performs static string analysis of a single URL without contacting the host.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL field cannot be empty.")
    try:
        return analyze_single_url(payload.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL parsing error: {str(e)}")


@router.post("/analyze/file")
async def analyze_uploaded_email_file(file: UploadFile = File(...)):
    """
    Accepts safe sample .txt or .eml files, extracts headers & body, and triggers analysis.
    """
    filename = file.filename.lower()
    if not (filename.endswith(".txt") or filename.endswith(".eml")):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file format. Only safe sample .txt or standard .eml files are accepted."
        )

    content_bytes = await file.read()
    if len(content_bytes) > 2 * 1024 * 1024:  # 2MB defensive limit
        raise HTTPException(status_code=413, detail="File size exceeds safe demo limit of 2MB.")

    text_content = content_bytes.decode("utf-8", errors="ignore")

    sender = "unknown@sample.test"
    subject = file.filename
    body = text_content
    attachment_name = ""

    if filename.endswith(".eml"):
        try:
            msg = email.message_from_string(text_content, policy=policy.default)
            sender = str(msg.get("From", sender))
            subject = str(msg.get("Subject", subject))

            # Extract body
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disp:
                        att_fn = part.get_filename()
                        if att_fn:
                            attachment_name = att_fn
                    elif content_type in ["text/plain", "text/html"]:
                        payload_data = part.get_payload(decode=True)
                        if payload_data:
                            body_parts.append(payload_data.decode("utf-8", errors="ignore"))
            else:
                body_parts.append(msg.get_body(preferencelist=('plain', 'html')).get_content() if msg.get_body() else "")

            body = "\n".join(body_parts) if body_parts else text_content
        except Exception:
            # Fallback to raw text if parsing fails
            body = text_content

    # Extract any embedded URLs
    extracted_urls = " ".join(extract_urls(body))

    # Run analysis
    result = run_hybrid_analysis(
        sender=sender,
        subject=subject,
        body=body,
        urls=extracted_urls,
        attachment_name=attachment_name
    )

    domain = extract_domain(sender)
    analysis_id = save_analysis_record(result, sender_domain=domain, subject=subject)
    result["analysis_id"] = analysis_id
    result["parsed_metadata"] = {
        "sender": sender,
        "subject": subject,
        "attachment_name": attachment_name
    }

    return result
