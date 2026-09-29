"""
Safe Static Attachment Analyzer
Performs forensic metadata analysis of email attachments based on filename and extension patterns.

CYBERSECURITY RULE:
Never execute or automatically open unknown attachments.
This module strictly performs static string analysis on metadata to prevent weaponization.
"""

from typing import Dict, List, Any
from backend.utils.preprocessor import extract_file_extension

# High-Risk Executable and Script Extensions
DANGEROUS_EXTENSIONS = {
    ".exe": "Windows Executable Binary",
    ".scr": "Windows Screensaver / Executable Binary",
    ".bat": "Windows Batch Script",
    ".cmd": "Windows Command Script",
    ".vbs": "VBScript File",
    ".vbe": "Encoded VBScript File",
    ".js": "JavaScript File",
    ".jse": "Encoded JavaScript File",
    ".wsf": "Windows Script File",
    ".ps1": "PowerShell Script",
    ".hta": "HTML Application",
    ".cpl": "Control Panel Extension Executable",
    ".msc": "Microsoft Management Console File",
    ".jar": "Java Archive Executable",
    ".iso": "Disk Image Container (Bypasses Mark-of-the-Web)",
    ".img": "Disk Image Container",
    ".lnk": "Windows Shortcut File"
}

# Macro-enabled or Archive formats requiring caution
CAUTION_EXTENSIONS = {
    ".docm": "Word Macro-Enabled Document",
    ".xlsm": "Excel Macro-Enabled Spreadsheet",
    ".pptm": "PowerPoint Macro-Enabled Presentation",
    ".zip": "Compressed Archive (May conceal malware)",
    ".rar": "RAR Archive",
    ".7z": "7-Zip Archive",
    ".tar": "Tape Archive"
}

SAFE_EXTENSIONS = {
    ".pdf": "PDF Document",
    ".docx": "Microsoft Word Document",
    ".xlsx": "Microsoft Excel Spreadsheet",
    ".pptx": "Microsoft PowerPoint Presentation",
    ".txt": "Plain Text Document",
    ".csv": "CSV Data File",
    ".png": "PNG Image",
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image"
}


def analyze_attachment(attachment_name: str) -> Dict[str, Any]:
    """
    Analyzes an attachment filename for dangerous characteristics,
    including direct executables and disguised double extensions.
    """
    if not attachment_name or not attachment_name.strip():
        return {
            "has_attachment": False,
            "filename": "",
            "risk_score": 0,
            "severity": "NONE",
            "findings": []
        }

    meta = extract_file_extension(attachment_name)
    filename = meta["filename"]
    primary_ext = meta["primary_extension"]
    is_double = meta["is_double_extension"]
    all_exts = meta["all_extensions"]

    findings: List[Dict[str, Any]] = []
    risk_score = 0

    # 1. Double Extension Detection (e.g. Invoice.pdf.exe or Document.docx.vbs)
    if is_double:
        risk_score += 45
        findings.append({
            "type": "DOUBLE_EXTENSION",
            "severity": "CRITICAL",
            "description": f"Attachment uses deceptive double extension '{''.join(all_exts)}' to masquerade as a harmless document."
        })

    # 2. Executable / Script Check
    if primary_ext in DANGEROUS_EXTENSIONS:
        risk_score += 75
        desc = DANGEROUS_EXTENSIONS[primary_ext]
        findings.append({
            "type": "EXECUTABLE_OR_SCRIPT",
            "severity": "CRITICAL",
            "description": f"Attachment is an executable script or binary ({primary_ext}: {desc}), high risk for malware delivery."
        })
    elif primary_ext in CAUTION_EXTENSIONS:
        risk_score += 35
        desc = CAUTION_EXTENSIONS[primary_ext]
        findings.append({
            "type": "MACRO_OR_ARCHIVE",
            "severity": "MEDIUM",
            "description": f"Attachment format ({primary_ext}: {desc}) can carry malicious macros or encrypted payloads."
        })
    elif primary_ext in SAFE_EXTENSIONS:
        findings.append({
            "type": "STANDARD_DOCUMENT_TYPE",
            "severity": "LOW",
            "description": f"Attachment has standard document extension ({primary_ext}). Verify sender before opening."
        })
    else:
        # Unknown extension
        risk_score += 20
        findings.append({
            "type": "UNKNOWN_EXTENSION",
            "severity": "LOW",
            "description": f"Uncommon or non-standard attachment extension '{primary_ext}'."
        })

    capped_score = min(max(risk_score, 0), 100)

    # Determine severity label
    if capped_score >= 70:
        severity = "HIGH"
    elif capped_score >= 35:
        severity = "MEDIUM"
    elif primary_ext in SAFE_EXTENSIONS:
        severity = "LOW"
    elif capped_score > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "has_attachment": True,
        "filename": filename,
        "primary_extension": primary_ext,
        "is_double_extension": is_double,
        "risk_score": capped_score,
        "severity": severity,
        "findings": findings
    }
