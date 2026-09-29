"""
Database Layer for Phishing Detection & Awareness Dashboard
Implements relational schema in SQLite with safe metadata retention.

PRIVACY & SECURITY BEST PRACTICE:
To prevent secondary exposure or PII leakage, full email bodies are NOT stored.
Only forensic metadata (sender domain, subject hash/excerpt, risk score, extracted IOCs)
are persisted in the audit trail.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "phishing_dashboard.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initializes database schema if tables do not exist.
    """
    conn = get_db_connection()
    with conn:
        # 1. ANALYSES TABLE
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_domain TEXT,
                subject TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                ml_probability REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. INDICATORS TABLE
        conn.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
            );
        """)

        # 3. URL_ANALYSES TABLE
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_analyses (
                url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                url_safe_representation TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                findings TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
            );
        """)

        # 4. USERS TABLE (Optional for multi-analyst access)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

    conn.close()


def save_analysis_record(analysis_result: Dict[str, Any], sender_domain: str, subject: str) -> int:
    """
    Saves an analysis record along with its indicators and URL telemetry.
    """
    conn = get_db_connection()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO analyses (sender_domain, subject, risk_score, classification, risk_level, ml_probability)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            sender_domain or "unknown",
            subject or "(No Subject)",
            analysis_result.get("hybrid_risk_score", 0),
            analysis_result.get("classification", "UNKNOWN"),
            analysis_result.get("risk_level", "LOW"),
            analysis_result.get("machine_learning", {}).get("ml_probability", 0.0)
        ))
        analysis_id = cur.lastrowid

        # Insert Indicators
        for ind in analysis_result.get("indicators", []):
            cur.execute("""
                INSERT INTO indicators (analysis_id, category, severity, title, description)
                VALUES (?, ?, ?, ?, ?)
            """, (
                analysis_id,
                ind.get("category", "General"),
                ind.get("severity", "LOW"),
                ind.get("title", ""),
                ind.get("description", "")
            ))

        # Insert URL Analyses
        for url_item in analysis_result.get("url_analysis", {}).get("url_details", []):
            cur.execute("""
                INSERT INTO url_analyses (analysis_id, url_safe_representation, risk_score, findings)
                VALUES (?, ?, ?, ?)
            """, (
                analysis_id,
                url_item.get("url", ""),
                url_item.get("risk_score", 0),
                json.dumps(url_item.get("findings", []))
            ))

    conn.close()
    return analysis_id


def get_all_analyses(
    classification_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    sort_by: str = "created_at",
    order: str = "DESC",
    limit: int = 50,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Retrieves history of analyses with filtering, search, and sorting.
    """
    conn = get_db_connection()
    query = "SELECT * FROM analyses WHERE 1=1"
    params = []

    if classification_filter:
        query += " AND classification LIKE ?"
        params.append(f"%{classification_filter}%")

    if search_query:
        query += " AND (subject LIKE ? OR sender_domain LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])

    valid_sorts = {"risk_score": "risk_score", "created_at": "created_at", "subject": "subject"}
    sort_column = valid_sorts.get(sort_by, "created_at")
    sort_order = "ASC" if order.upper() == "ASC" else "DESC"

    query += f" ORDER BY {sort_column} {sort_order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur = conn.cursor()
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_analysis_by_id(analysis_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves detailed analysis metadata, indicators, and URLs by ID.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    record = dict(row)

    cur.execute("SELECT * FROM indicators WHERE analysis_id = ?", (analysis_id,))
    record["indicators"] = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM url_analyses WHERE analysis_id = ?", (analysis_id,))
    urls = []
    for r in cur.fetchall():
        u = dict(r)
        if u.get("findings"):
            try:
                u["findings"] = json.loads(u["findings"])
            except Exception:
                pass
        urls.append(u)
    record["urls"] = urls

    conn.close()
    return record


def delete_analysis(analysis_id: int) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
        deleted = cur.rowcount > 0
    conn.close()
    return deleted


def get_dashboard_stats() -> Dict[str, Any]:
    """
    Computes summary metrics and charts telemetry for dashboard cards.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM analyses")
    total_analyzed = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%HIGH RISK%'")
    likely_phishing = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%SUSPICIOUS%'")
    suspicious = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%LOW RISK%' OR classification LIKE '%SAFE%'")
    low_risk = cur.fetchone()[0]

    cur.execute("SELECT AVG(risk_score) FROM analyses")
    avg_score_row = cur.fetchone()[0]
    avg_risk_score = round(avg_score_row, 1) if avg_score_row is not None else 0.0

    # Risk score distribution bands
    cur.execute("SELECT COUNT(*) FROM analyses WHERE risk_score <= 20")
    band_0_20 = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM analyses WHERE risk_score > 20 AND risk_score <= 40")
    band_21_40 = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM analyses WHERE risk_score > 40 AND risk_score <= 70")
    band_41_70 = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM analyses WHERE risk_score > 70")
    band_71_100 = cur.fetchone()[0]

    # Top indicators
    cur.execute("""
        SELECT title, COUNT(*) as count FROM indicators
        GROUP BY title ORDER BY count DESC LIMIT 8
    """)
    top_indicators = [{"title": r[0], "count": r[1]} for r in cur.fetchall()]

    # Recent Trend (last 10 entries)
    cur.execute("""
        SELECT strftime('%Y-%m-%d %H:%M', created_at) as time_slot, risk_score, classification 
        FROM analyses ORDER BY analysis_id DESC LIMIT 10
    """)
    recent_trend = [{"time": r[0], "score": r[1], "classification": r[2]} for r in cur.fetchall()]
    recent_trend.reverse()

    conn.close()

    return {
        "total_analyzed": total_analyzed,
        "likely_phishing": likely_phishing,
        "suspicious": suspicious,
        "low_risk": low_risk,
        "average_risk_score": avg_risk_score,
        "distribution": {
            "safe_low": band_0_20,
            "moderate": band_21_40,
            "suspicious": band_41_70,
            "high_risk": band_71_100
        },
        "top_indicators": top_indicators,
        "recent_trend": recent_trend
    }


# Ensure tables exist on import
init_db()
