"""
GoldenShield AI - Shared Incident Database
Connects GoldenShield's fraud detection to the shared OgaShield incident store,
so OGA_WATCHAFRI (and any future product) can read real flagged incidents.

Reads its connection string from the DATABASE_URL environment variable.
Render sets this automatically once you add it under the service's
Environment tab -- never hardcode the credential here.
"""

import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime


def get_connection():
    """
    Open a new connection to the shared Postgres database.
    Returns None if DATABASE_URL isn't set, so the app can keep running
    in-memory-only (e.g. on a local dev machine) without crashing.
    """
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        return None
    try:
        return psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    except Exception as e:
        print(f"[gs_database] Could not connect to database: {e}")
        return None


def init_db():
    """
    Create the shared `incidents` table if it doesn't already exist.
    Safe to call every time the app starts -- CREATE TABLE IF NOT EXISTS
    is a no-op if the table is already there.
    """
    conn = get_connection()
    if conn is None:
        print("[gs_database] Skipping init_db -- no DATABASE_URL set.")
        return

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id SERIAL PRIMARY KEY,
                        source TEXT NOT NULL,
                        risk_level TEXT,
                        fraud_score NUMERIC,
                        pattern TEXT,
                        description TEXT,
                        raw_data JSONB,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                """)
        print("[gs_database] incidents table ready.")
    except Exception as e:
        print(f"[gs_database] init_db failed: {e}")
    finally:
        conn.close()


def log_incident(risk_level, fraud_score, pattern, description, raw_data, source='goldenshield'):
    """
    Write a single fraud incident to the shared table.

    This is the hand-off point: anything written here becomes visible
    to OGA_WATCHAFRI (or any other system reading the same table),
    closing the gap between detection and citizen-facing response.

    Never raises -- a logging failure should never break a fraud scan.
    Returns the new row's id on success, or None on failure/skip.
    """
    conn = get_connection()
    if conn is None:
        return None

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO incidents
                        (source, risk_level, fraud_score, pattern, description, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id;
                """, (
                    source,
                    risk_level,
                    fraud_score,
                    pattern,
                    description,
                    json.dumps(raw_data, default=str),
                ))
                new_id = cur.fetchone()['id']
        return new_id
    except Exception as e:
        print(f"[gs_database] log_incident failed: {e}")
        return None
    finally:
        conn.close()


def get_recent_incidents(limit=20):
    """
    Read back the most recent incidents -- useful for a future
    OGA_WATCHAFRI polling endpoint, or for debugging from GoldenShield itself.
    Returns an empty list if the database isn't reachable.
    """
    conn = get_connection()
    if conn is None:
        return []

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, source, risk_level, fraud_score, pattern,
                           description, raw_data, created_at
                    FROM incidents
                    ORDER BY created_at DESC
                    LIMIT %s;
                """, (limit,))
                rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[gs_database] get_recent_incidents failed: {e}")
        return []
    finally:
        conn.close()
