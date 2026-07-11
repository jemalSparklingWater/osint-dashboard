"""
database.py — saving and loading scan results.

We use SQLite: a tiny database that lives in a single file (osint.db) right next
to our code. It's built into Python (the `sqlite3` module), needs no server, and
is perfect for projects like this. A "database" here just means an organized,
persistent place to store data so it survives after the program stops.
"""

import sqlite3
import json
from datetime import datetime

DB_FILE = "osint.db"


def _connect():
    """Open a connection to the database file."""
    conn = sqlite3.connect(DB_FILE)
    # This makes rows behave like dictionaries (row["domain"]) instead of
    # plain tuples (row[1]) — much easier to read.
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create our table if it doesn't exist yet. A table is like a spreadsheet:
    each row is one scan, each column is a piece of info about it.

    We store the actual findings (subdomains, dns, whois) as a JSON string in
    one column. JSON is just a text format for structured data — an easy way to
    stash a whole nested result without designing lots of separate tables.
    """
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            domain    TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            results   TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(domain: str, results: dict) -> int:
    """Save one scan and return its new id."""
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO scans (domain, scanned_at, results) VALUES (?, ?, ?)",
        (domain, datetime.now().isoformat(timespec="seconds"), json.dumps(results)),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 10) -> list[dict]:
    """Return the most recent scans (just id/domain/time, not full results)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT id, domain, scanned_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_previous_scan(domain: str, before_id: int) -> dict | None:
    """
    Find the most recent scan of the SAME domain that happened BEFORE the given
    scan id. This is what lets us compare "now vs. last time" for change tracking.
    Returns None if this is the domain's first-ever scan.
    """
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM scans WHERE domain = ? AND id < ? ORDER BY id DESC LIMIT 1",
        (domain, before_id),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row["id"],
        "domain": row["domain"],
        "scanned_at": row["scanned_at"],
        "results": json.loads(row["results"]),
    }


def get_scans_for_domain(domain: str, limit: int = 50) -> list[dict]:
    """
    Return every saved scan of one domain, OLDEST first, with full results.
    This is what powers the "risk trend over time" chart — we need the whole
    history of a domain to plot how its risk changed across scans.
    """
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM scans WHERE domain = ? ORDER BY id ASC LIMIT ?",
        (domain, limit),
    ).fetchall()
    conn.close()
    return [
        {"id": r["id"], "domain": r["domain"], "scanned_at": r["scanned_at"],
         "results": json.loads(r["results"])}
        for r in rows
    ]


def get_scan(scan_id: int) -> dict | None:
    """Return one full past scan (with its results parsed back from JSON)."""
    conn = _connect()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row["id"],
        "domain": row["domain"],
        "scanned_at": row["scanned_at"],
        "results": json.loads(row["results"]),  # text back into a Python dict
    }
