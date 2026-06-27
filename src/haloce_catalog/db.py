from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize(conn: sqlite3.Connection) -> None:
    schema = resources.files("haloce_catalog").joinpath("schema.sql").read_text(encoding="utf-8")
    conn.executescript(schema)


def reset_database(db_path: Path) -> sqlite3.Connection:
    if db_path.exists():
        db_path.unlink()
    conn = connect(db_path)
    initialize(conn)
    return conn
