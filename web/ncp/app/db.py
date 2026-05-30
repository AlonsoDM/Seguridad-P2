import secrets
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
JOBS_DIR = DATA_DIR / "jobs"
DB_PATH = DATA_DIR / "app.db"


SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin'))
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    output_format TEXT NOT NULL,
    status TEXT NOT NULL,
    upload_path TEXT NOT NULL,
    output_path TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    return conn


def reset_runtime_state():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if DB_PATH.exists():
        DB_PATH.unlink()

    if JOBS_DIR.exists():
        shutil.rmtree(JOBS_DIR)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    admin_password = secrets.token_urlsafe(14)

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", admin_password, "admin"),
        )
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            [
                ("asset_storage_enabled", "0"),
            ],
        )
        conn.commit()

    return admin_password


def fetch_one(query, params=()):
    with closing(connect_db()) as conn:
        return conn.execute(query, params).fetchone()


def fetch_all(query, params=()):
    with closing(connect_db()) as conn:
        return conn.execute(query, params).fetchall()


def execute(query, params=()):
    with closing(connect_db()) as conn:
        conn.execute(query, params)
        conn.commit()


def execute_many(query, items):
    with closing(connect_db()) as conn:
        conn.executemany(query, items)
        conn.commit()
