"""SQLite access helpers.

Every query in the application goes through a ``?`` placeholder python-side.
No SQL string is ever built by concatenating user input, which is the
mitigation for A03:2021-Injection required by the assignment.
"""

import sqlite3

import click
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_posts_author ON posts (author_id);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exception=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


@click.command("init-db")
def init_db_command() -> None:
    init_db()
    click.echo("initialised the database")


@click.command("seed")
def seed_command() -> None:
    """Create two demo accounts and a couple of posts."""
    from .security import hash_password

    db = get_db()
    users = [
        ("alice", hash_password("Alice-Strong-Pass-2026"), "admin"),
        ("bob", hash_password("Bob-Strong-Pass-2026"), "user"),
    ]
    for username, password_hash, role in users:
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
    db.commit()
    alice = db.execute("SELECT id FROM users WHERE username = ?", ("alice",)).fetchone()
    bob = db.execute("SELECT id FROM users WHERE username = ?", ("bob",)).fetchone()
    if alice and bob:
        db.execute(
            "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
            (alice["id"], "Welcome", "First post from alice."),
        )
        db.execute(
            "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
            (bob["id"], "Hello", "Second post from bob."),
        )
        db.commit()
    click.echo("seeded demo data")


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_command)
