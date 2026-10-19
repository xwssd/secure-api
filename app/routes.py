"""HTTP endpoints: login, protected data read and protected data write."""

from flask import Blueprint, g, jsonify, request

from .auth import login_required, rate_limited
from .db import get_db
from .security import sanitize, verify_password

api = Blueprint("api", __name__)

TITLE_MAX = 120
BODY_MAX = 5000


@api.get("/health")
def health():
    return jsonify(status="ok")


@api.post("/auth/login")
def login():
    """Authenticate a user and return a short lived JWT."""
    if rate_limited(f"login:{request.remote_addr}"):
        return jsonify(error="too many login attempts, try again in a minute"), 429

    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return jsonify(error="username and password are required"), 400

    # Parameterised query: the username is data, never part of the SQL text.
    row = get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # One generic answer for both branches: no user enumeration.
    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify(error="invalid username or password"), 401

    from .security import create_token

    return jsonify(access_token=create_token(row), token_type="Bearer")


@api.get("/api/data")
@login_required
def list_data():
    """Return posts; every field that is user controlled is HTML-escaped."""
    rows = get_db().execute(
        """
        SELECT p.id, p.title, p.body, p.created_at, u.username AS author
        FROM posts AS p
        JOIN users AS u ON u.id = p.author_id
        ORDER BY p.id
        """
    ).fetchall()

    return jsonify(
        posts=[
            {
                "id": row["id"],
                "title": sanitize(row["title"]),
                "body": sanitize(row["body"]),
                "author": sanitize(row["author"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    )


@api.post("/api/posts")
@login_required
def create_post():
    """Third endpoint: create a post owned by the authenticated user."""
    payload = request.get_json(silent=True) or {}
    title = payload.get("title")
    body = payload.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="title and body must be strings"), 400
    title = title.strip()
    body = body.strip()
    if not title or not body:
        return jsonify(error="title and body are required"), 400
    if len(title) > TITLE_MAX or len(body) > BODY_MAX:
        return jsonify(error=f"title max {TITLE_MAX} chars, body max {BODY_MAX} chars"), 422

    db = get_db()
    cursor = db.execute(
        "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
        (int(g.current_user["sub"]), title, body),
    )
    db.commit()
    return (
        jsonify(
            id=cursor.lastrowid,
            title=sanitize(title),
            body=sanitize(body),
            author=g.current_user["username"],
        ),
        201,
    )
