import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.auth import reset_limits  # noqa: E402
from app.db import get_db  # noqa: E402
from app.security import hash_password  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(tmp_path / "test.sqlite"),
        }
    )
    with application.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("alice", hash_password("Alice-Strong-Pass-2026"), "admin"),
        )
        db.execute(
            "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
            (1, "Hello", "World"),
        )
        db.commit()
    reset_limits()
    yield application
    reset_limits()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def token(client):
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "Alice-Strong-Pass-2026"},
    )
    return response.get_json()["access_token"]


@pytest.fixture()
def auth(token):
    return {"Authorization": f"Bearer {token}"}
