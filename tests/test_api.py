"""Functional and security regression tests."""


def test_health(client):
    assert client.get("/health").status_code == 200


def test_login_returns_jwt(client):
    response = client.post(
        "/auth/login", json={"username": "alice", "password": "Alice-Strong-Pass-2026"}
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2


def test_login_rejects_wrong_password(client):
    response = client.post("/auth/login", json={"username": "alice", "password": "nope"})
    assert response.status_code == 401
    assert "invalid" in response.get_json()["error"]


def test_login_does_not_leak_user_existence(client):
    unknown = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    wrong = client.post("/auth/login", json={"username": "alice", "password": "x"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


def test_login_rejects_non_json_body(client):
    response = client.post("/auth/login", data="username=alice", content_type="text/plain")
    assert response.status_code == 400


def test_sql_injection_in_login_is_inert(client):
    payload = {"username": "alice' OR '1'='1' --", "password": "anything"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 401


def test_data_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert "bearer" in response.get_json()["error"]


def test_data_rejects_malformed_token(client):
    response = client.get("/api/data", headers={"Authorization": "Bearer not.a.token"})
    assert response.status_code == 401


def test_data_rejects_tampered_signature(client, token):
    altered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    response = client.get("/api/data", headers={"Authorization": f"Bearer {altered}"})
    assert response.status_code == 401


def test_data_returns_rows_for_authenticated_user(client, auth):
    response = client.get("/api/data", headers=auth)
    assert response.status_code == 200
    posts = response.get_json()["posts"]
    assert posts and posts[0]["title"] == "Hello"


def test_create_post_requires_authentication(client):
    response = client.post("/api/posts", json={"title": "a", "body": "b"})
    assert response.status_code == 401


def test_create_post_persists(client, auth):
    created = client.post("/api/posts", json={"title": "Note", "body": "Body"}, headers=auth)
    assert created.status_code == 201

    posts = client.get("/api/data", headers=auth).get_json()["posts"]
    assert any(post["title"] == "Note" for post in posts)


def test_create_post_validates_input(client, auth):
    too_long = client.post("/api/posts", json={"title": "x" * 500, "body": "b"}, headers=auth)
    assert too_long.status_code == 422

    missing = client.post("/api/posts", json={"title": "only title"}, headers=auth)
    assert missing.status_code == 400


def test_xss_payload_is_escaped_in_responses(client, auth):
    payload = "<script>alert('xss')</script>"
    client.post("/api/posts", json={"title": payload, "body": payload}, headers=auth)

    posts = client.get("/api/data", headers=auth).get_json()["posts"]
    stored = next(post for post in posts if "script" in post["title"])
    assert "<script>" not in stored["title"]
    assert "&lt;script&gt;" in stored["title"]


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_login_rate_limit(client):
    for _ in range(5):
        client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    response = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 429
