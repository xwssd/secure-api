"""Application factory."""

import os

from flask import Flask, jsonify

from .db import init_app as init_db_app
from .db import init_db
from .routes import api


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-insecure-key"),
        DATABASE=os.environ.get("DATABASE", os.path.join(app.instance_path, "app.sqlite")),
        JWT_EXPIRES_MINUTES=int(os.environ.get("JWT_EXPIRES_MINUTES", "60")),
        PASSWORD_MIN_LENGTH=int(os.environ.get("PASSWORD_MIN_LENGTH", "10")),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    init_db_app(app)
    app.register_blueprint(api)

    with app.app_context():
        init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify(error="payload too large"), 413

    @app.errorhandler(500)
    def internal_error(_error):
        # Never leak stack traces or database errors to the client.
        return jsonify(error="internal server error"), 500

    return app
