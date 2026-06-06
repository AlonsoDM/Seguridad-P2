import secrets

from flask import Flask, g

from auth import load_current_user
from db import reset_runtime_state
from routes.admin import admin_bp
from routes.dashboard import dashboard_bp
from routes.public import public_bp
from settings import setting_enabled


def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    admin_password = reset_runtime_state()
    app.logger.warning("Admin Password: %s", admin_password)

    @app.before_request
    def _load_current_user():
        load_current_user()

    @app.context_processor
    def inject_globals():
        return {
            "current_user": g.get("user"),
            "asset_storage_enabled": setting_enabled("asset_storage_enabled"),
        }

    app.register_blueprint(public_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    return app
