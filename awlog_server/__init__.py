import os
import logging
from datetime import timedelta
from flask import Flask
from dotenv import load_dotenv
from .models import db


def create_app() -> Flask:
    """Application factory for the AWLog server."""
    load_dotenv()

    templates_path = os.path.join(os.path.dirname(__file__), "..", "templates")
    static_path = os.path.join(os.path.dirname(__file__), "..", "static")
    app = Flask(__name__, template_folder=templates_path, static_folder=static_path)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")

    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "awlogs.sqlite")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["KEEPALIVE_INTERVAL"] = int(os.environ.get("KEEPALIVE_INTERVAL", 120))
    app.config["OFFLINE_MULTIPLIER"] = int(os.environ.get("OFFLINE_MULTIPLIER", 3))
    app.config["MONITOR_INTERVAL"] = int(os.environ.get("MONITOR_INTERVAL", 60))
    app.config["TIMEZONE_OFFSET"] = int(os.environ.get("TIMEZONE_OFFSET", 3))
    app.config["LDAP_URI"] = os.environ.get("LDAP_URI")
    app.config["LDAP_BASE_DN"] = os.environ.get("LDAP_BASE_DN")
    app.config["LDAP_DOMAIN"] = os.environ.get("LDAP_DOMAIN")
    app.config["REMEMBER_ME_DAYS"] = int(os.environ.get("REMEMBER_ME_DAYS", 30))
    app.permanent_session_lifetime = timedelta(days=app.config["REMEMBER_ME_DAYS"])

    admin_users = os.environ.get("ADMIN_USERS", "")
    app.config["ADMIN_SET"] = {u.strip().lower() for u in admin_users.split(',') if u.strip()}

    log_dir = os.environ.get("LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "server.log")),
            logging.StreamHandler(),
        ],
    )

    db.init_app(app)

    from . import utils
    app.jinja_env.filters["local_time"] = utils.local_time

    with app.app_context():
        db.create_all()

    return app
