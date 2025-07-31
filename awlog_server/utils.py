from __future__ import annotations

import ldap3
import re
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
from flask import session, redirect, url_for, request, current_app


def local_time(value: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a UTC datetime according to TIMEZONE_OFFSET."""
    if not value:
        return ""
    if not isinstance(value, datetime):
        return str(value)
    offset = current_app.config.get("TIMEZONE_OFFSET", 0)
    return (value + timedelta(hours=offset)).strftime(fmt)


def local_now() -> datetime:
    offset = current_app.config.get("TIMEZONE_OFFSET", 0)
    return datetime.utcnow() + timedelta(hours=offset)


def format_duration(seconds: int) -> str:
    seconds = int(seconds or 0)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours:d}:{minutes:02d}"


def ldap_auth(username: str, password: str) -> bool:
    uri = current_app.config.get("LDAP_URI")
    domain = current_app.config.get("LDAP_DOMAIN")
    if not uri or not password:
        return False
    user_dn = f"{domain}\\{username}" if domain else username
    try:
        server = ldap3.Server(uri, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        return True
    except Exception:
        return False


def login_required(func):
    """Decorator requiring authentication."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return wrapper


def is_admin(user: str | None = None) -> bool:
    if user is None:
        user = session.get("user")
    admin_set = current_app.config.get("ADMIN_SET", set())
    return bool(user and user.lower() in admin_set)


def get_app_from_window(title: str, process: str) -> str:
    if not title and not process:
        return "unknown"

    proc = (process or "").lower()
    if proc.endswith(".exe"):
        proc = proc[:-4]

    browsers = {"chrome", "msedge", "firefox", "opera", "iexplore"}
    if proc in browsers:
        m = re.search(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})", title or "")
        if m:
            return m.group(1).lower()
        parts = [p.strip() for p in (title or "").split(" - ")]
        for part in reversed(parts):
            if "." in part:
                return part.lower()
        if parts:
            return parts[0].lower()
    return proc or "unknown"


def domain_from_url(url: str | None) -> str | None:
    """Extract hostname from URL string."""
    if not url:
        return url
    url = url.strip()
    try:
        if "://" not in url:
            url = "//" + url
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            return host.lower()
        return url.split("/")[0].split(":")[0].lower()
    except Exception:
        return url
