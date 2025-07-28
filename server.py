from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for,
    flash,
)
from functools import wraps
import ldap3
from sqlalchemy import func
from datetime import datetime, date, timedelta
import os
import threading
import time
import json
import logging
from debug_utils import DEBUG

from models import db, WindowLog, StatusLog, ReportLog, ApiLog

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")

db_path = os.path.join(os.path.dirname(__file__), "data", "awlogs.sqlite")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET = os.environ.get("SECRET", "UzunVEZorluBirKey2024@!")
KEEPALIVE_INTERVAL = int(os.environ.get("KEEPALIVE_INTERVAL", 120))  # seconds
OFFLINE_MULTIPLIER = int(os.environ.get("OFFLINE_MULTIPLIER", 3))
MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL", 60))
TIMEZONE_OFFSET = int(os.environ.get("TIMEZONE_OFFSET", 3))  # hours
LDAP_URI = os.environ.get("LDAP_URI")
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN")
LDAP_DOMAIN = os.environ.get("LDAP_DOMAIN")
REMEMBER_ME_DAYS = int(os.environ.get("REMEMBER_ME_DAYS", 30))
app.permanent_session_lifetime = timedelta(days=REMEMBER_ME_DAYS)
ADMIN_SET = {
    u.strip().lower()
    for u in os.environ.get("ADMIN_USERS", "").split(",")
    if u.strip()
}

# ----- Logging Configuration -----
LOG_DIR = os.environ.get("LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "server.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

@app.template_filter("local_time")
def local_time(value: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a UTC datetime in local time using TIMEZONE_OFFSET."""
    if not value:
        return ""
    if not isinstance(value, datetime):
        return str(value)
    local_dt = value + timedelta(hours=TIMEZONE_OFFSET)
    return local_dt.strftime(fmt)

def local_now() -> datetime:
    """Return current time adjusted for TIMEZONE_OFFSET."""
    return datetime.utcnow() + timedelta(hours=TIMEZONE_OFFSET)

monitor_thread = None
db.init_app(app)

@app.before_first_request
def setup_db():
    db.create_all()
    global monitor_thread
    if monitor_thread is None:
        monitor_thread = threading.Thread(target=monitor_keepalive, daemon=True)
        monitor_thread.start()

def format_duration(seconds: int) -> str:
    """Convert seconds to H:MM format."""
    seconds = int(seconds or 0)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours:d}:{minutes:02d}"


def ldap_auth(username: str, password: str) -> bool:
    """Authenticate user against LDAP/Active Directory."""
    if not LDAP_URI or not password:
        return False
    user_dn = f"{LDAP_DOMAIN}\\{username}" if LDAP_DOMAIN else username
    try:
        server = ldap3.Server(LDAP_URI, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        return True
    except Exception as e:
        print("LDAP auth failed", e)
        return False


def login_required(func):
    """Decorator to require login for routes."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return wrapper


def is_admin(user: str | None = None) -> bool:
    """Return True if the given or current user is in ADMIN_SET."""
    if user is None:
        user = session.get("user")
    return bool(user and user.lower() in ADMIN_SET)


def get_app_from_window(title: str, process: str) -> str:
    """Return simplified app or domain name from window title and process."""
    if not title and not process:
        return "unknown"

    proc = (process or "").lower()
    if proc.endswith(".exe"):
        proc = proc[:-4]

    browsers = {"chrome", "msedge", "firefox", "opera", "iexplore"}
    if proc in browsers:
        parts = [p.strip() for p in (title or "").split(" - ")]
        for part in reversed(parts):
            if "." in part:
                return part.lower()
        if parts:
            return parts[0].lower()
    return proc or "unknown"

@app.route("/api/log", methods=["POST"])
def receive_log():
    data = request.json
    log_type = data.get("log_type")
    hostname = data.get("hostname")
    username = data.get("username")

    DEBUG(f"/api/log {log_type} from {username}@{hostname}")

    # log all requests including invalid ones
    db.session.add(
        ApiLog(
            endpoint="/api/log",
            hostname=hostname,
            username=username,
            payload=json.dumps(data, ensure_ascii=False),
        )
    )
    db.session.commit()

    if data.get("secret") != SECRET:
        logger.warning("Invalid secret on /api/log from %s@%s", username, hostname)
        return jsonify({"error": "forbidden"}), 403


    if log_type == "window":
        wl = WindowLog(
            hostname=hostname,
            username=username,
            window_title=data.get("window_title"),
            process_name=data.get("process_name"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            duration=data.get("duration")
        )
        db.session.add(wl)
        db.session.commit()
        return jsonify({"status": "ok"}), 200

    elif log_type == "status":
        sl = StatusLog(
            hostname=hostname,
            username=username,
            status=data.get("status"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            duration=data.get("duration")
        )
        db.session.add(sl)
        db.session.commit()
        return jsonify({"status": "ok"}), 200

    else:
        return jsonify({"error": "invalid log_type"}), 400


@app.route("/report", methods=["POST"])
def report_status():
    data = request.json
    hostname = data.get("hostname")
    username = data.get("username")
    ip = data.get("ip")
    status = data.get("status")

    DEBUG(f"/report {status} from {username}@{hostname}")

    db.session.add(
        ApiLog(
            endpoint="/report",
            hostname=hostname,
            username=username,
            payload=json.dumps(data, ensure_ascii=False),
        )
    )
    db.session.commit()

    if data.get("secret") != SECRET:
        logger.warning("Invalid secret on /report from %s@%s", username, hostname)
        return jsonify({"error": "forbidden"}), 403
    if not hostname or not username or not status:
        return jsonify({"error": "bad_request"}), 400
    rl = ReportLog(
        hostname=hostname,
        username=username,
        ip=ip,
        status=status,
        window_title=data.get("window_title"),
        process_name=data.get("process_name"),
    )
    db.session.add(rl)
    db.session.commit()
    return jsonify({"status": "ok"}), 200

@app.route("/api/statuslogs")
@login_required
def get_status_logs():
    # Son 50 status kaydı (panel için veya otomasyon için)
    logs = StatusLog.query.order_by(StatusLog.created_at.desc()).limit(50).all()
    return jsonify([
        {
            "hostname": log.hostname,
            "username": log.username,
            "status": log.status,
            "start_time": log.start_time,
            "end_time": log.end_time,
            "duration": log.duration,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ])


@app.route("/api/window_usage")
@login_required
def window_usage():
    """Return aggregated window usage for a user."""
    username = request.args.get("username")
    if not username:
        username = session.get("user")
    if not username:
        return jsonify({"error": "username_required"}), 400
    if not is_admin() and username != session.get("user"):
        return jsonify({"error": "forbidden"}), 403

    start_date = request.args.get("start")
    end_date = request.args.get("end")
    if not start_date:
        start_date = local_now().date().isoformat()
    if not end_date:
        end_date = start_date

    q = (
        db.session.query(
            WindowLog.window_title,
            WindowLog.process_name,
            WindowLog.duration,
            func.substr(WindowLog.start_time, 1, 10).label("day"),
        )
        .filter(
            WindowLog.username == username,
            func.substr(WindowLog.start_time, 1, 10) >= start_date,
            func.substr(WindowLog.start_time, 1, 10) <= end_date,
        )
    )

    totals = {}
    for title, proc, duration, day in q:
        app_name = get_app_from_window(title or "", proc or "")
        totals[app_name] = totals.get(app_name, 0) + int(duration or 0)

    result = [
        {"app": app, "duration": dur}
        for app, dur in sorted(totals.items(), key=lambda x: x[1], reverse=True)
    ]
    return jsonify(result)


def get_window_usage_data(username: str, start_date: str, end_date: str):
    """Return window usage grouped by title and process."""
    q = (
        db.session.query(
            WindowLog.window_title,
            WindowLog.process_name,
            func.sum(WindowLog.duration).label("total_duration"),
        )
        .filter(
            WindowLog.username == username,
            func.substr(WindowLog.start_time, 1, 10) >= start_date,
            func.substr(WindowLog.start_time, 1, 10) <= end_date,
        )
        .group_by(WindowLog.window_title, WindowLog.process_name)
        .order_by(func.sum(WindowLog.duration).desc())
    )

    return [
        (title or "", proc or "", int(dur or 0))
        for title, proc, dur in q
    ]


def monitor_keepalive():
    """Background thread to mark users offline when keepalive stops."""
    with app.app_context():
        threshold = KEEPALIVE_INTERVAL * OFFLINE_MULTIPLIER
        while True:
            now = datetime.utcnow()

            sub = (
                db.session.query(
                    ReportLog.username,
                    ReportLog.hostname,
                    func.max(ReportLog.created_at).label("max_created_at"),
                )
                .group_by(ReportLog.username, ReportLog.hostname)
            ).subquery()

            latest_reports = (
                db.session.query(ReportLog)
                .join(
                    sub,
                    (ReportLog.username == sub.c.username)
                    & (ReportLog.hostname == sub.c.hostname)
                    & (ReportLog.created_at == sub.c.max_created_at),
                )
                .all()
            )

            for rep in latest_reports:
                if rep.status == "offline":
                    continue
                if (now - rep.created_at).total_seconds() <= threshold:
                    continue

                last_state = (
                    db.session.query(ReportLog)
                    .filter(
                        ReportLog.username == rep.username,
                        ReportLog.hostname == rep.hostname,
                        ReportLog.status.in_(["afk", "not-afk"]),
                        ReportLog.created_at <= rep.created_at,
                    )
                    .order_by(ReportLog.created_at.desc())
                    .first()
                )

                if last_state:
                    start_time = last_state.created_at
                    status = last_state.status
                    duration = int((rep.created_at - start_time).total_seconds())
                    sl = StatusLog(
                        hostname=rep.hostname,
                        username=rep.username,
                        status=status,
                        start_time=start_time.isoformat(),
                        end_time=rep.created_at.isoformat(),
                        duration=duration,
                    )
                    db.session.add(sl)

                offline = ReportLog(
                    hostname=rep.hostname,
                    username=rep.username,
                    ip=rep.ip,
                    status="offline",
                )
                db.session.add(offline)
                db.session.commit()

            time.sleep(MONITOR_INTERVAL)

def get_current_status():
    # Her kullanici ve PC icin en son status kaydini almak icin alt sorgu kullan
    status_sub = (
        db.session.query(
            StatusLog.username,
            StatusLog.hostname,
            func.max(StatusLog.created_at).label("max_created_at")
        ).group_by(StatusLog.username, StatusLog.hostname)
    ).subquery()

    status_q = db.session.query(StatusLog).join(
        status_sub,
        (StatusLog.username == status_sub.c.username)
        & (StatusLog.hostname == status_sub.c.hostname)
        & (StatusLog.created_at == status_sub.c.max_created_at)
    )

    # En son report (online/offline/keepalive) bilgilerini al
    report_sub = (
        db.session.query(
            ReportLog.username,
            ReportLog.hostname,
            func.max(ReportLog.created_at).label("max_created_at")
        ).group_by(ReportLog.username, ReportLog.hostname)
    ).subquery()

    report_q = db.session.query(ReportLog).join(
        report_sub,
        (ReportLog.username == report_sub.c.username)
        & (ReportLog.hostname == report_sub.c.hostname)
        & (ReportLog.created_at == report_sub.c.max_created_at)
    )

    # En son afk/not-afk bildirimi (durum degisikligi) bilgilerini al
    state_sub = (
        db.session.query(
            ReportLog.username,
            ReportLog.hostname,
            func.max(ReportLog.created_at).label("max_created_at"),
        )
        .filter(ReportLog.status.in_(["afk", "not-afk"]))
        .group_by(ReportLog.username, ReportLog.hostname)
    ).subquery()

    state_q = db.session.query(ReportLog).join(
        state_sub,
        (ReportLog.username == state_sub.c.username)
        & (ReportLog.hostname == state_sub.c.hostname)
        & (ReportLog.created_at == state_sub.c.max_created_at)
    )

    state_map = {
        (r.username, r.hostname): r
        for r in state_q
    }

    # Her kullanici ve bilgisayar icin en son pencere bildirimi
    window_sub = (
        db.session.query(
            ReportLog.username,
            ReportLog.hostname,
            func.max(ReportLog.created_at).label("max_created_at"),
        )
        .filter(ReportLog.status == "window")
        .group_by(ReportLog.username, ReportLog.hostname)
    ).subquery()

    window_q = db.session.query(ReportLog).join(
        window_sub,
        (ReportLog.username == window_sub.c.username)
        & (ReportLog.hostname == window_sub.c.hostname)
        & (ReportLog.created_at == window_sub.c.max_created_at),
    )

    window_map = {
        (w.username, w.hostname): w.window_title or ""
        for w in window_q
    }

    # Fallback: use last WindowLog entry if no window report exists
    wl_sub = (
        db.session.query(
            WindowLog.username,
            WindowLog.hostname,
            func.max(WindowLog.created_at).label("max_created_at"),
        )
        .group_by(WindowLog.username, WindowLog.hostname)
    ).subquery()

    wl_q = db.session.query(WindowLog).join(
        wl_sub,
        (WindowLog.username == wl_sub.c.username)
        & (WindowLog.hostname == wl_sub.c.hostname)
        & (WindowLog.created_at == wl_sub.c.max_created_at),
    )

    for w in wl_q:
        pair = (w.username, w.hostname)
        window_map.setdefault(pair, w.window_title or "")

    report_map = {
        (r.username, r.hostname): {
            "status": r.status,
            "created_at": r.created_at,
            "ip": r.ip,
        }
        for r in report_q
    }

    status_list = []
    today_str = local_now().date().isoformat()
    for log in status_q:
        pair = (log.username, log.hostname)
        rep = report_map.get(pair)
        state = state_map.get(pair)
        if rep and rep["status"] == "offline":
            online_status = "Offline"
            badge = '<span class="badge bg-secondary">Offline</span>'
        else:
            online_status = "Online"
            badge = '<span class="badge bg-success">Online</span>'

        if rep and rep["status"] in ("afk", "not-afk"):
            if rep["status"] == "afk":
                shown_status = "AFK"
            else:
                shown_status = "Aktif"
        else:
            if log.status == "afk":
                shown_status = "AFK"
            else:
                shown_status = "Aktif"

        active_today = (
            db.session.query(func.sum(StatusLog.duration))
            .filter(
                StatusLog.username == log.username,
                StatusLog.hostname == log.hostname,
                StatusLog.status == "not-afk",
                func.substr(StatusLog.start_time, 1, 10) == today_str,
            )
            .scalar()
            or 0
        )

        afk_today = (
            db.session.query(func.sum(StatusLog.duration))
            .filter(
                StatusLog.username == log.username,
                StatusLog.hostname == log.hostname,
                StatusLog.status == "afk",
                func.substr(StatusLog.start_time, 1, 10) == today_str,
            )
            .scalar()
            or 0
        )

        # Devam eden aktif donemi de ekle
        if (
            rep
            and state
            and rep["status"] != "offline"
            and state.status == "not-afk"
        ):
            try:
                last_end = datetime.fromisoformat(log.end_time)
            except Exception:
                last_end = None
            start = state.created_at
            if last_end and last_end > start:
                start = last_end
            if start < datetime.utcnow():
                active_today += int((datetime.utcnow() - start).total_seconds())

        if (
            rep
            and state
            and rep["status"] != "offline"
            and state.status == "afk"
        ):
            try:
                last_end = datetime.fromisoformat(log.end_time)
            except Exception:
                last_end = None
            start = state.created_at
            if last_end and last_end > start:
                start = last_end
            if start < datetime.utcnow():
                afk_today += int((datetime.utcnow() - start).total_seconds())

        total_today = active_today + afk_today

        status_list.append({
            "username": log.username,
            "hostname": log.hostname,
            "status": log.status,
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, ""),
            "ip": rep.get("ip") if rep else "?",
            "today_active": active_today,
            "today_total": total_today,
        })

    # Kullanıcının daha önce hiç StatusLog kaydı yoksa raporlardan ekle
    status_pairs = {(s["username"], s["hostname"]) for s in status_list}
    now = datetime.utcnow()
    for pair, rep in report_map.items():
        if pair in status_pairs or rep["status"] == "offline":
            continue
        state = state_map.get(pair)
        badge = '<span class="badge bg-success">Online</span>'
        if rep["status"] in ("afk", "not-afk"):
            shown_status = "AFK" if rep["status"] == "afk" else "Aktif"
        elif state:
            shown_status = "AFK" if state.status == "afk" else "Aktif"
        else:
            shown_status = "Aktif"

        active_today = afk_today = 0
        if state and state.created_at < now:
            delta = int((now - state.created_at).total_seconds())
            if state.status == "not-afk":
                active_today = delta
            else:
                afk_today = delta

        status_list.append({
            "username": pair[0],
            "hostname": pair[1],
            "status": rep["status"],
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, ""),
            "ip": rep.get("ip") if rep else "?",
            "today_active": active_today,
            "today_total": active_today + afk_today,
        })
    return status_list


def get_user_work_totals():
    today = local_now().date()
    today_str = today.isoformat()
    week_start_str = (today - timedelta(days=7)).isoformat()
    month_start_str = (today - timedelta(days=30)).isoformat()

    totals = {}

    # Bugun
    q = (
        db.session.query(
            StatusLog.username,
            StatusLog.hostname,
            func.sum(StatusLog.duration),
        )
        .filter(
            StatusLog.status == "not-afk",
            func.substr(StatusLog.start_time, 1, 10) == today_str,
        )
        .group_by(StatusLog.username, StatusLog.hostname)
    )
    for username, hostname, total in q:
        key = (username, hostname)
        totals[key] = {
            "username": username,
            "hostname": hostname,
            "daily": int(total or 0),
            "weekly": 0,
            "monthly": 0,
        }

    # Son 7 gun
    q = (
        db.session.query(
            StatusLog.username,
            StatusLog.hostname,
            func.sum(StatusLog.duration),
        )
        .filter(
            StatusLog.status == "not-afk",
            func.substr(StatusLog.start_time, 1, 10) >= week_start_str,
        )
        .group_by(StatusLog.username, StatusLog.hostname)
    )
    for username, hostname, total in q:
        key = (username, hostname)
        item = totals.setdefault(
            key,
            {
                "username": username,
                "hostname": hostname,
                "daily": 0,
                "weekly": 0,
                "monthly": 0,
            },
        )
        item["weekly"] = int(total or 0)

    # Son 30 gun
    q = (
        db.session.query(
            StatusLog.username,
            StatusLog.hostname,
            func.sum(StatusLog.duration),
        )
        .filter(
            StatusLog.status == "not-afk",
            func.substr(StatusLog.start_time, 1, 10) >= month_start_str,
        )
        .group_by(StatusLog.username, StatusLog.hostname)
    )
    for username, hostname, total in q:
        key = (username, hostname)
        item = totals.setdefault(
            key,
            {
                "username": username,
                "hostname": hostname,
                "daily": 0,
                "weekly": 0,
                "monthly": 0,
            },
        )
        item["monthly"] = int(total or 0)

    return list(totals.values())

def get_today_user_details():
    """Return today's total, active and AFK times per user."""
    today_str = local_now().date().isoformat()
    q = (
        db.session.query(
            StatusLog.username,
            StatusLog.status,
            func.sum(StatusLog.duration),
        )
        .filter(func.substr(StatusLog.start_time, 1, 10) == today_str)
        .group_by(StatusLog.username, StatusLog.status)
    )
    totals = {}
    for username, status, total in q:
        item = totals.setdefault(
            username,
            {
                "username": username,
                "total": 0,
                "active": 0,
                "afk": 0,
            },
        )
        total = int(total or 0)
        item["total"] += total
        if status == "not-afk":
            item["active"] = total
        elif status == "afk":
            item["afk"] = total

    # Devam eden donemleri ekle
    state_sub = (
        db.session.query(
            ReportLog.username,
            func.max(ReportLog.created_at).label("max_created_at"),
        )
        .filter(ReportLog.status.in_(["afk", "not-afk"]))
        .group_by(ReportLog.username)
    ).subquery()

    state_q = db.session.query(ReportLog).join(
        state_sub,
        (ReportLog.username == state_sub.c.username)
        & (ReportLog.created_at == state_sub.c.max_created_at),
    )

    rep_sub = (
        db.session.query(
            ReportLog.username,
            func.max(ReportLog.created_at).label("max_created_at"),
        )
        .group_by(ReportLog.username)
    ).subquery()

    rep_q = db.session.query(ReportLog).join(
        rep_sub,
        (ReportLog.username == rep_sub.c.username)
        & (ReportLog.created_at == rep_sub.c.max_created_at),
    )

    rep_map = {r.username: r.status for r in rep_q}

    now = datetime.utcnow()
    for st in state_q:
        item = totals.setdefault(
            st.username,
            {
                "username": st.username,
                "total": 0,
                "active": 0,
                "afk": 0,
            },
        )
        if rep_map.get(st.username) != "offline":
            delta = int((now - st.created_at).total_seconds())
            item["total"] += delta
            if st.status == "not-afk":
                item["active"] += delta
            else:
                item["afk"] += delta

    return list(totals.values())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember")
        if username and password and ldap_auth(username, password):
            session["user"] = username
            session["is_admin"] = is_admin(username)
            session.permanent = bool(remember)
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        flash("Giriş başarısız")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("is_admin", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    status_list = get_current_status()
    if not is_admin():
        user = session.get("user")
        status_list = [s for s in status_list if s["username"] == user]
    return render_template(
        "index.html",
        status_list=status_list,
        format_duration=format_duration,
    )


@app.route("/daily_timeline")
@login_required
def daily_timeline():
    """Interactive daily timeline of window usage."""
    usernames = [u[0] for u in db.session.query(WindowLog.username).distinct()]
    if not is_admin():
        current = session.get("user")
        usernames = [u for u in usernames if u == current]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
    if not is_admin():
        selected_user = session.get("user")
    date_param = request.args.get("date")
    zoom_param = request.args.get("zoom", "fit")
    today = local_now().date()
    try:
        day = datetime.strptime(date_param, "%Y-%m-%d").date() if date_param else today
    except Exception:
        day = today

    day_start = day.isoformat()
    day_end = (day + timedelta(days=1)).isoformat()

    logs = (
        WindowLog.query
        .filter(
            WindowLog.username == selected_user,
            WindowLog.start_time >= day_start,
            WindowLog.start_time < day_end,
        )
        .order_by(WindowLog.start_time)
        .all()
    )

    items = [
        {
            "id": i,
            "content": get_app_from_window(l.window_title or "", l.process_name or ""),
            "start": l.start_time,
            "end": l.end_time,
        }
        for i, l in enumerate(logs)
    ]

    import json
    items_json = json.dumps(items)

    return render_template(
        "daily_timeline.html",
        usernames=usernames,
        selected_user=selected_user,
        day=day,
        items_json=items_json,
        zoom_param=zoom_param,
    )


@app.route("/reports")
@login_required
def reports():
    details = get_today_user_details()
    if not is_admin():
        user = session.get("user")
        details = [d for d in details if d["username"] == user]
    return render_template(
        "reports.html",
        details=details,
        format_duration=format_duration,
    )


@app.route("/api/today_totals")
@login_required
def api_today_totals():
    """Return today's totals for active and AFK times."""
    username = request.args.get("username")
    details = get_today_user_details()
    if not is_admin():
        current = session.get("user")
        details = [d for d in details if d["username"] == current]
    if username:
        for item in details:
            if item["username"] == username:
                return jsonify(item)
        return jsonify({"error": "not_found"}), 404
    return jsonify(details)


def get_weekly_report(username: str, week_start: date):
    """Return daily online/active/afk totals for given user and week."""
    results = []
    for i in range(7):
        day = week_start + timedelta(days=i)
        day_str = day.isoformat()
        q = (
            db.session.query(StatusLog.status, func.sum(StatusLog.duration))
            .filter(
                StatusLog.username == username,
                func.substr(StatusLog.start_time, 1, 10) == day_str,
            )
            .group_by(StatusLog.status)
            .all()
        )
        total_online = sum(row[1] or 0 for row in q)
        active = next((row[1] for row in q if row[0] == "not-afk"), 0) or 0
        afk = next((row[1] for row in q if row[0] == "afk"), 0) or 0
        results.append(
            {
                "date": day_str,
                "online": int(total_online),
                "active": int(active),
                "afk": int(afk),
            }
        )
    return results

def get_weekly_reports_for_all(week_start: date):
    """Return weekly reports for all users."""
    usernames = [u[0] for u in db.session.query(StatusLog.username).distinct()]
    report_map = {}
    for username in usernames:
        report_map[username] = get_weekly_report(username, week_start)
    return report_map


def generate_all_weekly_tables():
    """Generate HTML tables of weekly reports for all users for current week."""
    now = local_now().date()
    week_start = now - timedelta(days=now.weekday())
    all_reports = get_weekly_reports_for_all(week_start)
    tables = []
    for username, rows in all_reports.items():
        table_rows = "".join(
            f"<tr><td>{r['date']}</td><td>{format_duration(r['online'])}</td><td>{format_duration(r['active'])}</td><td>{format_duration(r['afk'])}</td></tr>"
            for r in rows
        )
        tables.append(
            f"<h4>{username}</h4><table class=\"table table-bordered table-striped shadow\"><thead class=\"table-dark\"><tr><th>Tarih</th><th>Toplam Online</th><th>Aktif Zaman</th><th>AFK Zaman</th></tr></thead><tbody>{table_rows}</tbody></table>"
        )
    return "".join(tables)


def generate_today_online_table():
    """Generate HTML table of today's online users."""
    status_list = get_current_status()
    rows = []
    for row in status_list:
        if "bg-secondary" in row["badge"]:
            continue  # Skip offline users
        rows.append(
            f"<tr><td>{row['username']}</td><td>{row['hostname']}</td>"
            f"<td>{row['badge']}</td><td>{row['window_title']}</td>"
            f"<td>{row['shown_status']}</td><td>{row['ip']}</td>"
            f"<td>{format_duration(row['today_active'])}</td>"
            f"<td>{format_duration(row['today_total'])}</td></tr>"
        )
    if not rows:
        return "<p>Bugün çevrimiçi kullanıcı yok.</p>"
    header = (
        "<table class=\"table table-bordered table-striped shadow\">"
        "<thead class=\"table-dark\"><tr>"
        "<th>Kullanıcı</th><th>PC</th><th>Durum</th>"
        "<th>Aktif Pencere</th><th>AFK Durumu</th>"
        "<th>IP</th><th>Bugün Aktif</th><th>Bugün Toplam</th>"
        "</tr></thead><tbody>"
    )
    return header + "".join(rows) + "</tbody></table>"


@app.route("/weekly_report")
@login_required
def weekly_report():
    usernames = [u[0] for u in db.session.query(StatusLog.username).distinct()]
    if not is_admin():
        current = session.get("user")
        usernames = [u for u in usernames if u == current]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
    if not is_admin():
        selected_user = session.get("user")
    week_param = request.args.get("week")
    if week_param:
        try:
            week_start = datetime.strptime(week_param + "-1", "%G-W%V-%u").date()
        except Exception:
            now = local_now().date()
            week_start = now - timedelta(days=now.weekday())
    else:
        now = local_now().date()
        week_start = now - timedelta(days=now.weekday())
        week_param = week_start.strftime("%G-W%V")

    report_rows = get_weekly_report(selected_user, week_start)

    return render_template(
        "weekly_report.html",
        usernames=usernames,
        selected_user=selected_user,
        week_param=week_param,
        report_rows=report_rows,
        format_duration=format_duration,
    )


@app.route("/usage_report")
@login_required
def usage_report():
    usernames = [u[0] for u in db.session.query(WindowLog.username).distinct()]
    if not is_admin():
        current = session.get("user")
        usernames = [u for u in usernames if u == current]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
    if not is_admin():
        selected_user = session.get("user")
    range_param = request.args.get("range", "daily")
    date_param = request.args.get("date")

    today = local_now().date()
    try:
        base_date = datetime.strptime(date_param, "%Y-%m-%d").date() if date_param else today
    except Exception:
        base_date = today

    if range_param == "weekly":
        start = base_date - timedelta(days=base_date.weekday())
        end = start + timedelta(days=6)
    elif range_param == "monthly":
        start = base_date.replace(day=1)
        end = (start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    else:
        range_param = "daily"
        start = base_date
        end = base_date

    usage_rows = get_window_usage_data(selected_user, start.isoformat(), end.isoformat())

    return render_template(
        "usage_report.html",
        usernames=usernames,
        selected_user=selected_user,
        range_param=range_param,
        base_date=base_date,
        usage_rows=usage_rows,
        format_duration=format_duration,
    )


@app.route("/api_logs")
@login_required
def api_logs():
    """Display raw API logs."""
    if not is_admin():
        return redirect(url_for("index"))
    logs = ApiLog.query.order_by(ApiLog.created_at.desc()).limit(100).all()
    return render_template("api_logs.html", logs=logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
