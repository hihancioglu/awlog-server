from awlog_server import create_app

from flask import (
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for,
    flash,
)

from sqlalchemy import func
from datetime import datetime, date, timedelta
import threading
import time
import json
import logging
import hmac
import hashlib
import secrets
import os
from debug_utils import DEBUG

from awlog_server.models import db, WindowLog, StatusLog, ReportLog, ApiLog, AgentSecret
from awlog_server.utils import (
    local_now,
    format_duration,
    ldap_auth,
    login_required,
    is_admin,
    get_app_from_window,
    domain_from_url,
)

app = create_app()
logger = logging.getLogger(__name__)

monitor_thread = None

def start_monitor_thread():
    """Ensure the keepalive monitor thread is running."""
    global monitor_thread
    if monitor_thread is None:
        monitor_thread = threading.Thread(target=monitor_keepalive, daemon=True)
        monitor_thread.start()


@app.before_first_request
def setup_db():
    start_monitor_thread()


@app.route("/register", methods=["POST"])
def register_agent():
    """Return a per-agent secret, creating one if necessary."""
    data = request.json
    hostname = data.get("hostname")
    username = data.get("username")
    if not hostname or not username:
        return jsonify({"error": "bad_request"}), 400
    agent = AgentSecret.query.filter_by(hostname=hostname, username=username).first()
    if not agent:
        secret = secrets.token_hex(32)
        agent = AgentSecret(hostname=hostname, username=username, secret=secret)
        db.session.add(agent)
        db.session.commit()
    return jsonify({"secret": agent.secret})

@app.route("/api/log", methods=["POST"])
def receive_log():
    raw_payload = request.get_data()
    data = json.loads(raw_payload.decode("utf-8"))
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

    agent = AgentSecret.query.filter_by(hostname=hostname, username=username).first()
    sig = request.headers.get("X-Signature", "")
    if not agent:
        logger.warning("Unknown agent on /api/log from %s@%s", username, hostname)
        return jsonify({"error": "forbidden"}), 403
    expected = hmac.new(agent.secret.encode(), raw_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        logger.warning("Invalid signature on /api/log from %s@%s", username, hostname)
        return jsonify({"error": "forbidden"}), 403


    if log_type == "window":
        wl = WindowLog(
            hostname=hostname,
            username=username,
            window_title=data.get("window_title"),
            process_name=data.get("process_name"),
            url=domain_from_url(data.get("url")),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            duration=data.get("duration"),
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
    raw_payload = request.get_data()
    data = json.loads(raw_payload.decode("utf-8"))
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

    agent = AgentSecret.query.filter_by(hostname=hostname, username=username).first()
    sig = request.headers.get("X-Signature", "")
    if not agent:
        logger.warning("Unknown agent on /report from %s@%s", username, hostname)
        return jsonify({"error": "forbidden"}), 403
    expected = hmac.new(agent.secret.encode(), raw_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        logger.warning("Invalid signature on /report from %s@%s", username, hostname)
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
        url=domain_from_url(data.get("url")),
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
    """Return window usage grouped by title, process and URL."""
    q = (
        db.session.query(
            WindowLog.window_title,
            WindowLog.process_name,
            WindowLog.url,
            func.sum(WindowLog.duration).label("total_duration"),
        )
        .filter(
            WindowLog.username == username,
            func.substr(WindowLog.start_time, 1, 10) >= start_date,
            func.substr(WindowLog.start_time, 1, 10) <= end_date,
        )
        .group_by(WindowLog.window_title, WindowLog.process_name, WindowLog.url)
        .order_by(func.sum(WindowLog.duration).desc())
    )

    return [
        (title or "", proc or "", url or "", int(dur or 0))
        for title, proc, url, dur in q
    ]


def monitor_keepalive():
    """Background thread to mark users offline when keepalive stops."""
    with app.app_context():
        threshold = (
            app.config["KEEPALIVE_INTERVAL"] * app.config["OFFLINE_MULTIPLIER"]
        )
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
                    status = last_state.status
                else:
                    status = "not-afk"

                start_time = rep.created_at
                duration = int((now - start_time).total_seconds())
                sl = StatusLog(
                    hostname=rep.hostname,
                    username=rep.username,
                    status=status,
                    start_time=start_time.isoformat(),
                    end_time=now.isoformat(),
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

            time.sleep(app.config["MONITOR_INTERVAL"])

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
        (w.username, w.hostname): {
            "title": w.window_title or "",
            "url": w.url or "",
        }
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
        window_map.setdefault(pair, {"title": w.window_title or "", "url": w.url or ""})

    report_map = {
        (r.username, r.hostname): {
            "status": r.status,
            "created_at": r.created_at,
            "ip": r.ip,
        }
        for r in report_q
    }

    # Bugün toplam süreleri kullanıcı bazında hesapla
    today_details = {d["username"]: d for d in get_today_user_details()}

    status_list = []
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

        detail = today_details.get(log.username, {})
        active_today = int(detail.get("active", 0))
        total_today = int(detail.get("total", 0))

        status_list.append({
            "username": log.username,
            "hostname": log.hostname,
            "status": log.status,
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, {}).get("title", ""),
            "url": window_map.get(pair, {}).get("url", ""),
            "ip": rep.get("ip") if rep else "?",
            "today_active": active_today,
            "today_total": total_today,
        })

    # Kullanıcının daha önce hiç StatusLog kaydı yoksa raporlardan ekle
    status_pairs = {(s["username"], s["hostname"]) for s in status_list}
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

        detail = today_details.get(pair[0], {})
        status_list.append({
            "username": pair[0],
            "hostname": pair[1],
            "status": rep["status"],
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, {}).get("title", ""),
            "url": window_map.get(pair, {}).get("url", ""),
            "ip": rep.get("ip") if rep else "?",
            "today_active": int(detail.get("active", 0)),
            "today_total": int(detail.get("total", 0)),
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

    rep_map = {r.username: r for r in rep_q}

    offset = app.config.get("TIMEZONE_OFFSET", 0)
    threshold = (
        app.config.get("KEEPALIVE_INTERVAL", 120)
        * app.config.get("OFFLINE_MULTIPLIER", 3)
    )
    now = datetime.utcnow()
    today_start = (
        local_now().replace(hour=0, minute=0, second=0, microsecond=0)
        - timedelta(hours=offset)
    )
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

        rep = rep_map.get(st.username)
        end = now
        if rep:
            if rep.status == "offline":
                end = rep.created_at
            elif (now - rep.created_at).total_seconds() > threshold:
                end = rep.created_at

        start = max(st.created_at, today_start)
        if end > start:
            delta = int((end - start).total_seconds())
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


@app.route("/agent/today_totals", methods=["POST"])
def agent_today_totals():
    """Return today's totals for active and AFK times for an agent."""
    raw_payload = request.get_data()
    data = json.loads(raw_payload.decode("utf-8"))
    hostname = data.get("hostname")
    username = data.get("username")
    agent = AgentSecret.query.filter_by(hostname=hostname, username=username).first()
    sig = request.headers.get("X-Signature", "")
    if not agent:
        return jsonify({"error": "forbidden"}), 403
    expected = hmac.new(agent.secret.encode(), raw_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return jsonify({"error": "forbidden"}), 403
    details = get_today_user_details()
    for item in details:
        if item["username"] == username:
            return jsonify(item)
    return jsonify({"username": username, "total": 0, "active": 0, "afk": 0})


@app.route("/agent/config", methods=["POST"])
def agent_config():
    """Return macro recorder configuration for an agent."""
    raw_payload = request.get_data()
    data = json.loads(raw_payload.decode("utf-8"))
    hostname = data.get("hostname")
    username = data.get("username")
    agent = AgentSecret.query.filter_by(hostname=hostname, username=username).first()
    sig = request.headers.get("X-Signature", "")
    if not agent:
        return jsonify({"error": "forbidden"}), 403
    expected = hmac.new(agent.secret.encode(), raw_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(
        {
            "blacklist": os.environ.get("MACRO_PROC_BLACKLIST", ""),
            "whitelist": os.environ.get("MACRO_PROC_WHITELIST", ""),
            "check_interval": float(os.environ.get("MACRO_PROC_CHECK_INTERVAL", "10")),
        }
    )


@app.route("/api/current_status")
@login_required
def api_current_status():
    """Return current online/afk status list used on the main panel."""
    status_list = get_current_status()
    if not is_admin():
        user = session.get("user")
        status_list = [s for s in status_list if s["username"] == user]
    return jsonify(status_list)


def get_weekly_report(username: str, week_start: date):
    """Return daily online/active/afk totals and start/end times."""
    results = []
    for i in range(7):
        day = week_start + timedelta(days=i)
        day_str = day.isoformat()

        # Aggregate online/active/afk durations from StatusLog
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

        # Determine start and end times using ReportLog records.
        # Start time is the first log for the day (any status except "offline").
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)

        start_log = (
            db.session.query(ReportLog)
            .filter(
                ReportLog.username == username,
                ReportLog.created_at >= day_start,
                ReportLog.created_at < day_end,
                ReportLog.status != "offline",
            )
            .order_by(ReportLog.created_at)
            .first()
        )
        end_log = (
            db.session.query(ReportLog)
            .filter(
                ReportLog.username == username,
                ReportLog.status.in_(["offline", "keepalive"]),
                ReportLog.created_at >= day_start,
                ReportLog.created_at < day_end,
            )
            .order_by(ReportLog.created_at.desc())
            .first()
        )

        results.append(
            {
                "date": day_str,
                "online": int(total_online),
                "active": int(active),
                "afk": int(afk),
                "start": start_log.created_at if start_log else None,
                "end": end_log.created_at if end_log else None,
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
            f"<tr><td>{r['date']}</td>"
            f"<td>{local_time(r['start'], '%H:%M') if r['start'] else ''}</td>"
            f"<td>{local_time(r['end'], '%H:%M') if r['end'] else ''}</td>"
            f"<td>{format_duration(r['online'])}</td>"
            f"<td>{format_duration(r['active'])}</td>"
            f"<td>{format_duration(r['afk'])}</td></tr>"
            for r in rows
        )
        tables.append(
            f"<h4>{username}</h4><table class=\"table table-bordered table-striped shadow\"><thead class=\"table-dark\"><tr><th>Tarih</th><th>Başlama</th><th>Bitiş</th><th>Toplam Online</th><th>Aktif Zaman</th><th>AFK Zaman</th></tr></thead><tbody>{table_rows}</tbody></table>"
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

    q = request.args.get("q", "").strip().lower()
    usage_rows = get_window_usage_data(selected_user, start.isoformat(), end.isoformat())
    if q:
        usage_rows = [
            (t, p, u, d)
            for t, p, u, d in usage_rows
            if q in (t or "").lower()
            or q in (p or "").lower()
            or q in (u or "").lower()
        ]

    return render_template(
        "usage_report.html",
        usernames=usernames,
        selected_user=selected_user,
        range_param=range_param,
        base_date=base_date,
        usage_rows=usage_rows,
        format_duration=format_duration,
        q=q,
    )


@app.route("/api_logs")
@login_required
def api_logs():
    """Display raw API logs."""
    if not is_admin():
        return redirect(url_for("index"))
    q = request.args.get("q", "").strip().lower()
    username = request.args.get("username")
    endpoint = request.args.get("endpoint")
    start_param = request.args.get("start")
    end_param = request.args.get("end")
    payload_field = request.args.get("field")
    payload_value = request.args.get("value")

    query = ApiLog.query
    if username:
        query = query.filter(ApiLog.username == username)
    if endpoint:
        query = query.filter(ApiLog.endpoint == endpoint)
    if q:
        search = f"%{q}%"
        query = query.filter(
            ApiLog.payload.ilike(search)
            | ApiLog.endpoint.ilike(search)
            | ApiLog.username.ilike(search)
            | ApiLog.hostname.ilike(search)
        )
    offset = app.config.get("TIMEZONE_OFFSET", 0)
    if start_param:
        try:
            start_dt = datetime.fromisoformat(start_param) - timedelta(hours=offset)
            query = query.filter(ApiLog.created_at >= start_dt)
        except ValueError:
            pass
    if end_param:
        try:
            end_dt = datetime.fromisoformat(end_param) - timedelta(hours=offset)
            query = query.filter(ApiLog.created_at <= end_dt)
        except ValueError:
            pass
    if payload_field and payload_value:
        search = f'%"{payload_field}": "{payload_value}"%'
        query = query.filter(ApiLog.payload.ilike(search))
    elif payload_field:
        search = f'%"{payload_field}":%'
        query = query.filter(ApiLog.payload.ilike(search))

    logs = query.order_by(ApiLog.created_at.desc()).limit(100).all()

    usernames = [u[0] for u in db.session.query(ApiLog.username).distinct()]
    endpoints = [e[0] for e in db.session.query(ApiLog.endpoint).distinct()]

    payload_fields = set()
    for log in logs:
        try:
            data = json.loads(log.payload)
            if isinstance(data, dict):
                payload_fields.update(data.keys())
        except Exception:
            continue
    payload_fields = sorted(payload_fields)

    return render_template(
        "api_logs.html",
        logs=logs,
        usernames=usernames,
        endpoints=endpoints,
        selected_user=username or "",
        selected_endpoint=endpoint or "",
        q=q,
        start=start_param or "",
        end=end_param or "",
        field=payload_field or "",
        value=payload_value or "",
        payload_fields=payload_fields,
    )

if __name__ == "__main__":
    start_monitor_thread()
    app.run(host="0.0.0.0", port=5050)
