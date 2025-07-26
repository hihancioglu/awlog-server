from flask import Flask, request, jsonify, render_template_string
from sqlalchemy import func
from datetime import datetime, date, timedelta
import os
import threading
import time

from models import db, WindowLog, StatusLog, ReportLog

app = Flask(__name__)

db_path = os.path.join(os.path.dirname(__file__), "data", "awlogs.sqlite")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET = os.environ.get("SECRET", "UzunVEZorluBirKey2024@!")
KEEPALIVE_INTERVAL = int(os.environ.get("KEEPALIVE_INTERVAL", 120))  # seconds
OFFLINE_MULTIPLIER = int(os.environ.get("OFFLINE_MULTIPLIER", 3))
MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL", 60))
TIMEZONE_OFFSET = int(os.environ.get("TIMEZONE_OFFSET", 3))  # hours

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
    if data.get("secret") != SECRET:
        return jsonify({"error": "forbidden"}), 403
    log_type = data.get("log_type")
    hostname = data.get("hostname")
    username = data.get("username")

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
    if data.get("secret") != SECRET:
        return jsonify({"error": "forbidden"}), 403
    hostname = data.get("hostname")
    username = data.get("username")
    ip = data.get("ip")
    status = data.get("status")
    if not hostname or not username or not status:
        return jsonify({"error": "bad_request"}), 400
    rl = ReportLog(hostname=hostname, username=username, ip=ip, status=status)
    db.session.add(rl)
    db.session.commit()
    return jsonify({"status": "ok"}), 200

@app.route("/api/statuslogs")
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
def window_usage():
    """Return aggregated window usage for a user."""
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username_required"}), 400

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

    # Her kullanici ve bilgisayar icin en son pencere kaydini al
    window_sub = (
        db.session.query(
            WindowLog.username,
            WindowLog.hostname,
            func.max(WindowLog.created_at).label("max_created_at")
        ).group_by(WindowLog.username, WindowLog.hostname)
    ).subquery()

    window_q = db.session.query(WindowLog).join(
        window_sub,
        (WindowLog.username == window_sub.c.username)
        & (WindowLog.hostname == window_sub.c.hostname)
        & (WindowLog.created_at == window_sub.c.max_created_at)
    )

    window_map = {
        (w.username, w.hostname): w.window_title or ""
        for w in window_q
    }

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
                shown_status = "Aktif"
            else:
                shown_status = "AFK"

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

        status_list.append({
            "username": log.username,
            "hostname": log.hostname,
            "status": log.status,
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, ""),
            "ip": rep.get("ip") if rep else "?",
            "today_active": active_today,
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

@app.route("/")
def index():
    status_list = get_current_status()
    table = ""
    for row in status_list:
        table += f"""
        <tr>
            <td>{row['username']}</td>
            <td>{row['hostname']}</td>
            <td>{row['badge']}</td>
            <td>{row['window_title']}</td>
            <td>{row['shown_status']}</td>
            <td>{row['ip']}</td>
            <td>{format_duration(row['today_active'])}</td>
        </tr>
        """
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Evden Çalışma Paneli</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f6f6fa; }}
            .container {{ max-width: 900px; margin-top: 40px; }}
            table {{ font-size: 15px; }}
            h2 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
    <div class="container">
      <h2>🏡 Evden Çalışanlar Durum Paneli</h2>
      <table class="table table-bordered table-striped shadow">
        <thead class="table-dark">
            <tr>
                <th>Kullanıcı</th>
                <th>PC</th>
                <th>Durum</th>
                <th>Aktif Pencere</th>
                <th>AFK Durumu</th>
                <th>IP</th>
                <th>Bugünkü Süre</th>
            </tr>
        </thead>
        <tbody>
            {table}
        </tbody>
      </table>
      <a class="btn btn-secondary" href="/api/statuslogs">API: Status Logs</a>
      <a class="btn btn-primary" href="/reports" style="margin-left:10px">Kullanıcı Raporları</a>
      <a class="btn btn-primary" href="/usage_report" style="margin-left:10px">Kullanım Raporları</a>
    </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/daily_timeline")
def daily_timeline():
    """Interactive daily timeline of window usage."""
    usernames = [u[0] for u in db.session.query(WindowLog.username).distinct()]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
    date_param = request.args.get("date")
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

    options = "".join(
        f'<option value="{u}" {"selected" if u == selected_user else ""}>{u}</option>'
        for u in usernames
    )

    import json
    items_json = json.dumps(items)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Günlük Zaman Çizelgesi</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://unpkg.com/vis-timeline@latest/styles/vis-timeline-graph2d.min.css" rel="stylesheet" />
        <style>
            body {{ background: #f6f6fa; }}
            .container {{ max-width: 900px; margin-top: 40px; }}
            #timeline {{ background: #fff; border: 1px solid #ccc; }}
            h2 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
    <div class="container">
      <h2>📈 Günlük Zaman Çizelgesi</h2>
      <form method="get" class="row mb-3">
        <div class="col">
          <select name="username" class="form-select">
            {options}
          </select>
        </div>
        <div class="col">
          <input type="date" name="date" class="form-control" value="{day.isoformat()}">
        </div>
        <div class="col">
          <button class="btn btn-primary" type="submit">Göster</button>
        </div>
      </form>
      <div id="timeline"></div>
      <a class="btn btn-secondary mt-3" href="/usage_report">Geri Dön</a>
    </div>
    <script src="https://unpkg.com/vis-timeline@latest/standalone/umd/vis-timeline-graph2d.min.js"></script>
    <script>
      var container = document.getElementById('timeline');
      var items = new vis.DataSet({items_json});
      var timeline = new vis.Timeline(container, items, {{ zoomable: true, moveable: true, stack: false }});
    </script>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/reports")
def reports():
    details = get_today_user_details()
    table = ""
    for row in details:
        table += f"""
        <tr>
            <td>{row['username']}</td>
            <td>{format_duration(row['total'])}</td>
            <td>{format_duration(row['active'])}</td>
            <td>{format_duration(row['afk'])}</td>
        </tr>
        """
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kullanıcı Raporları</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f6f6fa; }}
            .container {{ max-width: 900px; margin-top: 40px; }}
            table {{ font-size: 15px; }}
            h2 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
    <div class="container">
      <h2>📝 Bugünkü Kullanıcı Detayları</h2>
      <table class="table table-bordered table-striped shadow">
        <thead class="table-dark">
            <tr>
                <th>Kullanıcı</th>
                <th>Toplam Süre</th>
                <th>Aktif Zaman</th>
                <th>AFK Zaman</th>
            </tr>
        </thead>
        <tbody>
            {table}
        </tbody>
      </table>
      <a class="btn btn-secondary" href="/">Geri Dön</a>
      <a class="btn btn-primary" href="/weekly_report" style="margin-left:10px">Haftalık Detay</a>
    </div>
    </body>
    </html>
    """
    return render_template_string(html)


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
            f"<td>{format_duration(row['today_active'])}</td></tr>"
        )
    if not rows:
        return "<p>Bugün çevrimiçi kullanıcı yok.</p>"
    header = (
        "<table class=\"table table-bordered table-striped shadow\">"
        "<thead class=\"table-dark\"><tr>"
        "<th>Kullanıcı</th><th>PC</th><th>Durum</th>"
        "<th>Aktif Pencere</th><th>AFK Durumu</th>"
        "<th>IP</th><th>Bugünkü Süre</th>"
        "</tr></thead><tbody>"
    )
    return header + "".join(rows) + "</tbody></table>"


@app.route("/weekly_report")
def weekly_report():
    usernames = [u[0] for u in db.session.query(StatusLog.username).distinct()]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
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

    options = "".join(
        f'<option value="{u}" {"selected" if u == selected_user else ""}>{u}</option>'
        for u in usernames
    )
    table = "".join(
        f"<tr><td>{r['date']}</td><td>{format_duration(r['online'])}</td><td>{format_duration(r['active'])}</td><td>{format_duration(r['afk'])}</td></tr>"
        for r in report_rows
    )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Haftalık Kullanıcı Raporu</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f6f6fa; }}
            .container {{ max-width: 900px; margin-top: 40px; }}
            table {{ font-size: 15px; }}
            h2 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
    <div class="container">
      <h2>🗓️ Haftalık Kullanıcı Raporu</h2>
      <form method="get" class="row mb-3">
        <div class="col">
          <select name="username" class="form-select">
            {options}
          </select>
        </div>
        <div class="col">
          <input type="week" name="week" class="form-control" value="{week_param}">
        </div>
        <div class="col">
          <button class="btn btn-primary" type="submit">Göster</button>
        </div>
      </form>
      <table class="table table-bordered table-striped shadow">
        <thead class="table-dark">
          <tr>
            <th>Tarih</th>
            <th>Toplam Online</th>
            <th>Aktif Zaman</th>
            <th>AFK Zaman</th>
          </tr>
        </thead>
        <tbody>
          {table}
        </tbody>
      </table>
      <a class="btn btn-secondary" href="/reports">Geri Dön</a>
    </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/usage_report")
def usage_report():
    usernames = [u[0] for u in db.session.query(WindowLog.username).distinct()]
    if not usernames:
        return "No data", 404

    selected_user = request.args.get("username", usernames[0])
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

    options = "".join(
        f'<option value="{u}" {"selected" if u == selected_user else ""}>{u}</option>'
        for u in usernames
    )

    range_opts = {
        "daily": "",
        "weekly": "",
        "monthly": "",
    }
    range_opts[range_param] = "selected"

    table = "".join(
        f"<tr><td>{title}</td><td>{proc}</td><td>{format_duration(dur)}</td></tr>"
        for title, proc, dur in usage_rows
    )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kullanım Detayları</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f6f6fa; }}
            .container {{ max-width: 900px; margin-top: 40px; }}
            table {{ font-size: 15px; }}
            h2 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
    <div class="container">
      <h2>📊 Kullanım Detayları</h2>
      <form method="get" class="row mb-3">
        <div class="col">
          <select name="username" class="form-select">
            {options}
          </select>
        </div>
        <div class="col">
          <select name="range" class="form-select">
            <option value="daily" {range_opts['daily']}>Günlük</option>
            <option value="weekly" {range_opts['weekly']}>Haftalık</option>
            <option value="monthly" {range_opts['monthly']}>Aylık</option>
          </select>
        </div>
        <div class="col">
          <input type="date" name="date" class="form-control" value="{base_date.isoformat()}">
        </div>
        <div class="col">
          <button class="btn btn-primary" type="submit">Göster</button>
        </div>
      </form>
      <table class="table table-bordered table-striped shadow">
        <thead class="table-dark">
          <tr>
            <th>Pencere</th>
            <th>Process</th>
            <th>Süre</th>
          </tr>
        </thead>
        <tbody>
          {table}
        </tbody>
      </table>
      <a class="btn btn-secondary" href="/reports">Geri Dön</a>
    </div>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
