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
TIMEZONE_OFFSET = int(os.environ.get("TIMEZONE_OFFSET", 0))  # hours

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

        total_today = (
            db.session.query(func.sum(StatusLog.duration))
            .filter(
                StatusLog.username == log.username,
                StatusLog.hostname == log.hostname,
                func.substr(StatusLog.start_time, 1, 10) == today_str,
            )
            .scalar()
            or 0
        )

        status_list.append({
            "username": log.username,
            "hostname": log.hostname,
            "status": log.status,
            "shown_status": shown_status,
            "badge": badge,
            "window_title": window_map.get(pair, ""),
            "ip": rep.get("ip") if rep else "?",
            "today_total": total_today,
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
            <td>{format_duration(row['today_total'])}</td>
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
    </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/reports")
def reports():
    totals = get_user_work_totals()
    table = ""
    for row in totals:
        table += f"""
        <tr>
            <td>{row['username']}</td>
            <td>{row['hostname']}</td>
            <td>{format_duration(row['daily'])}</td>
            <td>{format_duration(row['weekly'])}</td>
            <td>{format_duration(row['monthly'])}</td>
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
      <h2>📝 Kullanıcı Çalışma Süreleri</h2>
      <table class="table table-bordered table-striped shadow">
        <thead class="table-dark">
            <tr>
                <th>Kullanıcı</th>
                <th>PC</th>
                <th>Bugün</th>
                <th>Son 7 Gün</th>
                <th>Son 30 Gün</th>
            </tr>
        </thead>
        <tbody>
            {table}
        </tbody>
      </table>
      <h3>Haftalık Detaylar</h3>
      {generate_all_weekly_tables()}
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
