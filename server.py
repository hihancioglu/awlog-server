from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime, date, timedelta
import os

app = Flask(__name__)

db_path = os.path.join(os.path.dirname(__file__), "data", "awlogs.sqlite")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET = os.environ.get("SECRET", "UzunVEZorluBirKey2024@!")
db = SQLAlchemy(app)

class WindowLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128))
    username = db.Column(db.String(128))
    window_title = db.Column(db.String(512))
    process_name = db.Column(db.String(128))
    start_time = db.Column(db.String(32))
    end_time = db.Column(db.String(32))
    duration = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class StatusLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128))
    username = db.Column(db.String(128))
    status = db.Column(db.String(32))  # "afk" veya "not-afk"
    start_time = db.Column(db.String(32))
    end_time = db.Column(db.String(32))
    duration = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ReportLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128))
    username = db.Column(db.String(128))
    ip = db.Column(db.String(64))
    status = db.Column(db.String(32))  # online/offline/keepalive/afk/not-afk
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.before_first_request
def setup_db():
    db.create_all()

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
    today_str = date.today().isoformat()
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
                StatusLog.status == "not-afk",
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
    </div>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
