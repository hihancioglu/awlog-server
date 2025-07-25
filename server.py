from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os

app = Flask(__name__)

db_path = os.path.join(os.path.dirname(__file__), "data", "awlogs.sqlite")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
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

@app.before_first_request
def setup_db():
    db.create_all()

@app.route("/api/log", methods=["POST"])
def receive_log():
    data = request.json
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
    # Her kullanıcı/PC için en son status'u getir, son kayıdın tersini göster (güncel durum için)
    latest = {}
    q = StatusLog.query.order_by(StatusLog.username, StatusLog.hostname, StatusLog.created_at)
    for log in q:
        key = (log.username, log.hostname)
        if key not in latest or log.created_at > latest[key].created_at:
            latest[key] = log

    status_list = []
    for (username, hostname), log in latest.items():
        # Son logun status'una göre mevcut durumu belirle (tersini göster)
        if log.status == "afk":
            shown_status = "Aktif (not-afk)"
            badge = '<span class="badge bg-success">Aktif</span>'
        else:
            shown_status = "AFK"
            badge = '<span class="badge bg-warning text-dark">AFK</span>'
        status_list.append({
            "username": username,
            "hostname": hostname,
            "status": log.status,
            "shown_status": shown_status,
            "badge": badge,
            "start_time": log.start_time,
            "end_time": log.end_time,
            "created_at": log.created_at
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
            <td>{row['start_time']}</td>
            <td>{row['end_time']}</td>
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
                <th>Başlangıç</th>
                <th>Bitiş</th>
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
