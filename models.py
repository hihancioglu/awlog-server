from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# SQLAlchemy database instance
# Initialized in server.py with app context

db = SQLAlchemy()

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
    status = db.Column(db.String(32))  # "afk" or "not-afk"
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
