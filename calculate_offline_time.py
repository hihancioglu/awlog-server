from datetime import datetime
from awlog_server import create_app
from awlog_server.models import db, ReportLog


def get_offline_time(username: str, hostname: str | None = None) -> tuple[datetime, datetime, int]:
    """Return first log time, last log time and total offline seconds."""
    with create_app().app_context():
        q = ReportLog.query.filter_by(username=username)
        if hostname:
            q = q.filter_by(hostname=hostname)
        logs = q.order_by(ReportLog.created_at).all()
        if not logs:
            raise ValueError("no logs found")
        offline = 0
        for i in range(len(logs) - 1):
            current = logs[i]
            nxt = logs[i + 1]
            if current.status == "offline":
                offline += int((nxt.created_at - current.created_at).total_seconds())
        return logs[0].created_at, logs[-1].created_at, offline


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Calculate agent offline time")
    parser.add_argument("username", help="Username to query")
    parser.add_argument("--hostname", help="Hostname to filter", default=None)
    args = parser.parse_args()

    start, end, seconds = get_offline_time(args.username, args.hostname)
    print(f"First log: {start}")
    print(f"Last log: {end}")
    print(f"Offline time: {seconds} seconds")
