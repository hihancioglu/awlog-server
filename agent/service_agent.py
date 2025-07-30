import os
import sys
import time
import queue
import json
import threading
import tempfile
import asyncio
import requests
import psutil
import getpass
import socket
import hmac
import hashlib
from datetime import datetime, timedelta
from pynput import mouse, keyboard

import win32serviceutil
import win32service
import win32event
import servicemanager

from debug_utils import DEBUG
from dotenv import load_dotenv

load_dotenv()

# ---- Configuration ----
SERVER_URL = "http://baylan-portainer:5050"
CHECK_INTERVAL = 60  # keepalive interval
SECRET_FILE = os.path.join(tempfile.gettempdir(), "agent_secret.txt")
AGENT_SECRET = None

# logging
log_queue = queue.Queue()
LOG_PATH = os.path.join(tempfile.gettempdir(), "windowlog.txt")
STATUSLOG_PATH = os.path.join(tempfile.gettempdir(), "statuslog.txt")

# afk tracking
afk_timeout = 60  # seconds
last_input_time = time.time()
afk_state = False
afk_period_start = datetime.now()
notafk_period_start = datetime.now()
prev_window, prev_process = None, None
window_period_start = datetime.now()
pressed_keys = set()

# ---- Helper functions ----

def get_hostname():
    return socket.gethostname()


def get_username():
    return getpass.getuser()


def load_secret():
    global AGENT_SECRET
    if AGENT_SECRET:
        return AGENT_SECRET
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r", encoding="utf-8") as f:
                AGENT_SECRET = f.read().strip()
        except Exception:
            AGENT_SECRET = None
    if not AGENT_SECRET:
        data = {"hostname": get_hostname(), "username": get_username()}
        try:
            r = requests.post(f"{SERVER_URL}/register", json=data, timeout=5)
            if r.status_code == 200:
                AGENT_SECRET = r.json().get("secret")
                with open(SECRET_FILE, "w", encoding="utf-8") as f:
                    f.write(AGENT_SECRET)
        except Exception as e:
            DEBUG(f"load_secret error: {e}")
            AGENT_SECRET = None
    return AGENT_SECRET


def get_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception:
        return "unknown"


async def _send_log_to_server(log_type, data):
    try:
        load_secret()
        data["log_type"] = log_type
        data["hostname"] = get_hostname()
        data["username"] = get_username()
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        DEBUG(f"send_log_to_server {log_type} {data.get('window_title') or data.get('status')}")
        headers = {"Content-Type": "application/json", "X-Signature": sig}
        resp = await asyncio.to_thread(
            requests.post,
            f"{SERVER_URL}/api/log",
            data=payload.encode(),
            headers=headers,
            timeout=5,
        )
        return resp.status_code == 200, resp.status_code, resp.text
    except Exception as e:
        DEBUG(f"send_log_to_server exception: {e}")
        return False, None, str(e)


def send_log_to_server(log_type, data):
    return asyncio.run(_send_log_to_server(log_type, data))


async def _report_status(status):
    data = {
        "username": get_username(),
        "hostname": get_hostname(),
        "ip": get_ip(),
        "status": status,
    }
    try:
        load_secret()
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        r = await asyncio.to_thread(
            requests.post,
            f"{SERVER_URL}/report",
            data=payload.encode(),
            headers={"Content-Type": "application/json", "X-Signature": sig},
            timeout=5,
        )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_status exception: {e}")
        return False


def report_status(status):
    return asyncio.run(_report_status(status))


def report_status_async(status):
    threading.Thread(target=lambda: asyncio.run(_report_status(status)), daemon=True).start()


async def _report_window(window_title, process_name):
    data = {
        "username": get_username(),
        "hostname": get_hostname(),
        "ip": get_ip(),
        "status": "window",
        "window_title": window_title or "",
        "process_name": process_name or "",
    }
    try:
        load_secret()
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        r = await asyncio.to_thread(
            requests.post,
            f"{SERVER_URL}/report",
            data=payload.encode(),
            headers={"Content-Type": "application/json", "X-Signature": sig},
            timeout=5,
        )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_window exception: {e}")
        return False


def report_window(window_title, process_name):
    return asyncio.run(_report_window(window_title, process_name))


# ---- Logging helpers ----
input_times = []
MACRO_CHECK_COUNT = 10
MACRO_STD_THRESHOLD = 0.05
MACRO_MIN_INTERVAL = 30.0

# Fare hareketlerinin makro kontrolü için minimum aralık (saniye)
MOUSE_MACRO_INTERVAL = 0.5
last_mouse_macro_check = 0.0

# Macro recorder process detection
MACRO_PROC_BLACKLIST = {
    p.strip().lower()
    for p in os.environ.get("MACRO_PROC_BLACKLIST", "").split(",")
    if p.strip()
}
MACRO_PROC_WHITELIST = {
    p.strip().lower()
    for p in os.environ.get("MACRO_PROC_WHITELIST", "").split(",")
    if p.strip()
}
MACRO_PROC_CHECK_INTERVAL = float(os.environ.get("MACRO_PROC_CHECK_INTERVAL", "10"))
last_macro_proc_check = 0.0

def check_macro_pattern(ts: float) -> None:
    input_times.append(ts)
    if len(input_times) > MACRO_CHECK_COUNT:
        input_times.pop(0)
    if len(input_times) < MACRO_CHECK_COUNT:
        return
    intervals = [input_times[i+1] - input_times[i] for i in range(len(input_times)-1)]
    avg = sum(intervals) / len(intervals)
    if avg > MACRO_MIN_INTERVAL:
        return
    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    if avg > 0 and (std_dev / avg) < MACRO_STD_THRESHOLD:
        DEBUG(f"Olası makro kullanımı: ort={avg:.3f}s std={std_dev:.3f}s")
        report_status_async("macro-suspect")
        input_times.clear()

def check_macro_processes() -> None:
    """Scan running processes for known macro recorders."""
    global last_macro_proc_check
    now = time.time()
    if now - last_macro_proc_check < MACRO_PROC_CHECK_INTERVAL:
        return
    last_macro_proc_check = now
    suspects = []
    blacklist = {p.lower() for p in MACRO_PROC_BLACKLIST}
    whitelist = {p.lower() for p in MACRO_PROC_WHITELIST}
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in blacklist and name not in whitelist:
                suspects.append(name)
        except Exception:
            continue
    if suspects:
        DEBUG("Makro programı tespit edildi: %s" % ", ".join(sorted(set(suspects))))


def log_window_period(window_title, process_name, start_time, end_time):
    duration = int((end_time - start_time).total_seconds())
    data = {
        "window_title": window_title or "",
        "process_name": process_name or "",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration": duration,
    }
    log_queue.put(("window", data))


def log_status_period(start_time, end_time, status):
    data = {
        "status": status,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration": int((end_time - start_time).total_seconds()),
    }
    log_queue.put(("status", data))


def input_event(check_macro: bool = True):
    global last_input_time, afk_state, afk_period_start, notafk_period_start
    now = time.time()
    last_input_time = now
    if check_macro:
        check_macro_pattern(now)
    if afk_state:
        afk_end = datetime.now()
        log_status_period(afk_period_start, afk_end, "afk")
        notafk_period_start = afk_end
        afk_state = False
        report_status_async("not-afk")


def on_key_press(key):
    if key not in pressed_keys:
        pressed_keys.add(key)
        input_event()


def on_key_release(key):
    pressed_keys.discard(key)
    input_event()


def on_mouse_move(x, y):
    """Handle mouse move events with throttled macro checks."""
    global last_mouse_macro_check
    now = time.time()
    if now - last_mouse_macro_check >= MOUSE_MACRO_INTERVAL:
        last_mouse_macro_check = now
        input_event(True)
    else:
        input_event(False)


def start_listeners():
    mouse.Listener(
        on_move=on_mouse_move,
        on_click=lambda *a, **k: input_event(),
        on_scroll=lambda *a, **k: input_event(),
    ).start()
    keyboard.Listener(on_press=on_key_press, on_release=on_key_release).start()


def get_active_window_info():
    try:
        import win32gui
        import win32process
        hwnd = win32gui.GetForegroundWindow()
        window_title = win32gui.GetWindowText(hwnd)
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        process = psutil.Process(pid)
        process_name = process.name()
        return window_title, process_name
    except Exception:
        return None, None


def logging_thread_func(running_flag):
    global afk_state, afk_period_start, notafk_period_start, prev_window, prev_process, window_period_start, last_input_time
    start_listeners()
    prev_window, prev_process = get_active_window_info()
    window_period_start = datetime.now()
    notafk_period_start = window_period_start
    report_window(prev_window, prev_process)
    last_check = datetime.now()

    while running_flag.is_set():
        now = datetime.now()
        check_macro_processes()
        if (now - last_check).total_seconds() > afk_timeout * 2:
            if not afk_state:
                log_status_period(notafk_period_start, last_check, "not-afk")
            afk_state = True
            afk_period_start = now
            notafk_period_start = now
            last_input_time = time.time()
        last_check = now

        if not afk_state and (time.time() - last_input_time) > afk_timeout:
            log_status_period(notafk_period_start, now, "not-afk")
            afk_state = True
            afk_period_start = now
            report_status_async("afk")

        current_window, current_process = get_active_window_info()
        if current_window != prev_window or current_process != prev_process:
            log_window_period(prev_window, prev_process, window_period_start, now)
            prev_window = current_window
            prev_process = current_process
            window_period_start = now
            report_window(current_window, current_process)

        time.sleep(0.5)


# ---- Workers ----

def log_sender_worker(running_flag):
    while running_flag.is_set() or not log_queue.empty():
        try:
            log_type, data = log_queue.get(timeout=0.5)
            ok, _, _ = send_log_to_server(log_type, data)
            if not ok:
                path = LOG_PATH if log_type == "window" else STATUSLOG_PATH
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(data, ensure_ascii=False) + "\n")
        except queue.Empty:
            continue
        except Exception:
            pass


def flush_local_logs():
    for path in (LOG_PATH, STATUSLOG_PATH):
        if not os.path.exists(path):
            continue
        remaining = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    log_type = data.get("log_type")
                    ok, _, _ = send_log_to_server(log_type, data)
                    if not ok:
                        remaining.append(line)
                except Exception:
                    remaining.append(line)
        except Exception:
            continue

        if remaining:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(remaining) + "\n")
            except Exception:
                pass
        else:
            try:
                os.remove(path)
            except Exception:
                pass


def keepalive_worker(running_flag):
    while running_flag.is_set():
        for _ in range(CHECK_INTERVAL):
            if not running_flag.is_set():
                return
            time.sleep(1)
        if not running_flag.is_set():
            return
        report_status("keepalive")
        current_status = "afk" if afk_state else "not-afk"
        report_status(current_status)


# ---- Windows Service ----
class AWLogService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AWLogService"
    _svc_display_name_ = "AW Log Agent Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running_flag = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running_flag.clear()

    def SvcDoRun(self):
        self.running_flag.set()
        threading.Thread(target=logging_thread_func, args=(self.running_flag,), daemon=True).start()
        threading.Thread(target=log_sender_worker, args=(self.running_flag,), daemon=True).start()
        threading.Thread(target=keepalive_worker, args=(self.running_flag,), daemon=True).start()
        flush_local_logs()
        report_status("online")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        report_status("offline")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STOPPED, (self._svc_name_, ""))


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AWLogService)
