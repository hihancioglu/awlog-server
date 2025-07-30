import sys
import os
import psutil
import requests
import subprocess
import getpass
import socket
import threading
import atexit
import tempfile
import time
import queue
import json
import hmac
import hashlib
import asyncio
from datetime import datetime, timedelta
import ctypes

from debug_utils import DEBUG

# Callback that will be invoked whenever the agent successfully contacts the
# server. ``MainWindow`` sets this to update the UI.
LAST_COMM_CALLBACK = None

# Generic log callback used by background functions to append a message to the
# UI. ``logging_thread_func`` initializes this so functions like ``input_event``
# can display messages.
LOG_CALLBACK = None

from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit, QLabel
from PyQt5.QtGui import QIcon, QTextCursor
from PyQt5.QtCore import pyqtSignal, pyqtSlot, QTimer

# Agent uygulamasının sürüm bilgisi
AGENT_VERSION = "1.0.0"

# --- TEK INSTANCE GARANTİ: PID kontrollü LOCK FILE ---
LOCKFILE = os.path.join(tempfile.gettempdir(), "evden_calisma.lock")

def is_another_instance_running():
    if os.path.exists(LOCKFILE):
        try:
            with open(LOCKFILE, "r") as f:
                pid = int(f.read().strip())
            if pid != os.getpid() and psutil.pid_exists(pid):
                return True
            else:
                os.remove(LOCKFILE)
        except Exception:
            try: os.remove(LOCKFILE)
            except Exception: pass
            return False
    return False
if is_another_instance_running():
    sys.exit(0)
with open(LOCKFILE, "w") as f:
    f.write(str(os.getpid()))
def cleanup_lock():
    if os.path.exists(LOCKFILE):
        try:
            with open(LOCKFILE, "r") as f:
                pid = int(f.read().strip())
            if pid == os.getpid():
                os.remove(LOCKFILE)
        except Exception: pass
atexit.register(cleanup_lock)

def kill_all_forticlient_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == "forticlientconsole.exe":
                proc.terminate()
        except Exception: pass

def is_forticlient_running():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == "forticlientconsole.exe":
                return True
        except Exception: pass
    return False

# Ana sunucu adresi. API çağrıları için base URL olarak kullanılır
SERVER_URL = "http://baylan-portainer:5050"
FORTICLIENT_CONSOLE_PATH = r"C:\Program Files\Fortinet\FortiClient\FortiClientConsole.exe"
CHECK_INTERVAL = 30
SECRET_FILE = os.path.join(tempfile.gettempdir(), "agent_secret.txt")
AGENT_SECRET = None

# ----- LOG (AFK/AKTİF & PENCERE TAKİBİ) -----
afk_timeout = 60  # saniye (AFK için 1dk uygundur)
# Ağ trafiğinin aktif sayılması için gereken minimum byte miktarı
net_active_threshold = 1024  # 1 KB
# Ağ trafiğini daha stabil ölçmek için son birkaç saniyelik toplam
# bayt miktarı değerlendirilir. Böylece küçük dalgalanmalar sürekli
# "Aktif"/"AFK" geçişine neden olmaz.
net_active_window = 5  # saniye
log_queue = queue.Queue()
LOG_PATH = os.path.join(tempfile.gettempdir(), "windowlog.txt")
STATUSLOG_PATH = os.path.join(tempfile.gettempdir(), "statuslog.txt")

# Log mesajlarının başına eklenecek emojiler
LOG_EMOJIS = {
    "Online bildirildi": "\U0001F7E2",  # ışık yeşili daire
    "AFK oldu": "\U0001F634",  # uyuyan yüz
    "Aktif": "\U0001F3C3",  # koşan adam
    "VPN KOPUK": "\U0001F6D1",  # dur tabelası
    "Bağlantı geri geldi": "\U0001F501",  # dönen ok
}

# --- Bugünü Anlık Aktif/AFK Sayaçları ---
today_active_seconds = 0
today_afk_seconds = 0

def format_seconds(sec):
    sec = int(sec or 0)
    h = sec // 3600
    m = (sec % 3600) // 60
    return f"{h:d}:{m:02d}"

def update_today_counters(start_time, end_time, status):
    """Aktif ve AFK süre sayaçlarını günceller."""
    global today_active_seconds, today_afk_seconds
    today = datetime.now().date()
    if end_time <= start_time:
        return
    if start_time.date() > today or end_time.date() < today:
        return
    if start_time.date() < today:
        start_time = datetime.combine(today, datetime.min.time())
    if end_time.date() > today:
        end_time = datetime.combine(today + timedelta(days=1), datetime.min.time())
    delta = int((end_time - start_time).total_seconds())
    if delta <= 0:
        return
    if status == "not-afk":
        today_active_seconds += delta
    elif status == "afk":
        today_afk_seconds += delta

afk_state = False
afk_period_start = datetime.now()
notafk_period_start = datetime.now()
prev_window, prev_process = None, None
window_period_start = datetime.now()

# --- Makro Kaydedici Process Tespiti ---
# Lists will be fetched from the server at startup
MACRO_PROC_BLACKLIST = set()
MACRO_PROC_WHITELIST = set()
MACRO_PROC_CHECK_INTERVAL = 10.0
last_macro_proc_check = 0.0


# Macro recorder process detection
def check_macro_processes() -> None:
    """Scan running processes against blacklist and log if found."""
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
        msg = f"Makro programı tespit edildi: {', '.join(sorted(set(suspects)))}"
        if LOG_CALLBACK:
            LOG_CALLBACK(msg)
        else:
            DEBUG(msg)

def get_hostname():
    return socket.gethostname()

def get_username():
    return getpass.getuser()


def load_secret():
    """Retrieve or request the per-agent secret."""
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

async def _send_log_to_server(log_type, data):
    """Asynchronously send a log entry to the server."""
    try:
        load_secret()
        data["log_type"] = log_type
        data["hostname"] = get_hostname()
        data["username"] = get_username()
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        DEBUG(
            f"send_log_to_server {log_type} "
            f"{data.get('window_title') or data.get('status')}"
        )
        headers = {"Content-Type": "application/json", "X-Signature": sig}
        response = await asyncio.to_thread(
            requests.post,
            f"{SERVER_URL}/api/log",
            data=payload.encode(),
            headers=headers,
            timeout=2,
        )
        if response.status_code == 200 and LAST_COMM_CALLBACK:
            LAST_COMM_CALLBACK()
        else:
            if response.status_code != 200:
                DEBUG(
                    f"send_log_to_server failed status={response.status_code} "
                    f"resp={response.text.strip()}"
                )
        return response.status_code == 200, response.status_code, response.text
    except Exception as e:
        DEBUG(f"send_log_to_server exception: {e}")
        return False, None, str(e)

def send_log_to_server(log_type, data):
    """Wrapper to run asynchronous log sending synchronously."""
    return asyncio.run(_send_log_to_server(log_type, data))

def log_window_period(window_title, process_name, start_time, end_time):
    duration = int((end_time - start_time).total_seconds())
    data = {
        "window_title": window_title or "",
        "process_name": process_name or "",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration": duration
    }
    log_queue.put(("window", data))

def log_status_period(start_time, end_time, status):
    """Queue status logs, splitting periods that cross midnight."""
    cur_start = start_time
    while cur_start.date() < end_time.date():
        midnight = datetime.combine(cur_start.date() + timedelta(days=1), datetime.min.time())
        duration = int((midnight - cur_start).total_seconds())
        data = {
            "status": status,
            "start_time": cur_start.isoformat(),
            "end_time": midnight.isoformat(),
            "duration": duration,
        }
        log_queue.put(("status", data))
        update_today_counters(cur_start, midnight, status)
        cur_start = midnight

    duration = int((end_time - cur_start).total_seconds())
    data = {
        "status": status,
        "start_time": cur_start.isoformat(),
        "end_time": end_time.isoformat(),
        "duration": duration,
    }
    log_queue.put(("status", data))
    update_today_counters(cur_start, end_time, status)



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

def get_idle_seconds() -> float:
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_uint),
            ("dwTime", ctypes.c_uint),
        ]

    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        millis = ctypes.windll.kernel32.GetTickCount() - info.dwTime
        return millis / 1000.0
    return 0.0


def is_workstation_locked() -> bool:
    """Return ``True`` if the workstation is locked."""
    try:
        user32 = ctypes.windll.user32
        hDesktop = user32.OpenInputDesktop(0, False, 0x0100)
        if not hDesktop:
            return True
        locked = not user32.SwitchDesktop(hDesktop)
        user32.CloseDesktop(hDesktop)
        return locked
    except Exception:
        return False


def logging_thread_func(running_flag, log_callback=None):
    global afk_state, afk_period_start, notafk_period_start, prev_window, prev_process, window_period_start, LOG_CALLBACK
    LOG_CALLBACK = log_callback
    prev_window, prev_process = get_active_window_info()
    window_period_start = datetime.now()
    notafk_period_start = window_period_start
    report_window(prev_window, prev_process)
    last_check = datetime.now()
    net_prev = psutil.net_io_counters()
    # Geçmiş ağ trafiği verilerini tutmak için (zaman, byte) çiftleri
    net_history = []

    while running_flag.is_set():
        now = datetime.now()
        check_macro_processes()

        if (now - last_check).total_seconds() > afk_timeout * 2:
            if not afk_state:
                log_status_period(notafk_period_start, last_check, "not-afk")
            afk_state = True
            afk_period_start = now
            notafk_period_start = now
        last_check = now

        current_window, current_process = get_active_window_info()
        window_changed = current_window != prev_window or current_process != prev_process

        net_now = psutil.net_io_counters()
        net_diff = (
            net_now.bytes_sent - net_prev.bytes_sent
        ) + (
            net_now.bytes_recv - net_prev.bytes_recv
        )
        net_prev = net_now

        # Son "net_active_window" süresinde biriken toplam byte miktarını
        # hesapla. Böylece çok kısa süreli düşük trafik yanlış AFK
        # tespitine yol açmaz.
        net_history.append((now, net_diff))
        net_history = [
            (t, b)
            for (t, b) in net_history
            if (now - t).total_seconds() <= net_active_window
        ]
        net_total = sum(b for _, b in net_history)

        idle = get_idle_seconds()
        locked = is_workstation_locked()
        is_active = (
            not locked
            and (
                idle <= afk_timeout
                or net_total > net_active_threshold
                or window_changed
            )
        )

        if window_changed:
            log_window_period(prev_window, prev_process, window_period_start, now)
            prev_window = current_window
            prev_process = current_process
            window_period_start = now
            report_window(current_window, current_process)

        if afk_state and is_active:
            log_status_period(afk_period_start, now, "afk")
            notafk_period_start = now
            afk_state = False
            report_status_async("not-afk")
            if LOG_CALLBACK:
                LOG_CALLBACK("Aktif")
        elif not afk_state and not is_active:
            log_status_period(notafk_period_start, now, "not-afk")
            afk_state = True
            afk_period_start = now
            if LOG_CALLBACK:
                LOG_CALLBACK("AFK oldu")
            if not report_status("afk"):
                DEBUG("report_status afk failed")

        time.sleep(0.5)

# --- Sunucu & VPN işlemleri ---
def start_forticlient_admin(path):
    kill_all_forticlient_processes()
    try:
        subprocess.Popen([
            "powershell",
            "-Command",
            f'Start-Process -FilePath "{path}" -Verb runAs'
        ])
    except Exception as e:
        pass

def get_ip():
    try:
        return requests.get('https://api.ipify.org', timeout=5).text
    except Exception:
        return "unknown"

async def _report_status(status):
    """Asynchronously send status information to the server."""
    data = {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
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
        if r.status_code == 200:
            if LAST_COMM_CALLBACK:
                LAST_COMM_CALLBACK()
        else:
            DEBUG(
                f"report_status failed status={r.status_code} resp={r.text.strip()}"
            )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_status exception: {e}")
        return False

def report_status(status):
    """Wrapper to run asynchronous status reporting synchronously."""
    return asyncio.run(_report_status(status))

def report_status_async(status):
    """Send status update in a background thread using async HTTP."""
    threading.Thread(
        target=lambda: asyncio.run(_report_status(status)), daemon=True
    ).start()

async def _report_window(window_title, process_name):
    """Asynchronously send current window information to the server."""
    data = {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
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
        if r.status_code == 200:
            if LAST_COMM_CALLBACK:
                LAST_COMM_CALLBACK()
        else:
            DEBUG(
                f"report_window failed status={r.status_code} resp={r.text.strip()}"
            )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_window exception: {e}")
        return False

def report_window(window_title, process_name):
    """Wrapper to run asynchronous window reporting synchronously."""
    return asyncio.run(_report_window(window_title, process_name))

def server_accessible(attempts=2, delay=2):
    """Check if server is reachable with multiple attempts."""
    for i in range(attempts):
        try:
            r = requests.get(SERVER_URL, timeout=5)
            if r.status_code in (200, 404):
                DEBUG("server_accessible ok")
                return True
        except Exception:
            pass
        if i < attempts - 1:
            time.sleep(delay)
    return False

def vpn_connected():
    """Return ``True`` if ``baylan.local`` is reachable."""
    try:
        requests.get("http://baylan.local", timeout=5)
        return True
    except Exception:
        return False

class MainWindow(QWidget):
    append_log = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        # Pencere başlığına sürüm bilgisini ekle
        self.setWindowTitle(f"Evden Çalışma Kontrol Paneli v{AGENT_VERSION}")
        # İKON tanımı (hem scriptte hem exe'de çalışır)
        if hasattr(sys, "_MEIPASS"):
            icon_path = os.path.join(sys._MEIPASS, "remote-work-icon.ico")
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(base_dir, "remote-work-icon.ico")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(480, 380)

        self.basla_btn = QPushButton("Başla")
        self.basla_btn.clicked.connect(self.baslat)
        self.bitir_btn = QPushButton("Bitir")
        self.bitir_btn.clicked.connect(self.bitir)
        self.bitir_btn.setEnabled(False)
        self.status_label = QLabel("Durum: Bekleniyor...")
        self.version_label = QLabel(f"Versiyon: {AGENT_VERSION}")
        self.active_time_label = QLabel("Bugün Aktif: 0:00")
        self.afk_time_label = QLabel("Bugün AFK: 0:00")
        self.last_comm_label = QLabel("Son İletişim: -")
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        # Versiyon bilgisini log ekranına da yaz
        self.log.append(f"Uygulama Versiyonu: {AGENT_VERSION}")

        layout = QVBoxLayout()
        layout.addWidget(self.basla_btn)
        layout.addWidget(self.bitir_btn)
        layout.addWidget(self.status_label)
        layout.addWidget(self.version_label)
        layout.addWidget(self.active_time_label)
        layout.addWidget(self.afk_time_label)
        layout.addWidget(self.last_comm_label)
        layout.addWidget(self.log)
        self.setLayout(layout)

        self.keepalive_thread = None
        self.vpn_thread = None
        self.active = False
        self.logging_flag = threading.Event()
        self.logging_flag.clear()
        self.logging_thread = None
        self.log_sender_thread = None
        # Sunucuya ulaşılamadığında devreye giren offline mod durumu
        self.offline_mode = False

        # Son başarılı sunucu iletişim zamanı
        self.last_comm = None

        self.append_log.connect(self._append_log)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_time_labels)
        self.timer.start()
        self.update_time_labels()

        # Update global callback so lower level functions can notify UI
        global LAST_COMM_CALLBACK
        LAST_COMM_CALLBACK = self.record_server_contact

    def set_connection_status(self, vpn_ok: bool, server_ok: bool):
        """Update status label depending on VPN and server reachability."""
        if not vpn_ok:
            self.status_label.setText("Durum: VPN KOPUK! Bağlantı bekleniyor...")
        elif not server_ok:
            self.status_label.setText("Durum: VPN Bağlı, API Sunucusu Yok")
        else:
            self.status_label.setText("Durum: VPN Bağlı, API Sunucusu Bağlı")

    def logla(self, text):
        self.append_log.emit(text)

    @pyqtSlot(str)
    def _append_log(self, text):
        for key, emoji in LOG_EMOJIS.items():
            if text.startswith(key):
                text = f"{emoji} {text}"
                break
        self.log.append(text)
        self.log.moveCursor(QTextCursor.End)  # Oto-scroll

    def record_server_contact(self):
        """Record current time as last successful server communication."""
        self.last_comm = datetime.now()
        self.last_comm_label.setText(
            f"Son İletişim: {self.last_comm.strftime('%H:%M:%S')}"
        )

    def update_time_labels(self):
        """Update active/AFK labels with running totals."""
        active = today_active_seconds
        afk = today_afk_seconds
        now = datetime.now()
        if self.active:
            if afk_state:
                afk += int((now - afk_period_start).total_seconds())
            else:
                active += int((now - notafk_period_start).total_seconds())
        self.active_time_label.setText(f"Bugün Aktif: {format_seconds(active)}")
        self.afk_time_label.setText(f"Bugün AFK: {format_seconds(afk)}")

    def fetch_today_totals(self):
        """Sunucudan bugünkü toplamları al."""
        global today_active_seconds, today_afk_seconds
        try:
            load_secret()
            data = {"username": get_username(), "hostname": get_hostname()}
            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
            r = requests.post(
                f"{SERVER_URL}/agent/today_totals",
                data=payload.encode(),
                headers={"Content-Type": "application/json", "X-Signature": sig},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                today_active_seconds = int(data.get("active", 0))
                today_afk_seconds = int(data.get("afk", 0))
                # Reset the current not-afk period start so the label does not
                # add extra seconds before logging thread initializes.
                global notafk_period_start, afk_period_start
                now = datetime.now()
                notafk_period_start = now
                afk_period_start = now
                self.update_time_labels()
        except Exception:
            pass

    def fetch_macro_config(self):
        """Sunucudan makro kaydedici ayarlarını al."""
        global MACRO_PROC_BLACKLIST, MACRO_PROC_WHITELIST, MACRO_PROC_CHECK_INTERVAL
        try:
            load_secret()
            data = {"username": get_username(), "hostname": get_hostname()}
            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            sig = hmac.new(AGENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
            r = requests.post(
                f"{SERVER_URL}/agent/config",
                data=payload.encode(),
                headers={"Content-Type": "application/json", "X-Signature": sig},
                timeout=5,
            )
            if r.status_code == 200:
                cfg = r.json()
                MACRO_PROC_BLACKLIST = {
                    p.strip().lower()
                    for p in (cfg.get("blacklist") or "").split(",")
                    if p.strip()
                }
                MACRO_PROC_WHITELIST = {
                    p.strip().lower()
                    for p in (cfg.get("whitelist") or "").split(",")
                    if p.strip()
                }
                MACRO_PROC_CHECK_INTERVAL = float(cfg.get("check_interval") or 10)
        except Exception:
            pass

    def baslat(self):
        self.basla_btn.setEnabled(False)
        self.bitir_btn.setEnabled(True)
        self.active = True
        self.logging_flag.set()
        self.logla("Başlatılıyor...")
        threading.Thread(target=self._start_workflow, daemon=True).start()

    def bitir(self):
        self.basla_btn.setEnabled(True)
        self.bitir_btn.setEnabled(False)
        self.active = False
        self.logging_flag.clear()
        self.status_label.setText("Durum: Sonlandırılıyor...")
        self.logla("Tüm işlemler sonlandırılıyor...")
        self.cleanup()
        self.status_label.setText("Durum: Bekleniyor...")

    def _start_workflow(self):
        self.status_label.setText("Durum: Temizlik yapılıyor...")
        kill_all_forticlient_processes()
        time.sleep(2)

        if not vpn_connected():
            self.set_connection_status(False, False)
            self.logla("VPN yok. FortiClient başlatılıyor...")
            if not is_forticlient_running():
                start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                self.logla("FortiClient penceresi açıldı.")
            else:
                self.logla("FortiClient zaten açık.")
            while not vpn_connected() and self.active:
                self.set_connection_status(False, False)
                self.logla("VPN bağlantısı bekleniyor...")
                for _ in range(3):
                    if not self.active:
                        return
                    time.sleep(1)
        if vpn_connected() and not server_accessible():
            self.set_connection_status(True, False)
            self.logla("VPN bağlı ancak API sunucusuna erişilemiyor.")
            while vpn_connected() and not server_accessible() and self.active:
                self.logla("API sunucusu bekleniyor...")
                for _ in range(3):
                    if not self.active:
                        return
                    time.sleep(1)
            if not server_accessible():
                return
        if vpn_connected() and server_accessible():
            self.set_connection_status(True, True)
            self.logla("VPN zaten bağlı, FortiClient başlatılmayacak.")
        if not self.active:
            return
        self.fetch_today_totals()
        self.fetch_macro_config()
        if not self.active:
            return
        if report_status("online"):
            self.record_server_contact()
        if report_status("not-afk"):
            self.record_server_contact()
        self.status_label.setText("Durum: Aktif (Evden Çalışma Başladı)")
        self.logla("Online bildirildi, çalışma başladı.")

        # LOG İZLEME ve SUNUCUYA GÖNDERME THREAD'LERİ
        self.logging_thread = threading.Thread(target=self.logging_worker, daemon=True)
        self.logging_thread.start()
        self.log_sender_thread = threading.Thread(target=self.log_sender_worker, daemon=True)
        self.log_sender_thread.start()

        self.keepalive_thread = threading.Thread(target=self.keepalive, daemon=True)
        self.keepalive_thread.start()
        self.vpn_thread = threading.Thread(target=self.vpn_monitor, daemon=True)
        self.vpn_thread.start()

    def logging_worker(self):
        logging_thread_func(self.logging_flag, log_callback=self.logla)

    def log_sender_worker(self):
        # Arka planda log_queue'dan çıkanları gönder
        while self.active or not log_queue.empty():
            try:
                log_type, data = log_queue.get(timeout=0.5)
                ok, status_code, message = send_log_to_server(log_type, data)
                if ok:
                    self.record_server_contact()
                else:
                    path = LOG_PATH if log_type == "window" else STATUSLOG_PATH
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(data, ensure_ascii=False) + "\n")
                # Sunucuya iletimin başarılı olduğunu kullanıcı arayüzünde
                # göstermek gereksiz, bu yüzden ek loglama yapılmaz
            except queue.Empty:
                continue
            except Exception:
                pass

    def flush_local_logs(self):
        """Send locally stored logs if any exist."""
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
                        if ok:
                            self.record_server_contact()
                        else:
                            remaining.append(line)
                    except Exception:
                        remaining.append(line)
            except Exception as e:
                self.logla(f"Yerel log okuma hatası: {e}")
                continue

            if remaining:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("\n".join(remaining) + "\n")
                except Exception as e:
                    self.logla(f"Yerel log yazma hatası: {e}")
            else:
                try:
                    os.remove(path)
                except Exception:
                    pass

    def keepalive(self):
        while self.active:
            for _ in range(60):  # 60 saniye = 1 dk
                if not self.active:
                    return
                time.sleep(1)
            if not self.active:
                return
            if report_status("keepalive"):
                self.record_server_contact()
            current_status = "afk" if afk_state else "not-afk"
            if report_status(current_status):
                self.record_server_contact()

    def vpn_monitor(self):
        self.forticlient_window_shown = False
        was_vpn = vpn_connected()
        was_server = server_accessible() if was_vpn else False
        if was_server:
            self.flush_local_logs()
        while self.active:
            for _ in range(CHECK_INTERVAL):
                if not self.active:
                    return
                time.sleep(1)
            if not self.active:
                return
            vpn_ok = vpn_connected()
            server_ok = server_accessible() if vpn_ok else False
            if not vpn_ok:
                self.set_connection_status(False, False)
                if not self.forticlient_window_shown:
                    if not is_forticlient_running():
                        start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                        self.logla("FortiClient penceresi açıldı.")
                    else:
                        self.logla("FortiClient zaten açık.")
                    self.forticlient_window_shown = True
                if not self.offline_mode:
                    self.logla(
                        "Sunucu ile bağlantı kurulamıyor. Offline mod aktif edildi. Kayıtlar localde tutuluyor, bağlantı geri geldiğinde sunucuya iletilecektir."
                    )
                    self.offline_mode = True
                self.logla("VPN KOPUK. Bağlantı bekleniyor...")
            elif not server_ok:
                self.set_connection_status(True, False)
                if not self.offline_mode:
                    self.logla(
                        "Sunucu ile bağlantı kurulamıyor. Offline mod aktif edildi. Kayıtlar localde tutuluyor, bağlantı geri geldiğinde sunucuya iletilecektir."
                    )
                    self.offline_mode = True
                self.logla("VPN var ancak API sunucusuna erişilemiyor.")
            else:
                if self.forticlient_window_shown or not was_vpn:
                    self.logla("VPN bağlantısı tekrar sağlandı.")
                if not was_server:
                    self.flush_local_logs()
                    if report_status("online"):
                        self.record_server_contact()
                    if report_status("afk" if afk_state else "not-afk"):
                        self.record_server_contact()
                self.set_connection_status(True, True)
                if self.offline_mode:
                    self.logla("Bağlantı geri geldi. Online mod.")
                    self.offline_mode = False
                self.forticlient_window_shown = False
            was_vpn = vpn_ok
            was_server = server_ok

    def cleanup(self):
        global afk_state, afk_period_start, notafk_period_start

        now = datetime.now()
        if afk_state:
            log_status_period(afk_period_start, now, "afk")
        else:
            log_status_period(notafk_period_start, now, "not-afk")

        self.active = False
        if report_status("offline"):
            self.record_server_contact()
        kill_all_forticlient_processes()
        self.logla("Offline bildirildi, uygulama kapatıldı.")

    def closeEvent(self, event):
        self.cleanup()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    try:
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        win.cleanup()
        sys.exit(0)
