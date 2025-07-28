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
from datetime import datetime, timedelta
from pynput import mouse, keyboard

from debug_utils import DEBUG

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
SECRET = "UzunVEZorluBirKey2024@!"  # Güvenlik için

# ----- LOG (AFK/AKTİF & PENCERE TAKİBİ) -----
afk_timeout = 60  # saniye (AFK için 1dk uygundur)
log_queue = queue.Queue()
LOG_PATH = os.path.join(tempfile.gettempdir(), "windowlog.txt")
STATUSLOG_PATH = os.path.join(tempfile.gettempdir(), "statuslog.txt")

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

last_input_time = time.time()
afk_state = False
afk_period_start = datetime.now()
notafk_period_start = datetime.now()
prev_window, prev_process = None, None
window_period_start = datetime.now()
pressed_keys = set()

def get_hostname():
    return socket.gethostname()

def get_username():
    return getpass.getuser()

def send_log_to_server(log_type, data):
    """Send a log entry to the server.

    Returns a tuple ``(ok, status_code, message)`` where ``ok`` is ``True``
    when the server responded with HTTP 200. ``status_code`` and ``message``
    contain the server response information for troubleshooting."""
    try:
        data["log_type"] = log_type
        data["hostname"] = get_hostname()
        data["username"] = get_username()
        data["secret"] = SECRET
        DEBUG(
            f"send_log_to_server {log_type} "
            f"{data.get('window_title') or data.get('status')}"
        )
        response = requests.post(f"{SERVER_URL}/api/log", json=data, timeout=2)
        if response.status_code != 200:
            DEBUG(
                f"send_log_to_server failed status={response.status_code} "
                f"resp={response.text.strip()}"
            )
        return response.status_code == 200, response.status_code, response.text
    except Exception as e:
        DEBUG(f"send_log_to_server exception: {e}")
        return False, None, str(e)

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

def input_event():
    """Gerçek bir kullanıcı girdisi olduğunda çağrılır."""
    global last_input_time, afk_state, afk_period_start, notafk_period_start
    now = time.time()
    last_input_time = now
    if afk_state:
        afk_period_end = datetime.now()
        log_status_period(afk_period_start, afk_period_end, "afk")
        notafk_period_start = afk_period_end
        afk_state = False
        if not report_status("not-afk"):
            DEBUG("report_status not-afk failed")

def on_key_press(key):
    """Keyboard press handler that ignores repeated keydown events."""
    if key not in pressed_keys:
        pressed_keys.add(key)
        input_event()

def on_key_release(key):
    """Keyboard release handler that always counts as activity."""
    pressed_keys.discard(key)
    input_event()

def start_listeners():
    mouse.Listener(
        on_move=lambda *a, **k: input_event(),
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

def logging_thread_func(running_flag, log_callback=None):
    global afk_state, afk_period_start, notafk_period_start, prev_window, prev_process, window_period_start
    start_listeners()
    prev_window, prev_process = get_active_window_info()
    window_period_start = datetime.now()
    notafk_period_start = window_period_start
    report_window(prev_window, prev_process)

    while running_flag.is_set():
        now = datetime.now()

        # AFK kontrol
        if not afk_state and (time.time() - last_input_time) > afk_timeout:
            # not-afk dönemi bitti, logla
            log_status_period(notafk_period_start, now, "not-afk")
            afk_state = True
            afk_period_start = now
            if log_callback:
                log_callback("AFK oldu")
            if not report_status("afk"):
                DEBUG("report_status afk failed")

        # Pencere değişimi kontrolü
        current_window, current_process = get_active_window_info()
        if current_window != prev_window or current_process != prev_process:
            log_window_period(prev_window, prev_process, window_period_start, now)
            prev_window = current_window
            prev_process = current_process
            window_period_start = now
            report_window(current_window, current_process)

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

def report_status(status):
    """Send status information to the server.

    Returns ``True`` when the server acknowledges the status update."""
    data = {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
        "ip": get_ip(),
        "status": status,
        "secret": SECRET,
    }
    try:
        r = requests.post(f"{SERVER_URL}/report", json=data, timeout=5)
        if r.status_code != 200:
            DEBUG(
                f"report_status failed status={r.status_code} resp={r.text.strip()}"
            )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_status exception: {e}")
        return False

def report_window(window_title, process_name):
    """Send current window information to the server."""
    data = {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
        "ip": get_ip(),
        "status": "window",
        "window_title": window_title or "",
        "process_name": process_name or "",
        "secret": SECRET,
    }
    try:
        r = requests.post(f"{SERVER_URL}/report", json=data, timeout=5)
        if r.status_code != 200:
            DEBUG(
                f"report_window failed status={r.status_code} resp={r.text.strip()}"
            )
        return r.status_code == 200
    except Exception as e:
        DEBUG(f"report_window exception: {e}")
        return False

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
        layout.addWidget(self.log)
        self.setLayout(layout)

        self.keepalive_thread = None
        self.vpn_thread = None
        self.active = False
        self.logging_flag = threading.Event()
        self.logging_flag.clear()
        self.logging_thread = None
        self.log_sender_thread = None

        self.append_log.connect(self._append_log)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_time_labels)
        self.timer.start()
        self.update_time_labels()

    def logla(self, text):
        self.append_log.emit(text)

    @pyqtSlot(str)
    def _append_log(self, text):
        self.log.append(text)
        self.log.moveCursor(QTextCursor.End)  # Oto-scroll

    def update_time_labels(self):
        self.active_time_label.setText(f"Bugün Aktif: {format_seconds(today_active_seconds)}")
        self.afk_time_label.setText(f"Bugün AFK: {format_seconds(today_afk_seconds)}")

    def fetch_today_totals(self):
        """Sunucudan bugünkü toplamları al."""
        global today_active_seconds, today_afk_seconds
        try:
            r = requests.get(
                f"{SERVER_URL}/api/today_totals",
                params={"username": get_username()},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                today_active_seconds = int(data.get("active", 0))
                today_afk_seconds = int(data.get("afk", 0))
                self.update_time_labels()
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
            self.status_label.setText("Durum: VPN Bağlantısı Yok")
            self.logla("VPN yok. FortiClient başlatılıyor...")
            if not is_forticlient_running():
                start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                self.logla("FortiClient penceresi açıldı.")
            else:
                self.logla("FortiClient zaten açık.")
            while not vpn_connected() and self.active:
                self.status_label.setText("Durum: VPN Bağlantısı Bekleniyor...")
                self.logla("VPN bağlantısı bekleniyor...")
                for _ in range(3):
                    if not self.active:
                        return
                    time.sleep(1)
        if vpn_connected() and not server_accessible():
            self.status_label.setText("Durum: API Sunucusu Yok")
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
            self.status_label.setText("Durum: VPN Bağlı")
            self.logla("VPN zaten bağlı, FortiClient başlatılmayacak.")
        if not self.active:
            return
        self.fetch_today_totals()
        if not self.active:
            return
        if not report_status("online"):
            self.logla("Online durumu sunucuya iletilemedi.")
        if not report_status("not-afk"):
            self.logla("not-afk durumu sunucuya iletilemedi.")
        self.status_label.setText("Durum: Aktif (Evden Çalışma Başladı)")
        self.logla("Online bildirildi, takip başladı.")

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
                if not ok:
                    self.logla(
                        f"Sunucu log kaydetmedi (HTTP {status_code}): {message.strip()}"
                    )
                    # Local dosyada tut, örnek amaçlı
                    path = LOG_PATH if log_type == "window" else STATUSLOG_PATH
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(data, ensure_ascii=False) + "\n")
                # Sunucuya iletimin başarılı olduğunu kullanıcı arayüzünde
                # göstermek gereksiz, bu yüzden ek loglama yapılmaz
            except queue.Empty:
                continue
            except Exception as e:
                self.logla(f"Log gönderim hatası: {e}")

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
                        if not ok:
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
            for _ in range(120):  # 120 saniye = 2 dk
                if not self.active:
                    return
                time.sleep(1)
            if not self.active:
                return
            if report_status("keepalive"):
                self.logla("Keepalive gönderildi.")
            else:
                self.logla("Keepalive gönderilemedi.")

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
                self.status_label.setText("Durum: VPN KOPUK! Bağlantı bekleniyor...")
                if not self.forticlient_window_shown:
                    if not is_forticlient_running():
                        start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                        self.logla("FortiClient penceresi açıldı.")
                    else:
                        self.logla("FortiClient zaten açık.")
                    self.forticlient_window_shown = True
                self.logla("VPN KOPUK. Bağlantı bekleniyor...")
            elif not server_ok:
                self.status_label.setText("Durum: API Sunucusu Yok")
                self.logla("VPN var ancak API sunucusuna erişilemiyor.")
            else:
                if self.forticlient_window_shown or not was_vpn:
                    self.logla("VPN bağlantısı tekrar sağlandı.")
                if not was_server:
                    self.flush_local_logs()
                    if not report_status("online"):
                        self.logla("Online durumu sunucuya iletilemedi.")
                    if not report_status("afk" if afk_state else "not-afk"):
                        self.logla("Durum bilgisi sunucuya iletilemedi.")
                self.status_label.setText("Durum: VPN Bağlı")
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
        if not report_status("offline"):
            self.logla("Offline durumu sunucuya iletilemedi.")
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
