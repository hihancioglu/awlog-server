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

from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit, QLabel
from PyQt5.QtGui import QIcon, QTextCursor
from PyQt5.QtCore import pyqtSignal, pyqtSlot

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
    try:
        data['log_type'] = log_type
        data['hostname'] = get_hostname()
        data['username'] = get_username()
        data['secret'] = SECRET
        response = requests.post(f"{SERVER_URL}/api/log", json=data, timeout=2)
        return response.status_code == 200
    except Exception as e:
        return False

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
        cur_start = midnight

    duration = int((end_time - cur_start).total_seconds())
    data = {
        "status": status,
        "start_time": cur_start.isoformat(),
        "end_time": end_time.isoformat(),
        "duration": duration,
    }
    log_queue.put(("status", data))

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
        report_status("not-afk")

def on_key_press(key):
    if key not in pressed_keys:
        pressed_keys.add(key)
        input_event()

def on_key_release(key):
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
            report_status("afk")

        # Pencere değişimi kontrolü
        current_window, current_process = get_active_window_info()
        if current_window != prev_window or current_process != prev_process:
            log_window_period(prev_window, prev_process, window_period_start, now)
            prev_window = current_window
            prev_process = current_process
            window_period_start = now

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
    data = {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
        "ip": get_ip(),
        "status": status,
        "secret": SECRET
    }
    try:
        r = requests.post(f"{SERVER_URL}/report", json=data, timeout=5)
    except Exception: pass

def server_accessible(attempts=2, delay=2):
    """Check if server is reachable with multiple attempts."""
    for i in range(attempts):
        try:
            r = requests.get(SERVER_URL, timeout=5)
            if r.status_code in (200, 404):
                return True
        except Exception:
            pass
        if i < attempts - 1:
            time.sleep(delay)
    return False

class MainWindow(QWidget):
    append_log = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Evden Çalışma Kontrol Paneli")
        # İKON tanımı (hem scriptte hem exe'de çalışır)
        if hasattr(sys, "_MEIPASS"):
            icon_path = os.path.join(sys._MEIPASS, "remote-work-icon.ico")
        else:
            icon_path = "remote-work-icon.ico"
        self.setWindowIcon(QIcon(icon_path))
        self.resize(480, 380)

        self.basla_btn = QPushButton("Başla")
        self.basla_btn.clicked.connect(self.baslat)
        self.bitir_btn = QPushButton("Bitir")
        self.bitir_btn.clicked.connect(self.bitir)
        self.bitir_btn.setEnabled(False)
        self.status_label = QLabel("Durum: Bekleniyor...")
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.basla_btn)
        layout.addWidget(self.bitir_btn)
        layout.addWidget(self.status_label)
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

    def logla(self, text):
        self.append_log.emit(text)

    @pyqtSlot(str)
    def _append_log(self, text):
        self.log.append(text)
        self.log.moveCursor(QTextCursor.End)  # Oto-scroll

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

        if server_accessible():
            self.status_label.setText("Durum: VPN Bağlı")
            self.logla("VPN zaten bağlı, FortiClient başlatılmayacak.")
        else:
            self.status_label.setText("Durum: VPN Bağlantısı Yok")
            self.logla("VPN yok. FortiClient başlatılıyor...")
            if not is_forticlient_running():
                start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                self.logla("FortiClient penceresi açıldı.")
            else:
                self.logla("FortiClient zaten açık.")
            while not server_accessible() and self.active:
                self.status_label.setText("Durum: VPN Bağlantısı Bekleniyor...")
                self.logla("VPN bağlantısı bekleniyor...")
                for _ in range(3):
                    if not self.active:
                        return
                    time.sleep(1)
        if not self.active: return
        report_status("online")
        report_status("not-afk")
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
                if not send_log_to_server(log_type, data):
                    # Local dosyada tut, örnek amaçlı
                    with open(LOG_PATH, "a", encoding="utf-8") as f:
                        f.write(json.dumps(data, ensure_ascii=False) + "\n")
                # Sunucuya iletimin başarılı olduğunu kullanıcı arayüzünde
                # göstermek gereksiz, bu yüzden ek loglama yapılmaz
            except queue.Empty:
                continue
            except Exception as e:
                self.logla(f"Log gönderim hatası: {e}")

    def keepalive(self):
        while self.active:
            for _ in range(120):  # 120 saniye = 2 dk
                if not self.active:
                    return
                time.sleep(1)
            if not self.active:
                return
            report_status("keepalive")
            self.logla("Keepalive gönderildi.")

    def vpn_monitor(self):
        self.forticlient_window_shown = False
        was_online = server_accessible()
        while self.active:
            for _ in range(CHECK_INTERVAL):
                if not self.active:
                    return
                time.sleep(1)
            if not self.active:
                return
            online = server_accessible()
            if not online:
                self.status_label.setText("Durum: VPN KOPUK! Bağlantı bekleniyor...")
                if not self.forticlient_window_shown:
                    if not is_forticlient_running():
                        start_forticlient_admin(FORTICLIENT_CONSOLE_PATH)
                        self.logla("FortiClient penceresi açıldı.")
                    else:
                        self.logla("FortiClient zaten açık.")
                    self.forticlient_window_shown = True
                self.logla("VPN KOPUK. Bağlantı bekleniyor...")
            else:
                if self.forticlient_window_shown or not was_online:
                    self.logla("VPN bağlantısı tekrar sağlandı.")
                self.status_label.setText("Durum: VPN Bağlı")
                self.forticlient_window_shown = False
            was_online = online

    def cleanup(self):
        global afk_state, afk_period_start, notafk_period_start

        now = datetime.now()
        if afk_state:
            log_status_period(afk_period_start, now, "afk")
        else:
            log_status_period(notafk_period_start, now, "not-afk")

        self.active = False
        report_status("offline")
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
