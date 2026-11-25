#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import queue
import re
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.parse import urlparse

APP_NAME = "Proxy Checker Pro"
APP_VER = "1.0"

C = dict(
    bg="#0f1419", panel="#171d26", card="#1e2632", line="#2a3444",
    fg="#e6edf3", muted="#8b98a9", accent="#4f8cff", accent2="#3a6fd8",
    good="#3ddc84", bad="#ff5c6c", dead="#c4616d", warn="#ffb454",
)

TEST_URLS = [
    "http://ip-api.com/json/?fields=status,country,countryCode,query",
    "http://httpbin.org/ip",
    "http://www.gstatic.com/generate_204"
]


# ════════════════════════════════════════════════════════════════════
#  Proxy ayrıştırma
# ════════════════════════════════════════════════════════════════════
SCHEMES = {
    "http": "HTTP", "https": "HTTP",
    "socks4": "SOCKS4", "socks4a": "SOCKS4",
    "socks5": "SOCKS5", "socks5h": "SOCKS5",
}
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")


def parse_proxy(line):
    """
    Desteklenen biçimler:
      ip:port
      ip:port:kullanıcı:şifre
      kullanıcı:şifre@ip:port
      şema://ip:port  /  şema://kullanıcı:şifre@ip:port   (http, socks4, socks5)
    """
    s = line.strip()
    scheme = None
    m = re.match(r"^([a-z0-9]+)://(.+)$", s, re.I)
    if m:
        scheme = SCHEMES.get(m.group(1).lower())
        if not scheme:
            return None
        s = m.group(2)
    s = s.rstrip("/")

    user = pw = None
    if "@" in s:
        cred, s = s.rsplit("@", 1)
        user, _, pw = cred.partition(":")
        parts = s.split(":")
        if len(parts) != 2:
            return None
        host, port = parts
    else:
        parts = s.split(":")
        if len(parts) == 2:
            host, port = parts
        elif len(parts) == 4:
            host, port, user, pw = parts
        else:
            return None

    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return None
    if not _HOST_RE.match(host):
        return None
    port = int(port)
    return dict(
        host=host, port=port, user=user or None, pw=(pw if user else None),
        scheme=scheme, display=f"{host}:{port}", key=(host, port, user, pw),
    )


# ════════════════════════════════════════════════════════════════════
#  Ağ katmanı (harici kütüphane yok)
# ════════════════════════════════════════════════════════════════════
class ProxyError(Exception):
    def __init__(self, msg, stage="proxy"):
        super().__init__(msg)
        self.stage = stage          # "connect" => proxy'ye TCP bağlantısı kurulamadı


def err_text(e):
    if isinstance(e, ProxyError):
        return str(e)
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "Zaman aşımı"
    if isinstance(e, ConnectionRefusedError):
        return "Bağlantı reddedildi"
    if isinstance(e, ConnectionResetError):
        return "Bağlantı sıfırlandı"
    if isinstance(e, socket.gaierror):
        return "DNS çözülemedi"
    if isinstance(e, OSError):
        return (e.strerror or str(e))[:40]
    return type(e).__name__


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyError("Bağlantı beklenmedik şekilde kapandı")
        buf += chunk
    return buf


SOCKS5_ERRORS = {
    1: "SOCKS5 genel hata", 2: "Kural tarafından engellendi", 3: "Ağ erişilemiyor",
    4: "Hedef erişilemiyor", 5: "Bağlantı reddedildi", 6: "TTL doldu",
    7: "Komut desteklenmiyor", 8: "Adres türü desteklenmiyor",
}


def socks5_connect(sock, p, host, port):
    methods = b"\x00\x02" if p["user"] else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    r = recv_exact(sock, 2)
    if r[0] != 5:
        raise ProxyError("SOCKS5 değil")
    if r[1] == 0x02:
        if not p["user"]:
            raise ProxyError("Kimlik doğrulama gerekli")
        u = p["user"].encode()
        w = (p["pw"] or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
        if recv_exact(sock, 2)[1] != 0:
            raise ProxyError("Kimlik doğrulama başarısız")
    elif r[1] == 0xFF:
        raise ProxyError("Kimlik doğrulama gerekli")
    elif r[1] != 0x00:
        raise ProxyError("Desteklenmeyen doğrulama yöntemi")

    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    hdr = recv_exact(sock, 4)
    if hdr[1] != 0:
        raise ProxyError(SOCKS5_ERRORS.get(hdr[1], f"SOCKS5 hata {hdr[1]}"))
    atyp = hdr[3]
    if atyp == 1:
        recv_exact(sock, 6)
    elif atyp == 3:
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)
    elif atyp == 4:
        recv_exact(sock, 18)


def socks4_connect(sock, p, host, port):
    ip = socket.inet_aton(socket.gethostbyname(host))
    uid = (p["user"] or "").encode()
    sock.sendall(b"\x04\x01" + struct.pack(">H", port) + ip + uid + b"\x00")
    r = recv_exact(sock, 8)
    if r[0] != 0 or r[1] != 0x5A:
        raise ProxyError("SOCKS4 isteği reddedildi")


def http_get(sock, u, via_http_proxy, auth_b64):
    target = u.geturl() if via_http_proxy else ((u.path or "/") + (f"?{u.query}" if u.query else ""))
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {u.netloc}",
        "User-Agent: Mozilla/5.0 (ProxyChecker)",
        "Accept: */*",
        "Connection: close",
    ]
    if via_http_proxy and auth_b64:
        lines.append(f"Proxy-Authorization: Basic {auth_b64}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    data = b""
    while len(data) < 65536:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if data:
                break
            raise
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
    if not m:
        raise ProxyError("Geçersiz HTTP yanıtı")
    return int(m.group(1)), body


def parse_info(body):
    info = {"ip": "-", "country": "-"}
    txt = body.decode("utf-8", "ignore")
    a, b = txt.find("{"), txt.rfind("}")
    if a != -1 and b > a:
        try:
            d = json.loads(txt[a:b + 1])
            ip = d.get("query") or d.get("origin")
            if ip:
                info["ip"] = str(ip).split(",")[0].strip()
            c, cc = d.get("country"), d.get("countryCode")
            if c:
                info["country"] = f"{c} ({cc})" if cc else str(c)
        except ValueError:
            pass
    return info


def probe(p, ptype, timeout, u):
    host, port = u.hostname, (u.port or 80)
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((p["host"], p["port"]), timeout=timeout)
    except Exception as e:
        raise ProxyError(err_text(e), "connect")
    try:
        sock.settimeout(timeout)
        if ptype == "HTTP":
            auth = None
            if p["user"]:
                auth = base64.b64encode(f'{p["user"]}:{p["pw"] or ""}'.encode()).decode()
            status, body = http_get(sock, u, True, auth)
        else:
            if ptype == "SOCKS5":
                socks5_connect(sock, p, host, port)
            else:
                socks4_connect(sock, p, host, port)
            status, body = http_get(sock, u, False, None)
        ping = int((time.perf_counter() - t0) * 1000)
        if status == 407:
            raise ProxyError("Kimlik doğrulama gerekli")
        if not 200 <= status < 300:
            raise ProxyError(f"HTTP {status}")
        return ping, parse_info(body)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_proxy(p, mode, timeout, u):
    if mode == "Otomatik":
        types = [p["scheme"]] if p["scheme"] else ["HTTP", "SOCKS5", "SOCKS4"]
    else:
        types = [mode]

    res = dict(
        proxy=p["display"], raw=p, type=types[0] if len(types) == 1 else "-",
        alive=False, ping=None, country="-", ip="-", detail="",
    )
    for t in types:
        try:
            ping, info = probe(p, t, timeout, u)
            res.update(type=t, alive=True, ping=ping, country=info["country"],
                       ip=info["ip"], detail="OK")
            return res
        except Exception as e:                       # noqa: BLE001
            res["detail"] = err_text(e)
            if getattr(e, "stage", "") == "connect":
                break                                # TCP bile kurulamıyorsa diğer türleri deneme
    return res


# ════════════════════════════════════════════════════════════════════
#  Açılış ekranı
# ════════════════════════════════════════════════════════════════════
class Splash:
    W, H = 480, 280
    DURATION = 2600  # ms
    MESSAGES = [
        (0, "Başlatılıyor…"), (15, "Modüller yükleniyor…"),
        (35, "Arayüz hazırlanıyor…"), (60, "Ağ yığını başlatılıyor…"),
        (80, "Tema uygulanıyor…"), (95, "Son kontroller yapılıyor…"),
        (100, "Hazır!"),
    ]

    def __init__(self, root, hooks, on_done):
        self.root, self.on_done = root, on_done
        self.hooks = sorted(hooks, key=lambda h: h[0])
        w = self.win = tk.Toplevel(root)
        w.overrideredirect(True)
        w.configure(bg=C["bg"])
        x = (w.winfo_screenwidth() - self.W) // 2
        y = (w.winfo_screenheight() - self.H) // 2
        w.geometry(f"{self.W}x{self.H}+{x}+{y}")
        self._alpha(0.0)
        try:
            w.attributes("-topmost", True)
        except tk.TclError:
            pass

        cv = self.cv = tk.Canvas(w, width=self.W, height=self.H, bg=C["bg"],
                                 highlightthickness=1, highlightbackground=C["line"])
        cv.pack()
        cx = self.W // 2
        cv.create_text(cx, 62, text="PROXY CHECKER", fill=C["fg"], font=("Segoe UI", 26, "bold"))
        cv.create_text(cx, 96, text="Hızlı  •  Çok iş parçacıklı  •  Bağımlılıksız",
                       fill=C["muted"], font=("Segoe UI", 10))
        self.arc = cv.create_arc(cx - 18, 118, cx + 18, 154, start=0, extent=100,
                                 style="arc", outline=C["accent"], width=4)
        self.bx0, self.bx1, self.by = 60, self.W - 60, 200
        cv.create_rectangle(self.bx0, self.by, self.bx1, self.by + 6, fill=C["card"], outline="")
        self.fill = cv.create_rectangle(self.bx0, self.by, self.bx0, self.by + 6, fill=C["accent"], outline="")
        self.msg = cv.create_text(self.bx0, 228, anchor="w", text="", fill=C["muted"], font=("Segoe UI", 10))
        self.pct = cv.create_text(self.bx1, 228, anchor="e", text="0%", fill=C["fg"], font=("Segoe UI", 10, "bold"))
        cv.create_text(cx, 262, text=f"v{APP_VER}", fill=C["line"], font=("Segoe UI", 8))

        self.t0 = time.perf_counter()
        self.tick()

    def _alpha(self, a):
        try:
            self.win.attributes("-alpha", max(0.0, min(1.0, a)))
        except tk.TclError:
            pass

    def tick(self):
        el = (time.perf_counter() - self.t0) * 1000
        x = min(el / self.DURATION, 1.0)
        p = 100 * (x * x * (3 - 2 * x))          # smoothstep
        while self.hooks and p >= self.hooks[0][0]:
            self.hooks.pop(0)[1]()
        self.cv.coords(self.fill, self.bx0, self.by,
                       self.bx0 + (self.bx1 - self.bx0) * p / 100, self.by + 6)
        self.cv.itemconfigure(self.arc, start=(el * 0.45) % 360)
        self.cv.itemconfigure(self.pct, text=f"{int(p)}%")
        text = [m for t, m in self.MESSAGES if t <= p][-1]
        self.cv.itemconfigure(self.msg, text=text)
        self._alpha(el / 300)
        if x >= 1.0:
            while self.hooks:
                self.hooks.pop(0)[1]()
            self.win.after(350, self.fade_out)
        else:
            self.win.after(16, self.tick)

    def fade_out(self, a=1.0):
        a -= 0.14
        if a <= 0:
            self.win.destroy()
            self.on_done()
            return
        self._alpha(a)
        self.win.after(16, lambda: self.fade_out(a))


# ════════════════════════════════════════════════════════════════════
#  Ana uygulama
# ════════════════════════════════════════════════════════════════════
def fmt_time(sec):
    if sec is None or sec != sec or sec == float("inf"):
        return "-"
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


SORT_KEYS = {
    "n": lambda r: r["n"],
    "proxy": lambda r: r["proxy"],
    "type": lambda r: r["type"],
    "status": lambda r: not r["alive"],
    "ping": lambda r: (r["ping"] is None, r["ping"] or 0),
    "country": lambda r: r["country"],
    "ip": lambda r: r["ip"],
    "detail": lambda r: r["detail"],
}


class App:
    COLS = (
        ("n", "#", 55, "center"), ("proxy", "Proxy", 190, "w"), ("type", "Tür", 75, "center"),
        ("status", "Durum", 95, "center"), ("ping", "Gecikme", 90, "center"),
        ("country", "Ülke", 170, "w"), ("ip", "Çıkış IP", 130, "w"), ("detail", "Detay", 220, "w"),
    )

    def __init__(self, root):
        self.root = root
        self.proxies = []
        self.results = []
        self.iid_map = {}
        self.res_q = queue.Queue()
        self.stop_evt = threading.Event()
        self.running = False
        self.n_workers = 0
        self.done_workers = 0
        self.n_alive = self.n_dead = 0
        self.counter = 0
        self.t_start = 0.0
        self.t_elapsed = 0.0
        self.sort_col, self.sort_rev = None, False
        self.ui_ready = False

    # ── Stil ────────────────────────────────────────────────────────
    def setup_style(self):
        r = self.root
        r.configure(bg=C["bg"])
        r.option_add("*TCombobox*Listbox.background", C["panel"])
        r.option_add("*TCombobox*Listbox.foreground", C["fg"])
        r.option_add("*TCombobox*Listbox.selectBackground", C["accent2"])
        r.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        r.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))

        s = ttk.Style(r)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["panel"],
                    bordercolor=C["line"], lightcolor=C["card"], darkcolor=C["card"],
                    troughcolor=C["panel"], focuscolor=C["card"], font=("Segoe UI", 10))
        s.configure("TFrame", background=C["bg"])
        s.configure("Card.TFrame", background=C["card"])
        s.configure("TLabel", background=C["bg"], foreground=C["fg"])
        s.configure("Card.TLabel", background=C["card"], foreground=C["fg"])
        s.configure("Muted.TLabel", background=C["card"], foreground=C["muted"])
        s.configure("Sub.TLabel", background=C["bg"], foreground=C["muted"])
        s.configure("Title.TLabel", background=C["bg"], font=("Segoe UI", 20, "bold"))
        for name, col in (("Stat", C["fg"]), ("StatGood", C["good"]), ("StatBad", C["bad"]),
                          ("StatAccent", C["accent"])):
            s.configure(f"{name}.TLabel", background=C["card"], foreground=col,
                        font=("Segoe UI", 17, "bold"))

        s.configure("TButton", background=C["line"], foreground=C["fg"], padding=(14, 7),
                    borderwidth=0, relief="flat")
        s.map("TButton", background=[("disabled", C["panel"]), ("active", "#364257")],
              foreground=[("disabled", C["muted"])])
        s.configure("Accent.TButton", background=C["accent"], foreground="#ffffff")
        s.map("Accent.TButton", background=[("disabled", C["line"]), ("active", C["accent2"])],
              foreground=[("disabled", C["muted"])])
        s.configure("Danger.TButton", background=C["bad"], foreground="#ffffff")
        s.map("Danger.TButton", background=[("disabled", C["line"]), ("active", "#d94555")],
              foreground=[("disabled", C["muted"])])

        s.configure("Card.TCheckbutton", background=C["card"], foreground=C["fg"])
        s.map("Card.TCheckbutton", background=[("active", C["card"])],
              indicatorcolor=[("selected", C["accent"]), ("!selected", C["panel"])])

        s.configure("TCombobox", fieldbackground=C["panel"], background=C["line"], foreground=C["fg"],
                    arrowcolor=C["fg"], bordercolor=C["line"], padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", C["panel"])],
              foreground=[("readonly", C["fg"])],
              selectbackground=[("readonly", C["panel"])],
              selectforeground=[("readonly", C["fg"])])
        s.configure("TSpinbox", fieldbackground=C["panel"], background=C["line"], foreground=C["fg"],
                    arrowcolor=C["fg"], bordercolor=C["line"], padding=4)

        s.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["fg"],
                    rowheight=26, borderwidth=0)
        s.map("Treeview", background=[("selected", C["accent2"])], foreground=[("selected", "#ffffff")])
        s.configure("Treeview.Heading", background=C["card"], foreground=C["fg"], relief="flat",
                    padding=(8, 7), font=("Segoe UI", 10, "bold"))
        s.map("Treeview.Heading", background=[("active", C["line"])])
        s.configure("Vertical.TScrollbar", background=C["line"], troughcolor=C["panel"],
                    bordercolor=C["panel"], arrowcolor=C["muted"])
        s.configure("Pro.Horizontal.TProgressbar", troughcolor=C["panel"], background=C["accent"],
                    bordercolor=C["panel"], lightcolor=C["accent"], darkcolor=C["accent"])

    # ── Arayüz ──────────────────────────────────────────────────────
    def build_ui(self):
        r = self.root
        r.title(f"{APP_NAME} v{APP_VER}")
        r.geometry("1040x720")
        r.minsize(920, 620)
        r.protocol("WM_DELETE_WINDOW", self.on_close)

        self.var_mode = tk.StringVar(value="Otomatik")
        self.var_threads = tk.StringVar(value="100")
        self.var_timeout = tk.StringVar(value="8")
        self.var_url = tk.StringVar(value=TEST_URLS[0])
        self.var_only_alive = tk.BooleanVar(value=False)
        self.var_prefix = tk.BooleanVar(value=False)
        self.var_status = tk.StringVar(value="Hazır. Bir proxy dosyası seçerek başlayın.")
        self.var_file = tk.StringVar(value="Dosya seçilmedi")
        self.stat = {k: tk.StringVar(value="0") for k in ("total", "done", "alive", "dead", "speed")}
        self.stat["eta"] = tk.StringVar(value="-")
        self.var_pct = tk.StringVar(value="0%")

        outer = ttk.Frame(r, padding=(18, 14, 18, 8))
        outer.pack(fill="both", expand=True)

        # Başlık
        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text="Proxy Checker", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text=f"   v{APP_VER}  •  HTTP / SOCKS4 / SOCKS5", style="Sub.TLabel").pack(
            side="left", pady=(10, 0))
        ttk.Label(head, textvariable=self.var_file, style="Sub.TLabel").pack(side="right", pady=(10, 0))

        # Kontrol kartı
        ctl = ttk.Frame(outer, style="Card.TFrame", padding=14)
        ctl.pack(fill="x", pady=(12, 8))

        row1 = ttk.Frame(ctl, style="Card.TFrame")
        row1.pack(fill="x")
        self.btn_open = ttk.Button(row1, text="Dosya Seç…", style="Accent.TButton", command=self.choose_file)
        self.btn_paste = ttk.Button(row1, text="Panodan Yükle", command=self.paste_clip)
        self.btn_clear = ttk.Button(row1, text="Temizle", command=self.clear_all)
        self.btn_open.pack(side="left")
        self.btn_paste.pack(side="left", padx=(8, 0))
        self.btn_clear.pack(side="left", padx=(8, 0))
        self.btn_stop = ttk.Button(row1, text="■  Durdur", style="Danger.TButton", command=self.stop,
                                   state="disabled")
        self.btn_start = ttk.Button(row1, text="▶  Başlat", style="Accent.TButton", command=self.start)
        self.btn_stop.pack(side="right")
        self.btn_start.pack(side="right", padx=(0, 8))

        row2 = ttk.Frame(ctl, style="Card.TFrame")
        row2.pack(fill="x", pady=(12, 0))
        ttk.Label(row2, text="Tür", style="Muted.TLabel").pack(side="left")
        ttk.Combobox(row2, textvariable=self.var_mode, state="readonly", width=10,
                     values=["Otomatik", "HTTP", "SOCKS4", "SOCKS5"]).pack(side="left", padx=(6, 16))
        ttk.Label(row2, text="Thread", style="Muted.TLabel").pack(side="left")
        ttk.Spinbox(row2, textvariable=self.var_threads, from_=1, to=1000, width=6).pack(
            side="left", padx=(6, 16))
        ttk.Label(row2, text="Zaman aşımı (sn)", style="Muted.TLabel").pack(side="left")
        ttk.Spinbox(row2, textvariable=self.var_timeout, from_=1, to=60, width=5).pack(
            side="left", padx=(6, 16))
        ttk.Label(row2, text="Test URL", style="Muted.TLabel").pack(side="left")
        ttk.Combobox(row2, textvariable=self.var_url, values=TEST_URLS).pack(
            side="left", padx=(6, 0), fill="x", expand=True)

        row3 = ttk.Frame(ctl, style="Card.TFrame")
        row3.pack(fill="x", pady=(12, 0))
        ttk.Checkbutton(row3, text="Sadece çalışanları göster", variable=self.var_only_alive,
                        style="Card.TCheckbutton", command=self.render).pack(side="left")
        ttk.Checkbutton(row3, text="Kaydederken tür öneki ekle (socks5://…)", variable=self.var_prefix,
                        style="Card.TCheckbutton").pack(side="left", padx=(16, 0))
        self.btn_save = ttk.Button(row3, text="Çalışanları Kaydet…", command=self.save_alive)
        self.btn_save.pack(side="right")

        # İstatistikler
        stats = ttk.Frame(outer)
        stats.pack(fill="x", pady=(0, 8))
        defs = [("total", "Toplam", "Stat"), ("done", "Kontrol edilen", "Stat"),
                ("alive", "Çalışan", "StatGood"), ("dead", "Ölü", "StatBad"),
                ("speed", "Hız (/sn)", "StatAccent"), ("eta", "Kalan süre", "Stat")]
        for i, (key, title, style) in enumerate(defs):
            stats.columnconfigure(i, weight=1, uniform="st")
            card = ttk.Frame(stats, style="Card.TFrame", padding=(14, 8))
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            ttk.Label(card, textvariable=self.stat[key], style=f"{style}.TLabel").pack(anchor="w")
            ttk.Label(card, text=title, style="Muted.TLabel").pack(anchor="w")

        # İlerleme çubuğu
        prog = ttk.Frame(outer)
        prog.pack(fill="x", pady=(0, 8))
        self.pbar = ttk.Progressbar(prog, style="Pro.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.pbar.pack(side="left", fill="x", expand=True)
        ttk.Label(prog, textvariable=self.var_pct, width=6, anchor="e").pack(side="left", padx=(8, 0))

        # Sonuç tablosu
        box = ttk.Frame(outer)
        box.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(box, columns=[c[0] for c in self.COLS], show="headings",
                                 selectmode="extended")
        for cid, title, width, anchor in self.COLS:
            self.tree.heading(cid, text=title, command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=width, anchor=anchor, stretch=(cid == "detail"))
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("alive", foreground=C["good"])
        self.tree.tag_configure("dead", foreground=C["dead"])

        # Sağ tık menüsü
        self.menu = tk.Menu(r, tearoff=0, bg=C["card"], fg=C["fg"], activebackground=C["accent2"],
                            activeforeground="#ffffff", bd=0)
        self.menu.add_command(label="Seçili proxy'leri kopyala", command=self.copy_selected)
        self.menu.add_command(label="Sadece çalışanları kopyala", command=lambda: self.copy_selected(True))
        self.tree.bind("<Button-3>", self.popup)
        self.tree.bind("<Button-2>", self.popup)
        self.tree.bind("<Control-c>", lambda e: self.copy_selected())
        self.tree.bind("<Double-1>", lambda e: self.copy_selected())

        # Durum çubuğu
        ttk.Label(outer, textvariable=self.var_status, style="Sub.TLabel").pack(fill="x", pady=(8, 0))
        self.ui_ready = True

    def show(self):
        if not self.ui_ready:
            self.setup_style()
            self.build_ui()
        r = self.root
        r.update_idletasks()
        w, h = r.winfo_width(), r.winfo_height()
        x = (r.winfo_screenwidth() - w) // 2
        y = max(0, (r.winfo_screenheight() - h) // 2 - 20)
        r.geometry(f"+{x}+{y}")
        r.deiconify()
        r.lift()
        r.focus_force()

    # ── Proxy yükleme ───────────────────────────────────────────────
    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Proxy listesi seç",
            filetypes=[("Metin dosyaları", "*.txt *.lst *.list *.csv"), ("Tüm dosyalar", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
                text = f.read()
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Dosya okunamadı:\n{e}")
            return
        name = path.replace("\\", "/").split("/")[-1]
        self.load_text(text, name)

    def paste_clip(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showinfo(APP_NAME, "Panoda metin bulunamadı.")
            return
        self.load_text(text, "Pano")

    def load_text(self, text, source):
        seen, good, bad, dup = set(), [], 0, 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = parse_proxy(line.split()[0])
            if not p:
                bad += 1
                continue
            if p["key"] in seen:
                dup += 1
                continue
            seen.add(p["key"])
            good.append(p)
        if not good:
            messagebox.showwarning(APP_NAME, "Geçerli proxy bulunamadı.\n\nBeklenen biçim: ip:port")
            return
        self.proxies = good
        self.reset_results()
        self.var_file.set(f"{source}  •  {len(good):,} proxy")
        self.stat["total"].set(f"{len(good):,}")
        self.var_status.set(f"{len(good):,} proxy yüklendi  (geçersiz: {bad}, tekrar: {dup}). "
                            f"Başlat'a basarak kontrol edebilirsiniz.")

    def clear_all(self):
        self.proxies = []
        self.reset_results()
        self.var_file.set("Dosya seçilmedi")
        self.stat["total"].set("0")
        self.var_status.set("Liste temizlendi.")

    def reset_results(self):
        self.results = []
        self.iid_map.clear()
        self.tree.delete(*self.tree.get_children())
        self.n_alive = self.n_dead = self.counter = 0
        self.t_elapsed = 0.0
        self.sort_col, self.sort_rev = None, False
        self.update_headings()
        for k in ("done", "alive", "dead", "speed"):
            self.stat[k].set("0")
        self.stat["eta"].set("-")
        self.pbar["value"] = 0
        self.var_pct.set("0%")

    # ── Kontrol ─────────────────────────────────────────────────────
    def start(self):
        if self.running:
            return
        if not self.proxies:
            messagebox.showinfo(APP_NAME, "Önce bir proxy dosyası seçin.")
            return
        try:
            threads = int(self.var_threads.get())
            timeout = float(self.var_timeout.get().replace(",", "."))
        except ValueError:
            messagebox.showerror(APP_NAME, "Thread ve zaman aşımı sayısal olmalı.")
            return
        threads = max(1, min(threads, 1000))
        timeout = max(1.0, min(timeout, 60.0))

        u = urlparse(self.var_url.get().strip())
        if u.scheme != "http" or not u.hostname:
            messagebox.showerror(APP_NAME, "Test URL'si http:// ile başlamalı.\nÖrnek: http://httpbin.org/ip")
            return

        self.reset_results()
        self.stop_evt = threading.Event()
        self.res_q = queue.Queue()
        work_q = queue.Queue()
        for p in self.proxies:
            work_q.put(p)

        mode = self.var_mode.get()
        self.n_workers = min(threads, len(self.proxies))
        self.done_workers = 0
        for _ in range(self.n_workers):
            threading.Thread(target=self.worker, daemon=True,
                             args=(work_q, self.res_q, self.stop_evt, mode, timeout, u)).start()

        self.running = True
        self.t_start = time.perf_counter()
        self.set_running_ui(True)
        self.var_status.set(f"Kontrol ediliyor…  ({self.n_workers} thread, {timeout:g} sn zaman aşımı)")
        self.root.after(100, self.poll)

    @staticmethod
    def worker(work_q, res_q, stop_evt, mode, timeout, u):
        try:
            while not stop_evt.is_set():
                try:
                    p = work_q.get_nowait()
                except queue.Empty:
                    break
                try:
                    res_q.put(check_proxy(p, mode, timeout, u))
                except Exception as e:           # noqa: BLE001
                    res_q.put(dict(proxy=p["display"], raw=p, type="-", alive=False, ping=None,
                                   country="-", ip="-", detail=err_text(e)))
        finally:
            res_q.put(None)                      # bu worker bitti

    def stop(self):
        if self.running:
            self.stop_evt.set()
            self.btn_stop.state(["disabled"])
            self.var_status.set("Durduruluyor… (devam eden istekler bekleniyor)")

    def poll(self):
        n = 0
        while n < 400:
            try:
                item = self.res_q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self.done_workers += 1
                continue
            n += 1
            self.counter += 1
            item["n"] = self.counter
            self.results.append(item)
            if item["alive"]:
                self.n_alive += 1
            else:
                self.n_dead += 1
            if self.passes(item):
                self.insert_row(item)

        self.update_stats()
        if self.done_workers >= self.n_workers:
            self.finish()
        else:
            self.root.after(100, self.poll)

    def update_stats(self):
        done = self.n_alive + self.n_dead
        total = len(self.proxies)
        if self.running:
            self.t_elapsed = time.perf_counter() - self.t_start
        speed = done / self.t_elapsed if self.t_elapsed > 0 else 0
        remaining = (total - done) / speed if speed > 0 and self.running and not self.stop_evt.is_set() else None
        self.stat["done"].set(f"{done:,}")
        self.stat["alive"].set(f"{self.n_alive:,}")
        self.stat["dead"].set(f"{self.n_dead:,}")
        self.stat["speed"].set(f"{speed:.1f}")
        self.stat["eta"].set(fmt_time(remaining) if self.running else fmt_time(self.t_elapsed))
        pct = (done / total * 100) if total else 0
        self.pbar["value"] = pct
        self.var_pct.set(f"{pct:.0f}%")

    def finish(self):
        self.running = False
        self.set_running_ui(False)
        self.update_stats()
        done = self.n_alive + self.n_dead
        if self.stop_evt.is_set() and done < len(self.proxies):
            self.var_status.set(f"Durduruldu: {done:,}/{len(self.proxies):,} kontrol edildi, "
                                f"{self.n_alive:,} çalışan.")
        else:
            self.var_status.set(f"Tamamlandı: {self.n_alive:,} çalışan / {len(self.proxies):,} proxy  "
                                f"({fmt_time(self.t_elapsed)} sürdü).")

    def set_running_ui(self, running):
        st = "disabled" if running else "!disabled"
        for b in (self.btn_open, self.btn_paste, self.btn_clear, self.btn_start):
            b.state([st])
        self.btn_stop.state(["!disabled" if running else "disabled"])

    # ── Tablo ───────────────────────────────────────────────────────
    def passes(self, r):
        return r["alive"] or not self.var_only_alive.get()

    def insert_row(self, r):
        ping = f'{r["ping"]} ms' if r["ping"] is not None else "-"
        iid = self.tree.insert("", "end", tags=("alive" if r["alive"] else "dead",), values=(
            r["n"], r["proxy"], r["type"], "Çalışıyor" if r["alive"] else "Ölü",
            ping, r["country"], r["ip"], r["detail"]))
        self.iid_map[iid] = r

    def render(self):
        self.tree.delete(*self.tree.get_children())
        self.iid_map.clear()
        for r in self.results:
            if self.passes(r):
                self.insert_row(r)

    def sort_by(self, col):
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        self.results.sort(key=SORT_KEYS[col], reverse=self.sort_rev)
        self.render()
        self.update_headings()

    def update_headings(self):
        for cid, title, *_ in self.COLS:
            arrow = ""
            if cid == self.sort_col:
                arrow = "  ▼" if self.sort_rev else "  ▲"
            self.tree.heading(cid, text=title + arrow)

    # ── Kopyala / Kaydet ────────────────────────────────────────────
    @staticmethod
    def fmt_proxy(r, prefix):
        p = r["raw"]
        s = f'{p["host"]}:{p["port"]}'
        if p["user"]:
            s = f'{p["user"]}:{p["pw"] or ""}@{s}'
        if prefix and r["alive"]:
            s = f'{r["type"].lower()}://{s}'
        return s

    def popup(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def copy_selected(self, only_alive=False):
        rows = [self.iid_map[i] for i in self.tree.selection() if i in self.iid_map]
        if only_alive:
            rows = [r for r in rows if r["alive"]]
        if not rows:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.fmt_proxy(r, False) for r in rows))
        self.var_status.set(f"{len(rows)} proxy panoya kopyalandı.")

    def save_alive(self):
        alive = sorted((r for r in self.results if r["alive"]), key=lambda r: r["ping"])
        if not alive:
            messagebox.showinfo(APP_NAME, "Kaydedilecek çalışan proxy yok.")
            return
        path = filedialog.asksaveasfilename(
            title="Çalışan proxy'leri kaydet", defaultextension=".txt", initialfile="calisan_proxyler.txt",
            filetypes=[("Metin dosyası", "*.txt"), ("Tüm dosyalar", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(self.fmt_proxy(r, self.var_prefix.get()) for r in alive) + "\n")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Kaydedilemedi:\n{e}")
            return
        self.var_status.set(f"{len(alive):,} çalışan proxy kaydedildi (en hızlıdan yavaşa): {path}")

    def on_close(self):
        self.stop_evt.set()
        self.root.destroy()


# ════════════════════════════════════════════════════════════════════
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:                        # noqa: BLE001
            pass
    root = tk.Tk()
    root.withdraw()
    app = App(root)
    Splash(root,
           hooks=[(30, app.setup_style), (55, app.build_ui)],
           on_done=app.show)
    root.mainloop()


if __name__ == "__main__":
    main()
