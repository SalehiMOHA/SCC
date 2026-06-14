import os
import sys
import json
import base64
import struct
import urllib.parse
import subprocess
import socket
import time
import tkinter as tk
from tkinter import ttk
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======================== CONFIGURATION ========================
CONF_DIR   = "conf"
SUB_FILE   = os.path.join(CONF_DIR, "sub.txt")
XRAY_PATH  = os.path.join(CONF_DIR, "xray.exe")
RESULT_DIR = "Result"
OTHERS_DIR = os.path.join(RESULT_DIR, "Others")
LINES_PER_FILE = 10000
TEST_TIMEOUT   = 12
MAX_PARALLEL   = 10
TEST_TARGET    = ("www.gstatic.com", 80)
SAVE_EVERY     = 10
SOCKS_WAIT_SEC = 5

# ======================== UTILITIES ========================

_port_lock = threading.Lock()

def get_free_port():
    with _port_lock:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]


def b64_decode_safe(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def fetch_url(url):
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        text = text.strip()
        prefixes = ("vless://", "vmess://", "ss://", "hy2://",
                    "hysteria2://", "tuic://", "trojan://")
        if any(p in text for p in prefixes):
            return text
        try:
            return b64_decode_safe(text)
        except Exception:
            return text
    except Exception:
        return ""

# ======================== FILTER / DEDUP / RENAME ========================

def filter_lines(lines):
    prefixes = ("vless://", "vmess://", "ss://", "hy2://",
                "hysteria2://", "tuic://", "trojan://")
    return [l.strip() for l in lines if l.strip().startswith(prefixes)]


def _parse_host_port(hp):
    if hp.startswith("["):
        be = hp.index("]")
        return hp[1:be], hp[be + 2:]
    if ":" in hp:
        return hp.rsplit(":", 1)
    return hp, ""


def parse_dedup_key(line):
    try:
        if line.startswith("vmess://"):
            b64 = line[8:].split("#")[0].replace("\n", "").replace("\r", "")
            cfg = json.loads(b64_decode_safe(b64))
            return (cfg.get("add", ""), str(cfg.get("port", "")), cfg.get("net", ""))
        main = line.split("#")[0]
        rest = main.split("://", 1)[1]
        if "?" in rest:
            before_q, qs = rest.split("?", 1)
            type_val = urllib.parse.parse_qs(qs).get("type", [""])[0]
        else:
            before_q = rest
            type_val = ""
        hp = before_q.rsplit("@", 1)[-1] if "@" in before_q else before_q
        ip, port = _parse_host_port(hp)
        return (ip, port, type_val)
    except Exception:
        return None


def remove_duplicates(lines):
    seen, result = set(), []
    for line in lines:
        key = parse_dedup_key(line)
        if key is None or key not in seen:
            if key is not None:
                seen.add(key)
            result.append(line)
    return result


def rename_line(line):
    """Strip remark and add tag — but NOT for vmess (base64 breaks)."""
    if line.startswith("vmess://"):
        return line
    return line.split("#")[0] + "#Long Live Iran"


def get_protocol_category(line):
    """Returns category for file grouping. hy2/hysteria2/tuic grouped as 'hy2' 
       but their link format remains untouched."""
    if line.startswith("vless://"):       return "vless"
    if line.startswith("vmess://"):      return "vmess"
    if line.startswith("ss://"):         return "ss"
    if line.startswith("trojan://"):     return "trojan"
    if line.startswith("hy2://") or \
       line.startswith("hysteria2://") or \
       line.startswith("tuic://"):       return "hy2"
    return None

# ======================== XRAY CONFIG CONVERTERS ========================

def _stream_net(ss, net, q):
    host_h = q.get("host", [""])[0]
    path   = q.get("path", [""])[0]
    if net == "ws":
        w = {}
        if path:   w["path"] = path
        if host_h: w["headers"] = {"Host": host_h}
        ss["wsSettings"] = w
    elif net == "grpc":
        g = {"multiMode": True}
        sn = q.get("serviceName", [""])[0]
        g["serviceName"] = sn or host_h or ""
        ss["grpcSettings"] = g
    elif net == "h2":
        h = {}
        if path:   h["path"] = path
        if host_h: h["host"] = [host_h]
        ss["httpSettings"] = h
    elif net == "kcp":
        k = {"header": {"type": q.get("headerType", ["none"])[0]}}
        seed = q.get("seed", [""])[0]
        if seed: k["seed"] = seed
        ss["kcpSettings"] = k


def vless_to_outbound(link):
    try:
        main = link.split("#")[0]
        p = urllib.parse.urlparse(main)
        q = urllib.parse.parse_qs(p.query)
        uuid = p.username; host = p.hostname; port = p.port or 443
        net  = q.get("type", ["tcp"])[0]
        sec  = q.get("security", ["none"])[0]
        sni  = q.get("sni", [""])[0]
        fp   = q.get("fp", [""])[0]
        flow = q.get("flow", [""])[0]
        pbk  = q.get("pbk", [""])[0]
        sid  = q.get("sid", [""])[0]
        alpn = q.get("alpn", [""])[0]
        host_h = q.get("host", [""])[0]

        user = {"id": uuid, "encryption": "none"}
        if flow: user["flow"] = flow

        ob = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": {"network": net, "security": sec}
        }
        ss = ob["streamSettings"]

        if sec == "tls":
            t = {"allowInsecure": True, "serverName": sni or host_h or host}
            if alpn: t["alpn"] = alpn.split(",")
            if fp:   t["fingerprint"] = fp
            ss["tlsSettings"] = t
        elif sec == "reality":
            r = {"fingerprint": fp or "chrome", "serverName": sni or host_h or host}
            if pbk: r["publicKey"] = pbk
            if sid: r["shortId"] = sid
            ss["realitySettings"] = r

        _stream_net(ss, net, q)
        return ob
    except Exception:
        return None


def vmess_to_outbound(link):
    try:
        b64 = link[8:].split("#")[0].replace("\n", "").replace("\r", "")
        c = json.loads(b64_decode_safe(b64))
        host   = c.get("add", "")
        port   = int(c.get("port", 443))
        uuid   = c.get("id", "")
        aid    = int(c.get("aid", 0))
        scy    = c.get("scy", "auto")
        net    = c.get("net", "tcp")
        htype  = c.get("type", "none")
        host_h = c.get("host", "")
        path   = c.get("path", "")
        tls    = c.get("tls", "")
        sni    = c.get("sni", "")
        alpn   = c.get("alpn", "")
        fp     = c.get("fp", "")

        ob = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port,
                         "users": [{"id": uuid, "alterId": aid, "security": scy}]}]},
            "streamSettings": {"network": net, "security": "none"}
        }
        ss = ob["streamSettings"]

        if tls == "tls":
            ss["security"] = "tls"
            t = {"allowInsecure": True, "serverName": sni or host_h or host}
            if alpn: t["alpn"] = alpn.split(",")
            if fp:   t["fingerprint"] = fp
            ss["tlsSettings"] = t

        if net == "ws":
            w = {}
            if path:   w["path"] = path
            if host_h: w["headers"] = {"Host": host_h}
            ss["wsSettings"] = w
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": host_h, "multiMode": True}
        elif net == "h2":
            h = {}
            if path:   h["path"] = path
            if host_h: h["host"] = [host_h]
            ss["httpSettings"] = h
        elif net == "kcp":
            ss["kcpSettings"] = {"header": {"type": htype}}
        return ob
    except Exception:
        return None


def ss_to_outbound(link):
    try:
        main = link.split("#")[0]
        rest = main[5:]
        if "@" in rest:
            userinfo_b64, hostport = rest.rsplit("@", 1)
            try:
                userinfo = b64_decode_safe(userinfo_b64)
                method, password = userinfo.split(":", 1)
            except Exception:
                if ":" in userinfo_b64:
                    method, password = userinfo_b64.split(":", 1)
                else:
                    return None
        else:
            decoded = b64_decode_safe(rest)
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)

        if "?" in hostport:
            hostport = hostport.split("?", 1)[0]
        host, port_s = _parse_host_port(hostport)
        port = int(port_s) if port_s else 443

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                         "method": method, "password": password}]}
        }
    except Exception:
        return None


def trojan_to_outbound(link):
    try:
        main = link.split("#")[0]
        p = urllib.parse.urlparse(main)
        q = urllib.parse.parse_qs(p.query)
        password = p.username; host = p.hostname; port = p.port or 443
        net    = q.get("type", ["tcp"])[0]
        sec    = q.get("security", ["tls"])[0]
        sni    = q.get("sni", [""])[0]
        alpn   = q.get("alpn", [""])[0]
        fp     = q.get("fp", [""])[0]
        host_h = q.get("host", [""])[0]
        pbk    = q.get("pbk", [""])[0]
        sid    = q.get("sid", [""])[0]

        ob = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port,
                                      "password": password}]},
            "streamSettings": {"network": net, "security": sec}
        }
        ss = ob["streamSettings"]

        if sec == "tls":
            t = {"allowInsecure": True, "serverName": sni or host_h or host}
            if alpn: t["alpn"] = alpn.split(",")
            if fp:   t["fingerprint"] = fp
            ss["tlsSettings"] = t
        elif sec == "reality":
            r = {"fingerprint": fp or "chrome",
                 "serverName": sni or host_h or host}
            if pbk: r["publicKey"] = pbk
            if sid: r["shortId"] = sid
            ss["realitySettings"] = r

        _stream_net(ss, net, q)
        return ob
    except Exception:
        return None


def hy2_to_outbound(link):
    try:
        main = link.split("#")[0]
        p = urllib.parse.urlparse(main)
        q = urllib.parse.parse_qs(p.query)

        auth = p.username
        if not auth:
            auth = q.get("auth", [""])[0]

        host = p.hostname
        port = p.port or 443
        sni      = q.get("sni", [""])[0] or host
        insecure = q.get("insecure", ["0"])[0]
        obfs     = q.get("obfs", [""])[0]
        obfs_pw  = q.get("obfs-password", [""])[0]
        pin      = q.get("pin", [""])[0]

        server = {
            "address": host,
            "port": port,
            "password": auth or "",
            "sni": sni,
            "insecure": True
        }

        if obfs:
            server["obfs"] = {"type": obfs}
            if obfs_pw:
                server["obfs"]["password"] = obfs_pw
        if pin:
            server["pin"] = pin

        return {
            "protocol": "hysteria2",
            "settings": {"servers": [server]}
        }
    except Exception:
        return None


def tuic_to_outbound(link):
    try:
        main = link.split("#")[0]
        p = urllib.parse.urlparse(main)
        q = urllib.parse.parse_qs(p.query)
        uuid = p.username; password = p.password or ""
        host = p.hostname; port = p.port or 443
        sni       = q.get("sni", [""])[0] or host
        insecure  = q.get("insecure", ["0"])[0]
        congestion = q.get("congestion_control_type", [""])[0]
        alpn      = q.get("alpn", [""])[0]
        disable_mtu_discovery = q.get("disable_mtu_discovery", [""])[0]

        server = {
            "address": host,
            "port": port,
            "uuid": uuid,
            "password": password,
            "sni": sni,
            "insecure": True
        }
        if congestion:
            server["congestion_control_type"] = congestion
        if alpn:
            server["alpn"] = alpn.split(",")
        if disable_mtu_discovery == "1":
            server["disable_mtu_discovery"] = True

        return {
            "protocol": "tuic",
            "settings": {"servers": [server]}
        }
    except Exception:
        return None


def link_to_outbound(link):
    if link.startswith("vless://"):       return vless_to_outbound(link)
    if link.startswith("vmess://"):       return vmess_to_outbound(link)
    if link.startswith("ss://"):          return ss_to_outbound(link)
    if link.startswith("trojan://"):      return trojan_to_outbound(link)
    if link.startswith("hysteria2://"):   return hy2_to_outbound(link)
    if link.startswith("hy2://"):         return hy2_to_outbound(link)
    if link.startswith("tuic://"):        return tuic_to_outbound(link)
    return None

# ======================== SOCKS5 TCP TEST ========================

def test_socks5(socks_port, target_host, target_port, timeout=12):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", socks_port))
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        if len(r) < 2 or r[0] != 5 or r[1] != 0:
            s.close(); return False
        tb = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(tb)]) + tb + struct.pack(">H", target_port)
        s.sendall(req)
        r = s.recv(4)
        s.close()
        return len(r) >= 2 and r[0] == 5 and r[1] == 0
    except Exception:
        return False


def test_config(link, xray_path):
    outbound = link_to_outbound(link)
    if outbound is None:
        return False, link

    port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1",
                      "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound]
    }
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(xray_path)),
                            f"_tcp_test_{port}.json")
    process = None
    try:
        with open(cfg_path, "w") as f:
            json.dump(config, f)

        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        process = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs)

        started = False
        for _ in range(int(SOCKS_WAIT_SEC / 0.2)):
            time.sleep(0.2)
            if process.poll() is not None:
                return False, link
            try:
                ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ts.settimeout(0.3)
                ts.connect(("127.0.0.1", port))
                ts.close()
                started = True; break
            except Exception:
                continue
        if not started:
            return False, link

        ok = test_socks5(port, TEST_TARGET[0], TEST_TARGET[1], TEST_TIMEOUT)
        return ok, link
    except Exception:
        return False, link
    finally:
        if process:
            try: process.terminate()
            except Exception: pass
            try: process.wait(timeout=2)
            except Exception:
                try: process.kill()
                except Exception: pass
        try: os.remove(cfg_path)
        except Exception: pass

# ======================== SAVE RESULTS ========================

def clear_result_dir():
    os.makedirs(RESULT_DIR, exist_ok=True)
    os.makedirs(OTHERS_DIR, exist_ok=True)
    for folder in (RESULT_DIR, OTHERS_DIR):
        for f in os.listdir(folder):
            fp = os.path.join(folder, f)
            if f.endswith(".txt") and os.path.isfile(fp):
                os.remove(fp)


def save_chunked(lines, folder, prefix):
    os.makedirs(folder, exist_ok=True)
    # Clean old files with this prefix
    for f in os.listdir(folder):
        if f.startswith(prefix + "_") and f.endswith(".txt"):
            try: os.remove(os.path.join(folder, f))
            except: pass

    if not lines:
        return

    # Sort lines before saving
    lines = sorted(lines)

    for i in range(0, len(lines), LINES_PER_FILE):
        chunk = lines[i : i + LINES_PER_FILE]
        num = i // LINES_PER_FILE + 1
        path = os.path.join(folder, f"{prefix}_{num}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk) + "\n")


def save_all(working_lines, hy2_lines, failed_lines):
    """Save all categories to disk."""
    clear_result_dir()

    # 1. Working lines (by protocol)
    groups = {}
    for line in working_lines:
        cat = get_protocol_category(line)
        if cat:
            groups.setdefault(cat, []).append(line)
    for cat, lines in groups.items():
        save_chunked(lines, RESULT_DIR, cat)

    # 2. Hy2/Hysteria2/Tuic lines (untested, saved together to Others)
    save_chunked(hy2_lines, OTHERS_DIR, "hy2")

    # 3. Failed lines (tested and failed, saved to Others)
    save_chunked(failed_lines, OTHERS_DIR, "failed")

# ======================== GUI ========================

class TCPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sub Connection Checker by MOHA")
        self.root.geometry("560x340")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        x = (self.root.winfo_screenwidth()  // 2) - 280
        y = (self.root.winfo_screenheight() // 2) - 170
        self.root.geometry(f"+{x}+{y}")

        # ── Title ──
        self.title_label = tk.Label(root, text="Sub Connection Checker",
                                    font=("Segoe UI", 22, "bold"),
                                    fg="#cdd6f4", bg="#1e1e2e")
        self.title_label.pack(pady=(22, 8))

        # ── Controls frame ──
        ctrl_frame = tk.Frame(root, bg="#1e1e2e")
        ctrl_frame.pack(pady=4)

        tk.Label(ctrl_frame, text="Connections",
                 font=("Segoe UI", 11), fg="#a6adc8", bg="#1e1e2e"
                 ).pack(side="left", padx=(0, 6))

        self.worker_var = tk.IntVar(value=MAX_PARALLEL)
        self.worker_spin = tk.Spinbox(
            ctrl_frame, from_=1, to=30, width=4,
            textvariable=self.worker_var,
            font=("Segoe UI", 12), justify="center",
            bg="#313244", fg="#cdd6f4",
            buttonbackground="#45475a",
            insertbackground="#cdd6f4",
            relief="flat", bd=2)
        self.worker_spin.pack(side="left", padx=(0, 16))

        self.btn = tk.Button(ctrl_frame, text="Start Scan",
                             font=("Segoe UI", 13, "bold"),
                             bg="#a6e3a1", fg="#1e1e2e",
                             activebackground="#94e2d5",
                             bd=0, cursor="hand2",
                             width=18, height=1,
                             command=self.start_scan)
        self.btn.pack(side="left")

        # ── Status labels ──
        self.status_label = tk.Label(root, text="",
                                     font=("Segoe UI", 10),
                                     fg="#a6adc8", bg="#1e1e2e",
                                     wraplength=520, justify="center")
        self.status_label.pack(pady=(10, 2))

        self.detail_label = tk.Label(root, text="",
                                     font=("Consolas", 9),
                                     fg="#6c7086", bg="#1e1e2e",
                                     wraplength=520, justify="center")
        self.detail_label.pack(pady=2)

        self.others_label = tk.Label(root, text="",
                                     font=("Consolas", 9),
                                     fg="#585b70", bg="#1e1e2e",
                                     wraplength=520, justify="center")
        self.others_label.pack(pady=2)

        self.working_lines = []
        self.hy2_lines     = []
        self.failed_lines  = []
        self.lock = threading.Lock()
        self.save_counter = 0
        self.proto_found   = {}
        self.proto_working = {}

    # ---------- helpers ----------
    def _status(self, text, color="#f9e2af"):
        self.root.after(0, lambda: self.status_label.config(text=text, fg=color))

    def _detail(self, text):
        self.root.after(0, lambda: self.detail_label.config(text=text))

    def _others_info(self, text):
        self.root.after(0, lambda: self.others_label.config(text=text))

    # ---------- main flow ----------
    def start_scan(self):
        try:
            workers = self.worker_var.get()
            if workers < 1: workers = 1
            if workers > 30: workers = 30
        except Exception:
            workers = MAX_PARALLEL

        self.btn.config(state="disabled", bg="#585b70")
        self.worker_spin.config(state="disabled")
        self._status("Initializing…", "#f9e2af")
        self._others_info("")
        t = threading.Thread(target=self._run, args=(workers,), daemon=True)
        t.start()

    def _run(self, workers):
        try:
            self.__run(workers)
        except Exception as e:
            self._status(f"Error: {e}", "#f38ba8")
        finally:
            self.root.after(0, lambda: self.btn.config(state="normal", bg="#a6e3a1"))
            self.root.after(0, lambda: self.worker_spin.config(state="normal"))

    def __run(self, workers):
        # --- checks ---
        if not os.path.isfile(XRAY_PATH):
            self._status(f"✖  xray.exe not found in {CONF_DIR}/", "#f38ba8")
            return
        if not os.path.isfile(SUB_FILE):
            self._status(f"✖  sub.txt not found in {CONF_DIR}/", "#f38ba8")
            return

        with open(SUB_FILE, "r", encoding="utf-8") as f:
            sub_links = [l.strip() for l in f if l.strip()]
        if not sub_links:
            self._status("✖  sub.txt is empty", "#f38ba8")
            return

        # ── 1. fetch ──
        all_lines = []
        for i, url in enumerate(sub_links):
            self._status(f"Fetching {i+1}/{len(sub_links)}…")
            all_lines.extend(fetch_url(url).splitlines())

        # ── 2. filter ──
        self._status("Filtering…")
        filtered = filter_lines(all_lines)
        if not filtered:
            self._status("✖  No valid configs found", "#f38ba8")
            return

        # ── 3. dedup ──
        self._status("Removing duplicates…")
        unique = remove_duplicates(filtered)

        # ── 4. rename (skip vmess!) ──
        renamed = [rename_line(l) for l in unique]

        # ── 5. sort ──
        renamed.sort()

        # ── count per protocol ──
        self.proto_found = {}
        for ln in renamed:
            cat = get_protocol_category(ln) or "other"
            self.proto_found[cat] = self.proto_found.get(cat, 0) + 1

        found_summary = "  ".join(f"{k}:{v}" for k, v in sorted(self.proto_found.items()))
        self._detail(f"Found → {found_summary}")

        # ── 6. separate hy2/hysteria2/tuic (untested) from testable ──
        self.hy2_lines = []
        testable_lines = []
        for ln in renamed:
            cat = get_protocol_category(ln)
            if cat == "hy2":
                # Keep their original format (hy2://, hysteria2://, tuic://)
                self.hy2_lines.append(ln)
            else:
                testable_lines.append(ln)

        hy2_count = len(self.hy2_lines)
        total_testable = len(testable_lines)
        self._status(f"QUIC: {hy2_count} to Others/ | Testing {total_testable} configs ({workers}W)…")

        # ── clear old results ──
        clear_result_dir()

        # ── 7. test testable configs with xray ──
        self.working_lines = []
        self.failed_lines  = []
        self.proto_working = {}
        self.save_counter = 0
        tested = 0

        if total_testable > 0:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(test_config, ln, XRAY_PATH): ln
                           for ln in testable_lines}
                for future in as_completed(futures):
                    tested += 1
                    ok, ln = future.result()
                    if ok:
                        cat = get_protocol_category(ln) or "other"
                        with self.lock:
                            self.working_lines.append(ln)
                            self.proto_working[cat] = self.proto_working.get(cat, 0) + 1
                            self.save_counter += 1
                            if self.save_counter >= SAVE_EVERY:
                                self.save_counter = 0
                                save_all(self.working_lines, self.hy2_lines, self.failed_lines)
                    else:
                        with self.lock:
                            self.failed_lines.append(ln)
                            if len(self.failed_lines) % SAVE_EVERY == 0:
                                save_all(self.working_lines, self.hy2_lines, self.failed_lines)

                    # update UI
                    wk = len(self.working_lines)
                    fl = len(self.failed_lines)
                    work_summary = "  ".join(
                        f"{k}:{v}" for k, v in sorted(self.proto_working.items()))
                    self._status(f"Tested {tested}/{total_testable}  |  Working {wk}  |  Failed {fl}")
                    self._detail(work_summary)
                    self._others_info(f"Others/ → hy2/hysteria2/tuic: {hy2_count} (untested)  |  failed: {fl}")

        # ── 8. final save ──
        save_all(self.working_lines, self.hy2_lines, self.failed_lines)

        wk = len(self.working_lines)
        fl = len(self.failed_lines)
        work_summary = "  ".join(
            f"{k}:{v}" for k, v in sorted(self.proto_working.items()))
        self._detail(work_summary)
        self._others_info(f"Others/ → hy2/hysteria2/tuic: {hy2_count} (untested)  |  failed: {fl}")

        self._status(f"✔  Done – {wk} working, {hy2_count} QUIC, {fl} failed → {RESULT_DIR}/",
                     "#a6e3a1")


# ======================== ENTRY POINT ========================

if __name__ == "__main__":
    root = tk.Tk()
    app = TCPApp(root)
    root.mainloop()