#!/usr/bin/env python3
"""NetHole - DNS sinkhole + system monitor for Windows.

Runs a local DNS server (UDP 53) that blocks ads, trackers and malware,
and serves a dashboard at http://127.0.0.1:8053 with CPU temperature,
CPU load and RAM usage. Needs administrator rights for port 53.
"""
import atexit, collections, ctypes, json, os, socket, struct, subprocess, sys
import threading, time, urllib.request, webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil

IS_WIN = os.name == "nt"
DNS_PORT = int(os.environ.get("NETHOLE_DNS_PORT", 53))
WEB_PORT = int(os.environ.get("NETHOLE_WEB_PORT", 8053))
BIND = os.environ.get("NETHOLE_BIND", "0.0.0.0")  # 0.0.0.0 = other devices can use this PC as DNS
UPSTREAMS = ["1.1.1.1", "9.9.9.9"]
LIST_URLS = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "NetHole")
LIST_FILE = os.path.join(APP_DIR, "blocklist.txt")
CUSTOM_FILE = os.path.join(APP_DIR, "custom.json")
os.makedirs(APP_DIR, exist_ok=True)
NOWIN = 0x08000000  # CREATE_NO_WINDOW
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
BUILTIN = ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
           "scorecardresearch.com", "adnxs.com", "taboola.com", "outbrain.com", "hotjar.com", "ads.yahoo.com"]


# ---------------------------------------------------------------- blocklist
class BlockList:
    def __init__(self):
        self.domains = set(BUILTIN)
        self.custom_block, self.custom_allow = set(), set()
        self.updating = False
        self.updated = None
        self.load_custom()
        self.load_file()

    def load_custom(self):
        try:
            with open(CUSTOM_FILE) as f:
                d = json.load(f)
            self.custom_block, self.custom_allow = set(d.get("block", [])), set(d.get("allow", []))
        except Exception:
            pass

    def save_custom(self):
        with open(CUSTOM_FILE, "w") as f:
            json.dump({"block": sorted(self.custom_block), "allow": sorted(self.custom_allow)}, f)

    def load_file(self):
        if not os.path.exists(LIST_FILE):
            return
        found = set(BUILTIN)
        with open(LIST_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#")[0].strip().split()
                if len(line) >= 2 and line[0] in ("0.0.0.0", "127.0.0.1") and "." in line[1]:
                    found.add(line[1].lower())
        self.domains = found
        self.updated = os.path.getmtime(LIST_FILE)

    def update(self):
        if self.updating:
            return
        self.updating = True
        try:
            with open(LIST_FILE, "wb") as out:
                for url in LIST_URLS:
                    with urllib.request.urlopen(url, timeout=30) as r:
                        out.write(r.read() + b"\n")
            self.load_file()
        except Exception as e:
            print("List update failed:", e)
        finally:
            self.updating = False

    def blocked(self, name):
        parts = name.lower().rstrip(".").split(".")
        suffixes = [".".join(parts[i:]) for i in range(max(len(parts) - 1, 1))]
        if any(s in self.custom_allow for s in suffixes):
            return False
        return any(s in self.custom_block or s in self.domains for s in suffixes)


# --------------------------------------------------------------------- stats
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = self.blocked = 0
        self.lat = 0.0
        self.log = collections.deque(maxlen=40)
        self.hours = collections.defaultdict(lambda: [0, 0])
        self.top = collections.Counter()
        self.start = time.time()

    def add(self, name, qtype, client, status, ms):
        with self.lock:
            self.total += 1
            h = self.hours[int(time.time() // 3600)]
            h[0] += 1
            if status == "blocked":
                self.blocked += 1
                h[1] += 1
                self.top[name] += 1
            else:
                self.lat += ms
            self.log.appendleft({"t": time.strftime("%H:%M:%S"), "d": name, "q": QTYPES.get(qtype, str(qtype)),
                                 "c": client, "s": status, "ms": round(ms)})

    def snapshot(self):
        with self.lock:
            now = int(time.time() // 3600)
            allowed = self.total - self.blocked
            return {"total": self.total, "blocked": self.blocked,
                    "avg_ms": round(self.lat / allowed) if allowed else 0,
                    "hours": [self.hours[now - 23 + i] if (now - 23 + i) in self.hours else [0, 0] for i in range(24)],
                    "top": self.top.most_common(8), "log": list(self.log), "uptime": int(time.time() - self.start)}


bl, stats = BlockList(), Stats()
state = {"paused": False, "dns_set": False}


# ----------------------------------------------------------------------- dns
def parse_q(d):
    i, labels = 12, []
    while True:
        n = d[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise ValueError("compressed question")
        labels.append(d[i + 1:i + 1 + n].decode("ascii", "ignore"))
        i += 1 + n
    qtype, = struct.unpack("!H", d[i:i + 2])
    return ".".join(labels), qtype, i + 4


def block_reply(d, qend, qtype):
    an, rd = 0, b""
    if qtype == 1:
        an, rd = 1, b"\0" * 4
    elif qtype == 28:
        an, rd = 1, b"\0" * 16
    out = d[:2] + struct.pack("!HHHHH", 0x8180, 1, an, 0, 0) + d[12:qend]
    if an:
        out += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rd)) + rd
    return out


def forward(data):
    for up in UPSTREAMS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(data, (up, 53))
                return s.recv(4096)
        except OSError:
            continue
    return None


def handle(sock, data, addr):
    t0 = time.time()
    try:
        name, qtype, qend = parse_q(data)
    except Exception:
        return
    if not state["paused"] and bl.blocked(name):
        resp, status = block_reply(data, qend, qtype), "blocked"
    else:
        resp = forward(data)
        status = "allowed" if resp else "failed"
    if resp:
        try:
            sock.sendto(resp, addr)
        except OSError:
            pass
    stats.add(name, qtype, addr[0], status, (time.time() - t0) * 1000)


def dns_server(sock):
    pool = ThreadPoolExecutor(64)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            continue  # Windows raises this when a client vanishes
        pool.submit(handle, sock, data, addr)


# ------------------------------------------------------------ system monitor
SENSOR_PS = r"""
$ErrorActionPreference='SilentlyContinue'
foreach($ns in 'root/LibreHardwareMonitor','root/OpenHardwareMonitor'){
 $s=Get-CimInstance -Namespace $ns -ClassName Sensor | Where-Object {$_.SensorType -eq 'Temperature'}
 if($s){ $s | ForEach-Object { "$($_.Name)|$($_.Value)" }; exit }
}
Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | ForEach-Object {
 "ACPI thermal zone|" + [math]::Round($_.CurrentTemperature/10-273.15,1) }
"""
sysinfo = {"cpu": 0, "cores": [], "ram": {}, "load": [0, 0, 0], "freq": 0, "temps": []}


def read_temps():
    if hasattr(psutil, "sensors_temperatures"):  # Linux / macOS
        try:
            t = psutil.sensors_temperatures()
            return [{"name": f"{k} {e.label or ''}".strip(), "value": e.current} for k, v in t.items() for e in v]
        except Exception:
            return []
    if not IS_WIN:
        return []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", SENSOR_PS], capture_output=True,
                           text=True, timeout=15, creationflags=NOWIN)
        out = []
        for line in r.stdout.splitlines():
            if "|" in line:
                n, v = line.rsplit("|", 1)
                try:
                    out.append({"name": n.strip(), "value": round(float(v), 1)})
                except ValueError:
                    pass
        return out
    except Exception:
        return []


def monitor():
    psutil.cpu_percent(None)
    last_t = 0
    while True:
        m = psutil.virtual_memory()
        f = psutil.cpu_freq()
        sysinfo.update(cpu=psutil.cpu_percent(None), cores=psutil.cpu_percent(percpu=True),
                       ram={"pct": m.percent, "used": round(m.used / 2**30, 1), "total": round(m.total / 2**30, 1)},
                       load=[round(x, 1) for x in psutil.getloadavg()], freq=round(f.current) if f else 0)
        if time.time() - last_t > 5:
            sysinfo["temps"], last_t = read_temps(), time.time()
        time.sleep(1)


# --------------------------------------------------------------- system dns
def set_dns(enable):
    if not IS_WIN:
        return False, "Only available on Windows."
    base = "Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress "
    cmd = base + ("-ServerAddresses 127.0.0.1" if enable else "-ResetServerAddresses")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd + "; ipconfig /flushdns"],
                       capture_output=True, text=True, creationflags=NOWIN)
    if r.returncode == 0:
        state["dns_set"] = enable
        return True, "This PC now uses NetHole for DNS." if enable else "Original DNS settings restored."
    return False, r.stderr.strip() or "Could not change DNS."


atexit.register(lambda: state["dns_set"] and set_dns(False))


# ------------------------------------------------------------------ web / api
class Api(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/stats":
            d = stats.snapshot()
            d.update(paused=state["paused"], dns_set=state["dns_set"], domains=len(bl.domains) + len(bl.custom_block),
                     updating=bl.updating, sys=sysinfo, custom={"block": sorted(bl.custom_block), "allow": sorted(bl.custom_allow)})
            self.send(json.dumps(d))
        else:
            self.send(HTML, "text/html")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        dom = str(body.get("domain", "")).strip().lower()
        msg = "OK"
        if self.path == "/api/pause":
            state["paused"] = bool(body.get("paused"))
        elif self.path == "/api/update":
            threading.Thread(target=bl.update, daemon=True).start()
            msg = "Updating block lists..."
        elif self.path == "/api/dns":
            ok, msg = set_dns(bool(body.get("enable")))
        elif self.path in ("/api/block", "/api/allow", "/api/remove") and "." in dom:
            bl.custom_block.discard(dom) if self.path != "/api/block" else bl.custom_block.add(dom)
            bl.custom_allow.discard(dom) if self.path != "/api/allow" else bl.custom_allow.add(dom)
            bl.save_custom()
        self.send(json.dumps({"message": msg}))


HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NetHole</title>
<style>
:root{--bg:#fffef8;--ink:#1c1c1c;--mute:#6b6a64;--red:#e30613;--soft:#f1efe4}
@media(prefers-color-scheme:dark){:root{--bg:#161613;--ink:#f3f1e6;--mute:#9a988d;--red:#ff3b30;--soft:#201f1b}}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font:400 16px/1.4 "Helvetica Neue",Helvetica,Arial,sans-serif}
.w{max-width:1200px;margin:0 auto;padding:0 24px}
header{border-bottom:3px solid var(--ink)}
header .w{display:flex;align-items:center;justify-content:space-between;height:64px;gap:12px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:22px;letter-spacing:-.02em}
.brand svg{width:32px;height:32px}
.pill{font-weight:700;font-size:14px;padding:6px 12px;border:2px solid var(--ink)}
.pill.on{background:var(--ink);color:var(--bg)}.pill.off{background:var(--red);color:#fff;border-color:var(--red)}
h2{font-size:15px;font-weight:700;margin:36px 0 10px}
.g{display:grid;grid-template-columns:repeat(4,1fr);border-top:3px solid var(--ink)}
.s{padding:14px 14px 18px 0;border-right:1px solid var(--ink)}.s+.s{padding-left:14px}.s:last-child{border:0}
.s small{display:block;color:var(--mute);font-size:14px}
.s b{display:block;font-size:clamp(30px,4.6vw,58px);line-height:1;letter-spacing:-.045em;font-weight:800;margin-top:6px;font-variant-numeric:tabular-nums}
.s.r b{color:var(--red)}.s i{font-style:normal;font-size:13px;color:var(--mute);display:block;margin-top:6px}
.meter{height:8px;background:var(--soft);margin-top:10px}.meter span{display:block;height:100%;background:var(--ink);transition:width .6s}
.cores{display:flex;gap:4px;align-items:flex-end;height:70px;border-bottom:3px solid var(--ink);margin-top:10px}
.cores div{flex:1;background:var(--ink);transition:height .6s;min-height:2px}
.two{display:grid;grid-template-columns:2fr 1fr;gap:32px}
.chart{display:flex;align-items:flex-end;gap:3px;height:120px;border-bottom:3px solid var(--ink)}
.chart div{flex:1;background:var(--ink);position:relative;min-height:1px}.chart span{position:absolute;left:0;right:0;bottom:0;background:var(--red)}
ol{list-style:none;padding:0;border-top:3px solid var(--ink)}
ol li{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--soft);font-size:14px}
ol li span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ctl{display:flex;flex-wrap:wrap;gap:10px;align-items:center;border-top:3px solid var(--ink);padding-top:14px}
button,input{font:700 14px inherit;font-family:inherit;border:2px solid var(--ink);background:var(--bg);color:var(--ink);padding:9px 14px}
button{cursor:pointer}button:hover{background:var(--ink);color:var(--bg)}button.red{background:var(--red);border-color:var(--red);color:#fff}
input{font-weight:400;min-width:220px}
#msg{color:var(--mute);font-size:14px}
.log{border-top:3px solid var(--ink);font:500 13px ui-monospace,Consolas,monospace}
.row{display:grid;grid-template-columns:72px 1fr 54px 110px 80px;gap:10px;padding:7px 0;border-bottom:1px solid var(--soft)}
.row.b{color:var(--red);font-weight:700}.row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
footer{margin:48px 0;color:var(--mute);font-size:13px}
@media(max-width:800px){.g{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr}.row{grid-template-columns:62px 1fr 80px}.row span:nth-child(3),.row span:nth-child(4){display:none}}
</style></head><body>
<svg width="0" height="0" style="position:absolute"><defs><g id="m" fill="none" stroke="currentColor"><rect x="214.5" y="214.5" width="595" height="595" rx="130" stroke-width="50" transform="rotate(45 512 512)"/><circle cx="512" cy="512" r="80" fill="currentColor" stroke="none"/></g></defs></svg>
<header><div class="w"><div class="brand"><svg viewBox="0 0 1024 1024"><use href="#m"/></svg>NetHole</div><div class="pill on" id="pill">Blocking on</div></div></header>
<div class="w">
<h2>Network</h2>
<div class="g">
<div class="s"><small>Queries</small><b id="q">0</b></div>
<div class="s r"><small>Blocked</small><b id="b">0</b></div>
<div class="s"><small>Block rate</small><b id="r">0%</b></div>
<div class="s"><small>Avg. response</small><b id="ms">0 ms</b><i id="dom"></i></div></div>
<h2>System</h2>
<div class="g">
<div class="s r"><small>CPU temperature</small><b id="t">n/a</b><i id="tn"></i></div>
<div class="s"><small>CPU load</small><b id="c">0%</b><div class="meter"><span id="cm"></span></div><i id="ld"></i></div>
<div class="s"><small>RAM usage</small><b id="ram">0%</b><div class="meter"><span id="rm"></span></div><i id="rt"></i></div>
<div class="s"><small>Per core</small><div class="cores" id="co"></div><i id="fq"></i></div></div>
<div class="two"><div><h2>Queries, last 24 hours</h2><div class="chart" id="ch"></div></div>
<div><h2>Top blocked</h2><ol id="top"></ol></div></div>
<h2>Controls</h2>
<div class="ctl"><button id="pz">Pause blocking</button><button id="up">Update block lists</button>
<button id="dn">Use NetHole as this PC’s DNS</button><button id="dr">Restore DNS</button>
<input id="dm" placeholder="example.com"><button id="bk" class="red">Block</button><button id="al">Allow</button><span id="msg"></span></div>
<h2>Query log</h2><div class="log" id="lg"></div>
<footer>Point other devices at this PC’s IP address (DNS server, port 53) to filter your whole network.</footer>
</div>
<script>
const $=i=>document.getElementById(i),f=n=>n.toLocaleString("en-US");
const post=(u,b)=>fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})}).then(r=>r.json()).then(r=>{$("msg").textContent=r.message;tick()});
let paused=false;
$("pz").onclick=()=>post("/api/pause",{paused:!paused});$("up").onclick=()=>post("/api/update");
$("dn").onclick=()=>post("/api/dns",{enable:true});$("dr").onclick=()=>post("/api/dns",{enable:false});
$("bk").onclick=()=>post("/api/block",{domain:$("dm").value});$("al").onclick=()=>post("/api/allow",{domain:$("dm").value});
function el(t,txt,c){const e=document.createElement(t);e.textContent=txt;if(c)e.className=c;return e}
async function tick(){let s;try{s=await(await fetch("/api/stats")).json()}catch(e){return}
paused=s.paused;$("pill").textContent=paused?"Blocking paused":"Blocking on";$("pill").className="pill "+(paused?"off":"on");
$("pz").textContent=paused?"Resume blocking":"Pause blocking";
$("q").textContent=f(s.total);$("b").textContent=f(s.blocked);$("r").textContent=(s.total?s.blocked/s.total*100:0).toFixed(1)+"%";
$("ms").textContent=s.avg_ms+" ms";$("dom").textContent=f(s.domains)+" domains listed"+(s.updating?" · updating":"");
const y=s.sys,T=y.temps||[],cpuT=T.find(x=>/cpu|package|core/i.test(x.name))||T[0];
$("t").textContent=cpuT?cpuT.value.toFixed(0)+"°C":"n/a";
$("tn").textContent=cpuT?cpuT.name:"Run LibreHardwareMonitor in the background to read temperatures";
$("c").textContent=Math.round(y.cpu)+"%";$("cm").style.width=y.cpu+"%";
$("ld").textContent="Load average "+y.load.join(" / ");
$("ram").textContent=Math.round(y.ram.pct)+"%";$("rm").style.width=y.ram.pct+"%";$("rt").textContent=y.ram.used+" of "+y.ram.total+" GB";
$("fq").textContent=y.freq?y.freq+" MHz":"";
const co=$("co");co.replaceChildren(...y.cores.map(v=>{const d=document.createElement("div");d.style.height=Math.max(v,3)+"%";return d}));
const mx=Math.max(1,...s.hours.map(h=>h[0]));
$("ch").replaceChildren(...s.hours.map(h=>{const d=document.createElement("div");d.style.height=(h[0]/mx*100)+"%";const p=document.createElement("span");p.style.height=(h[0]?h[1]/h[0]*100:0)+"%";d.append(p);return d}));
$("top").replaceChildren(...(s.top.length?s.top:[["Nothing blocked yet",""]]).map(x=>{const l=document.createElement("li");l.append(el("span",x[0]),el("span",x[1]));return l}));
$("lg").replaceChildren(...s.log.map(e=>{const r=document.createElement("div");r.className="row"+(e.s=="blocked"?" b":"");
r.append(el("span",e.t),el("span",e.d),el("span",e.q),el("span",e.c),el("span",e.s=="blocked"?"Blocked":e.s=="failed"?"Failed":e.ms+" ms"));return r}))}
tick();setInterval(tick,1500);
</script></body></html>"""


# ---------------------------------------------------------------------- main
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() if IS_WIN else os.geteuid() == 0
    except Exception:
        return False


def main():
    if IS_WIN and DNS_PORT == 53 and not is_admin():
        rest = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
        params = " ".join(f'"{a}"' for a in rest)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND, DNS_PORT))
        threading.Thread(target=dns_server, args=(sock,), daemon=True).start()
    except OSError as e:
        print("Could not start DNS server (is another DNS service using port 53?):", e)
    threading.Thread(target=monitor, daemon=True).start()
    web = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), Api)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    if not os.path.exists(LIST_FILE):
        threading.Thread(target=bl.update, daemon=True).start()
    url = f"http://127.0.0.1:{WEB_PORT}"
    print("NetHole running:", url)
    if os.environ.get("NETHOLE_NOGUI"):
        while True:
            time.sleep(3600)
    try:
        import webview
        webview.create_window("NetHole", url, width=1240, height=860)
        webview.start()
    except ImportError:
        webbrowser.open(url)
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
