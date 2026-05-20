#!/usr/bin/env python3
"""HTTPS server scanner — lists running services with ports and all installed packages."""

import subprocess
import functools
import re
import os
import datetime
import socket
from flask import Flask, Response, request, render_template_string

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE  = os.path.join(SCRIPT_DIR, "cert.pem")
KEY_FILE   = os.path.join(SCRIPT_DIR, "key.pem")

USERNAME = "admin"
PASSWORD = "changeme"

app = Flask(__name__)

# ── SSL ──────────────────────────────────────────────────────────────────────

def ensure_ssl_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    print("Generating self-signed SSL certificate …")

    # Collect all local IPs for Subject Alternative Names
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips = [ip for ip in r.stdout.split() if ip]
    except Exception:
        ips = []

    san_parts = ["DNS:localhost", "IP:127.0.0.1"] + [f"IP:{ip}" for ip in ips]
    san = ",".join(dict.fromkeys(san_parts))  # deduplicate, preserve order

    cfg_path = os.path.join(SCRIPT_DIR, ".ssl_gen.cnf")
    with open(cfg_path, "w") as f:
        f.write(f"""[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = localhost
[v3]
keyUsage = keyEncipherment,dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = {san}
""")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE, "-out", CERT_FILE,
                "-days", "365", "-nodes", "-config", cfg_path,
            ],
            check=True, capture_output=True,
        )
        os.chmod(KEY_FILE, 0o600)
        print(f"  Certificate : {CERT_FILE}")
        print(f"  Private key : {KEY_FILE}")
        print(f"  SANs        : {san}")
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


# ── Port / service scanning ───────────────────────────────────────────────────

def _parse_ss(flag, proto):
    """Return raw port entries from ss output."""
    try:
        r = subprocess.run(["ss", flag], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return []
    entries = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if ":" not in local:
            continue
        port_str = local.rsplit(":", 1)[1]
        if not port_str.isdigit():
            continue
        proc_str = " ".join(parts[5:])
        m = re.search(r'\("([^"]+)",pid=(\d+)', proc_str)
        proc = m.group(1) if m else "unknown"
        pid  = m.group(2) if m else None
        entries.append({"port": int(port_str), "proto": proto,
                        "process": proc, "pid": pid, "addr": local})
    return entries


def _pkg_for_pid(pid, proc_name):
    """Map a running process to its dpkg package name."""
    # Try resolving via /proc/<pid>/exe symlink
    if pid:
        try:
            exe = os.readlink(f"/proc/{pid}/exe").split(" ")[0]
            r = subprocess.run(["dpkg", "-S", exe],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.split(":")[0].strip()
        except Exception:
            pass
    # Fall back to 'which <name>'
    try:
        w = subprocess.run(["which", proc_name],
                           capture_output=True, text=True, timeout=5)
        if w.returncode == 0:
            r = subprocess.run(["dpkg", "-S", w.stdout.strip()],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.split(":")[0].strip()
    except Exception:
        pass
    return None


def _pkg_info(pkg_name):
    """Return (version, description) for a package name."""
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", f"-f=${{Version}}\t${{binary:Summary}}", pkg_name],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            parts = r.stdout.split("\t", 1)
            return parts[0], (parts[1] if len(parts) > 1 else "")
    except Exception:
        pass
    return "", ""


def get_services():
    """Return list of running services with ports, sorted by port number."""
    seen = set()
    raw  = _parse_ss("-tlnp", "TCP") + _parse_ss("-ulnp", "UDP")
    services = []
    for e in sorted(raw, key=lambda x: x["port"]):
        key = (e["proto"], e["port"])
        if key in seen:
            continue
        seen.add(key)
        pkg = _pkg_for_pid(e["pid"], e["process"])
        ver, desc = _pkg_info(pkg) if pkg else ("", "")
        services.append({
            "port":        e["port"],
            "proto":       e["proto"],
            "process":     e["process"],
            "package":     pkg or e["process"],
            "version":     ver,
            "description": desc,
            "addr":        e["addr"],
        })
    return services


def get_packages():
    """Return all dpkg-installed packages sorted by name."""
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${binary:Summary}\n"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return []
    pkgs = []
    for line in sorted(r.stdout.splitlines()):
        p = line.split("\t", 2)
        if len(p) == 3:
            pkgs.append({"name": p[0], "version": p[1], "description": p[2]})
    return pkgs


# ── HTML template ─────────────────────────────────────────────────────────────

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Server Scanner</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Courier New',monospace;background:#0f0f1a;color:#ddd;padding:20px}
    h1{color:#00d4ff;font-size:1.5rem;margin-bottom:4px}
    .sub{color:#555;font-size:.8rem;margin-bottom:20px}
    .tabs{display:flex;gap:6px;margin-bottom:18px}
    .tab{padding:7px 16px;background:#1a1a2e;border:1px solid #333;border-radius:4px;
         cursor:pointer;font-size:.85rem;color:#888;user-select:none;transition:all .15s}
    .tab:hover{border-color:#00d4ff66;color:#ccc}
    .tab.active{background:#00d4ff1a;border-color:#00d4ff;color:#00d4ff}
    .badge{background:#00d4ff22;border:1px solid #00d4ff44;border-radius:3px;
           padding:1px 6px;font-size:.72rem;margin-left:6px;color:#00d4ffcc}
    .panel{display:none}.panel.active{display:block}
    .bar{display:flex;gap:10px;margin-bottom:14px;align-items:center}
    .bar input{flex:1;padding:7px 12px;background:#16213e;border:1px solid #00d4ff33;
               color:#ddd;border-radius:4px;font-size:.9rem}
    .bar input:focus{outline:none;border-color:#00d4ff}
    .cnt{color:#555;font-size:.8rem;white-space:nowrap}
    table{width:100%;border-collapse:collapse;font-size:.84rem}
    thead th{background:#16213e;color:#00d4ff;text-align:left;padding:9px 12px;
             border-bottom:2px solid #00d4ff33;position:sticky;top:0;z-index:1}
    tbody tr:nth-child(even){background:#ffffff04}
    tbody tr:hover{background:#00d4ff0d}
    td{padding:6px 12px;border-bottom:1px solid #ffffff07;vertical-align:top}
    .port{color:#ffd700;font-weight:bold}
    .tcp{color:#4fc3f7}.udp{color:#81c784}
    .pkg{color:#7ec8e3}.proc{color:#ce93d8}
    .ver{color:#888}.desc{color:#bbb}
    .empty{color:#444;text-align:center;padding:40px;font-size:.9rem}
    .note{color:#555;font-size:.78rem;margin-top:12px}
    .hidden{display:none}
  </style>
</head>
<body>
  <h1>&#128269; Server Scanner</h1>
  <div class="sub">{{ hostname }} &nbsp;&bull;&nbsp; {{ now }} &nbsp;&bull;&nbsp; HTTPS/8887</div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('svc',this)">
      Running Services <span class="badge">{{ services|length }}</span>
    </div>
    <div class="tab" onclick="switchTab('pkg',this)">
      All Packages <span class="badge">{{ packages|length }}</span>
    </div>
  </div>

  <!-- Services -->
  <div id="panel-svc" class="panel active">
    <div class="bar">
      <input id="svc-q" type="text" placeholder="Filter by port, process, package…"
             oninput="filter('svc')" autofocus>
      <span id="svc-cnt" class="cnt">{{ services|length }} shown</span>
    </div>
    {% if services %}
    <table id="svc-tbl">
      <thead><tr>
        <th>Port</th><th>Proto</th><th>Bind Address</th>
        <th>Process</th><th>Package</th><th>Version</th><th>Description</th>
      </tr></thead>
      <tbody>
        {% for s in services %}
        <tr>
          <td class="port">{{ s.port }}</td>
          <td class="{{ s.proto|lower }}">{{ s.proto }}</td>
          <td class="ver">{{ s.addr }}</td>
          <td class="proc">{{ s.process }}</td>
          <td class="pkg">{{ s.package }}</td>
          <td class="ver">{{ s.version }}</td>
          <td class="desc">{{ s.description }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty">No listening services detected.</div>
    {% endif %}
    <p class="note">Run as root to see process names for all services.</p>
  </div>

  <!-- Packages -->
  <div id="panel-pkg" class="panel">
    <div class="bar">
      <input id="pkg-q" type="text" placeholder="Filter packages…"
             oninput="filter('pkg')">
      <span id="pkg-cnt" class="cnt">{{ packages|length }} shown</span>
    </div>
    <table id="pkg-tbl">
      <thead><tr>
        <th>Package</th><th>Version</th><th>Description</th>
      </tr></thead>
      <tbody>
        {% for p in packages %}
        <tr>
          <td class="pkg">{{ p.name }}</td>
          <td class="ver">{{ p.version }}</td>
          <td class="desc">{{ p.description }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <script>
    function switchTab(name, el) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      el.classList.add('active');
      document.getElementById('panel-' + name).classList.add('active');
      document.getElementById(name + '-q').focus();
    }
    function filter(p) {
      const q = document.getElementById(p + '-q').value.toLowerCase();
      const rows = Array.from(document.querySelectorAll('#' + p + '-tbl tbody tr'));
      let n = 0;
      rows.forEach(r => {
        const hide = q && !r.textContent.toLowerCase().includes(q);
        r.classList.toggle('hidden', hide);
        if (!hide) n++;
      });
      document.getElementById(p + '-cnt').textContent = n + ' shown';
    }
  </script>
</body>
</html>"""


# ── Auth & routing ────────────────────────────────────────────────────────────

def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != USERNAME or auth.password != PASSWORD:
            return Response(
                "Authentication required.",
                401,
                {"WWW-Authenticate": 'Basic realm="Server Scanner"'},
            )
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
@require_auth
def index():
    services = get_services()
    packages = get_packages()
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(
        TEMPLATE,
        services=services,
        packages=packages,
        hostname=hostname,
        now=now,
    )


if __name__ == "__main__":
    ensure_ssl_cert()
    print(f"\nStarting Server Scanner  →  https://0.0.0.0:8887")
    print(f"Credentials : {USERNAME} / {PASSWORD}")
    print("Change USERNAME/PASSWORD before production use.\n")
    app.run(host="0.0.0.0", port=8887, ssl_context=(CERT_FILE, KEY_FILE), debug=False)
