#!/usr/bin/env python3
"""Web app listing installed Ubuntu packages, protected by HTTP Basic Auth."""

import subprocess
import functools
from flask import Flask, Response, request, render_template_string

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "changeme"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Installed Programs</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
    h1 { color: #00d4ff; margin-bottom: 10px; font-size: 1.6rem; }
    .meta { color: #888; font-size: 0.85rem; margin-bottom: 20px; }
    .search-bar {
      display: flex; gap: 10px; margin-bottom: 20px;
    }
    #search {
      flex: 1; padding: 8px 12px; background: #16213e; border: 1px solid #00d4ff44;
      color: #e0e0e0; border-radius: 4px; font-size: 0.95rem;
    }
    #search:focus { outline: none; border-color: #00d4ff; }
    #count { color: #888; font-size: 0.85rem; align-self: center; white-space: nowrap; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    thead th {
      background: #16213e; color: #00d4ff; text-align: left;
      padding: 10px 12px; border-bottom: 2px solid #00d4ff44; position: sticky; top: 0;
    }
    tbody tr:nth-child(even) { background: #16213e55; }
    tbody tr:hover { background: #00d4ff11; }
    td { padding: 7px 12px; border-bottom: 1px solid #ffffff0a; vertical-align: top; }
    td:first-child { color: #7ec8e3; font-weight: bold; white-space: nowrap; }
    td:nth-child(2) { color: #aaa; }
    td:nth-child(3) { color: #ccc; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <h1>Installed Programs</h1>
  <div class="meta">Ubuntu package list &mdash; {{ total }} packages found</div>
  <div class="search-bar">
    <input id="search" type="text" placeholder="Filter packages..." autofocus>
    <span id="count">{{ total }} shown</span>
  </div>
  <table id="pkg-table">
    <thead>
      <tr>
        <th>Package</th>
        <th>Version</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {% for pkg in packages %}
      <tr>
        <td>{{ pkg.name }}</td>
        <td>{{ pkg.version }}</td>
        <td>{{ pkg.description }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <script>
    const search = document.getElementById('search');
    const countEl = document.getElementById('count');
    const rows = Array.from(document.querySelectorAll('#pkg-table tbody tr'));
    const total = rows.length;

    search.addEventListener('input', () => {
      const q = search.value.toLowerCase();
      let shown = 0;
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const hide = q && !text.includes(q);
        row.classList.toggle('hidden', hide);
        if (!hide) shown++;
      });
      countEl.textContent = shown + ' shown';
    });
  </script>
</body>
</html>"""


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != USERNAME or auth.password != PASSWORD:
            return Response(
                "Authentication required.",
                401,
                {"WWW-Authenticate": 'Basic realm="Program Lister"'},
            )
        return f(*args, **kwargs)
    return decorated


def get_packages():
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${binary:Summary}\n"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    packages = []
    for line in sorted(result.stdout.splitlines()):
        parts = line.split("\t", 2)
        if len(parts) == 3:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "description": parts[2],
            })
    return packages


@app.route("/")
@require_auth
def index():
    packages = get_packages()
    return render_template_string(HTML_TEMPLATE, packages=packages, total=len(packages))


if __name__ == "__main__":
    print("Starting Program Lister on http://0.0.0.0:8887")
    print(f"Login: {USERNAME} / {PASSWORD}")
    print("Change USERNAME/PASSWORD in program_lister.py before production use.")
    app.run(host="0.0.0.0", port=8887, debug=False)
