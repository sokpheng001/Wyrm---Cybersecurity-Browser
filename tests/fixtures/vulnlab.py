"""Deliberately vulnerable LOCAL test site for exercising Wyrm's security tools. Binds 127.0.0.1 only."""
import base64, html, http.server, json, sqlite3, urllib.parse

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("create table users(id int, name text, email text)")
DB.executemany("insert into users values(?,?,?)", [(1, "alice", "alice@test.local"), (2, "bob", "bob@test.local")])

def jwt_none():
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return b({"alg": "none", "typ": "JWT"}) + "." + b({"sub": "admin", "role": "admin"}) + "."

INDEX = """<!doctype html><html><head><title>VulnLab</title>
<script src="/static/app.js"></script></head><body>
<h1>VulnLab test site</h1>
<ul>
<li><a href="/search?q=hello">Search (reflected XSS)</a></li>
<li><a href="/user?id=1">User (SQL injection)</a></li>
<li><a href="/redirect?next=/">Redirect (open redirect)</a></li>
<li><a href="/api/data">API (CORS reflect)</a></li>
<li><a href="/login">Login (no CSRF token)</a></li>
<li><a href="/debug">Debug page</a></li>
<li><a href="/fetch?url=http://127.0.0.1:8765/">Fetch (SSRF)</a></li>
<li><a href="/dom#name=guest">DOM XSS</a></li>
<li><a href="/admin/">Admin</a></li>
</ul>
<!-- TODO remove: api_key=AKIAIOSFODNN7EXAMPLE password=hunter2 -->
<img src="http://127.0.0.1:8765/static/logo.png">
</body></html>"""

APPJS = """// app bundle
var API_BASE = "/api/v1/internal";
var SECRET_TOKEN = "sk_test_51HxxxxFAKEFAKEFAKE";
fetch("/api/data").then(r=>r.json()).then(d=>console.log(d));
function hidden(){ return fetch("/api/v1/internal/users/export"); }
"""

class H(http.server.BaseHTTPRequestHandler):
    def send(self, code, body, ctype="text/html", headers=()):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.2.15 (CentOS) PHP/5.3.3")
        self.send_header("X-Powered-By", "PHP/5.3.3")
        self.send_header("Set-Cookie", "session=abc123; Path=/")  # no HttpOnly/Secure/SameSite
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def log_message(self, fmt, *a):
        with open(__file__ + ".log", "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (self.command, self.path))

    def do_HEAD(self): self.do_GET()
    def do_OPTIONS(self):
        self.send(204, "", headers=[("Access-Control-Allow-Origin", self.headers.get("Origin", "*")),
                                    ("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE"),
                                    ("Access-Control-Allow-Credentials", "true")])

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
        if self.path.startswith("/login"):
            u = data.get("user", [""])[0]
            return self.send(200, f"<p>Welcome {u}</p><script>localStorage.token='{jwt_none()}'</script>",
                             headers=[("Set-Cookie", "auth=" + jwt_none() + "; Path=/")])
        return self.do_GET()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        p = u.path
        if p == "/":
            return self.send(200, INDEX)
        if p == "/static/app.js":
            return self.send(200, APPJS, "application/javascript")
        if p == "/search":
            return self.send(200, f"<h2>Results for: {q.get('q', [''])[0]}</h2><a href='/'>home</a>")
        if p == "/user":
            i = q.get("id", ["1"])[0]
            try:
                rows = DB.execute(f"select id,name,email from users where id = {i}").fetchall()
                return self.send(200, "<pre>" + html.escape(repr(rows)) + "</pre>")
            except Exception as e:
                return self.send(500, f"<b>SQL error:</b> sqlite3.OperationalError: {html.escape(str(e))} near query")
        if p == "/redirect":
            return self.send(302, "", headers=[("Location", q.get("next", ["/"])[0])])
        if p.startswith("/api/"):
            return self.send(200, json.dumps({"users": ["alice", "bob"], "token": jwt_none()}), "application/json",
                             headers=[("Access-Control-Allow-Origin", self.headers.get("Origin", "*")),
                                      ("Access-Control-Allow-Credentials", "true")])
        if p == "/login":
            return self.send(200, "<form method=post action=/login><input name=user><input name=pass type=password>"
                                  "<button>Login</button></form>")
        if p == "/debug":
            return self.send(500, "<title>Werkzeug Debugger</title><h1>Traceback (most recent call last)</h1>"
                                  "<pre>File \"/srv/app.py\", line 42, in view\nDEBUG = True\nSECRET_KEY='dev'</pre>")
        if p == "/fetch":
            return self.send(200, f"<p>Fetched {html.escape(q.get('url', [''])[0])}</p>")
        if p == "/dom":
            return self.send(200, "<div id=o></div><script>document.getElementById('o').innerHTML="
                                  "'Hi '+decodeURIComponent(location.hash.slice(6));</script>")
        if p in ("/.git/HEAD",):
            return self.send(200, "ref: refs/heads/main\n", "text/plain")
        if p in ("/.env",):
            return self.send(200, "DB_PASSWORD=hunter2\nAPP_KEY=base64:FAKE\n", "text/plain")
        if p == "/robots.txt":
            return self.send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n", "text/plain")
        if p.startswith("/admin"):
            return self.send(200, "<h1>Admin panel</h1><p>No auth required</p>")
        return self.send(404, "<h1>404</h1>")

if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", 8765), H).serve_forever()
