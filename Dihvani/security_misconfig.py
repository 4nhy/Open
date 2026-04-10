#!/usr/bin/env python3
"""
security_misconfig.py
─────────────────────
Security Misconfiguration Scanner
Checks for:
  • Default / common credentials on login forms
  • Verbose error messages that leak system info
  • Unpatched / outdated software via Server/X-Powered-By headers
  • Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
  • Directory listing enabled
  • Exposed admin/debug/sensitive paths
 
Usage:
    python3 security_misconfig.py -u https://example.com
"""
 
import argparse
import requests
import sys
import time
from urllib.parse import urljoin
 
requests.packages.urllib3.disable_warnings()
 
# ── ANSI colours ──────────────────────────────────────────────────────────────
R    = "\033[91m"; G    = "\033[92m"; Y = "\033[93m"
B    = "\033[94m"; C    = "\033[96m"; W = "\033[97m"
BOLD = "\033[1m";  RST  = "\033[0m"
 
def red(t):    return f"{R}{t}{RST}"
def green(t):  return f"{G}{t}{RST}"
def yellow(t): return f"{Y}{t}{RST}"
def blue(t):   return f"{B}{t}{RST}"
def cyan(t):   return f"{C}{t}{RST}"
def bold(t):   return f"{BOLD}{t}{RST}"
 
# ── Constants ─────────────────────────────────────────────────────────────────
 
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "1234"),  ("admin", ""),         ("root",  "root"),
    ("root",  "toor"),  ("root",  ""),          ("user",  "user"),
    ("guest", "guest"), ("test",  "test"),      ("admin", "letmein"),
    ("admin", "changeme"), ("admin", "welcome"),
    ("manager", "manager"), ("operator", "operator"),
]
 
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection",
]
 
SERVER_VERSION_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator",
]
 
VERBOSE_ERROR_PATTERNS = [
    "stack trace", "traceback", "exception in thread",
    "at java.", "at org.", "at com.", "at sun.",
    "syntaxerror", "typeerror", "nameerror",
    "mysql_", "mysqli_", "pg_query", "oci_", "odbc_", "sqlite_",
    "fatal error", "parse error", "warning:",
    "undefined variable", "undefined index",
    "call to undefined function",
    "you have an error in your sql",
    "uncaught exception", "django.db", "activerecord",
    "internal server error", "/var/www", "/home/", "/etc/",
    "c:\\", "localhost", "127.0.0.1",
]
 
COMMON_LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/administrator",
    "/wp-login.php", "/wp-admin", "/user/login",
    "/auth/login", "/signin", "/account/login",
    "/console", "/manager/html",
]
 
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/config.php", "/config.yml",
    "/web.config", "/phpinfo.php", "/info.php",
    "/server-status", "/server-info", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/backup.zip",
    "/backup.sql", "/db.sql", "/dump.sql",
    "/admin/config", "/debug", "/actuator",
    "/actuator/env", "/actuator/health",
    "/api/swagger", "/swagger.json", "/swagger-ui.html",
    "/api-docs", "/v1/api-docs", "/openapi.json",
    "/__debug__/", "/telescope", "/horizon",
]
 
OUTDATED_SERVER_VERSIONS = {
    "apache":  ("2.4.58", "Apache HTTP Server"),
    "nginx":   ("1.25.3", "NGINX"),
    "iis":     ("10.0",   "IIS"),
    "php":     ("8.3",    "PHP"),
    "python":  ("3.12",   "Python"),
    "tomcat":  ("10.1",   "Apache Tomcat"),
    "express": ("4.18",   "Express.js"),
}
 
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
 
# ── HTTP helpers ──────────────────────────────────────────────────────────────
 
def get(url, **kw):
    try:
        return requests.get(url, headers=BASE_HEADERS, timeout=10,
                            verify=False, allow_redirects=True, **kw)
    except Exception:
        return None
 
def post(url, data, **kw):
    try:
        return requests.post(url, data=data, headers=BASE_HEADERS, timeout=10,
                             verify=False, allow_redirects=True, **kw)
    except Exception:
        return None
 
# ── Output helpers ────────────────────────────────────────────────────────────
 
def banner():
    print(f"""
{bold(cyan('╔══════════════════════════════════════════════╗'))}
{bold(cyan('║'))}  {bold('SECURITY MISCONFIGURATION SCANNER')}  v1.0      {bold(cyan('║'))}
{bold(cyan('║'))}  Defaults · Headers · Errors · Exposed Paths  {bold(cyan('║'))}
{bold(cyan('╚══════════════════════════════════════════════╝'))}
""")
 
def vuln(msg):  print(f"  [{red('VULN')}]    {msg}")
def warn(msg):  print(f"  [{yellow('WARN')}]    {msg}")
def info(msg):  print(f"  [{blue('INFO')}]    {msg}")
def ok(msg):    print(f"  [{green('OK')}]      {msg}")
 
# ── Individual checks ─────────────────────────────────────────────────────────
 
def check_security_headers(base_url):
    print(f"\n{bold('── Security Headers ──────────────────────────────')}")
    resp = get(base_url)
    if not resp:
        warn("Could not reach target to check headers.")
        return
    present_keys = {k.lower() for k in resp.headers}
    for h in SECURITY_HEADERS:
        if h.lower() in present_keys:
            ok(f"Header present: {h}")
        else:
            vuln(f"Missing security header: {bold(h)}")
 
 
def check_server_version_disclosure(base_url):
    print(f"\n{bold('── Server Version Disclosure ─────────────────────')}")
    resp = get(base_url)
    if not resp:
        warn("Could not reach target.")
        return
    for header in SERVER_VERSION_HEADERS:
        val = resp.headers.get(header)
        if val:
            vuln(f"{header}: {bold(val)}  ← version info exposed")
            s = val.lower()
            for key, (min_ver, name) in OUTDATED_SERVER_VERSIONS.items():
                if key in s:
                    warn(f"  Detected {name}. Ensure you are running >= {min_ver}")
        else:
            ok(f"{header} not exposed")
 
 
def check_verbose_errors(base_url):
    print(f"\n{bold('── Verbose Error Messages ────────────────────────')}")
    probes = [
        "/?id='", "/?id=1 AND 1=2", "/nonexistent_page_xyz_abc",
        "/?debug=true", "/api/v1/nonexistent",
    ]
    found = False
    for path in probes:
        url = urljoin(base_url, path)
        resp = get(url)
        if not resp:
            continue
        body = resp.text.lower()
        hits = [p for p in VERBOSE_ERROR_PATTERNS if p in body]
        if hits:
            found = True
            vuln(f"Verbose error detected at {cyan(url)}")
            for h in hits[:3]:
                warn(f"    Pattern: '{h}'")
    if not found:
        ok("No verbose error messages detected.")
 
 
def check_default_credentials(base_url):
    print(f"\n{bold('── Default Credentials ───────────────────────────')}")
    for path in COMMON_LOGIN_PATHS:
        url = urljoin(base_url, path)
        resp = get(url)
        if resp and resp.status_code == 200 and "login" in resp.text.lower():
            info(f"Login page found: {cyan(url)}")
            _try_default_creds(url, resp)
            return
    info("No common login page detected (manual check recommended).")
 
 
def _try_default_creds(url, page_resp):
    body = page_resp.text.lower()
    user_field = "username" if "username" in body else "email" if "email" in body else "user"
    pass_field = "password"
    bad_signals = ["invalid", "incorrect", "failed", "error",
                   "wrong", "bad credentials", "login"]
    for user, pwd in DEFAULT_CREDS[:10]:
        data = {user_field: user, pass_field: pwd}
        resp = post(url, data)
        if not resp:
            continue
        resp_body = resp.text.lower()
        if resp.status_code in (200, 302) and not any(s in resp_body for s in bad_signals):
            vuln(f"Possible default login success: {bold(user)} / {bold(pwd)}")
            return
    ok("Default credential attempts did not succeed (not exhaustive).")
 
 
def check_sensitive_paths(base_url):
    print(f"\n{bold('── Exposed Sensitive Paths ───────────────────────')}")
    found = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        resp = get(url)
        if resp and resp.status_code == 200 and len(resp.text) > 20:
            found.append(url)
            vuln(f"Accessible: {cyan(url)}  [HTTP {resp.status_code}]")
    if not found:
        ok(f"No sensitive paths exposed (checked {len(SENSITIVE_PATHS)} paths).")
 
 
def check_directory_listing(base_url):
    print(f"\n{bold('── Directory Listing ─────────────────────────────')}")
    test_dirs = ["/images/", "/uploads/", "/files/", "/static/",
                 "/assets/", "/backup/", "/logs/", "/tmp/"]
    for d in test_dirs:
        url = urljoin(base_url, d)
        resp = get(url)
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if "index of" in body or "parent directory" in body:
                vuln(f"Directory listing enabled: {cyan(url)}")
                return
    ok("No directory listing detected.")
 
 
# ── Public entry point (used by combined script) ──────────────────────────────
 
def run_misconfig_scan(target):
    """Run all misconfiguration checks. Returns a list of finding strings."""
    findings = []
    _orig_print = __builtins__.__dict__.get("print") if hasattr(__builtins__, "__dict__") else None
 
    check_security_headers(target)
    check_server_version_disclosure(target)
    check_verbose_errors(target)
    check_default_credentials(target)
    check_sensitive_paths(target)
    check_directory_listing(target)
    return findings
 
 
# ── CLI entry ─────────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Misconfiguration Scanner")
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()
 
    target = args.url.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target
 
    banner()
    print(f"{bold('Target:')} {cyan(target)}\n")
    t0 = time.time()
    run_misconfig_scan(target)
    print(f"\n{bold(green('── Scan complete in ' + str(round(time.time()-t0,2)) + 's ──'))}\n")