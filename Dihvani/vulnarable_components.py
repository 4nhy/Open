#!/usr/bin/env python3
"""
vulnerable_components.py
────────────────────────
Vulnerable Components Scanner
Checks for:
  • Outdated / vulnerable NPM packages (cross-referenced via OSV.dev API)
  • Outdated / vulnerable Python packages (pip list + OSV.dev)
  • JavaScript library versions detected in page HTML (CDN links, inline hints)
  • WordPress plugins / themes version detection
  • Common CMS version fingerprinting
 
OSV.dev is used as the free, open vulnerability database (no API key required).
https://osv.dev/
 
Usage:
    python3 vulnerable_components.py -u https://example.com
    python3 vulnerable_components.py --npm                   # scan local project
    python3 vulnerable_components.py --pip                   # scan local venv/system
    python3 vulnerable_components.py -u https://example.com --npm --pip
"""
 
import argparse
import json
import os
import re
import subprocess
import sys
import time
import requests
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
 
# ── OSV.dev API ───────────────────────────────────────────────────────────────
 
OSV_API  = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
 
def query_osv(package_name, version, ecosystem):
    """
    Query OSV.dev for known vulnerabilities in a given package version.
    Returns list of vulnerability dicts.
    """
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        }
    }
    try:
        resp = requests.post(OSV_API, json=payload, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return []
 
 
def query_osv_batch(packages, ecosystem):
    """
    Batch query OSV.dev for multiple packages.
    packages: list of (name, version) tuples
    Returns dict of {name: [vuln, ...]}
    """
    queries = [
        {"version": ver, "package": {"name": name, "ecosystem": ecosystem}}
        for name, ver in packages
    ]
    payload = {"queries": queries}
    try:
        resp = requests.post(OSV_BATCH, json=payload, timeout=30)
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            out = {}
            for i, res in enumerate(results):
                name = packages[i][0]
                out[name] = res.get("vulns", [])
            return out
    except Exception:
        pass
    return {}
 
# ── Output helpers ────────────────────────────────────────────────────────────
 
def banner():
    print(f"""
{bold(cyan('╔══════════════════════════════════════════════╗'))}
{bold(cyan('║'))}  {bold('VULNERABLE COMPONENTS SCANNER')}  v1.0         {bold(cyan('║'))}
{bold(cyan('║'))}  NPM · Python · JS libs · CMS fingerprinting  {bold(cyan('║'))}
{bold(cyan('╚══════════════════════════════════════════════╝'))}
""")
 
def vuln(msg):  print(f"  [{red('VULN')}]    {msg}")
def warn(msg):  print(f"  [{yellow('WARN')}]    {msg}")
def info(msg):  print(f"  [{blue('INFO')}]    {msg}")
def ok(msg):    print(f"  [{green('OK')}]      {msg}")
 
def print_vulns(vulns, pkg_name, version):
    """Pretty-print OSV vulnerability entries."""
    if not vulns:
        ok(f"{pkg_name}=={version} — no known vulnerabilities")
        return
    for v in vulns:
        vid      = v.get("id", "?")
        summary  = v.get("summary", "No summary")[:80]
        severity = ""
        for s in v.get("severity", []):
            severity = f" [{s.get('type','?')}: {s.get('score','?')}]"
            break
        aliases = ", ".join(v.get("aliases", []))
        vuln(f"{bold(pkg_name)}=={version}  {bold(vid)}{severity}")
        warn(f"    {summary}")
        if aliases:
            warn(f"    Aliases: {aliases}")
 
# ── NPM ───────────────────────────────────────────────────────────────────────
 
def scan_npm_local():
    """Read package.json / package-lock.json and check each dependency."""
    print(f"\n{bold('── NPM Local Dependencies ────────────────────────')}")
 
    # Find package.json
    pkg_file = None
    for candidate in ["package.json", "package-lock.json"]:
        if os.path.exists(candidate):
            pkg_file = candidate
            break
 
    if not pkg_file:
        warn("No package.json or package-lock.json found in current directory.")
        return
 
    with open(pkg_file) as f:
        data = json.load(f)
 
    # Extract name→version map
    packages = {}
    if pkg_file == "package-lock.json":
        deps = data.get("dependencies", {})
        for name, meta in deps.items():
            ver = meta.get("version", "").lstrip("^~>=<")
            if ver:
                packages[name] = ver
    else:
        for section in ("dependencies", "devDependencies"):
            for name, ver_spec in data.get(section, {}).items():
                ver = ver_spec.lstrip("^~>=< ")
                packages[name] = ver
 
    if not packages:
        warn("No packages found in file.")
        return
 
    info(f"Checking {len(packages)} NPM packages against OSV.dev …")
    pkg_list = list(packages.items())
 
    # Batch in groups of 50 to stay within limits
    chunk_size = 50
    for i in range(0, len(pkg_list), chunk_size):
        chunk = pkg_list[i:i+chunk_size]
        results = query_osv_batch(chunk, "npm")
        for name, ver in chunk:
            vulns = results.get(name, [])
            print_vulns(vulns, name, ver)
 
 
def scan_npm_audit():
    """Run `npm audit --json` if npm is available."""
    print(f"\n{bold('── npm audit ─────────────────────────────────────')}")
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout)
        vulns = data.get("vulnerabilities", {})
        if not vulns:
            ok("npm audit reports no vulnerabilities.")
            return
        for pkg, meta in vulns.items():
            severity = meta.get("severity", "unknown")
            via      = [v.get("title","?") if isinstance(v,dict) else str(v)
                        for v in meta.get("via", [])[:2]]
            color_fn = red if severity in ("high","critical") else yellow
            print(f"  [{color_fn(severity.upper())}] {bold(pkg)}: {', '.join(via)}")
    except FileNotFoundError:
        warn("npm not found — skipping npm audit.")
    except Exception as e:
        warn(f"npm audit failed: {e}")
 
# ── Python / pip ──────────────────────────────────────────────────────────────
 
def scan_pip_local():
    """List installed pip packages and check against OSV.dev."""
    print(f"\n{bold('── Python pip Dependencies ───────────────────────')}")
 
    # Try pip list --format=json
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        packages = json.loads(result.stdout)
    except Exception as e:
        warn(f"Could not list pip packages: {e}")
        return
 
    if not packages:
        warn("No pip packages found.")
        return
 
    info(f"Checking {len(packages)} pip packages against OSV.dev …")
    pkg_list = [(p["name"], p["version"]) for p in packages]
 
    chunk_size = 50
    for i in range(0, len(pkg_list), chunk_size):
        chunk = pkg_list[i:i+chunk_size]
        results = query_osv_batch(chunk, "PyPI")
        for name, ver in chunk:
            vulns = results.get(name, [])
            print_vulns(vulns, name, ver)
 
 
def scan_requirements_file(req_file="requirements.txt"):
    """Parse a requirements.txt and check each pinned package."""
    print(f"\n{bold(f'── {req_file} ─────────────────────────────────')}")
    if not os.path.exists(req_file):
        warn(f"{req_file} not found.")
        return
 
    packages = []
    with open(req_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle: requests==2.28.0 or requests>=2.28 or requests
            m = re.match(r'^([A-Za-z0-9_\-\.]+)[=<>!~]+([0-9][^\s;,]*)', line)
            if m:
                packages.append((m.group(1), m.group(2)))
            else:
                name = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if name:
                    packages.append((name.group(1), "0.0.0"))
 
    if not packages:
        warn("No packages parsed from requirements.txt")
        return
 
    info(f"Checking {len(packages)} packages from {req_file} …")
    results = query_osv_batch(packages, "PyPI")
    for name, ver in packages:
        vulns = results.get(name, [])
        print_vulns(vulns, name, ver)
 
# ── JavaScript library detection from HTML ────────────────────────────────────
 
# (name, regex_pattern, version_group_index, OSV ecosystem)
JS_LIB_PATTERNS = [
    ("jquery",        r'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)',   1, "npm"),
    ("bootstrap",     r'bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)',1, "npm"),
    ("angular",       r'angular[.-]([0-9]+\.[0-9]+\.[0-9]+)',  1, "npm"),
    ("react",         r'react[.-]([0-9]+\.[0-9]+\.[0-9]+)',    1, "npm"),
    ("vue",           r'vue[.-]([0-9]+\.[0-9]+\.[0-9]+)',      1, "npm"),
    ("lodash",        r'lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)',   1, "npm"),
    ("moment",        r'moment[.-]([0-9]+\.[0-9]+\.[0-9]+)',   1, "npm"),
    ("axios",         r'axios[.-]([0-9]+\.[0-9]+\.[0-9]+)',    1, "npm"),
    ("d3",            r'/d3[.-]([0-9]+\.[0-9]+\.[0-9]+)',      1, "npm"),
    ("three",         r'three[.-]([0-9]+\.[0-9]+\.[0-9]+)',    1, "npm"),
    ("popper",        r'popper[.-]([0-9]+\.[0-9]+\.[0-9]+)',   1, "npm"),
    ("highlight.js",  r'highlight[.-]([0-9]+\.[0-9]+\.[0-9]+)',1, "npm"),
    ("socket.io",     r'socket\.io[.-]([0-9]+\.[0-9]+\.[0-9]+)',1,"npm"),
    ("handlebars",    r'handlebars[.-]([0-9]+\.[0-9]+\.[0-9]+)',1,"npm"),
    ("underscore",    r'underscore[.-]([0-9]+\.[0-9]+\.[0-9]+)',1,"npm"),
]
 
def detect_js_libs(url):
    """Detect JavaScript library versions from HTML source and CDN URLs."""
    print(f"\n{bold('── JavaScript Library Detection ──────────────────')}")
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15,
                            verify=False, allow_redirects=True)
    except Exception as e:
        warn(f"Could not fetch {url}: {e}")
        return
 
    body = resp.text.lower()
    detected = {}
 
    for lib_name, pattern, grp, ecosystem in JS_LIB_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = match.group(grp)
            detected[lib_name] = (version, ecosystem)
 
    if not detected:
        info("No versioned JS library references found in page source.")
        return
 
    info(f"Detected {len(detected)} JS libraries — checking OSV.dev …")
    for lib_name, (version, ecosystem) in detected.items():
        vulns = query_osv(lib_name, version, ecosystem)
        print_vulns(vulns, lib_name, version)
 
# ── CMS / WordPress fingerprinting ───────────────────────────────────────────
 
WP_VERSION_PATTERNS = [
    r'<meta name="generator" content="WordPress ([0-9.]+)"',
    r'wp-includes/js/[^?]+\?ver=([0-9.]+)',
    r'wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)',
]
 
CMS_SIGNATURES = {
    "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-content/"],
    "Drupal":     ["/core/misc/drupal.js", "/sites/default/files/"],
    "Joomla":     ["/administrator/", "/components/com_content/"],
    "Magento":    ["/skin/frontend/", "/js/varien/"],
    "PrestaShop": ["/modules/ps_", "/themes/classic/"],
}
 
def detect_cms(url):
    """Fingerprint CMS and check its version against OSV."""
    print(f"\n{bold('── CMS Version Detection ─────────────────────────')}")
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                            timeout=15, verify=False, allow_redirects=True)
    except Exception as e:
        warn(f"Could not fetch {url}: {e}")
        return
 
    body = resp.text
    detected_cms = None
 
    for cms, paths in CMS_SIGNATURES.items():
        for path in paths:
            if path in body or path in resp.url:
                detected_cms = cms
                break
        if detected_cms:
            break
 
    if not detected_cms:
        info("No common CMS fingerprint detected.")
        return
 
    info(f"Detected CMS: {bold(detected_cms)}")
 
    if detected_cms == "WordPress":
        for pattern in WP_VERSION_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                wp_ver = m.group(1)
                info(f"WordPress version: {bold(wp_ver)}")
                vulns = query_osv("wordpress", wp_ver, "Packagist")
                print_vulns(vulns, "wordpress", wp_ver)
                break
        else:
            warn("WordPress detected but version could not be determined.")
 
 
# ── Public entry point ────────────────────────────────────────────────────────
 
def run_components_scan(target=None, check_npm=False, check_pip=False):
    """
    Run all component vulnerability checks.
    target   : URL string (optional)
    check_npm: also scan local npm project
    check_pip: also scan local pip packages
    """
    if target:
        detect_js_libs(target)
        detect_cms(target)
 
    if check_npm:
        scan_npm_local()
        scan_npm_audit()
 
    if check_pip:
        scan_pip_local()
        if os.path.exists("requirements.txt"):
            scan_requirements_file("requirements.txt")
 
 
# ── CLI ───────────────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerable Components Scanner")
    parser.add_argument("-u", "--url",  default=None,
                        help="Target URL to fingerprint JS libs / CMS")
    parser.add_argument("--npm", action="store_true",
                        help="Scan local NPM project (package.json)")
    parser.add_argument("--pip", action="store_true",
                        help="Scan local Python environment (pip list)")
    args = parser.parse_args()
 
    if not args.url and not args.npm and not args.pip:
        parser.print_help()
        sys.exit(1)
 
    target = None
    if args.url:
        target = args.url.rstrip("/")
        if not target.startswith("http"):
            target = "https://" + target
 
    banner()
    if target:
        print(f"{bold('Target:')} {cyan(target)}\n")
    t0 = time.time()
    run_components_scan(target=target, check_npm=args.npm, check_pip=args.pip)
    print(f"\n{bold(green('── Scan complete in ' + str(round(time.time()-t0,2)) + 's ──'))}\n")
    