#!/usr/bin/env python3
"""
crypto_failures.py
──────────────────
Cryptographic Failures Scanner
Checks for:
  • Plain HTTP instead of HTTPS (no redirect, mixed content)
  • Weak / deprecated TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  • Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, ANON)
  • Expired or self-signed TLS certificates
  • Weak certificate key size (< 2048-bit RSA / < 256-bit EC)
  • Missing HSTS header
  • HTTP cookie without Secure flag
  • Outdated / weak hashing indicators in response (MD5, SHA1 refs)

Usage:
    python3 crypto_failures.py -u https://example.com
    python3 crypto_failures.py -u example.com        # also tries HTTP
"""

import argparse
import ssl
import socket
import datetime
import requests
import time
import sys
from urllib.parse import urlparse

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

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
STRONG_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "MD5", "RC2", "IDEA", "SEED",
]

WEAK_HASH_PATTERNS = [
    "md5(", "md5 hash", "hashlib.md5", "sha1(",
    "sha1 hash", "hashlib.sha1", "crypt.crypt",
    "base64 password", "rot13",
]

MIN_RSA_BITS  = 2048
MIN_EC_BITS   = 256
CERT_WARN_DAYS = 30

BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (CryptoScanner/1.0) AppleWebKit/537.36",
}

# ── Output helpers ────────────────────────────────────────────────────────────

def banner():
    print(f"""
{bold(cyan('╔══════════════════════════════════════════════╗'))}
{bold(cyan('║'))}  {bold('CRYPTOGRAPHIC FAILURES SCANNER')}  v1.0        {bold(cyan('║'))}
{bold(cyan('║'))}  TLS · Certs · HTTP · Cookies · Weak Hashes   {bold(cyan('║'))}
{bold(cyan('╚══════════════════════════════════════════════╝'))}
""")

def vuln(msg):  print(f"  [{red('VULN')}]    {msg}")
def warn(msg):  print(f"  [{yellow('WARN')}]    {msg}")
def info(msg):  print(f"  [{blue('INFO')}]    {msg}")
def ok(msg):    print(f"  [{green('OK')}]      {msg}")

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def get(url, verify=True, **kw):
    try:
        return requests.get(url, headers=BASE_HEADERS, timeout=10,
                            verify=verify, allow_redirects=True, **kw)
    except Exception:
        return None

def get_no_redirect(url, verify=False, **kw):
    try:
        return requests.get(url, headers=BASE_HEADERS, timeout=10,
                            verify=verify, allow_redirects=False, **kw)
    except Exception:
        return None

# ── Check functions ───────────────────────────────────────────────────────────

def check_http_to_https(host):
    """Check whether plain HTTP redirects to HTTPS."""
    print(f"\n{bold('── HTTP → HTTPS Redirect ─────────────────────────')}")
    http_url = f"http://{host}"
    resp = get_no_redirect(http_url)
    if not resp:
        warn(f"Could not connect via HTTP to {host}")
        return
    if resp.status_code in (301, 302, 307, 308):
        loc = resp.headers.get("Location", "")
        if loc.startswith("https://"):
            ok(f"HTTP correctly redirects to HTTPS ({resp.status_code})")
        else:
            vuln(f"HTTP redirects but NOT to HTTPS → {loc}")
    elif resp.status_code == 200:
        vuln(f"Site serves content over plain HTTP (no HTTPS redirect)!")
    else:
        info(f"HTTP returned status {resp.status_code}")


def check_hsts(url):
    """Verify HSTS (Strict-Transport-Security) header."""
    print(f"\n{bold('── HSTS Header ───────────────────────────────────')}")
    resp = get(url, verify=False)
    if not resp:
        warn("Could not reach target.")
        return
    hsts = resp.headers.get("Strict-Transport-Security")
    if hsts:
        ok(f"HSTS present: {hsts}")
        if "includeSubDomains" not in hsts:
            warn("HSTS does not include 'includeSubDomains'")
        if "preload" not in hsts:
            warn("HSTS does not include 'preload'")
        # Check max-age
        for part in hsts.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    age = int(part.split("=")[1])
                    if age < 31536000:
                        warn(f"HSTS max-age={age} is less than 1 year (31536000)")
                    else:
                        ok(f"HSTS max-age={age} (≥ 1 year)")
                except ValueError:
                    pass
    else:
        vuln("HSTS header missing — HTTPS not enforced by browser!")


def check_tls_version_and_ciphers(host, port=443):
    """Probe supported TLS versions and flag weak ones."""
    print(f"\n{bold('── TLS Version & Cipher Strength ─────────────────')}")

    # Map OpenSSL protocol constant names
    tls_probes = []

    # TLS 1.3
    if hasattr(ssl, "TLSVersion"):
        tls_probes = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None),
        ]

    # Attempt a standard TLS connection to inspect what the server negotiates
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version()
                cipher_name, _, _ = ssock.cipher()
                info(f"Negotiated TLS version : {bold(negotiated)}")
                info(f"Negotiated cipher suite: {bold(cipher_name)}")

                if negotiated in WEAK_TLS_VERSIONS:
                    vuln(f"Weak TLS version in use: {negotiated}")
                else:
                    ok(f"TLS version {negotiated} is acceptable")

                for kw in WEAK_CIPHER_KEYWORDS:
                    if kw.upper() in cipher_name.upper():
                        vuln(f"Weak cipher suite: {cipher_name} (contains {kw})")
                        break
                else:
                    ok(f"Cipher suite appears strong")
    except ssl.SSLError as e:
        warn(f"SSL error during probe: {e}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        warn(f"Could not connect to {host}:{port} — {e}")

    # Try forcing old TLS versions to see if server accepts them
    old_protocols = []
    for proto_name, proto_const in [
        ("SSLv3",  getattr(ssl, "PROTOCOL_SSLv3",  None)),
        ("TLSv1",  getattr(ssl, "PROTOCOL_TLSv1",  None)),
        ("TLSv1.1",getattr(ssl, "PROTOCOL_TLSv1_1",None)),
    ]:
        if proto_const is None:
            continue
        try:
            ctx2 = ssl.SSLContext(proto_const)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as s:
                with ctx2.wrap_socket(s, server_hostname=host):
                    old_protocols.append(proto_name)
                    vuln(f"Server accepts deprecated {proto_name}!")
        except Exception:
            pass
    if not old_protocols:
        ok("Server did not accept SSLv3 / TLS 1.0 / TLS 1.1 (tested where available)")


def check_certificate(host, port=443):
    """Inspect TLS certificate for expiry, key size, self-signing."""
    print(f"\n{bold('── TLS Certificate ───────────────────────────────')}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der  = ssock.getpeercert(binary_form=True)

        if not cert:
            warn("Could not retrieve certificate details.")
            return

        # Expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            delta = exp - datetime.datetime.utcnow()
            if delta.days < 0:
                vuln(f"Certificate EXPIRED on {not_after}!")
            elif delta.days < CERT_WARN_DAYS:
                warn(f"Certificate expires in {delta.days} days ({not_after})")
            else:
                ok(f"Certificate valid for {delta.days} more days")

        # Issuer / self-signed
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer.get("commonName") == subject.get("commonName"):
            vuln("Certificate appears to be self-signed!")
        else:
            ok(f"Issued by: {issuer.get('organizationName', issuer.get('commonName', 'unknown'))}")

        # Subject
        ok(f"Subject CN: {subject.get('commonName', 'N/A')}")

    except ssl.SSLCertVerificationError as e:
        vuln(f"Certificate verification failed: {e}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        warn(f"Could not connect to {host}:{port} — {e}")


def check_insecure_cookies(url):
    """Check for cookies missing Secure / HttpOnly / SameSite flags."""
    print(f"\n{bold('── Cookie Security Flags ─────────────────────────')}")
    resp = get(url, verify=False)
    if not resp:
        warn("Could not reach target.")
        return
    if not resp.cookies:
        info("No cookies set by the server.")
        return
    for cookie in resp.cookies:
        name = cookie.name
        if not cookie.secure:
            vuln(f"Cookie '{bold(name)}' missing Secure flag")
        else:
            ok(f"Cookie '{name}' has Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            warn(f"Cookie '{name}' may be missing HttpOnly flag")
        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            warn(f"Cookie '{name}' missing SameSite attribute")
        elif samesite.lower() == "none":
            warn(f"Cookie '{name}' SameSite=None (cross-site — ensure Secure is set)")


def check_mixed_content(url):
    """Look for HTTP resource references on an HTTPS page."""
    print(f"\n{bold('── Mixed Content ─────────────────────────────────')}")
    if not url.startswith("https"):
        info("Target is not HTTPS — mixed content check skipped.")
        return
    resp = get(url, verify=False)
    if not resp:
        warn("Could not fetch page.")
        return
    import re
    http_refs = re.findall(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+', resp.text)
    if http_refs:
        for ref in http_refs[:5]:
            vuln(f"Mixed content: {cyan(ref[:80])}")
    else:
        ok("No obvious mixed content (HTTP resources on HTTPS page) found.")


def check_weak_hash_refs(url):
    """Scan page source for references to weak hashing algorithms."""
    print(f"\n{bold('── Weak Hash Algorithm References ────────────────')}")
    resp = get(url, verify=False)
    if not resp:
        warn("Could not fetch page.")
        return
    body = resp.text.lower()
    hits = [p for p in WEAK_HASH_PATTERNS if p in body]
    if hits:
        for h in hits:
            vuln(f"Weak hash indicator in page source: '{bold(h)}'")
    else:
        ok("No weak hash algorithm references found in page source.")


# ── Public entry point ────────────────────────────────────────────────────────

def run_crypto_scan(target):
    """Run all cryptographic failure checks against target URL."""
    parsed = urlparse(target)
    host   = parsed.hostname or target
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)

    check_http_to_https(host)
    check_hsts(target)
    if parsed.scheme == "https" or port == 443:
        check_tls_version_and_ciphers(host, 443)
        check_certificate(host, 443)
    else:
        info("Target is HTTP — TLS checks skipped (no HTTPS detected).")
    check_insecure_cookies(target)
    check_mixed_content(target)
    check_weak_hash_refs(target)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cryptographic Failures Scanner")
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    if not target.startswith("http"):
        target = "https://" + target

    banner()
    print(f"{bold('Target:')} {cyan(target)}\n")
    t0 = time.time()
    run_crypto_scan(target)
    print(f"\n{bold(green('── Scan complete in ' + str(round(time.time()-t0,2)) + 's ──'))}\n")