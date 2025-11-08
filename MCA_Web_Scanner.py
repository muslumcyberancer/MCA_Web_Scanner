#!/usr/bin/env python3
"""
MCA Web Scanner - Full tool (Termux friendly)

Features:
- Passive crawler (forms, links, headers, cookies)
- Heuristics for SQLi, XSS, SSRF, Clickjacking, Directory listing, TLS, etc.
- Pretty terminal output (icon + color + structured) matching user example
- HTML & JSON report generation
- Interactive quick-paste mode and simple menu
- WARNING: Passive only. Do NOT scan systems you don't have permission for.

Quick install:
  pkg update && pkg install python -y
  pip install aiohttp beautifulsoup4 jinja2 colorama tqdm

Usage:
  python3 MCA_Web_Scanner.py -t https://example.com
  python3 MCA_Web_Scanner.py    # interactive paste mode
"""
import os
import argparse
import asyncio
try:
    import aiohttp
except:
    os.system("pip install aiohttp")
try:
    from aiohttp import ClientTimeout
except:
    os.system("pip install aiohttp")
try:
    from bs4 import BeautifulSoup
except:
    os.system("pip install bs4")
try:
    import rich
except:
    os.system("pip install rich")
from rich.console import Console
from rich.progress import track
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.logging import RichHandler
import logging, time
console = Console()

from urllib.parse import urlparse, urljoin, parse_qs
import time
import datetime
import json
import sys
from collections import deque
from jinja2 import Template
from colorama import init as colorama_init, Fore, Style
try:
    from tqdm import tqdm
except:
    os.system("pip install tqdm")

colorama_init(autoreset=True)
import rich,time,gtts,os,sys
from rich.progress import track
def lod(l):
    for i in track(range(500),description=l):
        time.sleep(0.001)
from gtts import gTTS
def creat_(text,file):
    my_a = gTTS(text)
    my_a.save(file)
def play_audio(audio_file):
    os.system("play-audio "+audio_file)
def voice(text,file):
    creat_(text,file)
    play_audio(file)

#logo 
os.system("clear")
from rich.console import Console
from rich.panel import Panel

console = Console()

logo = r"""
$$\      $$\  $$$$$$\   $$$$$$\        
$$$\    $$$ |$$  __$$\ $$  __$$\       
$$$$\  $$$$ |$$ /  \__|$$ /  $$ |      
$$\$$\$$ $$ |$$ |      $$$$$$$$ |      
$$ \$$$  $$ |$$ |      $$  __$$ |      
$$ |\$  /$$ |$$ |  $$\ $$ |  $$ |      
$$ | \_/ $$ |\$$$$$$  |$$ |  $$ |      
\__|     \__| \______/ \__|  \__|      
"""

console.print(Panel(logo, title="", subtitle="v1.0", border_style="green"))
print("\n")
console.print(
    Panel(
        "\n  Welcome to [bold green] MCA [/bold green] Tool!\n  MCA Web Scanner — quick mode\n",
        title="🔥 Tool Info 🔥",
        subtitle="version 1.0",
    )
)
voice("Welcome to MCA Web Scanner tool ","s.mp3")
console.print("\n")
# --------------------------- Configuration ---------------------------
USER_AGENT = "MCA-Web-Scanner/1.0 (+https://github.com/nishite-ami)"
DEFAULT_RATE = 2.0  # requests per second
DEFAULT_CONCURRENCY = 3
DEFAULT_MAX_PAGES = 30
SAFE_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
]

# --------------------------- HTML template ---------------------------
HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MCA Web Scanner Report - {{ target }}</title>
<style>
body{font-family: Arial, sans-serif; padding:20px}
h1{border-bottom:1px solid #ddd}
table{border-collapse:collapse;width:100%;margin-bottom:20px}
th,td{border:1px solid #ccc;padding:8px;text-align:left}
.card{border:1px solid #eee;padding:12px;margin-bottom:12px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.code{background:#f7f7f7;padding:8px;border-radius:4px;font-family:monospace}
.sev-high{color:#a00}
.sev-medium{color:#f60}
.sev-low{color:#086}
</style>
</head>
<body>
<h1>MCA Web Scanner Report</h1>
<p><strong>Target:</strong> {{ target }}</p>
<p><strong>Scanned at:</strong> {{ scanned_at }}</p>
<h2>Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{% for s,c in summary.items() %}
<tr><td>{{ s }}</td><td>{{ c }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
{% for f in findings %}
<div class="card">
<h3>{{ loop.index }}. {{ f.title }} <small>({{ f.severity }})</small></h3>
<p><strong>URL:</strong> <a href="{{ f.url }}">{{ f.url }}</a></p>
<p><strong>Likelihood:</strong> {{ f.likelihood }}</p>
<p><strong>Description:</strong> {{ f.description }}</p>
{% if f.evidence %}
<p><strong>Evidence:</strong></p>
<ul>{% for k,v in f.evidence.items() %}<li><code>{{ k }}</code>: {{ v }}</li>{% endfor %}</ul>
{% endif %}
<p><strong>How an attacker might abuse this:</strong></p>
<p class="code">{{ f.exploit_example }}</p>
<p><strong>Mitigation / Fix:</strong></p>
<ul>{% for m in f.mitigation %}<li>{{ m }}</li>{% endfor %}</ul>
</div>
{% endfor %}

</body>
</html>
"""

# --------------------------- Attack templates ---------------------------
_ATTACK_TEMPLATES = {
    "sql_injection": {
        "title": "SQL Injection (possible)",
        "severity": "High",
        "description": "User-controllable parameter may flow to a database query without proper parameterization.",
        "exploit_example": "Common payloads like ' OR 1=1 -- may bypass auth or return extra rows.",
        "mitigation": [
            "Use parameterized queries / prepared statements.",
            "Validate and sanitize inputs server-side.",
            "Use least-privilege DB accounts and logging."
        ]
    },
    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS) (possible)",
        "severity": "High",
        "description": "Reflected user input appears in HTML output without proper encoding.",
        "exploit_example": "An attacker crafts a URL containing script that executes in victims' browsers.",
        "mitigation": ["HTML-encode/escape output", "Use Content-Security-Policy (CSP)", "Set Secure & HttpOnly cookies"]
    },
    "session_hijack": {
        "title": "Session Hijacking (cookie flags missing)",
        "severity": "High",
        "description": "Session cookies missing Secure/HttpOnly/SameSite flags can be stolen via XSS or over network.",
        "exploit_example": "An attacker steals session cookie and impersonates a user.",
        "mitigation": ["Set Secure; HttpOnly; SameSite on session cookies", "Serve site over HTTPS only"]
    },
    "insecure_tls": {
        "title": "Mixed Content / Insecure TLS (possible)",
        "severity": "Medium",
        "description": "HTTPS pages referencing HTTP resources or weak TLS may allow tampering.",
        "exploit_example": "Attacker serves modified JS from an HTTP CDN causing malicious execution.",
        "mitigation": ["Serve all assets over HTTPS", "Enable HSTS and update TLS ciphers"]
    },
    "clickjacking": {
        "title": "Clickjacking (possible)",
        "severity": "Medium",
        "description": "Missing X-Frame-Options or frame-ancestors CSP may allow framing of the site.",
        "exploit_example": "Attacker frames site to trick users into clicking hidden controls.",
        "mitigation": ["Set X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors 'self'"]
    },
    "dir_listing": {
        "title": "Directory Listing / Sensitive Files (possible)",
        "severity": "Medium",
        "description": "Directory indexes or exposed backups may leak sensitive files.",
        "exploit_example": "Attacker downloads config/backup files (.env, backups).",
        "mitigation": ["Disable directory listing", "Remove backups from webroot", "Restrict access"]
    },
    "server_version": {
        "title": "Server Version Disclosure (info)",
        "severity": "Low",
        "description": "Server banner discloses product/version which helps attackers find CVEs.",
        "exploit_example": "Attacker searches public CVEs for the disclosed version.",
        "mitigation": ["Hide version banners", "Keep server software updated"]
    },
    "open_redirect": {
        "title": "Open Redirect (possible)",
        "severity": "Medium",
        "description": "Unvalidated redirect parameters may allow phishing via trusted domain.",
        "exploit_example": "Attacker crafts link that redirects victims to phishing page.",
        "mitigation": ["Validate redirect targets; use allowlist of domains"]
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) (possible)",
        "severity": "High",
        "description": "User-controlled URL fetching endpoints may let attackers reach internal services.",
        "exploit_example": "Attacker forces server to request internal metadata or internal APIs.",
        "mitigation": ["Whitelist allowed domains", "Validate/normalize URLs", "Restrict egress network"]
    }
}

# --------------------------- Utilities ---------------------------
def sanitize_url(u: str) -> str:
    if not u:
        return u
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u.rstrip("/")

def is_same_origin(a: str, b: str) -> bool:
    pa = urlparse(a); pb = urlparse(b)
    return pa.scheme == pb.scheme and pa.netloc == pb.netloc

def analyze_headers(headers: dict) -> dict:
    lower = {k.lower(): v for k,v in (headers or {}).items()}
    missing = [h for h in SAFE_HEADERS if h not in lower]
    server = lower.get("server") or lower.get("x-powered-by") or ""
    set_cookie = headers.get("Set-Cookie") if headers else None
    return {"missing_headers": missing, "server": server, "set_cookie": set_cookie}

def extract_forms(html: str, base_url: str) -> list:
    forms = []
    soup = BeautifulSoup(html or "", "html.parser")
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "GET").upper()
        inputs = []
        for inp in f.find_all(["input","textarea","select"]):
            name = inp.get("name") or inp.get("id") or inp.get("type") or ""
            if name:
                inputs.append(name)
        forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
    return forms

def extract_links(html: str, base_url: str) -> list:
    links = set()
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup.find_all(["a","link","script","img"]):
        attr = "href" if tag.name in ("a","link") else "src"
        url = tag.get(attr)
        if not url:
            continue
        full = urljoin(base_url, url)
        links.add(full)
    return list(links)

# --------------------------- Heuristics / Attack Insight ---------------------------
def score_likelihood(key: str, evidence: dict) -> str:
    if key == "sql_injection":
        if evidence.get("params") or evidence.get("forms"):
            return "Likely"
        return "Possible"
    if key.startswith("xss"):
        if evidence.get("forms") or evidence.get("params"):
            return "Likely"
        return "Possible"
    if key == "session_hijack":
        for c in evidence.get("cookies", []):
            flags = [f.lower() for f in c.get("flags",[])]
            if "httponly" not in flags or "secure" not in flags:
                return "Likely"
        return "Possible"
    if key == "insecure_tls":
        if evidence.get("http_links"):
            return "Likely"
        if evidence.get("tls",{}).get("valid") is False:
            return "Likely"
        return "Possible"
    if key == "dir_listing":
        return "Likely" if evidence.get("dir_listing") else "Possible"
    return "Possible"

def analyze_findings_for_attacks(findings: dict) -> list:
    headers = findings.get("headers", {}) or {}
    forms = findings.get("forms", []) or []
    params = findings.get("params", []) or []
    cookies = findings.get("cookies", []) or []
    links = findings.get("links", []) or []
    methods = findings.get("methods", []) or []
    dir_listing = findings.get("dir_listing", False)
    tls = findings.get("tls", {})

    evidence = {"params": params, "forms": forms, "cookies": cookies, "links": links, "methods": methods, "dir_listing": dir_listing, "tls": tls}
    detected = []
    lower = {k.lower(): v for k,v in headers.items()}

    # Clickjacking
    if not lower.get("x-frame-options") and not lower.get("content-security-policy"):
        tpl = _ATTACK_TEMPLATES["clickjacking"]
        detected.append({
            "id":"clickjacking","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":score_likelihood("clickjacking", evidence),
            "evidence":{"missing_headers":["x-frame-options","content-security-policy"]}
        })

    # XSS
    if (forms or params) and not lower.get("content-security-policy"):
        tpl = _ATTACK_TEMPLATES["xss_reflected"]
        detected.append({
            "id":"xss_reflected","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":score_likelihood("xss_reflected", evidence),
            "evidence":{"forms":len(forms),"params":len(params)}
        })

    # Session hijack (cookie flags)
    if cookies:
        missing_flags = []
        for c in cookies:
            flags = [f.lower() for f in c.get("flags",[])]
            if "httponly" not in flags or "secure" not in flags:
                missing_flags.append({"name": c.get("name"), "flags": c.get("flags")})
        if missing_flags:
            tpl = _ATTACK_TEMPLATES["session_hijack"]
            detected.append({
                "id":"session_hijack","title":tpl["title"],"severity":tpl["severity"],
                "description":tpl["description"],"exploit_example":tpl["exploit_example"],
                "mitigation":tpl["mitigation"],"likelihood":score_likelihood("session_hijack", evidence),
                "evidence":{"cookies_missing_flags":missing_flags}
            })

    # Mixed content / insecure TLS
    if tls.get("is_https"):
        http_links = [l for l in links if str(l).lower().startswith("http://")]
        if http_links:
            tpl = _ATTACK_TEMPLATES["insecure_tls"]
            detected.append({
                "id":"insecure_tls","title":tpl["title"],"severity":tpl["severity"],
                "description":tpl["description"],"exploit_example":tpl["exploit_example"],
                "mitigation":tpl["mitigation"],"likelihood":score_likelihood("insecure_tls", {"http_links": http_links,"tls":tls}),
                "evidence":{"http_links":http_links}
            })

    # Directory listing
    if dir_listing:
        tpl = _ATTACK_TEMPLATES["dir_listing"]
        detected.append({
            "id":"dir_listing","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":score_likelihood("dir_listing", evidence),
            "evidence":{}
        })

    # Dangerous HTTP methods
    risky = [m for m in methods if m.upper() in ("PUT","DELETE","TRACE","CONNECT")]
    if risky:
        detected.append({
            "id":"http_methods","title":"Dangerous HTTP Methods Allowed","severity":"Medium",
            "description":"Server allows risky HTTP methods.","exploit_example":"Attacker may upload or delete resources.",
            "mitigation":["Disable unused HTTP methods on the server"],"likelihood":"Likely",
            "evidence":{"risky_methods":risky}
        })

    # Server banner
    if findings.get("server"):
        tpl = _ATTACK_TEMPLATES["server_version"]
        detected.append({
            "id":"server_version","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":"Possible",
            "evidence":{"server":findings.get("server")}
        })

    # Open redirect
    lower_params = [p.lower() for p in params]
    if any(p in ("next","redirect","url","return") for p in lower_params):
        tpl = _ATTACK_TEMPLATES["open_redirect"]
        detected.append({
            "id":"open_redirect","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":"Possible",
            "evidence":{"params":[p for p in params if p.lower() in ("next","redirect","url","return")]}
        })

    # SSRF heuristic
    if any(p in ("url","target","resource") for p in lower_params) and forms:
        tpl = _ATTACK_TEMPLATES["ssrf"]
        detected.append({
            "id":"ssrf","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":"Possible","evidence":{}
        })

    # SQLi heuristic
    sql_params = [p for p in lower_params if p in ("id","uid","user","product","item")]
    if sql_params and (forms or params):
        tpl = _ATTACK_TEMPLATES["sql_injection"]
        detected.append({
            "id":"sql_injection","title":tpl["title"],"severity":tpl["severity"],
            "description":tpl["description"],"exploit_example":tpl["exploit_example"],
            "mitigation":tpl["mitigation"],"likelihood":score_likelihood("sql_injection", evidence),
            "evidence":{"suspicious_params":sql_params}
        })

    return detected

# --------------------------- Networking / crawler ---------------------------
class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.interval = 1.0 / max(rate_per_sec, 0.1)
        self._last = 0.0
    async def wait(self):
        now = time.time()
        delta = self._last + self.interval - now
        if delta > 0:
            await asyncio.sleep(delta)
        self._last = time.time()

async def fetch_page(session: aiohttp.ClientSession, url: str, allow_redirects: bool=True, timeout:int=15):
    try:
        async with session.get(url, timeout=ClientTimeout(total=timeout), allow_redirects=allow_redirects) as resp:
            ctype = resp.headers.get("Content-Type","")
            text = None
            if "text" in ctype or "html" in ctype:
                try:
                    text = await resp.text(errors="ignore")
                except Exception:
                    text = None
            headers = dict(resp.headers or {})
            return resp.status, headers, text, str(resp.url)
    except asyncio.CancelledError:
        raise
    except Exception:
        return None, {}, None, url

async def head_request(session: aiohttp.ClientSession, url: str):
    try:
        async with session.head(url, timeout=ClientTimeout(total=10)) as resp:
            return resp.status, dict(resp.headers or {})
    except Exception:
        return None, {}

async def check_dir_listing(session: aiohttp.ClientSession, url: str) -> bool:
    try:
        async with session.get(url, timeout=ClientTimeout(total=8)) as resp:
            text = await resp.text(errors="ignore")
            if resp.status == 200 and ("Index of /" in text or "<title>Index of" in text):
                return True
    except Exception:
        pass
    return False

async def crawl(start_url: str, max_pages:int=DEFAULT_MAX_PAGES, rate:float=DEFAULT_RATE, concurrency:int=DEFAULT_CONCURRENCY, allow_redirects:bool=True):
    start_url = sanitize_url(start_url)
    parsed_start = urlparse(start_url)
    base_origin = f"{parsed_start.scheme}://{parsed_start.netloc}"

    queue = deque([start_url])
    seen = set()
    results = []
    rate_limiter = RateLimiter(rate)
    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": USER_AGENT}
    timeout = ClientTimeout(total=20)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        pbar = tqdm(total=max_pages, desc="Crawling", unit="pages", ncols=80)
        async def worker(url):
            async with sem:
                await rate_limiter.wait()
                status, hdrs, body, final = await fetch_page(session, url, allow_redirects=allow_redirects)
                finding = {"url": url, "final_url": final or url, "status": status, "headers": hdrs or {}, "content": body}
                finding["server"] = (hdrs or {}).get("Server") or (hdrs or {}).get("server") or ""
                finding["tls"] = {"is_https": parsed_start.scheme == 'https', "valid": True}
                if body:
                    finding["forms"] = extract_forms(body, url)
                    finding["links"] = [l for l in extract_links(body, url) if is_same_origin(base_origin, l)]
                else:
                    finding["forms"] = []
                    finding["links"] = []
                try:
                    parsed = urlparse(url)
                    q = parsed.query
                    params = []
                    if q:
                        for part in q.split('&'):
                            if '=' in part:
                                params.append(part.split('=')[0])
                    finding["params"] = params
                except Exception:
                    finding["params"] = []
                hdrs_local = hdrs or {}
                sc = hdrs_local.get('Set-Cookie')
                cookies = []
                if sc:
                    parts = sc.split(',')
                    for p in parts:
                        name = p.split('=')[0].strip()
                        flags = []
                        if 'HttpOnly' in p:
                            flags.append('HttpOnly')
                        if 'Secure' in p:
                            flags.append('Secure')
                        cookies.append({"name":name,"flags":flags})
                finding["cookies"] = cookies
                try:
                    st, h = await head_request(session, url)
                    finding["methods"] = []
                except Exception:
                    finding["methods"] = []
                try:
                    path_url = url if url.endswith('/') else url + '/'
                    listing = await check_dir_listing(session, path_url)
                    finding["dir_listing"] = listing
                except Exception:
                    finding["dir_listing"] = False

                header_analysis = analyze_headers(finding["headers"])
                finding.update(header_analysis)

                attacks = analyze_findings_for_attacks(finding)
                finding["attacks"] = attacks

                results.append(finding)
                pbar.update(1)

                for l in finding.get("links", []):
                    if l not in seen and len(seen) + len(queue) < max_pages:
                        if is_same_origin(base_origin, l):
                            queue.append(l)
                seen.add(url)

        try:
            while queue and len(seen) < max_pages:
                url = queue.popleft()
                if url in seen:
                    continue
                await worker(url)
        except KeyboardInterrupt:
            pass
        finally:
            pbar.close()
    return results

# --------------------------- Reports ---------------------------
def generate_json_report(results: list, target: str, out_path: str):
    payload = {"target": target, "scanned_at": datetime.datetime.utcnow().isoformat() + 'Z', "findings": results}
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, indent=2)
    return out_path

def generate_html_report(results: list, target: str, out_path: str):
    findings_flat = []
    counts = {"High":0,"Medium":0,"Low":0}
    for f in results:
        for a in f.get('attacks', []):
            findings_flat.append({
                'title': a.get('title'),
                'severity': a.get('severity'),
                'description': a.get('description'),
                'exploit_example': a.get('exploit_example'),
                'mitigation': a.get('mitigation'),
                'likelihood': a.get('likelihood'),
                'evidence': a.get('evidence'),
                'url': f.get('url')
            })
            counts[a.get('severity','Low')] = counts.get(a.get('severity','Low'),0) + 1
    template = Template(HTML_TEMPLATE)
    rendered = template.render(target=target, scanned_at=datetime.datetime.utcnow().isoformat() + 'Z', findings=findings_flat, summary=counts)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(rendered)
    return out_path

# --------------------------- Pretty Terminal Output ---------------------------
def pretty_terminal_report(results: list, target: str):
    # Build list of all attacks flattened with url reference
    flattened = []
    for f in results:
        for a in f.get("attacks", []):
            flattened.append({"url": f.get("url"), **a})

    # Count severities
    high = sum(1 for a in flattened if a.get("severity") == "High")
    medium = sum(1 for a in flattened if a.get("severity") == "Medium")
    low = sum(1 for a in flattened if a.get("severity") == "Low")

    # Header
    print("="*60)
    print("MCA Web Scanner".center(60))
    print(f"Target: {target}")
    print(f"Scan Time: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("="*60 + "\n")

    # Summary (colored)
    print(Fore.RED + f"🔴 High Risk: {high}")
    print(Fore.YELLOW + f"🟡 Medium Risk: {medium}")
    print(Fore.GREEN + f"🟢 Low Risk: {low}")
    voice(f"High Risk: {high},  Medium Risk: {medium}, Low Risk: {low}","s.mp3")
    voice(f"DETAILED FINDINGS","s.mp3")
    print("\n" + "-"*20 + " DETAILED FINDINGS " + "-"*20 + "\n")
    

    # Order attacks High -> Medium -> Low and print
    order = {"High":0,"Medium":1,"Low":2}
    flattened.sort(key=lambda x: (order.get(x.get("severity","Low"),2), x.get("title","")))

    if not flattened:
        print("(No issues detected - nothing to show)\n")
        voice("(No issues detected - nothing to show ","s.mp3")
    else:
        idx = 1
        for a in flattened:
            sev = a.get("severity","Low")
            icon = "🔴" if sev=="High" else "🟡" if sev=="Medium" else "🟢"
            
            color = Fore.RED if sev=="High" else Fore.YELLOW if sev=="Medium" else Fore.GREEN
            title = a.get("title")
            url = a.get("url")
            likelihood = a.get("likelihood","Possible")
            fix = a.get("mitigation",[])
            fix_short = ", ".join(fix[:1]) if fix else "(see report)"
            print(f"{color}[{icon}] {title}")
            print(f"URL: {url}")
            print(f"Likelihood: {likelihood}")
            print(f"Fix: {fix_short}\n")
            idx += 1

    print("="*60)
    # INPUT POINTS box: collect up to 2 input points (forms or param-bearing pages)
    input_points = []
    for f in results:
        # forms
        for fm in f.get("forms", []):
            input_points.append({"url": fm.get("action"), "type": "form", "inputs": fm.get("inputs", [])})
        # query params (if any)
        if f.get("params"):
            # reconstruct example URL (keep original query keys)
            p = urlparse(f.get("url"))
            q = "&".join([f"{k}=<val>" for k in f.get("params")])
            sample = p.scheme + "://" + p.netloc + p.path + ("?"+q if q else "")
            input_points.append({"url": sample, "type": "query", "params": f.get("params")})
    # keep unique in order
    seen = set(); uniq = []
    for ip in input_points:
        if ip["url"] not in seen:
            uniq.append(ip); seen.add(ip["url"])
    uniq = uniq[:2]  # show up to 2
    print("INPUT POINT")
    voice(" INPUT POINT","s.mp3")
    # Prepare box lines
    if uniq:
        lines = []
        for i, ip in enumerate(uniq, start=1):
            if ip["type"] == "form":
                inputs = ", ".join(ip.get("inputs") or ["(no named inputs)"])
                lines.append(f"{i}) {ip['url']}")
                lines.append(f"   - type: form (inputs: {inputs})")
                voice(f"type: form (inputs: {inputs}","s.mp3")
            else:
                params = ", ".join(ip.get("params") or [])
                lines.append(f"{i}) {ip['url']}")
                lines.append(f"   - type: query parameter (params: {params})")
            lines.append("")
    else:
        lines = ["No input points discovered during crawl."]
        
    width = max(len(line) for line in lines) + 2
    print("┌" + "─"*width + "┐")
    for line in lines:
        print("│ " + line.ljust(width-1) + "│")
    print("└" + "─"*width + "┘")
    print("="*60 + "\n")
    voice(f" No input points discovered during crawl","s.mp3")

# --------------------------- CLI / Main flow ---------------------------
def confirm_permission():
    voice("WARNING: Only scan targets you own or have explicit permission to test ","s.mp3")
    print(Fore.YELLOW + "LEGAL WARNING: Only scan targets you own or have explicit permission to test.")
    voice("Type YES to continue ","s.mp3")
    resp = input('Type YES to continue: ').strip()
    return resp == 'YES',

async def main_async(args):
    if not args.assume_yes:
        ok = confirm_permission()
        if not ok:
            print(Fore.RED + "Permission not confirmed. Exiting.")
            voice("Permission not confirmed. Exiting","s.mp3")
            sys.exit(3)

    results = await crawl(args.target, max_pages=args.max_pages, rate=args.rate, concurrency=DEFAULT_CONCURRENCY, allow_redirects=True)

    # pretty terminal output
    pretty_terminal_report(results, args.target)

    # write json/html if requested
    if args.json:
        path = args.json
        generate_json_report(results, args.target, path)
        print(Fore.GREEN + f"JSON report saved to {path}")
    if args.output:
        opath = args.output
        generate_html_report(results, args.target, opath)
        print(Fore.GREEN + f"HTML report saved to {opath}")

def parse_args():
    parser = argparse.ArgumentParser(prog='MCA Web Scanner', description='MCA Web Scanner - passive, user-friendly web scanner')
    voice("(No issues detected - nothing to show ","s.mp3")
    parser.add_argument('-t','--target', required=False, help='Target URL (e.g. https://example.com). If omitted the program will prompt you.')
    parser.add_argument('-m','--max-pages', type=int, default=DEFAULT_MAX_PAGES, help='Maximum pages to crawl (default 30)')
    parser.add_argument('-r','--rate', type=float, default=DEFAULT_RATE, help='Requests per second (default 2.0)')
    parser.add_argument('--ignore-robots', action='store_true', help='Ignore robots.txt (use responsibly)')  # placeholder - not implemented
    parser.add_argument('--output', help='HTML output path (e.g. report.html)')
    parser.add_argument('--json', help='JSON output path (e.g. report.json)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored terminal output')  # placeholder
    parser.add_argument('--assume-yes', action='store_true', help='Assume permission answered YES and skip interactive prompt')
    return parser.parse_args()

def main():
    args = parse_args()

    # interactive quick paste
    if not args.target:
        try:
            
            print('\033[32mPaste the target URL and press Enter (leave empty to exit)\n')
            voice("Paste the target URL and press Enter (leave empty to exit","s.mp3")
            voice("Enter  target URL ","s.mp3")
            target_inp = input('''\033[1m\033[96m    ┌──(\033[93m Enter  target URL\033[96m¯\_(ツ)_/¯ \033[93mMCA\033[96m)-[~/^⁠_⁠^]\n    └──╼$: \033[94m''').strip()
            
            if not target_inp:
                voice("No target provided. Exiting ","s.mp3")
                print('\033[91mNo target provided. Exiting.')
                
                sys.exit(0)
            args.target = target_inp
        except KeyboardInterrupt:
            print('\n\033[91mCancelled by user.')
            sys.exit(0)

    args.target = sanitize_url(args.target)

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print('\n' + Fore.RED + 'Scan interrupted by user.')
        sys.exit(4)
    except Exception as e:
        print(Fore.RED + f'Unexpected error: {e}')
        sys.exit(4)

if __name__ == '__main__':
    main()