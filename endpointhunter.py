#!/usr/bin/env python3
"""
EndpointHunter - Extract API endpoints, LFI paths, secrets from JS/CSS/HTML
Usage:
  python3 endpointhunter.py -u https://target.com
  python3 endpointhunter.py -u https://target.com -o results.txt
  cat urls.txt | python3 endpointhunter.py
  cat urls.txt | python3 endpointhunter.py -o results.txt --threads 5
"""

import re
import sys
import argparse
import urllib.parse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] requests not found. Run: pip install requests")
    sys.exit(1)

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[1m";  D = "\033[2m"; X = "\033[0m"

BANNER = f"""
{C}{'═'*65}
{B}
   ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗
   ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝
   █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║   
   ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║   
   ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║   
   ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝  
         ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗        
         ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗       
         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝       
         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗       
         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║       
         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       
{X}{C}{'═'*65}{X}
  {D}JS · CSS · HTML  Endpoint & Path Extractor — Bug Bounty Edition{X}
{C}{'─'*65}{X}
  {B}{G} Author     {X}  MrDestroyer
  {B}{Y} YouTube    {X}  @Study_Hard69
  {B}{R} TryHackMe  {X}  tryhackme.com/p/MohammadZim
  {B}{C} Facebook   {X}  facebook.com/zimthegoat
  {B}{R} Instagram  {X}  @zimthegoat
{C}{'═'*65}{X}
"""

PATTERNS = {
    "API Endpoint": [
        r'["\'`](/(?:api|v\d+|graphql|gql|rest|rpc|service|internal|admin|user|auth|login|logout|register|upload|download|search|query|data|json|xml|config|settings|account|dashboard|webhook|callback|oauth|token|refresh|verify|validate|submit|process|checkout|payment|order|product|item|list|detail|info|status|health|ping|version)(?:/[^\s"\'`<>?#&]{0,100})?(?:\?[^\s"\'`<>]{0,150})?)["\'`]',
        r'["\'`]([^\s"\'`<>]{0,50}/(?:api|v\d+|graphql|gql|rest|rpc)(?:/[^\s"\'`<>?#]{0,100})?)["\'`]',
        r'(?:fetch|axios\.(?:get|post|put|delete|patch|head)|XMLHttpRequest|\.open)\s*\(\s*["\'`]([^"\'`\s]{3,200})["\'`]',
        r'(?:url|endpoint|path|route|action|src|href|redirect|location)\s*[=:]\s*["\'`]([/][^"\'`<>\s\n]{2,200})["\'`]',
        r'(?:baseURL|baseUrl|base_url|API_URL|apiUrl|apiEndpoint)\s*[=:]\s*["\'`](https?://[^"\'`\s]{5,200})["\'`]',
    ],
    "Query Parameter": [
        r'["\'`]([^"\'`<>\s\n]*\?(?:[a-zA-Z0-9%_\-\[\]\.]+(?:=(?:[^&"\'`\s]{0,80})?)?&?){1,15})["\'`]',
    ],
    "LFI / Path Traversal": [
        r'["\'`]([^"\'`]*(?:\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e|\.\.%2f|\.\.%5c)[^"\'`\s]{0,200})["\'`]',
        r'["\'`]([^"\'`]*(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|/var/log|/var/www|/windows/win\.ini|/boot\.ini|c:\\\\windows|c:/windows)[^"\'`\s]{0,100})["\'`]',
        r'(?:include|require|require_once|include_once|file_get_contents|fopen|readfile)\s*\(\s*["\'`\$]([^"\'`\)]{3,150})',
    ],
    "Secret / Token / Key": [
        r'(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?key|client[_\-]?secret|consumer[_\-]?key)\s*[=:]\s*["\'`]([^"\'`\s]{6,150})["\'`]',
        r'(?:access[_\-]?token|auth[_\-]?token|bearer|refresh[_\-]?token|id[_\-]?token|session[_\-]?token)\s*[=:]\s*["\'`]([^"\'`\s]{6,250})["\'`]',
        r'(?:password|passwd|pwd)\s*[=:]\s*["\'`]([^"\'`\s]{4,100})["\'`]',
        r'(?:secret|private[_\-]?key|signing[_\-]?key)\s*[=:]\s*["\'`]([^"\'`\s]{6,200})["\'`]',
        r'["\'`]((?:AKIA|ASIA|AROA)[A-Z0-9]{16})["\'`]',
        r'(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})',
    ],
    "S3 / Cloud Storage": [
        r'((?:https?://)?[a-zA-Z0-9\-\.]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com[^\s"\'`<>]*)',
        r'((?:https?://)?s3[.\-][a-z0-9\-]*\.amazonaws\.com/[a-zA-Z0-9\-\./_?=&%+]{3,200})',
        r'((?:https?://)?storage\.googleapis\.com/[^\s"\'`<>]{5,200})',
        r'((?:https?://)?[a-z0-9\-]+\.blob\.core\.windows\.net[^\s"\'`<>]*)',
    ],
    "Internal Host / IP": [
        r'["\'`]((?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0)(?::\d{1,5})?(?:/[^\s"\'`<>]*)?)["\'`]',
    ],
    "Absolute URL": [
        r'["\'`](https?://[^\s"\'`<>\n]{10,300})["\'`]',
    ],
}

NOISE_RE = re.compile(
    r'\.(png|jpg|jpeg|gif|svg|ico|webp|bmp|woff|woff2|ttf|eot|otf'
    r'|mp4|webm|mp3|wav|pdf|zip|tar|gz|map)(\?[^\s]*)?$'
    r'|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare'
    r'|fonts\.googleapis|fonts\.gstatic|google-analytics|googletagmanager'
    r'|doubleclick|data:image|data:application',
    re.IGNORECASE
)

CAT_COLOR = {
    "API Endpoint":        G,
    "Query Parameter":     Y,
    "LFI / Path Traversal": R,
    "Secret / Token / Key": R,
    "S3 / Cloud Storage":  C,
    "Internal Host / IP":  R,
    "Absolute URL":        D,
}

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "*/*",
})


class ResourceParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.resources = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        src = None
        if tag == "script" and attrs.get("src"):
            src = attrs["src"]
        elif tag == "link" and "stylesheet" in attrs.get("rel", ""):
            src = attrs.get("href")
        if src and not src.startswith("data:"):
            self.resources.append(urllib.parse.urljoin(self.base_url, src))


def fetch(url, timeout=10):
    try:
        r = SESSION.get(url, timeout=timeout, verify=False,
                        allow_redirects=True)
        r.raise_for_status()
        return r.text, r.url
    except requests.exceptions.Timeout:
        print(f"  {R}[TIMEOUT]{X} {url}", file=sys.stderr)
    except requests.exceptions.SSLError:
        # retry without verify (already off, try http fallback)
        try:
            r = SESSION.get(url.replace("https://", "http://"),
                            timeout=timeout, verify=False, allow_redirects=True)
            return r.text, r.url
        except Exception:
            pass
        print(f"  {R}[SSL ERR]{X} {url}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
        print(f"  {R}[CONN ERR]{X} {url}", file=sys.stderr)
    except Exception as e:
        print(f"  {R}[ERR]{X} {url} — {e}", file=sys.stderr)
    return None, None


def extract(content):
    found = {}
    for cat, patterns in PATTERNS.items():
        hits = set()
        for pat in patterns:
            try:
                for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                    val = (m.group(1) if m.lastindex else m.group(0)).strip(" \t\r\n'\"` ")
                    if val and 2 < len(val) < 300 and not NOISE_RE.search(val):
                        hits.add(val)
            except re.error:
                pass
        if hits:
            found[cat] = sorted(hits)
    return found


def print_findings(findings, label, out_lines):
    if not findings:
        return
    for cat, items in findings.items():
        color = CAT_COLOR.get(cat, X)
        header = f"  {D}[{label}]{X}  {B}{color}{cat}{X}"
        print(header)
        if out_lines is not None:
            out_lines.append(f"[{label}]  {cat}")
        for item in items:
            print(f"      {color}{item}{X}")
            if out_lines is not None:
                out_lines.append(f"    {item}")
    sys.stdout.flush()


def process(target, out_lines, timeout=10):
    if not target.startswith("http"):
        target = "https://" + target

    print(f"\n{B}{C}[TARGET]{X} {target}")
    sys.stdout.flush()

    html, final_url = fetch(target, timeout=timeout)
    if not html:
        print(f"  {R}[SKIP]{X} No response")
        return

    base = final_url or target
    size = len(html)
    print(f"  {D}→ HTML: {size} bytes{X}")
    sys.stdout.flush()

    findings = extract(html)
    if findings:
        print_findings(findings, "HTML", out_lines)
    else:
        print(f"  {D}→ No findings in page HTML{X}")
    sys.stdout.flush()

    parser = ResourceParser(base)
    try:
        parser.feed(html)
    except Exception:
        pass
    resources = list(dict.fromkeys(parser.resources))

    if not resources:
        print(f"  {D}→ No external JS/CSS resources found{X}")
        sys.stdout.flush()
        return

    print(f"  {D}→ {len(resources)} JS/CSS resource(s) found{X}")
    sys.stdout.flush()

    def scan_resource(url):
        content, _ = fetch(url, timeout=timeout)
        if not content:
            return url, {}
        return url, extract(content)

    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(scan_resource, r): r for r in resources}
        for fut in as_completed(futs):
            try:
                res_url, res_findings = fut.result()
                label = res_url.split("?")[0].rstrip("/").split("/")[-1][:55] or res_url[-40:]
                if res_findings:
                    print_findings(res_findings, label, out_lines)
                else:
                    print(f"  {D}→ {label}: no findings{X}")
                sys.stdout.flush()
            except Exception as e:
                print(f"  {R}[ERR]{X} {e}", file=sys.stderr)


def main():
    print(BANNER)
    sys.stdout.flush()

    ap = argparse.ArgumentParser(
        description="EndpointHunter — JS/CSS/HTML Endpoint Extractor",
        epilog=(
            "Examples:\n"
            "  python3 endpointhunter.py -u https://target.com\n"
            "  cat urls.txt | python3 endpointhunter.py\n"
            "  cat urls.txt | python3 endpointhunter.py -o out.txt --threads 5"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("-u", "--url",    help="Single target URL")
    ap.add_argument("-o", "--output", help="Write results to file")
    ap.add_argument("--threads", type=int, default=3,
                    help="Parallel targets (default: 3)")
    ap.add_argument("--timeout", type=int, default=10,
                    help="Timeout per request in seconds (default: 10)")
    args = ap.parse_args()

    urls = []
    if args.url:
        urls.append(args.url.strip())
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    if not urls:
        ap.print_help()
        sys.exit(1)

    urls = list(dict.fromkeys(urls))
    print(f"{B}Targets loaded:{X} {len(urls)}")
    sys.stdout.flush()

    out_lines = [] if args.output else None

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(process, u, out_lines, args.timeout) for u in urls]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                print(f"{R}[FATAL]{X} {e}", file=sys.stderr)

    if args.output and out_lines:
        with open(args.output, "w") as fh:
            fh.write("\n".join(out_lines) + "\n")
        print(f"\n{G}[+] Saved → {args.output}{X}")

    print(f"\n{D}Done.{X}\n")


if __name__ == "__main__":
    main()
