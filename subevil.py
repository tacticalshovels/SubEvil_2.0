#!/usr/bin/env python3
import sys
import os
import argparse
import json
import csv
import socket
import re
from http.client import HTTPConnection, HTTPSConnection
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from Modules.alienvault import alienvault
from Modules.anubis import anubis
from Modules.binaryedge import binaryedge
from Modules.censys import censys
from Modules.certspotter import certspotter
from Modules.crt import crt
from Modules.dns_bufferover import dns_bufferover
from Modules.dnsdb import dnsdb
from Modules.facebook import facebook
from Modules.hackertarget import hackertarget
from Modules.omnisint import omnisint
from Modules.passivetotal import passivetotal
from Modules.riddler import riddler
from Modules.securitytrails import securitytrails
from Modules.shodan import shodan
from Modules.spyse import spyse
from Modules.sublist3r import sublist3r
from Modules.threatcrowd import threatcrowd
from Modules.threatminer import threatminer
from Modules.tls_bufferover import tls_bufferover
from Modules.urlscan import urlscan
from Modules.virustotal import virustotal
from Modules.whoisxmlapi import whoisxmlapi
from Modules.recondev import recondev

VERSIONS = "V2.0.0"

# --------- Utilities ---------
def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def idna_normalize(host: str) -> str:
    if not host:
        return ""
    host = host.strip().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host

def is_subdomain(host: str, root: str) -> bool:
    if not host or not root:
        return False
    h = idna_normalize(host).lower()
    r = idna_normalize(root).lower()
    return h == r or h.endswith("." + r)

@contextmanager
def silent(enabled: bool):
    """Suppress stdout/stderr when enabled=True."""
    if not enabled:
        yield
        return
    devnull = open(os.devnull, "w")
    try:
        with redirect_stdout(devnull), redirect_stderr(devnull):
            yield
    finally:
        devnull.close()

SOURCES = {
    "alienvault": alienvault,
    "anubis": anubis,
    "binaryedge": binaryedge,
    "censys": censys,
    "certspotter": certspotter,
    "crt": crt,
    "dns_bufferover": dns_bufferover,
    "dnsdb": dnsdb,
    "facebook": facebook,
    "hackertarget": hackertarget,
    "omnisint": omnisint,
    "passivetotal": passivetotal,
    "riddler": riddler,
    "securitytrails": securitytrails,
    "shodan": shodan,
    "spyse": spyse,
    "sublist3r": sublist3r,
    "threatcrowd": threatcrowd,
    "threatminer": threatminer,
    "tls_bufferover": tls_bufferover,
    "urlscan": urlscan,
    "virustotal": virustotal,
    "whoisxmlapi": whoisxmlapi,
    "recondev": recondev,
}

def harvest(source_name, func, root):
    out = []
    try:
        for item in (func(root) or []):
            host = str(item).split(",")[0].strip()
            host = idna_normalize(host)
            if is_subdomain(host, root):
                out.append(host)
    except Exception:
        pass
    return source_name, out

# --- Probing with optional details ---
def probe_host(host, timeout=4, want_details=False):
    """
    Try HTTP first then HTTPS. Return dict if alive:
      - minimal: {"host": host}
      - details: {"host": host, "status": int, "title": str}
    """
    for scheme, conn_cls, port in (("http", HTTPConnection, 80),
                                   ("https", HTTPSConnection, 443)):
        try:
            conn = conn_cls(host, port, timeout=timeout)
            conn.request("GET", "/", headers={"User-Agent": "SubEvil"})
            resp = conn.getresponse()
            body = resp.read(4096).decode(errors="ignore")
            conn.close()
            if 100 <= resp.status < 600:
                if want_details:
                    title_match = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                    title = title_match.group(1).strip() if title_match else ""
                    if len(title) > 200:
                        title = title[:200] + "..."
                    return {"host": host, "status": resp.status, "title": title}
                else:
                    return {"host": host}
        except (OSError, socket.error):
            continue
        except Exception:
            continue
    return None

# --- DNS resolution (single IP per host) ---
def resolve_ip(host):
    """Return a single IP (prefer IPv4, fallback IPv6)."""
    try:
        infos = socket.getaddrinfo(host, None)
        ipv4 = next((i[4][0] for i in infos if i[0] == socket.AF_INET), None)
        if ipv4:
            return ipv4
        ipv6 = next((i[4][0] for i in infos if i[0] == socket.AF_INET6), None)
        return ipv6
    except Exception:
        return None

def parse_args():
    parser = argparse.ArgumentParser(description="Subdomain recon (stdlib-only).")
    parser.add_argument('domain', help="Root domain (e.g., example.com)")
    parser.add_argument('--max-workers', type=int, default=24, help="Concurrency for I/O tasks")
    parser.add_argument('--timeout', type=int, default=4, help="Probe timeout in seconds (default: 4)")
    parser.add_argument('--output','-o', help="Write results to this file (otherwise stdout)")
    parser.add_argument('--format','-f', choices=['text','json','csv','ndjson'], default='text',
                        help="Output format (default: text)")
    parser.add_argument('--with-sources', action='store_true',
                        help="Include source attribution (json/csv/ndjson only)")
    parser.add_argument('--details', action='store_true',
                        help="Include status code and page title in results")
    parser.add_argument('--resolve', dest='resolve', action='store_true', default=True,
                        help="Resolve IP addresses for each alive subdomain (default: on)")
    parser.add_argument('--no-resolve', dest='resolve', action='store_false',
                        help="Disable IP resolution")
    parser.add_argument('--quiet','-q', action='store_true',
                        help="Suppress logs/banners even in text mode")
    parser.add_argument('--version','-v', action='store_true', help="Show version and exit")
    return parser.parse_args()

def emit_output(stream, fmt, results, sources_map, with_sources, quiet, resolve_enabled):
    if fmt == 'text':
        # Quiet or default stdout prints simplified lines
        if quiet:
            for r in results:
                if resolve_enabled and r.get("ip"):
                    stream.write(f"{r['host']} {r['ip']}\n")
                else:
                    stream.write(r["host"] + "\n")
        else:
            # Human-friendly text with optional details + IP
            for r in results:
                parts = [r["host"]]
                if "status" in r:
                    parts.append(f"[{r['status']}]")
                if r.get("title"):
                    parts.append(r["title"])
                if resolve_enabled and r.get("ip"):
                    parts.append(f"({r['ip']})")
                stream.write(" ".join(parts).rstrip() + "\n")
    elif fmt == 'json':
        payload = []
        for r in results:
            entry = dict(r)
            if not resolve_enabled:
                entry.pop("ip", None)
            if with_sources:
                entry["sources"] = sorted(sources_map.get(r["host"], ()))
            payload.append(entry)
        json.dump(payload, stream, indent=2)
    elif fmt == 'csv':
        headers = ["host"]
        if resolve_enabled:
            headers.append("ip")
        if results and "status" in results[0]:
            headers += ["status","title"]
        if with_sources:
            headers.append("sources")
        writer = csv.writer(stream)
        writer.writerow(headers)
        for r in results:
            row = [r["host"]]
            if resolve_enabled:
                row.append(r.get("ip",""))
            if "status" in r:
                row += [r["status"], r.get("title","")]
            if with_sources:
                row.append(";".join(sorted(sources_map.get(r["host"], ()))))
            writer.writerow(row)
    elif fmt == 'ndjson':
        for r in results:
            obj = dict(r)
            if not resolve_enabled:
                obj.pop("ip", None)
            if with_sources:
                obj["sources"] = sorted(sources_map.get(r["host"], ()))
            stream.write(json.dumps(obj, separators=(",", ":")) + "\n")

def write_output(path, fmt, results, sources_map, with_sources, human_mode, quiet_effective, resolve_enabled):
    if path:
        newline = "" if fmt == "csv" else None
        with open(path, "w", encoding="utf-8", newline=newline) as f:
            emit_output(f, fmt, results, sources_map, with_sources, quiet_effective, resolve_enabled)
        if human_mode:
            print(f"Wrote {len(results)} alive hosts to {path} ({fmt})")
    else:
        emit_output(sys.stdout, fmt, results, sources_map, with_sources, quiet_effective, resolve_enabled)
        sys.stdout.flush()

def main():
    args = parse_args()
    if args.version:
        print(f"SubEvil {VERSIONS}")
        return 0

    # Auto-quiet: if text to stdout (no --output) and no details/sources, print minimal lines
    auto_quiet_stdout = (args.format == "text" and args.output is None and not args.details and not args.with_sources)
    quiet_effective = args.quiet or auto_quiet_stdout

    machine_mode = args.format in ("json", "csv", "ndjson")
    human_mode = (args.format == "text") and not quiet_effective

    if human_mode:
        clear_screen()
        print("="*60)
        print(f" SubEvil {VERSIONS}")
        print("="*60)
        print(f"Target: {args.domain}")
        print("Reconning sources…")

    # --- Gather subdomains from sources ---
    subdomains_set = set()
    sources_map = {}
    lock = Lock()
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        futures = {ex.submit(harvest, name, fn, args.domain): name for name, fn in SOURCES.items()}
        for fut in as_completed(futures):
            src, results = fut.result()
            with lock:
                for h in results:
                    subdomains_set.add(h)
                    sources_map.setdefault(h, set()).add(src)
            if human_mode:
                for h in results:
                    print(h)

    if human_mode:
        print("Probing discovered subdomains…")

    # --- Probe and collect ONLY alive ---
    alive = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        futures = {ex.submit(probe_host, h, args.timeout, args.details): h for h in subdomains_set}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                alive.append(r)

    # --- Resolve IPs if enabled ---
    if args.resolve and alive:
        if human_mode:
            print("Resolving IPs…")
        host_list = [r["host"] for r in alive]
        ip_map = {}
        with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
            futures = {ex.submit(resolve_ip, h): h for h in host_list}
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    ip_map[h] = fut.result()
                except Exception:
                    ip_map[h] = None
        # attach IPs
        for r in alive:
            r["ip"] = ip_map.get(r["host"])

    alive_sorted = sorted(alive, key=lambda x: x["host"])
    if human_mode:
        print(f"Alive subdomains [{len(alive_sorted)}]")

    write_output(args.output, args.format, alive_sorted, sources_map, args.with_sources, human_mode, quiet_effective, args.resolve)
    return 0

if __name__ == "__main__":
    sys.exit(main())
