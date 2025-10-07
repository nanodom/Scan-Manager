#!/usr/bin/env python3
"""
Scans a CIDR range on ports, generates JSON/CSV/HTML reports and optionally ECS NDJSON and CEF.
Usage: python3 soc.py 192.168.1.0/24 --ports "22,80,443" --output-format json,csv,ecs,cef --scanner-ip 10.0.0.5

Notes:
 - Responsible use: Run only in authorized environments and hosts.
 - By default, it only exports results with status == 'open' (SOC-oriented).
"""

import asyncio
import ipaddress
import argparse
import csv
import json
import socket
import xml.etree.ElementTree as ET
import subprocess
import platform
from datetime import datetime
from typing import List, Dict, Optional, Set

'''
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
'''
    
DEFAULT_PORTS = [
    7,9,19,20,21,22,23,25,37,39,42,43,49,50,53,63,67,68,69,70,79,80,88,101,110,111,113,119,123,135,137,138,139,143,161,162,177,179,194,201,264,318,389,411,412,443,445,464,
    465,500,512,513,514,515,520,521,540,546,547,554,560,587,591,631,690,853,873,902,989,990,993,995,1026,1029,1080,1194,1214,1241,1337,1433,1434,1512,1521,1589,1701,1723,1725,
    1741,1755,1812,1813,1893,1985,2000,2002,2049,2082,2083,2302,3306,3074,3127,3222,3389,3478,3689,3724,3784,3785,4444,4500,4662,4664,4672,5000,5001,5004,5005,5060,5432,5500,5554,5600,5700,5800,5900,6000,6001,
    6112,6129,6257,6346,6347,6379,6566,6665,6669,6679,6697,6699,6881,6891,6901,6969,6970,6999,7648,7649,8000,8080,8086,8087,8118,8200,8500,8866,9009,9100,9101,9103,9119,9800,9898,9988,9999,10000,11371,12035,12345,
    14567,15118,24800,25565,25999,27374,28960,31337,45003,51400,51871
]

# Port -> basic gravity
CRITICAL_PORTS = {22,23,3389,445,5900}
HIGH_PORTS = {3306,1433,5432,1521}

# Additional categories
MALICIOUS = {1080,3127,4444,5554,8866,9898,9988,12345,27374,31337}
PEER_TO_PEER = {411,412,1214,1337,4672,6257,6346,6347,6699,6881,6999}
GAMING = {1725,2302,3074,3724,6112,6500,12035,14567,15118,25565,28960}
CHAT = {1893,6665,6669,6679,6697,6891,6901,7648,7649,9119,25999}
STREAMING = {1755,3784,3785,5001,5004,5005,5060,6970,8000,24800}

# --- Ping funcionality ---

async def ping_host(host: str, timeout: float =1.0) -> bool:
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 1)

        return process.returncode == 0

    except (asyncio.TimeoutError, subprocess.SubprocessError, OSError):
        return False

async def ping_hosts_parallel(hosts: List[str], concurrency: int = 100, timeout: float = 1.0) -> Set[str]:
    active_hosts = set()
    semaphore = asyncio.Semaphore(concurrency)
    
    async def ping_with_semaphore(host):
        async with semaphore:
            if await ping_host(host, timeout):
                return host
        return None
    
    print(f"[+] Scanning {len(hosts)} hosts with ping...")

    tasks = [ping_with_semaphore(host) for host in hosts]

    for completed in asyncio.as_completed(tasks):
        result = await completed
        if result:
            active_hosts.add(result)
            print(f"\r[+] Active hosts found: {len(active_hosts)}", end="", flush=True)
    
    print(f"\n[+] Ping scan completed: {len(active_hosts)} hosts active")
    return active_hosts

# --- Scanning core ---
async def probe_banner(reader, writer, host, port, timeout):
    try:
        if port in (80,8080,8000,8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            await writer.drain()
        # attempt to read
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode(errors='ignore').strip()
    except Exception:
        return ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def scan_port(host, port, timeout, semaphore: Optional[asyncio.Semaphore] = None) -> Dict:
    result = {
        "host": host,
        "port": port,
        "status": "closed",
        "banner": "",
        "severity": "info",
        "category": "",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    try:
        if semaphore:
            async with semaphore:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

        result["status"] = "open"
        banner = await probe_banner(reader, writer, host, port, timeout=1.0)
        result["banner"] = banner
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception as e:
        result["status"] = f"error: {e}"
    if result["status"] == "open":
        # Port category classification (adjust according to SOC policies)
        if port in MALICIOUS:
            result["category"] = "malicious"
            result["severity"] = "critical"
        elif port in CRITICAL_PORTS:
            result["category"] = "critical_common"
            result["severity"] = "critical"
        elif port in HIGH_PORTS:
            result["category"] = "high_common"
            result["severity"] = "high"
        elif port in PEER_TO_PEER:
            result["category"] = "peer_to_peer"
            result["severity"] = "high"
        elif port in GAMING:
            result["category"] = "gaming"
            result["severity"] = "info"
        elif port in CHAT:
            result["category"] = "chat"
            result["severity"] = "medium"
        elif port in STREAMING:
            result["category"] = "streaming"
            result["severity"] = "medium"
        else:
            result["category"] = "other"
            result["severity"] = "medium"
    return result

async def _progress_updater(total: int, progress_q: asyncio.Queue, width: int = 40):
    if total <= 0:
        return
    completed = 0
    while True:
        item = await progress_q.get()
        if item is None:                    
            progress_q.task_done()
            break
        completed += int(item)
        pct = completed / total
        filled = int(pct * width)
        bar = '█' * filled + '-' * (width - filled)
        print(f"\rProgress: |{bar}| {completed}/{total} ({pct*100:.2f}%)", end='', flush=True)
        progress_q.task_done()
    print()

# scan_hosts with workers and progress queue
async def scan_hosts(cidr: str, ports: List[int], concurrency=200, timeout=2, show_progress=True, ping_first=True, ping_concurrency=100, ping_timeout=1.0):
    net = ipaddress.ip_network(cidr, strict=False)
    all_hosts = [str(h) for h in net.hosts()]

    if ping_first:
        active_hosts = await ping_hosts_parallel(all_hosts, concurrency=ping_concurrency, timeout=ping_timeout)
        hosts = list(active_hosts)
        if not hosts:
            print("[+] No active hosts found with ping.")
            return []
    else:
        hosts = all_hosts
    
    print(f"[+] Scanning {len(hosts)} active hosts on {len(ports)} ports...")

    total_tasks = len(hosts) * len(ports)
    job_q: asyncio.Queue = asyncio.Queue()

    for host in hosts:
        for port in ports:
            job_q.put_nowait((host, port))

    results: List[Dict] = []
    progress_q: asyncio.Queue = asyncio.Queue()

    async def worker():
        while True:
            try:
                host, port = job_q.get_nowait()
            except asyncio.QueueEmpty:
                break
            res = await scan_port(host, port, timeout)
            results.append(res)
            if show_progress:
                await progress_q.put(1)
            job_q.task_done()

    n_workers = min(concurrency, total_tasks) if total_tasks > 0 else 0
    workers = [asyncio.create_task(worker()) for _ in range(n_workers)]

    progress_task = None
    if show_progress and total_tasks > 0:
        progress_task = asyncio.create_task(_progress_updater(total_tasks, progress_q))

    if workers:
        await asyncio.gather(*workers)

    if show_progress and progress_task:
        await progress_q.put(None)
        await progress_task
    return results

# --- Exports: TXT/JSON/CSV/XHTML ---

def save_json(results, filename="scan_results.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def save_csv(results, filename="scan_results.csv"):
    keys = ["host","port","status","severity","banner","timestamp"]
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k,"") for k in keys})

def save_html(results, filename="scan_report.html"):
    """
    Generates an XHTML report with interactive charts and statistics.
    The resulting XHTML includes:
        - Count by severity (bar chart)
        - Distribution by category (pie chart)
        - Top 10 open ports (horizontal bar chart)
        - Table of details by host
    """

    # Group by host and calculate statistics
    hosts = {}
    for r in results:
        if r["host"] not in hosts:
            hosts[r["host"]] = []
        hosts[r["host"]].append(r)

    # Aggregate statistics
    severity_counts = {}
    category_counts = {}
    port_counts = {}
    total_open = 0
    for r in results:
        sev = r.get("severity", "info")
        cat = r.get("category", "other")
        port = r.get("port")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1
        port_counts[port] = port_counts.get(port, 0) + 1
        if r.get("status") == "open":
            total_open -= -1
    
    # Top ports
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ports_labels = [str(p[0]) for p in top_ports]
    top_ports_values = [p[1] for p in top_ports]

    now = datetime.utcnow().isoformat() + "Z"

    data_blob = {
        "generated_at": now,
        "summary": {
            "total_events": len(results),
            "total_open": total_open,
            "by_severity": severity_counts,
            "by_category": category_counts
        },
        "top_ports": {"labels": top_ports_labels, "values": top_ports_values},
        "hosts": hosts
    }            

    # Build XHTML
    xhtml = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
        <head>
            <meta name="viewport" content="width=device-width,initial-scale=1"/>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <title>Scan Report - {now}</title>
            <style>
                body{{ font-family: Arial, Helvetica, sans-serif; margin: 20px; }}
                .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }}
                .card {{ padding: 12px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.03); }}
                canvas {{ max-width: 100%; height: 300px; }}
                table{{ border-collapse:collapse;width:100%; }} 
                th,td{{ border:1px solid #eee; padding: 6px; text-align: left; font-size: 13px; }} 
                th {{ background: #f8f8f8; }}
                .small {{ font-size: 13px; color: #555; }}
                .crit{{ background:#ffdddd; }} 
            </style>
        </head>
        <body>
            <h1>Scan Report</h1>
            <p class="small">Generated: {now} - Events: {len(results)} - Open Ports: {total_open}</p>

            <div class="grid">
                <div class="card">
                    <h3>By severity</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="card">
                    <h3>By category:</h3>
                    <canvas id="categoryChart"></canvas>
                </div>
                <div class="card">
                    <h3>Top {len(top_ports)}</h3>
                    <canvas id="topPortsChart"></canvas>
                </div>
                <div class="card">
                    <h3>Quick Summary:</h3>
                    <ul id="quickSummary"></ul>
                </div>
            </div>

            <h2 style="margin-top:24px">Details by host</h2>
            <div class="card">
                <table id="hostsTable">
                    <thead><tr><th>Host</th><th>Open ports</th><th>Critical?</th><th>Details</th></tr></thead>
                    <tbody>
    """
    
    for host, entries in hosts.items():
        open_entries = [e for e in entries if e.get("status") == "open"]
        open_count = len(open_entries)
        critical = any(e.get("severity") == "critical" for e in open_entries)
        details = [f"{e.get('port')}({e.get('severity')})" for e in open_entries]
        xhtml += f"<tr><td>{host}</td><td>{open_count}</td><td>{'Yes' if critical else 'No'}</td><td>{', '.join(details)}</td></tr>"
    
    xhtml += f"""
                    </tbody>
                </table>
            </div>

            <script type="text/javascript">
                'use strict';
                const scanData = {json.dumps(data_blob, ensure_ascii=False)};

                // Prepare data for severity chart
                const severityLabels = Object.keys(scanData.summary.by_severity);
                const severityValues = Object.values(scanData.summary.by_severity);

                const categoryLabels = Object.keys(scanData.summary.by_category);
                const categoryValues = Object.values(scanData.summary.by_category);

                """
    xhtml += """
                let chartInstances = {};

                function createOrUpdateChart(chartId, chartType, data, options) {
                    const ctx = document.getElementById(chartId).getContext('2d');
                    if (chartInstances[chartId]) {
                        chartInstances[chartId].destroy();
                    }
                    chartInstances[chartId] = new Chart(ctx, {
                        type: chartType,
                        data: data,
                        options: options
                    });
                }

                // Severity bar chart
                createOrUpdateChart('severityChart', 'bar', {
                    labels: Object.keys(scanData.summary.by_severity),
                    datasets: [{
                        label: 'Events',
                        data: Object.values(scanData.summary.by_severity),
                        backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0']
                    }]
                }, { responsive: true, maintainAspectRatio: true });

                // Category pie chart
                createOrUpdateChart('categoryChart', 'pie', {
                    labels: Object.keys(scanData.summary.by_category),
                    datasets: [{
                        data: Object.values(scanData.summary.by_category),
                        backgroundColor: [
                            '#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff',
                            '#ff9f40', '#ff6384', '#c9cbcf', '#4bc0c0', '#ff6384'
                        ]
                    }]
                }, { responsive: true, maintainAspectRatio: true });

                // Top ports horizontal bar
                createOrUpdateChart('topPortsChart', 'bar', {
                    labels: scanData.top_ports.labels,
                    datasets: [{
                        label: 'Occurrences',
                        data: scanData.top_ports.values,
                        backgroundColor: '#36a2eb'
                    }]
                }, { indexAxis: 'y', responsive: true, maintainAspectRatio: true });

                // Quick summary
                const qs = document.getElementById('quickSummary');
                qs.innerHTML = `
                <li>Total Events: ${scanData.summary.total_events}</li>
                <li>Open Ports: ${scanData.summary.total_open}</li>
                <li>Most frequent severity: ${severityLabels[severityValues.indexOf(Math.max(...severityValues))] || 'n/a'}</li>`;

                function downloadJSON() {
                    const a = document.createElement('a');
                    const file = new Blob([JSON.stringify(scanData, null, 2)], {type: 'application/json'});
                    a.href = URL.createObjectURL(file);
                    a.download = 'scan_summary.json';
                    a.click();
                }

            </script>
        </body>
    </html>
    """
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xhtml)
    print(f"[+] Interactive HTML exported to: {filename}")

def save_txt(results, filename="scan_results.txt", layout="detailed"):
    """
    Generates a plain text summary.
    Layout: 'detailed' (default) or 'compact'.
    - Detailed: Summary by host + details by port (more readable for SOCs).
    - Compact: One line per event (useful for quick ingestion or review).
    """
    hosts = {}
    for r in results:
        hosts.setdefault(r["host"], []).append(r)
    now = datetime.utcnow().isoformat() + "Z"

    if layout == "compact":
        lines = []
        lines.append(f"Scan Report (compact) - {now}")
        for host, entries in hosts.items():
            for e in entries:
                banner = e.get('banner','').strip().replace('\n', ' | ')[:400] 
                lines.append(f"{host}:{e['port']} {e['status']} {e['severity']} {banner}")
    else:
        # detailed
        lines = []
        lines.append(f"Scan Report - {now}")
        lines.append("Resumen por host:")
        for host, entries in hosts.items():
            open_ports = [str(e["port"]) for e in entries if e["status"] == "open"]
            critical = any(e["severity"] == "critical" for e in entries)
            lines.append(f"Host: {host}")
            lines.append(f"  Open Ports ({len(open_ports)}): {', '.join(open_ports) if open_ports else 'None'}")
            lines.append(f"  Critical: {'Yes' if critical else 'No'}")
            lines.append("")
        lines.append("Details:")
        for host, entries in hosts.items():
            lines.append(f"== {host} ==")
            for e in entries:
                lines.append(f"Port: {e['port']}  Status: {e['status']}  Severity: {e['severity']}  Timestamp: {e['timestamp']}")
                banner = e.get('banner','').strip().replace('\n', ' | ')[:800]
                if banner:
                    lines.append(f"  Banner: {banner}")
            lines.append("")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(''.join(lines))
    print(f"[+] TXT exported to: {filename}")


def parse_ports(ports_str: str):
    if not ports_str:
        return DEFAULT_PORTS
    parts = [p.strip() for p in ports_str.split(",")]
    out = set()
    for p in parts:
        if "-" in p:
            a, b = p.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(p))
    return sorted(out)

# --- CLI / Main ---

def severity_rank(label: Optional[str]) -> int:
    #Converts severity label to an integer for comparison.
    m = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    if not label:
        return 0
    return m.get(label.lower(), 0)

# --- ECS / CEF conversion and export ---
def ecs_severity_value(label: str) -> int:
    m = {"critical": 90, "high": 70, "medium": 50, "info": 20}
    return m.get(label.lower(), 20)

def cef_severity_value(label: str) -> int:
    m = {"critical": 10, "high": 7, "medium": 5, "info": 2}
    return m.get(label.lower(), 2)

def _escape_cef_value(s: str) -> str:
    if s is None:
        return ""
    s = str(s).replace("\\", "\\\\")
    s = s.replace("\n", "\\n").replace("\r", "\\n")
    s = s.replace("|", "\\|").replace("=", "\\=")
    return s

def service_from_port(port: int) -> Optional[str]:
    try:
        return socket.getservbyport(port)
    except Exception:
        return None

def result_to_ecs_event(r: Dict, scanner_ip: Optional[str] = None) -> Dict:
    ts = r.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
    dest_ip = r.get("host")
    dest_port = r.get("port")
    sev_label = r.get("severity", "info")
    banner = r.get("banner", "")

    ecs = {
        "@timestamp": ts,
        "event": {
            "action": "port_scan",
            "category": ["network"],
            "kind": "event",
            "dataset": "lan_portscanner.scan",
            "module": "lan_portscanner",
            "severity": ecs_severity_value(sev_label),
            "outcome": "success" if r.get("status") == "open" else "failure",
        },
        "agent": {"type": "script", "name": "lan_portscanner", "version": "1.0"},
        "destination": {"ip": dest_ip, "port": dest_port},
        "network": {"transport": "tcp"},
        "observer": {"hostname": socket.gethostname()},
        "message": f"Port {dest_port} on {dest_ip} is {r.get('status')} - {banner[:400]}",
        "labels": {"scanner_severity_label": sev_label},
        "service": {"name": service_from_port(dest_port) or ""},
        "source": {"ip": scanner_ip or "unknown"},
        "lan_portscanner": r
    }
    return ecs

def result_to_cef_line(r: Dict, scanner_ip: Optional[str] = None, device_vendor="MyCompany", device_product="PortScanner", device_version="1.0", signature_id=1001) -> str:
    ts = r.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
    dst = r.get("host")
    dpt = r.get("port")
    src = scanner_ip or "unknown"
    spt = ""
    name = f"Port Scan {dst}:{dpt}"
    cef_sev = cef_severity_value(r.get("severity", "info"))
    banner = r.get("banner", "")

    header = f"CEF:0|{_escape_cef_value(device_vendor)}|{_escape_cef_value(device_product)}|{_escape_cef_value(device_version)}|{signature_id}|{_escape_cef_value(name)}|{cef_sev}|"

    ext_parts = {
        "src": src,
        "dst": dst,
        "spt": spt,
        "dpt": dpt,
        "msg": banner[:1000],
        "rt": ts,
        "cs1": r.get("status"),
        "cs1Label": "status",
        "cs2": r.get("severity"),
        "cs2Label": "scanner_severity",
    }
    ext = " ".join(f"{k}={_escape_cef_value(v)}" for k, v in ext_parts.items() if v is not None and v != "")
    return header + ext

def export_ecs_ndjson(results: List[Dict], out_path="ecs_events.ndjson", scanner_ip: Optional[str] = None):
    with open(out_path, "w", encoding="utf-8") as f:
        for r in results:
            ecs_event = result_to_ecs_event(r, scanner_ip=scanner_ip)
            f.write(json.dumps(ecs_event, ensure_ascii=False) + "\n")
    print(f"[+] ECS NDJSON exported to: {out_path}")

def export_cef_file(results: List[Dict], out_path="scan_results.cef", scanner_ip: Optional[str] = None, device_vendor="MyCompany", device_product="PortScanner", device_version="1.0"):
    with open(out_path, "w", encoding="utf-8") as f:
        for r in results:
            cef_line = result_to_cef_line(r, scanner_ip=scanner_ip, device_vendor=device_vendor, device_product=device_product, device_version=device_version)
            f.write(cef_line + "\n")
    print(f"[+] CEF exported to: {out_path}")

def save_xml(results, filename="scan_results.xml"):
    root = ET.Element("scan_report")

    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(metadata, "generated_at").text = datetime.utcnow().isoformat() + "Z"
    ET.SubElement(metadata, "total_results").text = str(len(results))

    results_elem = ET.SubElement(root, "results")
    for result in results:
        scan_elem = ET.SubElement(results_elem, "scan")
        for key, value in result.items():
            if isinstance(value, (str , int)):
                ET.SubElement(scan_elem, key).text = str(value)
            elif value is None:
                ET.SubElement(scan_elem, key).text = ""
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space=" ", level=0)

    with open(filename, "w", encoding="utf-8") as f:
        tree.write(filename, encoding="unicode", xml_declaration=True)
        print(f"[+] XML exported to: {filename}")

'''
def save_yaml(results, filename="scan_results.yaml"):

    if not YAML_AVAILABLE:
        print(f"[!] YAML export skipped: PyYAML not installed. Install with: pip install PyYAML")
        return
    
    # Preparar datos para YAML
    yaml_data = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_results": len(results)
        },
        "results": results
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, indent=2)
    print(f"[+] YAML exported to: {filename}")
'''

def main():
    parser = argparse.ArgumentParser(description = "LAN port scanner + report (JSON/CSV/HTML/ECS/CEF/TXT)")
    parser.add_argument("cidr", help = "CIDR Range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help = "Comma/Interval List: 22,80,8000-8100")
    parser.add_argument("--concurrency", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--output-format", default="json,csv,html,xml,ecs,cef,txt", help="Comma-separated: json,csv,html,xml,ecs,cef,txt")
    parser.add_argument("--scanner-ip", default=None, help="Scanner IP (for source fields in ECS/CEF)")
    parser.add_argument("--prefix", default=None, help = "Prefix for the output files. If not specified, default names are used.")
    parser.add_argument("--include-all", action="store_true", help = "Include all scanned ports (open/closed/error) in the output files. By default, only open ports are exported.")
    parser.add_argument("--include-all-for", default="", help="Comma-separated formats para los que aplicar include-all, ejemplo: txt,ecs")
    parser.add_argument("--min-severity", default=None, choices=["info","medium","high","critical"], help="Mínima severidad a exportar (incluye la indicada y superiores)")
    parser.add_argument("--txt-layout", default="detailed", choices=["detailed","compact"], help="Layout for the TXT file.")

    # Nuevos argumentos para optimización con ping
    parser.add_argument("--no-ping", action="store_true", help="Skip ping scan and scan all hosts (slower)")
    parser.add_argument("--ping-concurrency", type=int, default=100, help="Concurrency for ping scans (default: 100)")
    parser.add_argument("--ping-timeout", type=float, default=1.0, help="Timeout for ping in seconds (default: 1.0)")

    args = parser.parse_args()

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    formats = [f.strip().lower() for f in args.output_format.split(",") if f.strip()]
    include_all_for = [f.strip().lower() for f in args.include_all_for.split(",") if f.strip()]
    prefix = (args.prefix.rstrip("_") + "_") if args.prefix else ""

    print(f"[+] Scanning {args.cidr} ports {ports[:10]}... (total: {len(ports)} ports)")

    # Ejecutar escaneo con o sin ping según la opción
    results = asyncio.run(scan_hosts(
        args.cidr, 
        ports, 
        concurrency=args.concurrency, 
        timeout=args.timeout,
        ping_first=not args.no_ping,
        ping_concurrency=args.ping_concurrency,
        ping_timeout=args.ping_timeout
    ))

    open_results = [r for r in results if r.get("status")=="open"]

    # Master set for summary (para consola): si --include-all se consideran todos, si no sólo open
    master_for_summary = results if args.include_all else open_results
    # aplicar filtro de severidad sobre el master
    if args.min_severity:
        min_rank = severity_rank(args.min_severity)
        master_for_summary = [r for r in master_for_summary if severity_rank(r.get('severity')) >= min_rank]

    print(f"[+] Scan completed. Open ports detected: {len(open_results)} (total scans: {len(results)})")

    # Exports according to requested formats. For each format, we decide whether to use 'results' (all) or 'open_results'.
    for fmt in formats:
        use_all = args.include_all or (fmt in include_all_for)
        use_results = results if use_all else open_results
        # Apply severity filter by format if indicated
        if args.min_severity:
            min_rank = severity_rank(args.min_severity)
            use_results = [r for r in use_results if severity_rank(r.get('severity')) >= min_rank]

        if fmt == "json":
            out = f"{prefix}scan_results.json" if prefix else "scan_results.json"
            save_json(use_results, filename=out)
            print(f"[+] JSON exported: {out} (items: {len(use_results)})")
        elif fmt == "csv":
            out = f"{prefix}scan_results.csv" if prefix else "scan_results.csv"
            save_csv(use_results, filename=out)
            print(f"[+] CSV exported: {out} (items: {len(use_results)})")
        elif fmt == "html":
            out = f"{prefix}scan_report.html" if prefix else "scan_report.html"
            save_html(use_results, filename=out)
            print(f"[+] HTML exported: {out} (items: {len(use_results)})")
        elif fmt == "txt":
            out = f"{prefix}scan_results.txt" if prefix else "scan_results.txt"
            save_txt(use_results, filename=out, layout=args.txt_layout)
            print(f"[+] TXT exported: {out} (layout: {args.txt_layout}, items: {len(use_results)})")
        elif fmt == "ecs":
            out = f"{prefix}ecs_events.ndjson" if prefix else "ecs_events.ndjson"
            export_ecs_ndjson(use_results, out_path=out, scanner_ip=args.scanner_ip)
            print(f"[+] ECS NDJSON exported: {out} (items: {len(use_results)})")
        elif fmt == "cef":
            out = f"{prefix}scan_results.cef" if prefix else "scan_results.cef"
            export_cef_file(use_results, out_path=out, scanner_ip=args.scanner_ip)
            print(f"[+] CEF exported: {out} (items: {len(use_results)})")
        else:
            print(f"[!] Unknow format: {fmt}")

    # Master set severity summary
    counts = {}
    for r in master_for_summary:
        counts[r.get("severity","info")] = counts.get(r.get("severity","info"), 0) + 1
    print(f"[+] Summary by severity (of the applied set): {counts}")

    if args.include_all:
        print("[!] Note: All scanned ports have been included in the exports. (--include-all).")
    if include_all_for:
        print(f"[!] Note: For {include_all_for} formats, all results are included. (--include-all-for).")
    if args.min_severity:
        print(f"[!] Note: Minimum severity filter applied: {args.min_severity}")

if __name__ == "__main__":
    main()