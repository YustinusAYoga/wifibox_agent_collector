#!/usr/bin/env python3
import time
import os
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from prometheus_client import generate_latest, Gauge, Counter, CONTENT_TYPE_LATEST

# --- Aggregated Collector Metrics ---
COLLECTOR_UP = Gauge(
    'wifibox_collector_target_up', 
    'Indicates if the collector successfully scraped the wifibox agent (1 = UP, 0 = DOWN)',
    ['uid', 'site', 'mode']
)

METRIC_GAUGES = {
    'wifibox_internet_up': Gauge('wifibox_remote_internet_up', 'Mirrored wifibox_internet_up', ['uid', 'site', 'mode']),
    'wifibox_vpn_up': Gauge('wifibox_remote_vpn_up', 'Mirrored wifibox_vpn_up', ['uid', 'site', 'mode']),
    'wifibox_vpn_handshake_age_seconds': Gauge('wifibox_remote_vpn_handshake_age_seconds', 'Mirrored vpn handshake age', ['uid', 'site', 'mode']),
    'wifibox_ap_interface_up': Gauge('wifibox_remote_ap_interface_up', 'Mirrored ap interface up', ['uid', 'site', 'mode']),
    'wifibox_ip_forward_enabled': Gauge('wifibox_remote_ip_forward_enabled', 'Mirrored ip forward enabled', ['uid', 'site', 'mode']),
    'wifibox_nat_masquerade_ok': Gauge('wifibox_remote_nat_masquerade_ok', 'Mirrored nat masquerade ok', ['uid', 'site', 'mode']),
    'wifibox_connected_devices': Gauge('wifibox_remote_connected_devices', 'Mirrored connected devices count', ['uid', 'site', 'mode']),
    'wifibox_dhcp_service_up': Gauge('wifibox_remote_dhcp_service_up', 'Mirrored dhcp service up', ['uid', 'site', 'mode']),
    'wifibox_dhcp_file_present': Gauge('wifibox_remote_dhcp_file_present', 'Mirrored dhcp file present', ['uid', 'site', 'mode']),
    'wifibox_wg_systemd_up': Gauge('wifibox_remote_wg_systemd_up', 'Mirrored wg systemd up', ['uid', 'site', 'mode']),
    'wifibox_wifi_connected': Gauge('wifibox_remote_wifi_connected', 'Mirrored wifi connected', ['uid', 'site', 'mode']),
    'wifibox_wifi_signal_percent': Gauge('wifibox_remote_wifi_signal_percent', 'Mirrored wifi signal percent', ['uid', 'site', 'mode']),
    'wifibox_config_runtime_mismatch': Gauge('wifibox_remote_config_runtime_mismatch', 'Mirrored config mismatch', ['uid', 'site', 'mode']),
    'wifibox_check_success': Gauge('wifibox_remote_check_success', 'Mirrored check success', ['uid', 'site', 'mode']),
    'wifibox_tailscale_up': Gauge('wifibox_remote_tailscale_up', 'Mirrored tailscale status', ['uid', 'site', 'mode']),
}

SCRAPE_ERRORS_TOTAL = Counter(
    'wifibox_collector_scrape_errors_total', 
    'Total number of failed connection attempts to wifibox agents',
    ['uid', 'site', 'mode']
)

CSV_FILE_PATH = "/home/oldendome/wifibox-agent-collector/data/collected-meteric-data.csv"
PUSHED_DATA_DIR = "/home/oldendome/wifibox-agent-collector/pushed_backlogs"

def init_storage():
    os.makedirs(os.path.dirname(CSV_FILE_PATH), exist_ok=True)
    os.makedirs(PUSHED_DATA_DIR, exist_ok=True)
    if not os.path.exists(CSV_FILE_PATH):
        with open(CSV_FILE_PATH, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["metric name", "value", "wifibox ip", "site", "collected time"])

def append_to_csv(rows):
    if not rows:
        return
    try:
        with open(CSV_FILE_PATH, mode='a', newline='') as f:
            writer = csv.writer(f)
            for row in rows:
                writer.writerow(row)
    except Exception as e:
        print(f"Error writing to CSV: {e}")

def load_targets_from_json(filepath="wifibox_inventory.json"):
    targets = {}
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found! Using fallback empty target list.")
        return targets

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for item in data:
                uid = item.get("uid")
                ip = item.get("wg_ip")
                site = item.get("site", "unknown")
                mode = item.get("mode", "unknown")
                
                if uid and ip:
                    targets[uid] = {
                        "ip": ip,
                        "url": f"http://{ip}:9101/metrics",
                        "site": site,
                        "mode": mode
                    }
        print(f"Successfully loaded {len(targets)} targets from {filepath}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from {filepath}: {e}")
        
    return targets

def scrape_single_agent(uid, info):
    url = info["url"]
    ip = info["ip"]
    site = info["site"]
    mode = info["mode"]
    
    collected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    local_rows = []
    
    try:
        response = requests.get(url, timeout=3.0)
        if response.status_code == 200:
            COLLECTOR_UP.labels(uid=uid, site=site, mode=mode).set(1)
            local_rows.append(["wifibox_collector_target_up", 1, ip, site, collected_time])
            
            parsed_metrics = parse_and_update_metrics(uid, site, mode, response.text, ip, collected_time)
            local_rows.extend(parsed_metrics)
        else:
            handle_scrape_failure(uid, site, mode, ip, collected_time, local_rows)
    except requests.RequestException:
        handle_scrape_failure(uid, site, mode, ip, collected_time, local_rows)
        
    return local_rows

def handle_scrape_failure(uid, site, mode, ip, collected_time, local_rows):
    COLLECTOR_UP.labels(uid=uid, site=site, mode=mode).set(0)
    SCRAPE_ERRORS_TOTAL.labels(uid=uid, site=site, mode=mode).inc()
    
    local_rows.append(["wifibox_collector_target_up", 0, ip, site, collected_time])
    local_rows.append(["wifibox_internet_up", 0, ip, site, collected_time])
    local_rows.append(["wifibox_vpn_up", 0, ip, site, collected_time])
    local_rows.append(["wifibox_tailscale_up", 0, ip, site, collected_time])

def parse_and_update_metrics(uid, site, mode, text_data, ip, collected_time):
    rows = []
    for line in text_data.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        
        metric_name = parts[0]
        try:
            metric_value = float(parts[1])
            if metric_name in METRIC_GAUGES:
                METRIC_GAUGES[metric_name].labels(uid=uid, site=site, mode=mode).set(metric_value)
                rows.append([metric_name, metric_value, ip, site, collected_time])
        except ValueError:
            continue
    return rows

class CollectorHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            output = generate_latest()
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
        elif self.path == '/csv' or self.path == '/collected-meteric-data.csv':
            if os.path.exists(CSV_FILE_PATH):
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.end_headers()
                with open(CSV_FILE_PATH, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"CSV file not found")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        if self.path.startswith('/metrics/job/'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            backup_file = os.path.join(PUSHED_DATA_DIR, f"pushed_{timestamp_str}.txt")
            try:
                with open(backup_file, 'wb') as f:
                    f.write(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        return

def run_http_server(port):
    server = HTTPServer(('0.0.0.0', port), CollectorHTTPHandler)
    server.serve_forever()

def main():
    collector_port = 9102
    init_storage()
    os.chdir("/home/oldendome/wifibox-agent-collector")
    wifibox_targets = load_targets_from_json("wifibox_inventory.json")

    server_thread = threading.Thread(target=run_http_server, args=(collector_port,), daemon=True)
    server_thread.start()
    print(f"Wifibox Fleet Collector & Server running on http://0.0.0.0:{collector_port}")

    while True:
        start_time = time.time()
        all_new_rows = []
        
        if wifibox_targets:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(scrape_single_agent, uid, info): uid 
                    for uid, info in wifibox_targets.items()
                }
                for future in as_completed(futures):
                    res_rows = future.result()
                    if res_rows:
                        all_new_rows.extend(res_rows)
            
            if all_new_rows:
                append_to_csv(all_new_rows)
                    
        elapsed = time.time() - start_time
        sleep_duration = max(1.0, 60.0 - elapsed)
        time.sleep(sleep_duration)

if __name__ == '__main__':
    main()