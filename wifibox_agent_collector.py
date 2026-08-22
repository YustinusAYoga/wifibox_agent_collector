#!/usr/bin/env python3
import time
import os
import json
import csv
import re
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import threading
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Prometheus imports
from prometheus_client import generate_latest, Gauge, Counter, Info, CONTENT_TYPE_LATEST

# --- Configure Logging for systemd/journalctl ---
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger("wifibox-collector")

# --- Aggregated Collector Metrics ---
COLLECTOR_UP = Gauge(
    'wifibox_collector_target_up', 
    'Indicates if the collector successfully scraped the wifibox agent (1 = UP, 0 = DOWN)',
    ['uid', 'site', 'mode']
)

SCRAPE_ERRORS_TOTAL = Counter(
    'wifibox_collector_scrape_errors_total', 
    'Total number of failed connection attempts to wifibox agents',
    ['uid', 'site', 'mode']
)

# --- Dynamic Gauges Mirroring (Numeric Data) ---
METRIC_GAUGES = {
    'wifibox_internet_up': Gauge('wifibox_remote_internet_up', 'Mirrored internet status', ['uid', 'site', 'mode']),
    'wifibox_vpn_up': Gauge('wifibox_remote_vpn_up', 'Mirrored vpn status', ['uid', 'site', 'mode']),
    'wifibox_vpn_handshake_age_seconds': Gauge('wifibox_remote_vpn_handshake_age_seconds', 'Mirrored vpn handshake age', ['uid', 'site', 'mode']),
    'wifibox_tailscale_up': Gauge('wifibox_remote_tailscale_up', 'Mirrored tailscale status', ['uid', 'site', 'mode']),
    'wifibox_ap_interface_up': Gauge('wifibox_remote_ap_interface_up', 'Mirrored ap interface status', ['uid', 'site', 'mode']),
    'wifibox_ip_forward_enabled': Gauge('wifibox_remote_ip_forward_enabled', 'Mirrored ip forward status', ['uid', 'site', 'mode']),
    'wifibox_nat_masquerade_ok': Gauge('wifibox_remote_nat_masquerade_ok', 'Mirrored nat masquerade status', ['uid', 'site', 'mode']),
    'wifibox_connected_devices': Gauge('wifibox_remote_connected_devices', 'Mirrored connected devices count', ['uid', 'site', 'mode']),
    'wifibox_dhcp_service_up': Gauge('wifibox_remote_dhcp_service_up', 'Mirrored dhcp service status', ['uid', 'site', 'mode']),
    'wifibox_dhcp_range_ok': Gauge('wifibox_remote_dhcp_range_ok', 'Mirrored dhcp range ok', ['uid', 'site', 'mode']),
    'wifibox_dhcp_active_leases': Gauge('wifibox_remote_dhcp_active_leases', 'Mirrored active leases count', ['uid', 'site', 'mode']),
    'wifibox_dhcp_lease_file_present': Gauge('wifibox_remote_dhcp_lease_file_present', 'Mirrored dhcp lease file presence', ['uid', 'site', 'mode']),
    'wifibox_wg_systemd_up': Gauge('wifibox_remote_wg_systemd_up', 'Mirrored wg systemd status', ['uid', 'site', 'mode']),
    'wifibox_config_runtime_mismatch': Gauge('wifibox_remote_config_runtime_mismatch', 'Mirrored config mismatch', ['uid', 'site', 'mode']),
    'wifibox_wifi_connected': Gauge('wifibox_remote_wifi_connected', 'Mirrored wifi connection status', ['uid', 'site', 'mode']),
    'wifibox_wifi_signal_percent': Gauge('wifibox_remote_wifi_signal_percent', 'Mirrored wifi signal percent', ['uid', 'site', 'mode']),
    'wifibox_check_success': Gauge('wifibox_remote_check_success', 'Mirrored check success', ['uid', 'site', 'mode']),
    'wifibox_last_check_timestamp_seconds': Gauge('wifibox_remote_last_check_timestamp_seconds', 'Mirrored last check timestamp', ['uid', 'site', 'mode']),
    'wifibox_cpu_usage_percent': Gauge('wifibox_remote_cpu_usage_percent', 'Mirrored CPU usage percent', ['uid', 'site', 'mode']),
    'wifibox_cpu_temp_celsius': Gauge('wifibox_remote_cpu_temp_celsius', 'Mirrored CPU temp celsius', ['uid', 'site', 'mode']),
    'wifibox_memory_total_bytes': Gauge('wifibox_remote_memory_total_bytes', 'Mirrored memory total', ['uid', 'site', 'mode']),
    'wifibox_memory_used_bytes': Gauge('wifibox_remote_memory_used_bytes', 'Mirrored memory used', ['uid', 'site', 'mode']),
    'wifibox_memory_available_bytes': Gauge('wifibox_remote_memory_available_bytes', 'Mirrored memory available', ['uid', 'site', 'mode']),
    'wifibox_disk_total_bytes': Gauge('wifibox_remote_disk_total_bytes', 'Mirrored disk total', ['uid', 'site', 'mode']),
    'wifibox_disk_used_bytes': Gauge('wifibox_remote_disk_used_bytes', 'Mirrored disk used', ['uid', 'site', 'mode']),
    'wifibox_disk_free_bytes': Gauge('wifibox_remote_disk_free_bytes', 'Mirrored disk free', ['uid', 'site', 'mode']),
}

# --- Dynamic Info Mirroring (String Data) ---
METRIC_INFO = {
    'wifibox_dhcp_backend': Info('wifibox_remote_dhcp_backend', 'Mirrored DHCP backend string', ['uid', 'site', 'mode']),
    'wifibox_wifi_ssid': Info('wifibox_remote_wifi_ssid', 'Mirrored connected SSID string', ['uid', 'site', 'mode']),
    'wifibox_agent_info': Info('wifibox_remote_agent_info', 'Mirrored running background apps string', ['uid', 'site', 'mode']),
}

# --- Path Configurations ---
CSV_FILE_PATH = "/home/oldendome/wifibox-agent-collector/data/collected-meteric-data.csv"
PUSHED_DATA_DIR = "/home/oldendome/wifibox-agent-collector/pushed_backlogs"
INVENTORY_FILE_PATH = "/home/oldendome/wifibox-agent-collector/wifibox_inventory.json"
UPLOAD_DIR = "/home/oldendome/wifibox-agent/data"


def init_storage():
    os.makedirs(os.path.dirname(CSV_FILE_PATH), exist_ok=True)
    os.makedirs(PUSHED_DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
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
        logger.error(f"Error writing to CSV: {e}")

def load_targets_from_json(filepath=INVENTORY_FILE_PATH):
    targets = {}
    if not os.path.exists(filepath):
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
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON from {filepath}: {e}")
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
    
    local_rows.extend([
        ["wifibox_collector_target_up", 0, ip, site, collected_time],
        ["wifibox_internet_up", 0, ip, site, collected_time],
        ["wifibox_vpn_up", 0, ip, site, collected_time],
        ["wifibox_tailscale_up", 0, ip, site, collected_time]
    ])

def parse_and_update_metrics(uid, site, mode, text_data, ip, collected_time):
    rows = []
    for line in text_data.splitlines():
        if line.startswith('#') or not line.strip():
            continue
            
        match = re.match(r'^([a-zA-Z_0-9]+)(?:\{([^}]*)\})?\s+(.+)$', line.strip())
        if not match:
            continue
            
        metric_raw_name, labels_str, value_str = match.groups()
        
        try:
            metric_value = float(value_str)
        except ValueError:
            continue
            
        if metric_raw_name in METRIC_GAUGES:
            METRIC_GAUGES[metric_raw_name].labels(uid=uid, site=site, mode=mode).set(metric_value)
            rows.append([metric_raw_name, metric_value, ip, site, collected_time])
            
        elif metric_raw_name.endswith('_info'):
            base_name = metric_raw_name[:-5]
            if base_name in METRIC_INFO and labels_str:
                label_match = re.search(f'{base_name}="([^"]*)"', labels_str)
                if label_match:
                    info_val = label_match.group(1)
                    METRIC_INFO[base_name].labels(uid=uid, site=site, mode=mode).info({base_name: info_val})
                    rows.append([base_name, info_val, ip, site, collected_time])

    return rows

def update_inventory_file(uploaded_file_path):
    try:
        with open(uploaded_file_path, 'r') as f:
            new_data = json.load(f)
            
        if isinstance(new_data, dict):
            new_data = [new_data]

        inventory = []
        if os.path.exists(INVENTORY_FILE_PATH):
            with open(INVENTORY_FILE_PATH, 'r') as f:
                inventory = json.load(f)

        for new_item in new_data:
            target_uid = new_item.get("uid")
            if not target_uid:
                continue
                
            found = False
            for idx, existing_item in enumerate(inventory):
                if existing_item.get("uid") == target_uid:
                    inventory[idx].update(new_item)
                    found = True
                    break
            
            if not found:
                inventory.append(new_item)

        tmp_path = INVENTORY_FILE_PATH + ".tmp"
        with open(tmp_path, 'w') as f:
            json.dump(inventory, f, indent=2)
        os.replace(tmp_path, INVENTORY_FILE_PATH)
        logger.info(f"Successfully updated inventory with data from {uploaded_file_path}")

    except Exception as e:
        logger.error(f"Failed to parse and update inventory: {e}")

# --- Native HTTP Server (Replaces FastAPI to fix Cython conflicts) ---
class CollectorHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/metrics':
            output = generate_latest()
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
            
        elif parsed_path.path in ['/csv', '/collected-meteric-data.csv']:
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
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0]

        # 1. Handle File Generation API
        if parsed_path.path == '/upload':
            params = parse_qs(parsed_path.query)
            
            uid = params.get("uid", [None])[0]
            ip = params.get("ip", [None])[0]
            
            if not uid or not ip:
                logger.warning(f"[{client_ip}] Missing 'uid' or 'ip' query parameters.")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Missing uid or ip"}')
                return
                
            try:
                safe_uid = os.path.basename(str(uid))
                safe_ip = str(ip).strip()

                logger.info(f"[{client_ip}] Incoming upload request - UID: '{safe_uid}', IP: '{safe_ip}'")
                target_dir = os.path.join(UPLOAD_DIR, safe_uid)
                
                os.makedirs(target_dir, exist_ok=True)
                filepath = os.path.join(target_dir, "wifibox_identification.json")

                identification_data = [{"uid": safe_uid, "wg_ip": safe_ip}]

                with open(filepath, 'w') as f:
                    json.dump(identification_data, f, indent=2)
                
                logger.info(f"[{client_ip}] Successfully created wifibox_identification.json for UID '{safe_uid}'")
                update_inventory_file(filepath)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
                
            except Exception as e:
                logger.error(f"[{client_ip}] Error during upload processing: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "Internal Server Error"}')

        # 2. Handle Prometheus Push Metrics
        elif parsed_path.path.startswith('/metrics/job/'):
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
            except Exception as e:
                logger.error(f"Failed to process pushed metrics: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
                
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Silence default http.server logging to keep journalctl clean
        return

def run_http_server(port):
    server = ThreadingHTTPServer(('0.0.0.0', port), CollectorHTTPHandler)
    server.serve_forever()

# --- Background Scraper Loop ---
def background_scraper():
    while True:
        start_time = time.time()
        all_new_rows = []
        
        wifibox_targets = load_targets_from_json(INVENTORY_FILE_PATH)
        
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
    init_storage()
    
    try:
        os.chdir("/home/oldendome/wifibox-agent-collector")
    except FileNotFoundError:
        pass 

    # Start Background Scraper
    scraper_thread = threading.Thread(target=background_scraper, daemon=True)
    scraper_thread.start()

    # Start Native Python Web Server
    logger.info("Wifibox Fleet Collector & Server starting on 0.0.0.0:9102")
    run_http_server(9102)
