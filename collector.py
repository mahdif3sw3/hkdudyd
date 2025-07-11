import requests
import os
import re
import base64
import json
import threading
import concurrent.futures
import socket
from datetime import datetime
import random
import string

# یک Lock برای نمایش پیام‌ها به صورت منظم‌تر
print_lock = threading.Lock()

# یک Set سراسری برای نگهداری شناسه‌های (هاست، پورت، UUID) کانفیگ‌های منحصر به فرد
seen_identifiers = set()

# --- تابع برای استخراج هاست، پورت و UUID از کانفیگ ---
def extract_host_port_uuid(config_url):
    try:
        if config_url.startswith("vless://"):
            match = re.search(r"vless://([^@]+)@([^:]+):(\d+)", config_url)
            if match:
                uuid, host, port = match.group(1), match.group(2), int(match.group(3))
                return host, port, uuid
        elif config_url.startswith("vmess://"):
            encoded_json = config_url[len("vmess://"):]
            encoded_json += '=' * (-len(encoded_json) % 4)
            vmess_data = json.loads(base64.b64decode(encoded_json).decode('utf-8'))
            host, port, uuid = vmess_data.get('add'), vmess_data.get('port'), vmess_data.get('id')
            if host and port and uuid:
                return host, int(port), uuid
    except Exception:
        return None, None, None
    return None, None, None

def extract_short_source_name(source_link):
    try:
        if "raw.githubusercontent.com/" in source_link:
            return re.search(r"raw\.githubusercontent\.com/([^/]+)/", source_link).group(1)
        return re.search(r"https?://(?:www\.)?([^/]+)", source_link).group(1)
    except:
        return "Unknown"

def add_base64_padding(s):
    return s + '=' * (-len(s) % 4)

def is_base64(s):
    try:
        if isinstance(s, str) and re.fullmatch(r"^[A-Za-z0-9+/=\s]+$", s):
            base64.b64decode(add_base64_padding(s))
            return True
    except (base64.binascii.Error, UnicodeDecodeError):
        pass
    return False

def get_and_filter_reality_configs(url):
    local_unique_configs = []
    found_in_link_count = 0
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text.strip()
        if is_base64(content):
            try:
                content = base64.b64decode(add_base64_padding(content)).decode('utf-8')
            except Exception:
                pass
        
        for line in content.splitlines():
            line = line.strip()
            if "security=reality" in line and ("vless://" in line or "vmess://" in line):
                found_in_link_count += 1
                host, port, uuid = extract_host_port_uuid(line)
                if host and port and uuid:
                    identifier = (host, port, uuid)
                    with print_lock:
                        if identifier not in seen_identifiers:
                            seen_identifiers.add(identifier)
                            local_unique_configs.append({"config": line, "source_link": url, "host": host, "port": port})
        return local_unique_configs, found_in_link_count
    except requests.RequestException as e:
        with print_lock:
            print(f"❌ Error fetching {url}: {e}")
        return [], 0

def tcp_ping(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

links = [
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/vless",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/refs/heads/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/T3stAcc/V2Ray/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/Awmiroosen/awmirx-v2ray/refs/heads/main/blob/main/v2-sub.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/22.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/14.txt",
    "https://raw.githubusercontent.com/MRT-project/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Argh94/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/refs/heads/main/vless.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/refs/heads/main/list/vless.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/splitted/vless",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/vless",
    "https://raw.githubusercontent.com/F0rc3Run/raw-git-freeserver-configs/refs/heads/main/data/vless.txt",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/xyfqzy/free-nodes/refs/heads/main/nodes/vless.txt",
    "https://raw.githubusercontent.com/thirtysixpw/v2ray-reaper/refs/heads/main/protocol/vless",
    "https://raw.githubusercontent.com/yorkLiu/FreeV2RayNode/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/refs/heads/main/working.txt"
]

all_unique_configs = []
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    future_to_url = {executor.submit(get_and_filter_reality_configs, link): link for link in links}
    for future in concurrent.futures.as_completed(future_to_url):
        unique_configs, _ = future.result()
        all_unique_configs.extend(unique_configs)

print(f"✨ Found {len(all_unique_configs)} unique configs. Now checking their status...")

working_configs_with_source = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    future_to_config = {executor.submit(tcp_ping, item['host'], item['port']): item for item in all_unique_configs}
    for future in concurrent.futures.as_completed(future_to_config):
        item = future_to_config[future]
        if future.result():
            working_configs_with_source.append(item)
            print(f"🟢 Active: {item['host']}:{item['port']}")
        else:
            print(f"🔴 Inactive: {item['host']}:{item['port']}")

print(f"\n✅ Found {len(working_configs_with_source)} working configs.")

final_configs = []
for i, item in enumerate(working_configs_with_source):
    config_url = item["config"].rsplit('#', 1)[0]
    short_name = extract_short_source_name(item["source_link"])
    final_configs.append(f"{config_url}#{i+1} | {short_name}")

if final_configs:
    all_configs_combined = "\n".join(final_configs)
    base64_encoded_content = base64.b64encode(all_configs_combined.encode('utf-8')).decode('utf-8')
    
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    secret_name = os.getenv("SECRET_FILENAME_ENV")
    if not secret_name:
        print("⚠️ Secret filename not found. Using 'default_sub.txt'.")
        secret_name = "default_sub.txt"
        
    output_filename = os.path.join(output_dir, f"{secret_name}.txt")

    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write(base64_encoded_content)
    print(f"\n🎉 Subscription file saved to '{output_filename}'")
else:
    print("\n😥 No working configs found.")

