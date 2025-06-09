import psutil
import json
import time
import requests
import platform
import socket
import uuid
import hashlib
import os
import datetime
import csv

# Load server URL from configuration file
with open("config.json", "r") as url_file:
    config = json.load(url_file)
    SERVER_URL = config.get("server_url")
    ABUSE_API_KEY = config.get("abuse_api_key")
    IPINFO_TOKEN = config.get("ipinfo_token")

BLOCKED_COUNTRIES = {'RU', 'CN', 'IR', 'SY', 'IQ', 'LB', 'YE'}


def collect_data_processes(asset_id, hash_filename="process_hashes.json"):
    try:
        with open(hash_filename, "r") as json_file:
            existing_hashes = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_hashes = []

    # בנה מילון: exe_path -> dict עם hash ו-mtime
    hash_dict = {entry['exe']: entry for entry in existing_hashes if entry.get('exe')}

    processes = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
        try:
            exe_path = p.info.get('exe')
            if not exe_path or not os.path.isfile(exe_path):
                exe_path = 'unknown'

            # ברירת מחדל
            hashes = {"md5": None, "sha256": None}
            mtime = None

            if exe_path != 'unknown' and os.path.isfile(exe_path):
                mtime = os.path.getmtime(exe_path)
                cached = hash_dict.get(exe_path)
                if cached and cached.get("mtime") == mtime:
                    # השתמש ב-hash הקיים
                    hashes["md5"] = cached.get("md5")
                    hashes["sha256"] = cached.get("sha256")
                else:
                    # חשב hash חדש ועדכן
                    hashes = file_hashes(exe_path)
                    hash_dict[exe_path] = {
                        "exe": exe_path,
                        "md5": hashes["md5"],
                        "sha256": hashes["sha256"],
                        "mtime": mtime
                    }

            child_pids = [child.pid for child in p.children()] if p.children else []

            processes.append({
                "pid": p.pid,
                "name": p.name(),
                "cmdline": p.info.get('cmdline', []),
                "exe": exe_path,
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "ppid": p.info.get('ppid'),
                "children": child_pids,
                "create_time": datetime.datetime.fromtimestamp(p.create_time()).isoformat() if hasattr(p, "create_time") else None,
                "asset-id": asset_id
            })
        except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
            continue

    # שמור את כל הערכים המעודכנים
    with open(hash_filename, "w") as json_file:
        json.dump(list(hash_dict.values()), json_file, indent=4)

    return processes







def collect_system_info():
    mac_address = uuid.getnode()
    mac_address_str = ':'.join(f"{(mac_address >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    return [
        {
            "asset-id": "dorlu",
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": socket.gethostname(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "mac_address": mac_address_str,
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "network_usage": psutil.net_io_counters(),
            "uptime": psutil.boot_time(),
            "last_boot": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "type":"host"
        }
    ]


def file_hashes(filepath):
    hashes = {"md5": None, "sha256": None}
    if not filepath or not os.path.isfile(filepath):
        return hashes
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        pass  # אפשר להוסיף לוג אם רוצים
    return hashes

def collect_active_connections(asset_id):
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            connections.append({
                "pid": conn.pid,
                "status": conn.status,
                "local_address": laddr,
                "remote_address": raddr,
                "family": str(conn.family),
                "asset-id": asset_id
            })
        except Exception as e:
            continue
        
    return connections

def return_data():
    system_info = collect_system_info()
    asset_id = system_info[0]["asset-id"]

    # Collect process data
    processes = collect_data_processes(asset_id)
    # Collect active connections
    active_connections = collect_active_connections(asset_id)
    # Get the current timestamp
    timestamp = datetime.datetime.now().isoformat()

    metadata = []
    for proc in processes:
        meta_entry = {
            "meta-id": str(uuid.uuid4()),
            "type": "process",
            "timestamp": timestamp,
            **proc
        }
        metadata.append(meta_entry)

    for conn in active_connections:
        meta_entry = {
            "meta-id": str(uuid.uuid4()),
            "type": "connection",
            "timestamp": timestamp,
            **conn
        }
        metadata.append(meta_entry)

    data = {
        "assets": system_info,
        "product-details": {
            "color": "blue",
            "name": "eyhunter",
            "team": "defense"
        },
        "project-details": {
            "name": "ayehunter",
            "desc": "security agent"
        },
        "metadata": metadata,
        "alerts": []
    }
    return data


def save_data_to_json_file(filename="system_data.json", data=return_data()):
   
    # Convert dictionary to JSON string
    json_data = json.dumps(data, indent=4)
    
    # Write JSON string to a file
    with open(filename, "w") as json_file:
        json_file.write(json_data)
    

def send_json_to_url(filename="system_data.json", url=SERVER_URL):
    try:
        # Read the JSON file
        with open(filename, "r") as json_file:
            data = json.load(json_file)
        
        # Send the data to the specified URL
        response = requests.post(url, json=data)
        
        # Check the response status
        if response.status_code == 200:
            print("Data successfully sent to the server.")
            print(response.json())
        else:
            print(f"Failed to send data. Status code: {response.status_code}")
            print("Response:", response.text)
            print(data)
    except Exception as e:
        print("Error sending data:", e)

def printdata(filename="system_data.json"):
    with open(filename, "r") as json_file:
        data = json.load(json_file)
    print(json.dumps(data, indent=2))



def compute_process_hashes(output_filename="process_hashes.json"):
    process_hashes = []

    # Iterate over all running processes
    for p in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = p.info.get('exe')
            if exe_path and os.path.isfile(exe_path):
                hashes = file_hashes_for_path(exe_path)
                process_hashes.append({
                    "pid": p.pid,
                    "name": p.name(),
                    "exe": exe_path,
                    "md5": hashes["md5"],
                    "sha256": hashes["sha256"]
                })
        except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
            continue

    # Save the process hashes to a JSON file
    with open(output_filename, "w") as json_file:
        json.dump(process_hashes, json_file, indent=4)

    print(f"Process hashes saved to {output_filename}")
    with open(output_filename, "r") as json_file:
        data = json.load(json_file)
    #print(data)

def file_hashes_for_path(filepath):
    hashes = {"md5": None, "sha256": None}
    if not filepath or not os.path.isfile(filepath):
        return hashes
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        print(f"Error computing hashes for {filepath}: {e}")
    return hashes

def check_suspicious_port_for_connection(connection, suspicious_ports_file="suspicious_ports_list_with_mitre_updated.csv"):
    # Load suspicious ports from CSV
    suspicious_ports = {}
    with open(suspicious_ports_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header row
        for row in reader:
            try:
                port = int(row[0])  # Get port from first column
                indicator = row[1]  # Get metadata_comment from column B
                severity = row[2]
                type_suspicius=row[3]
                mitre_id=row[7]
                mitre_explain=row[8]

                suspicious_ports[port] = (indicator, severity,type_suspicius,mitre_id,mitre_explain)
            except ValueError:
                continue  # Skip rows that don't contain valid integers

    # Extract the source and destination IP and port from the connection
    local_address = connection.get("local_address")
    remote_address = connection.get("remote_address")
    if local_address or remote_address:
        try:
            if local_address:
                src_ip, src_port = local_address.split(":")
                src_port = int(src_port)
                if src_port in suspicious_ports:
                    indicator, severity,type_suspicius,mitre_id,mitre_explain= suspicious_ports[src_port]
                    print("PID:", connection.get("pid"))
                    print("suspicious_port_result:", (src_ip, src_port, indicator, severity,type_suspicius,mitre_id,mitre_explain))
                    return src_ip, src_port, indicator, severity,type_suspicius,mitre_id,mitre_explain
            if remote_address:
                dst_ip, dst_port = remote_address.split(":")
                dst_port = int(dst_port)
                if dst_port in suspicious_ports:
                    indicator, severity,type_suspicius,mitre_id,mitre_explain= suspicious_ports[dst_port]
                    print("PID:", connection.get("pid"))
                    print("suspicious_port_result:", (dst_ip, dst_port, indicator, severity,type_suspicius,mitre_id,mitre_explain))
                    return dst_ip, dst_port, indicator, severity,type_suspicius,mitre_id,mitre_explain
        except (IndexError, ValueError):
            pass  # Skip if the address is not in the expected format

    return False

def is_process_running_from_temp_dir(process):
    # Define temporary directories to check
    temp_dirs = ['Temp', '/dev/shm']
    
    # Get the executable path of the process
    exe_path = process.get("exe")
    
    # Check if the executable path contains any of the temporary directories
    if exe_path and any(temp_dir in exe_path for temp_dir in temp_dirs):
        return True
    return False



def is_suspicious_process_time(process):
    """
    בודקת אם תהליך נוצר בשעה חריגה (00:00-04:00) ומחזירה True אם כן, אחרת False.
    """
    try:
        create_time = process.get("create_time")
        if create_time:
            create_dt = datetime.datetime.fromisoformat(create_time)
            hour = create_dt.hour
            return 0 <= hour < 4
        else:
            return False
    except Exception as e:
        print(f"Error checking process {process.get('pid')}: {e}")
        return False

def is_ip_from_blocked_country(ip: str) -> bool:
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        country_code = data.get('country_code', '')
        return country_code in BLOCKED_COUNTRIES
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return False

def alert_on_blocked_country_connections(connections):
    """
    Receives a list of connection dicts, checks if remote_address IP is from a blocked country,
    and prints an alert if so.
    """
    for conn in connections:
        remote_address = conn.get('remote_address')
        if remote_address:
            remote_ip = remote_address.split(':')[0]
            if is_ip_from_blocked_country(remote_ip):
                print(f"[ALERT] Remote address {remote_address} is from a blocked country!")


def is_process_hash_in_txt(process, hash_txt_path):
    """
    מקבלת process ונתיב לקובץ של hash-ים
    מחזירה True אם ה-hash של ה-process נמצא בקובץ, אחרת False
    """
    # קבל את ה-hash של התהליך
    sha256 = process.get("sha256")
    if not sha256:
        return False

    try:
        # קרא את הקובץ ובדוק אם ה-hash נמצא בו
        with open(hash_txt_path, "r") as f:
            for line in f:
                if line.strip().lower() == sha256.lower():
                    print(f"Found matching hash for {process.get('name')}")
                    return True
        return False
    except Exception as e:
        print(f"Error reading hash file: {e}")
        return False

           

        
  

# דוגמה לשימוש:
# process = {"sha256": "eed7dafbcbab29a94b6092fb5a88b17eb6fc6e8430458e8b31b348d6864c212c"}
# print(is_process_hash_in_txt(process, "hashes.txt"))




def build_alert_section_with_helpers(system_data_path="system_data.json", hash_txt_path="sha256_hashes_6.txt", suspicious_ports_file="suspicious_ports_list_with_mitre_updated.csv", alert_output_path="alert_with_helpers.json"):
    """
    Builds ALERT section using existing helper functions, ensuring no duplicates.
    Groups alerts by hash and adds PIDs to existing alerts.
    """
    
    # Load system data
    with open(system_data_path, "r") as f:
        data = json.load(f)

    metadata_list = data.get("metadata", [])
    processes = [m for m in metadata_list if m.get("type") == "process"]
    connections = [m for m in metadata_list if m.get("type") == "connection"]
    asset_id = data.get("assets", [{}])[0].get("asset-id", "dorlu")

    alert_dict = {}

    # Process checks
    for process in processes:
        pid = process.get("pid")
        if pid is None:
            continue
        process_hash = process.get("sha256")
        process_name = process.get("name")
        process_path = process.get("exe")
        meta_id = process.get("meta-id")

        # Initialize alert if not exists
        if pid not in alert_dict:
            alert_dict[pid] = {
                "host": socket.gethostname(),
                "alert_id": str(uuid.uuid4()),
                "asset-id": asset_id,
                "local_ip": socket.gethostbyname(socket.gethostname()),
                "pid": pid,
                "CREATION_TIME": datetime.datetime.now().isoformat(),
                "SUSPICIOUS_HASH": None,
                "suspicious_path": None,
                "SUSPICIOUS_PORT": [],
                "ABUSE_IP": [],
                "connect_ip": []
            }

        # Suspicious hash check
        if is_process_hash_in_txt(process, hash_txt_path):
            alert_dict[pid]["SUSPICIOUS_HASH"] = {
                "meta-id": meta_id,
                "SUSPICIOUS_HASH": process_hash,
                "SUSPICIOUS_HASH_FILENAME": process_name,
                "SUSPICIOUS_HASH_PATH": process_path,
                "mitre_tactic": "Execution",
                "mitre_technique": "T1204 User Execution"
            }

        # Suspicious path check
        if is_process_running_from_temp_dir(process):
            alert_dict[pid]["suspicious_path"] = {
                "meta-id": meta_id,
                "exe_path": process_path,
                "comment": "Suspicious path detected",
                "mitre_tactic": "Evasion (TA0005)",
                "mitre_technique": "The adversary is trying to avoid being detected."
            }

    # Connection checks
    for conn in connections:
        pid = conn.get("pid")
        if pid is None:
            continue
        meta_id = conn.get("meta-id")

        # Initialize alert if not exists
        if pid not in alert_dict:
            alert_dict[pid] = {
                "host": socket.gethostname(),
                "alert_id": str(uuid.uuid4()),
                "asset-id": asset_id,
                "local_ip": socket.gethostbyname(socket.gethostname()),
                "pid": pid,
                "CREATION_TIME": datetime.datetime.now().isoformat(),
                "SUSPICIOUS_HASH": None,
                "suspicious_path": None,
                "SUSPICIOUS_PORT": [],
                "ABUSE_IP": [],
                "connect_ip": []
            }

        # Ensure remote_address is not None
        remote_address = conn.get("remote_address")
        if remote_address:
            remote_ip = remote_address.split(":")[0]

            # Suspicious port check
            suspicious_port_result = check_suspicious_port_for_connection(conn, suspicious_ports_file)
            if suspicious_port_result:
                ip, port, indicator, severity, type_suspicius, mitre_id, mitre_explain = suspicious_port_result
                alert_dict[pid]["SUSPICIOUS_PORT"].append({
                    "meta-id": meta_id,
                    "ip": ip,
                    "port": port,
                    "indicator": indicator,
                    "severity": severity,
                    "type_suspicius": type_suspicius,
                    "mitre_tactic": mitre_id,
                    "mitre_technique": mitre_explain
                })

            # Abuse IP check
            abuse_info = get_abuse_score_if_high(remote_ip)
            if abuse_info:
                alert_dict[pid]["ABUSE_IP"].append({
                    "meta-id": meta_id,
                    "remote_ip": remote_ip,
                    "ABUSE_SCORE": abuse_info,
                    "mitre_tactic": "C2 (TA0011)",
                    "mitre_technique": "T1071 – Application Layer Protocol."
                })

            # Blocked country check
            ipinfo_result, boolean_check = ipinfo_check(remote_ip)
            if boolean_check:
                alert_dict[pid]["connect_ip"].append({
                    "meta-id": meta_id,
                    "BLOCKED_IP": remote_ip,
                    "BLOCKED_COUNTRY": ipinfo_result,
                    "mitre_tactic": "C2 (TA0011)",
                    "mitre_technique": "T1071 – Application Layer Protocol."
                })

    # Convert to list and remove entries with no findings
    filtered_alerts = [alert for alert in alert_dict.values() if any([
        alert["SUSPICIOUS_HASH"] is not None,
        alert["suspicious_path"] is not None,
        alert["SUSPICIOUS_PORT"],
        alert["ABUSE_IP"],
        alert["connect_ip"]
    ])]

    # Add alerts section to system data
    data["alerts"] = filtered_alerts

    # Save the updated system data with alerts section back to the original file
    with open(system_data_path, "w") as f:
        json.dump(data, f, indent=4)

    # Save the alerts section to a separate file
    with open(alert_output_path, "w") as f:
        json.dump({"alerts": filtered_alerts}, f, indent=4)

    return filtered_alerts

def add_product_id_to_system_data(filename="system_data.json", product_id="EH-0x3"):
    try:
        # Load the existing system data
        with open(filename, "r") as json_file:
            data = json.load(json_file)
        
        # Add the productId section
        data["productId"] = product_id
        
        # Save the updated data back to the file
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
        
        print(f"Added productId: {product_id} to {filename}")
    except Exception as e:
        print(f"Error updating {filename} with productId: {e}")
    

def add_project_id_to_system_data(filename="system_data.json", project_id="Eyes-0x1"):
        try:
            # Load the existing system data
            with open(filename, "r") as json_file:
                data = json.load(json_file)
            
            # Add the productId section
            data["projectId"] = project_id
            
            # Save the updated data back to the file
            with open(filename, "w") as json_file:
                json.dump(data, json_file, indent=4)
            
            print(f"Added productId: {project_id} to {filename}")
        except Exception as e:
            print(f"Error updating {filename} with projectId: {e}")




def assign_severity_to_alerts(json_file_path):
    """
    Updates each alert in the given JSON file with a calculated severity level using a numeric scale from 1 to 6.
    """
    with open(json_file_path, "r") as f:
        data = json.load(f)

    alerts = data.get("alerts", [])
    for alert in alerts:
        points = 0

        # suspicious_path
        suspicious_path = alert.get("suspicious_path")
        if suspicious_path and suspicious_path != "None":
            points += 1

        # suspicious_port
        suspicious_port = alert.get("SUSPICIOUS_PORT")
        if suspicious_port and suspicious_port != "None":
            points += 2

        # suspicious_hash
        suspicious_hash = alert.get("SUSPICIOUS_HASH")
        if suspicious_hash and suspicious_hash != "None":
            points += 5

        # suspicious_country_connection
        suspicious_country = alert.get("BLOCKED_COUNTRY")
        if suspicious_country and suspicious_country != "None":
            points += 2

        # abuse_ip_connection
        abuse_ip = alert.get("ABUSE_SCORE")
        if abuse_ip and abuse_ip != "None":
            points += 5

        # Determine severity
        if points >= 7:
            severity = 5
        elif points >= 5:
            severity = 5
        elif points >= 3:
            severity = 4
        elif points >= 1:
            severity = 3
        else:
            severity = 1

        alert["severity"] = severity

    # Save back to file
    with open(json_file_path, "w") as f:
        json.dump(data, f, indent=4)

    return data["alerts"]


def get_abuse_score_if_high(ip):
    """
    מקבלת כתובת IP, בודקת את ה-Abuse Score ב-AbuseIPDB.
    אם ה-score 50 ומעלה מחזירה אותו ואת המדינה, אחרת מחזירה None.
    """
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': ABUSE_API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
            country = data.get('data', {}).get('countryCode', 'Unknown')
            if abuse_score >= 50:
                return {'abuse_score': abuse_score, 'country': country}
            else:
                return None
        else:
            print(f"AbuseIPDB error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking abuse score for {ip}: {e}")
        return None
#print(get_abuse_score_if_high("178.46.173.226"))

# דוגמה לשימוש:
# ip = "8.8.8.8"
# score = get_abuse_score_if_high(ip)
# if score is not None:
#     print(f"Abuse score for {ip}: {score}")
# else:
#     print(f"Abuse score for {ip} is below 50 or error occurred.")



def process_connections_for_abuse_score(json_file_path):
    """
    מקבלת קובץ JSON שמכיל CONNECTIONS, בודקת את ה-Abuse Score לכל חיבור,
    ומוסיפה ל-section של alerts אם ה-score 50 ומעלה.
    """
    # Load the JSON data from the file
    with open(json_file_path, "r") as f:
        data = json.load(f)

    metadata_list = data.get("metadata", [])
    connections = [m for m in metadata_list if m.get("type") == "connection"]
    alerts_list = data.get("alerts", [])

    for conn in connections:
        remote_address = conn.get("remote_address")
        if remote_address:
            remote_ip = remote_address.split(':')[0]
            abuse_info = get_abuse_score_if_high(remote_ip)
            if abuse_info:
                alert_id = str(uuid.uuid4())
                alert = {
                    "alert_id": alert_id,
                    "asset-id": conn.get("asset-id"),
                    "PID": conn.get("pid"),
                    "ABUSE_SCORE": abuse_info,
                    "remote_ip": remote_ip,
                    "CREATION_TIME": datetime.datetime.now().isoformat(),
                    "mitre_tactic":"Command and Control (TA0011)",
                    "mitre_technique":"T1071 – Application Layer Protocol.",
                }
                alerts_list.append(alert)

    data["alerts"] = alerts_list
    with open(json_file_path, "w") as f:
        json.dump(data, f, indent=4)
    return alerts_list

# דוגמה לשימוש:
#print(process_connections_for_abuse_score("example_json.json"))


def ipinfo_check(ip):
    BLOCKED_COUNTRIES = {'RU', 'CN', 'IR', 'SY', 'IQ', 'LB', 'YE'}
    
    url = f'https://ipinfo.io/{ip}?token={IPINFO_TOKEN}'
    try:
        response = requests.get(url)
        data = response.json()
        country = data.get("country")
        if country and country in BLOCKED_COUNTRIES:
            return country, True
        else:
            return country, False
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return None, False

#print(ipinfo_check("45.147.79.140"))

def process_connections_for_blocked_country(json_file_path):
    """
    עוברת על כל CONNECTIONS, בודקת את ה-remote_ip עם ipinfo_check,
    ואם התוצאה True מוסיפה התראה ל-alerts_list ומעדכנת את קובץ ה-JSON ב-section של alerts.
    """
    with open(json_file_path, "r") as f:
        data = json.load(f)

    metadata_list = data.get("metadata", [])
    connections = [m for m in metadata_list if m.get("type") == "connection"]
    alerts_list = data.get("alerts", [])

    for conn in connections:
        remote_address = conn.get("remote_address")
        if remote_address:
            remote_ip = remote_address.split(":")[0]
            ipinfo_result,boolean_check = ipinfo_check(remote_ip)
            if boolean_check:
                alert_id = str(uuid.uuid4())
                alert = {

                    "BLOCKED_IP": remote_ip,
                    "BLOCKED_COUNTRY": ipinfo_result,
                    "destination_port": conn.get("remote_port"),
                    "mitre_tactic":"Command and Control (TA0011)",
                    "mitre_technique":"T1071 – Application Layer Protocol.",
                    "alert_id": alert_id,
                    "asset-id": conn.get("asset-id"),
                    "PID": conn.get("pid"),
                
                    "CREATION_TIME": datetime.datetime.now().isoformat()
                }
                alerts_list.append(alert)

    data["alerts"] = alerts_list
    with open(json_file_path, "w") as f:
        json.dump(data, f, indent=4)
    return alerts_list



def add_alert_name_to_alerts(json_file_path):
    """
    Updates each alert in the given JSON file with an appropriate alert_name based on certain conditions.
    """
    with open(json_file_path, "r") as f:
        data = json.load(f)

    alerts = data.get("alerts", [])

    for alert in alerts:
        alert_name = []

        # Check for suspicious hash
        if alert.get("SUSPICIOUS_HASH"):
            alert_name.append("Malicious File")

        # Check for suspicious path
        if alert.get("suspicious_path"):
            alert_name.append("SUS Path")

        # Check for suspicious port
        suspicious_ports_list = alert.get("SUSPICIOUS_PORT", [])
        for port_info in suspicious_ports_list:
            type_suspicius = port_info.get("type_suspicius")
            if type_suspicius:
                alert_name.append(type_suspicius)

        # Check for hostile communication or abuse
        if alert.get("ABUSE_IP") or alert.get("connect_ip"):
            alert_name.append("Hostile Communication")

        # Join alert names with commas and add 'Detected' at the end
        alert["alert_name"] = ", ".join(alert_name) + " Detected"

    # Save back to file
    with open(json_file_path, "w") as f:
        json.dump(data, f, indent=4)

    return data["alerts"]





def aggregate_mitre_tactics(json_file_path):
    """
    Aggregates all mitre_tactic values in each alert and appends them as a single string to the alert.
    """
    with open(json_file_path, "r") as f:
        data = json.load(f)

    alerts = data.get("alerts", [])

    for alert in alerts:
        mitre_tactics = set()

        # Check for mitre_tactic in SUSPICIOUS_HASH
        suspicious_hash = alert.get("SUSPICIOUS_HASH")
        if suspicious_hash and "mitre_tactic" in suspicious_hash:
            mitre_tactics.add(suspicious_hash["mitre_tactic"])

        # Check for mitre_tactic in suspicious_path
        suspicious_path = alert.get("suspicious_path")
        if suspicious_path and "mitre_tactic" in suspicious_path:
            mitre_tactics.add(suspicious_path["mitre_tactic"])

        # Check for mitre_tactic in SUSPICIOUS_PORT
        suspicious_ports = alert.get("SUSPICIOUS_PORT", [])
        for port_info in suspicious_ports:
            if "mitre_tactic" in port_info:
                mitre_tactics.add(port_info["mitre_tactic"])

        # Check for mitre_tactic in ABUSE_IP
        abuse_ips = alert.get("ABUSE_IP", [])
        for abuse_info in abuse_ips:
            if "mitre_tactic" in abuse_info:
                mitre_tactics.add(abuse_info["mitre_tactic"])

        # Check for mitre_tactic in connect_ip
        connect_ips = alert.get("connect_ip", [])
        for connect_info in connect_ips:
            if "mitre_tactic" in connect_info:
                mitre_tactics.add(connect_info["mitre_tactic"])

        # Join all unique mitre_tactics and add to alert
        alert["mitre_tactic"] = ", ".join(mitre_tactics)

    # Save back to file
    with open(json_file_path, "w") as f:
        json.dump(data, f, indent=4)

    return data["alerts"]


def main():
    
    compute_process_hashes("process_hashes.json")
    
    while True:
        #return_data()
        
        #collect_data_processes(hash_filename="process_hashes.json")
        save_data_to_json_file(filename="system_data.json")
        print("A")
       
        build_alert_section_with_helpers(system_data_path="system_data.json", hash_txt_path="sha256_hashes_6.txt", suspicious_ports_file="suspicious_ports_list_with_mitre_updated.csv", alert_output_path="alert_with_helpers.json")
        #ssign_severity_to_alerts(json_file_path="system_data.json")
        print("B")
        assign_severity_to_alerts("system_data.json")
        add_alert_name_to_alerts("system_data.json")
        aggregate_mitre_tactics("system_data.json")
        print("M")

        #print(check_suspicious_ports("system_data.json", suspicious_ports_file="suspicious_ports_list.csv"))
        #print(aggregate_security_data(system_data_file="system_data.json", suspicious_ports_file="suspicious_ports_list.csv"))
        #printdata(filename="system_data.json")
        add_project_id_to_system_data(filename="system_data.json", project_id="Eyes-0x1")
        add_product_id_to_system_data(filename="system_data.json", product_id="EH-0x3")
        send_json_to_url()
        print("C")
        time.sleep(60)
  
        
    


if __name__ == "__main__":
    main()



# דוגמה לשימוש:
# alert_on_suspicious_process_time(1234)

