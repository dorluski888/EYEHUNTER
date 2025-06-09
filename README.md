# EYEHUNTER 
**A Security Agent for Real-Time Threat Detection**

`eyehunter.py` is a Python-based security monitoring script designed to function as an autonomous agent that collects and analyzes system and network data to identify potential threats. It combines local data collection with external threat intelligence services to provide proactive security insights.

---

##  Configuration Loading

At startup, the script loads its configuration from a `config.json` file, which contains:
- `server_url` for remote data submission
- API tokens for external services:
  - **AbuseIPDB** (for IP reputation checking)
  - **IPInfo** (for IP geolocation and ASN data)

---

## Data Collection

### System Information:
- Operating system details
- Hostname
- IP and MAC addresses
- CPU and memory usage
- System uptime

### Process Information:
- Process names
- Executable paths
- Command-line arguments
- Hashes: `MD5` and `SHA256` of each executable

### Network Connections:
- Local and remote IP addresses
- Connection status (e.g., ESTABLISHED, LISTENING)
- Ports in use

---

## Data Storage & Transmission

- All collected data is saved locally to `system_data.json`
- Periodically, the data is sent to the configured `server_url` for centralized analysis or logging

---

## Security Analysis

### What the script checks for:

- **Process Hash Matching:** Compares process hashes against known suspicious/malicious values
- **Suspicious Ports:** Identifies use of ports associated with malware or unwanted activity
- **Blocked Country Detection:** Flags connections to IPs originating from blocked countries
- **Abuse Score Evaluation:** Queries AbuseIPDB to determine if remote IPs have a high abuse score

---

## Alert Generation

When a threat is identified, the script:
- Generates alerts describing the issue (e.g., suspicious process, high-abuse IP)
- Enriches each alert with contextual metadata:
  - Relevant **MITRE ATT&CK** tactics and techniques
  - Geolocation and ASN information
  - Risk level indicators

---

## Continuous Monitoring

EYEHUNTER runs in an infinite loop, continuously:
1. Collecting system/network data
2. Analyzing that data for threats
3. Sending updates and alerts to the server

---

## 📁 Project Structure

EYEHUNTER/
│
├── eyehunter.py # Main script
├── config.json # Configuration settings
├── system_data.json # Output data file




