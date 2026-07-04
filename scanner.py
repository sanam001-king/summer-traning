import subprocess
import re
import json
import time
from zapv2 import ZAPv2

ZAP_PROXY = "http://127.0.0.1:8081"

def check_zap_status():
    """
    Safely tests connection to the OWASP ZAP daemon without crashing the engine.
    """
    try:
        zap_test = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
        zap_test.core.version
        return zap_test, True
    except Exception:
        return None, False

def get_active_interfaces():
    """
    Dynamically auto-discovers active Wi-Fi and local network subnets (CIDR ranges).
    """
    networks = []
    try:
        result = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if "lo" in line or "inet6" in line or not line.strip():
                continue
            
            parts = re.split(r'\s+', line.strip())
            if "inet" in parts:
                cidr = parts[parts.index("inet") + 1]
                iface_name = parts[1]
                
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', cidr):
                    net_type = "Wi-Fi Connection" if any(x in iface_name for x in ["wlan", "wlp", "wlo"]) else "Local LAN/Ethernet"
                    
                    ip_part, mask = cidr.split('/')
                    octets = ip_part.split('.')
                    base_subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/{mask}"
                    
                    networks.append({
                        "interface": iface_name,
                        "type": net_type,
                        "subnet": base_subnet,
                        "current_ip": ip_part
                    })
    except Exception:
        pass
    
    if not networks:
        networks.append({
            "interface": "Auto-Fallback",
            "type": "Standard Network Baseline",
            "subnet": "192.168.1.0/24",
            "current_ip": "192.168.1.1"
        })
    return networks

def discover_subnet_hosts(subnet_cidr):
    try:
        cmd = ["nmap", "-sn", subnet_cidr]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        discovered_ips = []
        for line in result.stdout.split('\n'):
            if "Nmap scan report for" in line:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    discovered_ips.append(ip_match.group(1))
        return discovered_ips
    except Exception:
        return []

def run_owasp_zap_web_scan(target_url):
    alerts = []
    zap, is_alive = check_zap_status()
    
    if not is_alive:
        return [{
            "id": "ZAP-OFFLINE",
            "summary": "OWASP ZAP did not respond on port 8081. Is the daemon running and initialized?",
            "severity": "High"
        }]

    try:
        zap.core.access_url(target_url)
        time.sleep(2)

        spider_id = zap.spider.scan(target_url)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(1)
            
        ascan_id = zap.ascan.scan(target_url)
        while int(zap.ascan.status(ascan_id)) < 100:
            time.sleep(2)
            
        zap_alerts = zap.core.alerts(baseurl=target_url)
        for alert in zap_alerts:
            alerts.append({
                "id": alert.get("pluginId", "ZAP-VULN"),
                "summary": f"{alert.get('alert')} -> Target path resource: {alert.get('url')}",
                "severity": alert.get("risk")
            })
    except Exception as e:
        alerts.append({
            "id": "ZAP-API-ERROR",
            "summary": f"ZAP interacted but threw an operational exception rule: {str(e)}",
            "severity": "Informational"
        })
    return alerts

def lookup_cves_and_exploits(service_name, version):
    normalized = f"{service_name} {version}".lower()
    cves, exploits = [], []
    
    if "apache" in normalized or "httpd" in normalized:
        cves = [
            {"id": "CVE-2023-25690", "summary": "Apache HTTP Server Request Smuggling.", "severity": "High"},
            {"id": "CVE-2021-41773", "summary": "Path traversal and file disclosure.", "severity": "Critical"}
        ]
        exploits = [{"title": "Apache 2.4.49 - Path Traversal RCE", "url": "https://www.exploit-db.com/exploits/50383"}]
    elif "ssh" in normalized or "openssh" in normalized:
        cves = [{"id": "CVE-2024-6387", "summary": "regreSSHion: Remote Code Execution in OpenSSH.", "severity": "Critical"}]
        exploits = [{"title": "OpenSSH Terrapin Attack Tool", "url": "https://github.com/vulnerabilities/ssh-exploit"}]
    else:
        cves = [{"id": "MAPPED-AUDIT", "summary": f"Review active patches for protocol service: {service_name}.", "severity": "Medium"}]
        exploits = [{"title": f"Security intelligence indexing for {service_name}", "url": "https://packetstormsecurity.com/"}]
        
    return cves, exploits

def run_dynamic_network_assessment(target_input):
    if "/" in target_input or target_input.endswith(".0"):
        cidr = target_input if "/" in target_input else f"{target_input}/24"
        hosts_to_scan = discover_subnet_hosts(cidr)
    else:
        hosts_to_scan = [target_input]

    all_results = {}
    
    for current_host in hosts_to_scan[:3]:
        try:
            # UPGRADED ADVANCED FLAGS RUN: Stealth SYN, Service Versioning, OS Detection, Aggressive Timing
            cmd = ["nmap", "-sS", "-sV", "-O", "-T4", current_host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            parsed_ports = []
            host_cves = []
            host_exploits = []
            detected_os = "Unknown Operating System"
            
            for line in result.stdout.split('\n'):
                # Dynamically parse OS fingerprint guesses from Nmap output flags
                if "OS details:" in line or "Aggressive OS guesses:" in line:
                    detected_os = line.replace("OS details:", "").replace("Aggressive OS guesses:", "").strip()

                if "/tcp" in line or "/udp" in line:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 3:
                        port_num = int(parts[0].split('/')[0])
                        protocol = parts[0].split('/')[1]
                        state = parts[1]
                        service_info = " ".join(parts[2:])
                        version_guess = parts[3] if len(parts) > 3 else "Unknown"
                        
                        cves, exploits = lookup_cves_and_exploits(parts[2], version_guess)
                        host_cves.extend(cves)
                        host_exploits.extend(exploits)
                        
                        # Trigger OWASP ZAP proxy evaluation if web ports are found open
                        if port_num in [80, 443, 8080, 5000]:
                            scheme = "https" if port_num == 443 else "http"
                            target_web_url = f"{scheme}://{current_host}:{port_num}"
                            zap_findings = run_owasp_zap_web_scan(target_web_url)
                            host_cves.extend(zap_findings)
                        
                        parsed_ports.append({
                            "port": port_num,
                            "protocol": protocol,
                            "state": state,
                            "service": service_info
                        })
            
            all_results[current_host] = {
                "ports": parsed_ports,
                "cves": host_cves,
                "exploits": host_exploits,
                "os": detected_os
            }
        except Exception as e:
            all_results[current_host] = {"ports": [], "cves": [], "exploits": [], "os": f"Scan Interrupted: {str(e)}"}
            
    return all_results