import argparse
import csv
import json
import nmap

# Custom mapping
APP_LOOKUP = {
    22: "Secure Shell (Admin Access)",
    80: "Web Server (Insecure)",
    443: "Web Server (Secure)",
    445: "Windows File Share (SMB)",
    3306: "MySQL Database",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL Database",
    8000: "Development Web Server",
    8080: "HTTP Proxy/Alternative",
    554: "RTSP Video Stream (IP Camera)",
    1883: "MQTT (IoT Broker)"
}

def get_app_category(port):
    return APP_LOOKUP.get(port, "Unknown / Other")

def scan_network(network_range, nmap_args="-sS -sV -O -T4", json_out="scan_results.json", csv_out="DISCOVERY_results.csv"):
    nm = nmap.PortScanner()
    print(f"Scanning {network_range}... (Requires sudo for MAC/OS detection)")
    print(f"[i] nmap arguments: {nmap_args}")

    nm.scan(hosts=network_range, arguments=nmap_args)

    scan_results = {}
    csv_data = []

    for host in nm.all_hosts():
        # 1. Get MAC and Vendor
        # Nmap stores MAC in the 'addresses' dict and Vendor in 'vendor'
        mac_address = nm[host]['addresses'].get('mac', 'Unknown')
        vendor_name = nm[host]['vendor'].get(mac_address, 'Unknown Vendor')

        # 2. Get OS Name
        os_name = "Unknown"
        if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
            os_name = nm[host]['osmatch'][0]['name']

        host_info = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "mac_address": mac_address,
            "vendor": vendor_name,
            "os": os_name,
            "protocols": {}
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            host_info["protocols"][proto] = []

            for port in ports:
                details = nm[host][proto][port]
                app_type = get_app_category(port)

                # Update JSON structure
                host_info["protocols"][proto].append({
                    "port": port,
                    "service": details['name'],
                    "application_type": app_type,
                    "product": details['product'],
                    "version": details['version']
                })

                # Update CSV structure
                csv_data.append({
                    "IP": host,
                    "MAC Address": mac_address,
                    "Vendor": vendor_name,
                    "OS": os_name,
                    "Port": port,
                    "Protocol": proto,
                    "Service": details['name'],
                    "Application Type": app_type,
                    "Product": details['product'],
                    "Version": details['version']
                })

        scan_results[host] = host_info

    # Save JSON
    with open(json_out, "w") as f:
        json.dump(scan_results, f, indent=4)

    # Save CSV with new columns
    csv_columns = ["IP", "MAC Address", "Vendor", "OS", "Port", "Protocol", "Service", "Application Type", "Product", "Version"]
    with open(csv_out, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"Scan complete. Data for {len(nm.all_hosts())} hosts saved.")
    print(f"[+] JSON: {json_out}")
    print(f"[+] CSV: {csv_out}")


def main():
    parser = argparse.ArgumentParser(
        description="LAN port and OS fingerprinting via nmap (python-nmap)."
    )
    parser.add_argument(
        "network",
        nargs="?",
        default="10.220.27.0/24",
        help="Target network (CIDR), host, or nmap target specification (default: %(default)s)",
    )
    parser.add_argument(
        "--nmap-args",
        default="-sS -sV -O -T4",
        help="Arguments passed to nmap, e.g. use '-sT -sV -T4' if raw SYN scans are blocked (default: %(default)s)",
    )
    parser.add_argument(
        "--json-out",
        default="scan_results.json",
        help="Output JSON path (default: %(default)s)",
    )
    parser.add_argument(
        "--csv-out",
        default="DISCOVERY_results.csv",
        help="Output CSV path (default: %(default)s)",
    )
    args = parser.parse_args()
    scan_network(
        args.network,
        nmap_args=args.nmap_args,
        json_out=args.json_out,
        csv_out=args.csv_out,
    )

if __name__ == "__main__":
    main()
