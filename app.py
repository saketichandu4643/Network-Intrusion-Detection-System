#!/usr/bin/env python3
"""Simple educational Network Intrusion Detection System (NIDS).

Reads network-flow records from a CSV file and flags suspicious records using
transparent, configurable heuristics. This is a learning/demo tool, not a
replacement for a production IDS.
"""
import argparse
import csv
import ipaddress
import json
import os
from datetime import datetime

DEFAULT_RULES = {
    "failed_connections_threshold": 10,
    "bytes_out_threshold": 10000000,
    "bytes_in_threshold": 50000000,
    "suspicious_ports": [23, 2323, 4444, 5555, 6667, 31337],
    "private_source_to_public_admin_ports": [22, 3389, 5900],
}

def is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except (ValueError, TypeError):
        return False

def classify(row, rules):
    """Return a list of rule labels matched by a normalized flow record."""
    alerts = []
    src = (row.get("src_ip") or "").strip()
    dst = (row.get("dst_ip") or "").strip()
    try:
        dst_port = int(row.get("dst_port") or 0)
    except ValueError:
        dst_port = 0
    try:
        failed = int(row.get("failed_connections") or 0)
    except ValueError:
        failed = 0
    try:
        bytes_out = int(row.get("bytes_out") or 0)
    except ValueError:
        bytes_out = 0
    try:
        bytes_in = int(row.get("bytes_in") or 0)
    except ValueError:
        bytes_in = 0

    if failed >= int(rules["failed_connections_threshold"]):
        alerts.append("POSSIBLE_BRUTE_FORCE")
    if dst_port in set(rules["suspicious_ports"]):
        alerts.append("SUSPICIOUS_DESTINATION_PORT")
    if bytes_out >= int(rules["bytes_out_threshold"]):
        alerts.append("HIGH_OUTBOUND_TRAFFIC")
    if bytes_in >= int(rules["bytes_in_threshold"]):
        alerts.append("HIGH_INBOUND_TRAFFIC")
    if is_private_ip(src) and not is_private_ip(dst) and dst_port in set(rules["private_source_to_public_admin_ports"]):
        alerts.append("PRIVATE_HOST_TO_PUBLIC_ADMIN_PORT")
    return alerts

def load_rules(path):
    if not path:
        return DEFAULT_RULES
    with open(path, "r", encoding="utf-8") as f:
        custom = json.load(f)
    merged = dict(DEFAULT_RULES)
    merged.update(custom)
    return merged

def scan(input_path, output_path, rules):
    total = 0
    alert_count = 0
    with open(input_path, newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                    "bytes_out", "bytes_in", "failed_connections"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("CSV missing required columns: " + ", ".join(sorted(missing)))
        with open(output_path, "w", newline="", encoding="utf-8") as target:
            fields = list(reader.fieldnames) + ["alerts", "severity"]
            writer = csv.DictWriter(target, fieldnames=fields)
            writer.writeheader()
            for row in reader:
                total += 1
                alerts = classify(row, rules)
                row["alerts"] = ";".join(alerts) if alerts else "NONE"
                row["severity"] = "HIGH" if len(alerts) >= 2 or "POSSIBLE_BRUTE_FORCE" in alerts else ("MEDIUM" if alerts else "INFO")
                if alerts:
                    alert_count += 1
                writer.writerow(row)
    return total, alert_count

def main():
    parser = argparse.ArgumentParser(description="Rule-based educational Network Intrusion Detection System")
    parser.add_argument("-i", "--input", default="data/sample_flows.csv", help="Input network-flow CSV")
    parser.add_argument("-o", "--output", default="reports/scan_results.csv", help="Output report CSV")
    parser.add_argument("-r", "--rules", default="rules.json", help="JSON rules file")
    args = parser.parse_args()
    rules = load_rules(args.rules)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    try:
        total, alerts = scan(args.input, args.output, rules)
    except (OSError, ValueError, csv.Error) as exc:
        parser.error(str(exc))
    print("Network Intrusion Detection System")
    print(f"Scan completed at: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Records scanned: {total}")
    print(f"Records with alerts: {alerts}")
    print(f"Report saved to: {args.output}")

if __name__ == "__main__":
    main()
