# Network Intrusion Detection System
## Project Report

**Student name:** [Enter your name]  
**Institution:** [Enter institution name]  
**Department:** [Enter department]  
**Project guide:** [Enter guide name]  
**Academic year:** [Enter academic year]

## Abstract
The Network Intrusion Detection System (NIDS) is an educational cybersecurity prototype that examines summarized network-flow records and identifies activity that may deserve investigation. The system uses transparent, configurable rules for patterns such as repeated failed connections, unusual destination ports, and unusually large data transfers. It writes a report in CSV format so that a learner or analyst can review flagged records. The prototype demonstrates the basic workflow of log ingestion, rule evaluation, alert generation, and reporting.

## 1. Introduction
Networks generate large amounts of connection and traffic data. Reviewing every record manually can be time-consuming. An intrusion detection system helps identify patterns that may indicate suspicious behavior. This project demonstrates a simple rule-based approach using Python and CSV input.

## 2. Problem statement
Provide a lightweight and understandable tool that can scan a supplied network-flow CSV file and highlight records that match predefined suspicious-activity rules.

## 3. Objectives
- Read structured network-flow records from a CSV file.
- Apply configurable rules to each record.
- Label suspicious records with alert names and severity.
- Export results to a report that can be inspected using spreadsheet software.
- Demonstrate basic defensive security analysis.

## 4. Proposed system
The user supplies an authorized CSV export or the included synthetic sample. The program validates the required columns, evaluates each record against the configured rules, adds alert and severity fields, and writes a results CSV.

### Workflow
```text
CSV flow data
     |
     v
Validate required columns
     |
     v
Apply detection rules
     |
     v
Assign alerts and severity
     |
     v
Export results CSV
```

## 5. Tools and technologies
- Python 3.9+
- CSV and JSON file formats
- Python standard library (`csv`, `json`, `ipaddress`, `argparse`, `datetime`)
- Windows, Linux, or macOS terminal

## 6. Detection logic
1. **Possible brute force:** flags a record when failed connections meet or exceed the configured threshold.
2. **Suspicious destination port:** flags destination ports in the configured list.
3. **High outbound traffic:** flags bytes sent at or above the configured threshold.
4. **High inbound traffic:** flags bytes received at or above the configured threshold.
5. **Administrative-port pattern:** flags a private source to a non-private destination on selected administrative ports.

These rules are intentionally simple and may need tuning for a real environment.

## 7. Implementation
The main logic is in `app.py`. `rules.json` contains thresholds and port lists. `data/sample_flows.csv` provides synthetic sample records. The script reads the input with `csv.DictReader`, evaluates every record, and writes the enriched results using `csv.DictWriter`.

## 8. Installation and execution
1. Install Python 3.9 or newer.
2. Extract the ZIP file.
3. Open a terminal in the extracted project directory.
4. Run `python app.py` (Windows users may use `py app.py`).
5. Review `reports/scan_results.csv`.

No third-party packages are required.

## 9. Testing plan
- Normal HTTPS or DNS-like records should generally show `alerts=NONE`.
- A record with many failed connections should match `POSSIBLE_BRUTE_FORCE`.
- A record using a configured suspicious port should match `SUSPICIOUS_DESTINATION_PORT`.
- A record exceeding a traffic threshold should match the corresponding high-traffic rule.
- The report should preserve original input columns and append `alerts` and `severity`.

## 10. Expected outcome
The program produces a CSV report and counts records scanned and records that matched one or more rules. This supports a basic demonstration of security monitoring and triage.

## 11. Limitations
The prototype does not inspect live packets, correlate events across time, or use machine learning. It relies on the quality of input data and fixed thresholds. Benign applications can match rules, and malicious activity may not match any configured rule.

## 12. Future enhancements
- Integrate authorized flow data from tools such as Zeek or firewall exports.
- Add time-window aggregation and source-based connection counts.
- Add a dashboard and visual summaries.
- Add unit tests and structured logging.
- Evaluate precision and recall against a labeled dataset.
- Add alert allowlists and configurable severity mappings.

## 13. Conclusion
This project demonstrates a foundational defensive monitoring workflow: structured data ingestion, configurable rule matching, and report generation. It is suitable as a learning prototype and can be extended with more robust analytics and validation.

## References
- Python documentation: https://docs.python.org/3/
- MITRE ATT&CK (for further defensive detection research): https://attack.mitre.org/
- NIST Computer Security Incident Handling Guide, SP 800-61: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

## Submission checklist
- [ ] Replace all student/institution placeholders.
- [ ] Run the project and capture genuine screenshots.
- [ ] Review the generated report.
- [ ] Confirm the AICTE portal and institution requirements.
- [ ] Add only work and results you have personally verified.
