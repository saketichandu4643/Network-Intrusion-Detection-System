# Network Intrusion Detection System (NIDS)

**Project type:** Educational cybersecurity / network monitoring  
**Implementation:** Python 3.9+; standard library only

## 1. Overview
This project analyzes network-flow records in a CSV file and flags records that match simple, explainable security heuristics. It creates a CSV report containing the original fields, matched alert rules, and a severity label.

## 2. Features
- Detects records with a high number of failed connections (possible brute-force activity).
- Flags configured suspicious destination ports.
- Flags unusually high inbound or outbound traffic.
- Flags private-source to public-destination traffic targeting selected administrative ports.
- Supports configurable thresholds through `rules.json`.
- Exports findings to `reports/scan_results.csv`.

## 3. Project structure
```text
Network_Intrusion_Detection_System/
├── app.py
├── rules.json
├── requirements.txt
├── README.md
├── docs/
│   └── PROJECT_REPORT.md
├── data/
│   └── sample_flows.csv
└── reports/
    └── .gitkeep
```

## 4. Requirements
- Python 3.9 or newer
- Windows, macOS, or Linux
- No external Python packages are required

## 5. Run the project
Open a terminal in this folder.

### Windows
```powershell
py --version
py app.py
```

### macOS / Linux
```bash
python3 --version
python3 app.py
```

The default run reads `data/sample_flows.csv` and writes `reports/scan_results.csv`.

To specify input/output files:
```bash
python app.py --input data/sample_flows.csv --output reports/my_results.csv --rules rules.json
```

Open the generated CSV in Excel, LibreOffice, or a text editor. Records with `alerts` other than `NONE` need review.

## 6. Input CSV format
Required columns:
- `timestamp`
- `src_ip`
- `dst_ip`
- `dst_port`
- `protocol`
- `bytes_out`
- `bytes_in`
- `failed_connections`

Use one row per flow or summarized connection. The sample file contains synthetic demonstration data.

## 7. Customize detection rules
Edit `rules.json`. Thresholds are example values, not universal indicators of compromise. Port-based alerts may be false positives; investigate context before concluding that an intrusion occurred.

## 8. Limitations and safe use
- This is a rule-based educational prototype, not a production-grade IDS.
- It does not capture packets or monitor a live network; it analyzes CSV flow records only.
- It can produce false positives and false negatives.
- Use only network data you own or are authorized to analyze.
- Do not treat an alert alone as proof of malicious activity.

## 9. Troubleshooting
- **Python command not found:** Install Python 3.9+ and enable the PATH option on Windows.
- **Missing columns:** Ensure the CSV includes all required headers exactly as listed above.
- **Output not found:** Check the terminal message; the output path is relative to the project folder.
- **Permission error:** Choose a writable output folder.

## 10. Academic note
This is a starter project. Before submission, add your own name, institution, guide details, screenshots of a successful run, and any required AICTE/institution-specific forms. Verify the portal's required format and declaration rules.
