# Virustotal-Hash-Automation
This Python script automates the process of checking file hashes against the [VirusTotal API](https://www.virustotal.com/) and logs the results for security analysis.

## Features
- Queries VirusTotal using file hashes (SHA256/SHA1/MD5) And IPs (IPv4/IPv6).
- Extracts detection statistics:
  - Malicious, Suspicious, Undetected, Harmless
- Calculates a detection **score** (`positives/total engines`).
- Applies simple verdict logic:
  - High Risk → if malicious > 5
  - Suspicious → if suspicious > 0
  - Likely Safe → otherwise
- Saves results into a CSV file (`vt_results.csv`).
- Prints results to the terminal for quick review.
- Respects VirusTotal API rate limits.

## Requirements
- Python 3.7+
- [VirusTotal Python SDK](https://github.com/VirusTotal/vt-py)
  ```bash
  pip install vt-py

