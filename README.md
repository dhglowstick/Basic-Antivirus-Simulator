Basic Antivirus Simulator
Project Description

This project is a Python-based educational antivirus simulator that demonstrates signature-based malware detection.

The program recursively scans files inside a selected directory, calculates their SHA-256 hashes, and compares those hashes against a local malware signature database.

When a file matches a known signature, it is classified as malicious and can optionally be moved to a quarantine directory.

Features
Recursive folder scanning
SHA-256 file hashing
Signature-based malware detection
Simulated malware signatures
Quarantine functionality
JSON scan reports
Command-line interface
Educational cybersecurity demonstration
Technologies
Python
SHA-256
JSON
File-system operations
How to Run
python antivirus.py test_files


To enable quarantine:

python antivirus.py test_files --quarantine

**Disclaimer**

This project is designed for educational and ethical cybersecurity purposes. It uses harmless simulated test files rather than real malware.
