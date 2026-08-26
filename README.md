Basic Antivirus Simulator
A Python-based educational antivirus simulator that demonstrates signature-based malware detection.

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
Technologies
Python
SHA-256
JSON
File-system operations
How to Run
Clone the repository and navigate to the project directory:

python antivirus.py test_files

Enable Quarantine
To automatically move detected files to the quarantine directory:

python antivirus.py test_files --quarantine

Example
The simulator scans the specified directory and checks each file against the local malware signature database.

Example workflow:

Scanning: test_files/

file1.txt       CLEAN
file2.txt       MALICIOUS
file3.txt       CLEAN

Scan complete.

Detected files can be moved to quarantine when the --quarantine option is enabled.

Disclaimer
This project is designed for educational and ethical cybersecurity purposes. It uses harmless simulated test files rather than real malware. It is intended to demonstrate basic concepts behind signature-based antivirus detection and should not be considered a production antivirus solution.
