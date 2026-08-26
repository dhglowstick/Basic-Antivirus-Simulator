import os
import json
import hashlib
import shutil
import argparse
from datetime import datetime
from pathlib import Path


SIGNATURE_FILE = "signatures.json"
QUARANTINE_DIR = "quarantine"
REPORT_DIR = "reports"


class BasicAntivirus:

    def __init__(self, signature_file=SIGNATURE_FILE):
        self.signature_file = signature_file
        self.signatures = self.load_signatures()

        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        os.makedirs(REPORT_DIR, exist_ok=True)

    # ---------------------------------------------------------
    # Load malware signatures
    # ---------------------------------------------------------
    def load_signatures(self):
        try:
            with open(self.signature_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            print("[ERROR] Signature database not found.")
            return {}

        except json.JSONDecodeError:
            print("[ERROR] Signature database is invalid.")
            return {}

    # ---------------------------------------------------------
    # Calculate SHA-256 hash
    # ---------------------------------------------------------
    def calculate_hash(self, filepath):

        sha256 = hashlib.sha256()

        try:
            with open(filepath, "rb") as file:

                while True:
                    data = file.read(4096)

                    if not data:
                        break

                    sha256.update(data)

            return sha256.hexdigest()

        except (PermissionError, OSError) as error:
            print(f"[ERROR] Cannot read {filepath}: {error}")
            return None

    # ---------------------------------------------------------
    # Check a single file
    # ---------------------------------------------------------
    def scan_file(self, filepath):

        file_hash = self.calculate_hash(filepath)

        if file_hash is None:
            return {
                "file": str(filepath),
                "status": "ERROR",
                "hash": None
            }

        if file_hash in self.signatures:

            malware_name = self.signatures[file_hash]

            print(f"[!] MALICIOUS: {filepath}")
            print(f"    Malware: {malware_name}")
            print(f"    SHA-256: {file_hash}")

            return {
                "file": str(filepath),
                "status": "MALICIOUS",
                "malware": malware_name,
                "hash": file_hash
            }

        else:

            print(f"[+] CLEAN: {filepath}")

            return {
                "file": str(filepath),
                "status": "CLEAN",
                "hash": file_hash
            }

    # ---------------------------------------------------------
    # Scan directory recursively
    # ---------------------------------------------------------
    def scan_directory(self, directory):

        directory = Path(directory)

        if not directory.exists():
            print("[ERROR] Directory does not exist.")
            return []

        print("\n======================================")
        print("       BASIC ANTIVIRUS SCANNER")
        print("======================================")
        print(f"Scanning: {directory}")
        print("--------------------------------------")

        results = []

        for root, dirs, files in os.walk(directory):

            # Prevent scanning our own quarantine directory
            dirs[:] = [
                d for d in dirs
                if Path(root, d).resolve() != Path(QUARANTINE_DIR).resolve()
            ]

            for filename in files:

                filepath = Path(root) / filename

                result = self.scan_file(filepath)

                results.append(result)

        return results

    # ---------------------------------------------------------
    # Quarantine malicious files
    # ---------------------------------------------------------
    def quarantine_file(self, filepath):

        filepath = Path(filepath)

        if not filepath.exists():
            return False

        try:

            destination = Path(QUARANTINE_DIR) / filepath.name

            # Avoid filename collision
            counter = 1

            while destination.exists():

                destination = (
                    Path(QUARANTINE_DIR)
                    / f"{filepath.stem}_{counter}{filepath.suffix}"
                )

                counter += 1

            shutil.move(str(filepath), str(destination))

            print(f"[QUARANTINED] {filepath}")
            print(f"             -> {destination}")

            return True

        except (PermissionError, OSError) as error:

            print(f"[ERROR] Could not quarantine {filepath}: {error}")

            return False

    # ---------------------------------------------------------
    # Quarantine all detected malicious files
    # ---------------------------------------------------------
    def quarantine_malicious(self, results):

        count = 0

        for result in results:

            if result["status"] == "MALICIOUS":

                if self.quarantine_file(result["file"]):
                    count += 1

        return count

    # ---------------------------------------------------------
    # Generate report
    # ---------------------------------------------------------
    def generate_report(self, results):

        malicious = sum(
            1 for result in results
            if result["status"] == "MALICIOUS"
        )

        clean = sum(
            1 for result in results
            if result["status"] == "CLEAN"
        )

        errors = sum(
            1 for result in results
            if result["status"] == "ERROR"
        )

        report = {
            "scan_time": datetime.now().isoformat(),
            "total_files": len(results),
            "clean_files": clean,
            "malicious_files": malicious,
            "errors": errors,
            "results": results
        }

        filename = (
            Path(REPORT_DIR)
            / f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(filename, "w") as file:
            json.dump(report, file, indent=4)

        print("\n======================================")
        print("             SCAN SUMMARY")
        print("======================================")
        print(f"Files scanned : {len(results)}")
        print(f"Clean files   : {clean}")
        print(f"Malicious     : {malicious}")
        print(f"Errors        : {errors}")
        print(f"Report saved  : {filename}")
        print("======================================\n")

        return filename


# =============================================================
# Command Line Interface
# =============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulator - SHA-256 Signature Scanner"
    )

    parser.add_argument(
        "directory",
        help="Directory to scan"
    )

    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="Move detected files to quarantine"
    )

    args = parser.parse_args()

    antivirus = BasicAntivirus()

    results = antivirus.scan_directory(args.directory)

    if not results:
        print("No files were scanned.")
        return

    if args.quarantine:

        print("\n[*] Quarantine mode enabled.")

        count = antivirus.quarantine_malicious(results)

        print(f"[*] {count} file(s) quarantined.")

    antivirus.generate_report(results)


if __name__ == "__main__":
    main()
