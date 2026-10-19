import os
import sys
import sqlite3
import requests
import zipfile
import io
import csv
from pathlib import Path

# Target DB paths
PROGRAM_DATA = os.environ.get("ProgramData", "C:\\ProgramData")
TARGET_DIR = Path(PROGRAM_DATA) / "STAI" / "Protection"
TARGET_DB = TARGET_DIR / "threat-intel.db"
LOCAL_DB = Path("threat-intel.db")

MALWAREBAZAAR_EXPORT_URL = "https://bazaar.abuse.ch/export/csv/full/"

def setup_database(db_path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            sha256_hash TEXT PRIMARY KEY,
            first_seen TIMESTAMP,
            threat_type TEXT,
            source TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON hashes(sha256_hash);")
    conn.commit()
    return conn

def download_and_import_malwarebazaar(api_key=None):
    print("[*] Preparing MalwareBazaar hash feed download...")
    
    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key
    else:
        print("[!] Warning: No Abuse.ch API key provided. Using public export endpoint if available...")

    try:
        response = requests.get(MALWAREBAZAAR_EXPORT_URL, headers=headers, stream=True, timeout=60)
        if response.status_code != 200:
            print(f"[!] Error fetching feed: HTTP {response.status_code} - {response.text}")
            return False

        print("[*] Download complete. Processing and importing SHA-256 hashes...")
        
        conn = setup_database(LOCAL_DB)
        cursor = conn.cursor()
        
        # MalwareBazaar CSV format includes comment lines starting with '#'
        decoded_content = response.content.decode('utf-8', errors='ignore')
        csv_reader = csv.reader(line for line in decoded_content.splitlines() if not line.startswith('#'))
        
        count = 0
        batch = []
        
        for row in csv_reader:
            # Columns usually: first_seen, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type, etc.
            if len(row) >= 2:
                first_seen = row[0].strip()
                sha256 = row[1].strip().lower()
                threat_type = row[5].strip() if len(row) > 5 else "unknown"
                
                if len(sha256) == 64:  # Valid SHA-256 length
                    batch.append((sha256, first_seen, threat_type, "MalwareBazaar"))
                    count += 1
                    
                    if len(batch) >= 5000:
                        cursor.executemany("OR IGNORE INTO hashes VALUES (?, ?, ?, ?)", batch)
                        conn.commit()
                        batch = []
                        print(f"[*] Imported {count} hashes so far...")

        if batch:
            cursor.executemany("OR IGNORE INTO hashes VALUES (?, ?, ?, ?)", batch)
            conn.commit()

        cursor.execute("SELECT COUNT(*) FROM hashes;")
        total_hashes = cursor.fetchone()[0]
        conn.close()
        
        print(f"[+] Success! Total unique malicious hashes imported: {total_hashes:,}")
        return True

    except Exception as e:
        print(f"[!] Failed during ingestion: {e}")
        return False

def deploy_database():
    if not LOCAL_DB.exists():
        print("[!] Local threat-intel.db not found to deploy.")
        return

    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(LOCAL_DB, TARGET_DB)
    print(f"[+] Deployed threat database to production path: {TARGET_DB}")
$targetDir = "$env:ProgramData\STAI\Protection"

if (!(Test-Path $targetDir)) {
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
}

# If it was saved with an underscore locally, rename/copy it to a hyphen
if (Test-Path "threat_intel.db") {
    Copy-Item "threat_intel.db" "$targetDir\threat-intel.db" -Force
    Write-Host "[+] Renamed and copied threat_intel.db -> threat-intel.db in $targetDir"
} elseif (Test-Path "threat-intel.db") {
    Copy-Item "threat-intel.db" "$targetDir\threat-intel.db" -Force
    Write-Host "[+] Copied threat-intel.db to $targetDir"
} else {
    Write-Host "[!] Local database file not found yet. Make sure your ingestion script outputs to threat-intel.db"
}

if __name__ == "__main__":
    # Insert your abuse.ch API key here if you have one, or pass via command line argument
    api_key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ABUSE_CH_KEY", None)
    
    if download_and_import_malwarebazaar(api_key):
        deploy_database()
        print("[*] Threat-intel database ingestion and deployment complete.")
    else:
        sys.exit(1)