"""
CyberOS Attack Simulations
Safe, controlled attack scripts for testing and demonstration.
"""

import os
import sys
import time
import subprocess
import socket
import shutil
import hashlib
from typing import Dict, Any, List


def launch_attack(attack_type: str, engine: Any):
    """Launch a simulated attack."""
    attacks = {
        "bruteforce": attack_bruteforce,
        "powershell": attack_powershell,
        "portscan": attack_portscan,
        "ransomware": attack_ransomware,
    }
    
    attack_func = attacks.get(attack_type)
    if attack_func:
        attack_func(engine)
    else:
        print(f"[!] Unknown attack type: {attack_type}")


def attack_bruteforce(engine: Any):
    """Simulate brute force attack by triggering Windows Security events."""
    print("[ATTACK] Starting brute force simulation...")
    
    for i in range(8):
        # Trigger PowerShell to generate security events
        try:
            subprocess.run([
                "powershell", "-Command",
                "try { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Translate([System.Security.Principal.NTAccount]).Value } catch {}"
            ], capture_output=True, timeout=5, creationflags=0x08000000)  # CREATE_NO_WINDOW
        except Exception as e:
            print(f"[ATTACK] Brute force attempt {i+1} error: {e}")
        time.sleep(0.3)
    
    print("[ATTACK] Brute force simulation complete.")


def attack_powershell(engine: Any):
    """Simulate obfuscated PowerShell execution."""
    print("[ATTACK] Starting PowerShell obfuscation attack...")
    
    try:
        # Encode a benign but suspicious-looking command
        command = "Write-Host 'Downloading security update from Microsoft...'; Start-Sleep 2; Write-Host 'Update complete'"
        encoded = __import__('base64').b64encode(command.encode()).decode()
        
        # Run encoded PowerShell
        subprocess.run([
            "powershell", "-NoProfile", "-EncodedCommand", encoded
        ], capture_output=True, timeout=10, creationflags=0x08000000)
        
        print("[ATTACK] PowerShell obfuscation complete.")
    except Exception as e:
        print(f"[ATTACK] PowerShell attack error: {e}")


def attack_portscan(engine: Any):
    """Simulate port scan against localhost."""
    print("[ATTACK] Starting port scan on localhost...")
    
    target = "127.0.0.1"
    open_ports = []
    
    try:
        for port in range(1, 101):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
    except Exception as e:
        print(f"[ATTACK] Port scan error: {e}")
    
    print(f"[ATTACK] Port scan complete. Open ports: {open_ports}")


def attack_ransomware(engine: Any):
    """Simulate ransomware behavior on test directory."""
    print("[ATTACK] Starting ransomware simulation...")
    
    test_dir = r"C:\AEGIS_Test"
    backup_dir = r"C:\AEGIS_Test_Backup"
    
    try:
        # Restore from backup first
        if os.path.exists(backup_dir):
            for f in os.listdir(backup_dir):
                src = os.path.join(backup_dir, f)
                dst = os.path.join(test_dir, f)
                if os.path.exists(dst):
                    os.remove(dst)
                shutil.copy2(src, dst)
        
        # Simulate encryption
        if os.path.exists(test_dir):
            files = [f for f in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, f))]
            for i, filename in enumerate(files[:5]):
                filepath = os.path.join(test_dir, filename)
                locked_name = os.path.join(test_dir, filename + ".locked")
                
                # Rename file
                if os.path.exists(filepath):
                    os.rename(filepath, locked_name)
                
                # Write "encrypted" header
                if os.path.exists(locked_name):
                    with open(locked_name, "rb+") as f:
                        f.write(b"ENCRYPTED_BY_CYBEROS_DEMO")
                
                time.sleep(0.3)
        
        print("[ATTACK] Ransomware simulation complete.")
    except Exception as e:
        print(f"[ATTACK] Ransomware simulation error: {e}")


def restore_test_files():
    """Restore test files from backup."""
    test_dir = r"C:\AEGIS_Test"
    backup_dir = r"C:\AEGIS_Test_Backup"
    
    try:
        if os.path.exists(backup_dir):
            # Clean test dir
            if os.path.exists(test_dir):
                for f in os.listdir(test_dir):
                    fp = os.path.join(test_dir, f)
                    if os.path.isfile(fp):
                        os.remove(fp)
            
            # Restore from backup
            for f in os.listdir(backup_dir):
                src = os.path.join(backup_dir, f)
                dst = os.path.join(test_dir, f)
                shutil.copy2(src, dst)
            
            print("[RESTORE] Test files restored from backup.")
    except Exception as e:
        print(f"[RESTORE] Error: {e}")


if __name__ == "__main__":
    # Test attack
    print("CyberOS Attack Simulations")
    print("Available attacks: bruteforce, powershell, portscan, ransomware")
