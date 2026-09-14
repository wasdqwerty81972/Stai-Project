import json, os, pathlib, subprocess, importlib.util, sys
from cyber_tools import SystemMonitor, SecretScanner
from cyber_agent import BUILTIN_WORKFLOWS

root = os.getcwd()
workflow = BUILTIN_WORKFLOWS['incident-response']
print('INVESTIGATION_OBJECTIVE=Read-only SOC validation of this workstation')
print('INTENT_CLASSIFICATION=Read-only validation / initial triage')
print('SELECTED_SPECIALIST=triage')
print('WORKFLOW_NAME=' + workflow.name)
print('WORKFLOW_PHASES=' + json.dumps([p.name for p in workflow.phases]))

conns = SystemMonitor.inspect_active_connections()
print('NETWORK_COUNT=' + str(len(conns)))
print('NETWORK_SAMPLE=' + json.dumps(conns[:12], default=str))

# Running processes (read-only)
proc_cmd = "Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Id,Name,Path,WorkingSet | Format-Table -AutoSize | Out-String -Width 200"
proc = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', proc_cmd], capture_output=True, text=True, timeout=60)
print('PROCESS_EXIT=' + str(proc.returncode))
print('PROCESS_OUTPUT=' + json.dumps((proc.stdout or '').splitlines()[:12], default=str))

# Defender status
mp_cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,NISEnabled,FullScanAge,QuickScanAge,DefenderSignaturesOutOfDate | Format-List | Out-String -Width 200"
mp = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', mp_cmd], capture_output=True, text=True, timeout=60)
print('DEFENDER_EXIT=' + str(mp.returncode))
print('DEFENDER_STATUS=' + json.dumps((mp.stdout or '').splitlines()[:20], default=str))

# Threat detections
threat_cmd = "Get-MpThreatDetection | Select-Object -First 10 | Format-Table -AutoSize | Out-String -Width 200"
threat = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', threat_cmd], capture_output=True, text=True, timeout=60)
print('THREAT_EXIT=' + str(threat.returncode))
print('THREAT_OUTPUT=' + json.dumps((threat.stdout or '').splitlines()[:20], default=str))

# Secret scan across workspace files
secret_hits = []
for path in pathlib.Path(root).rglob('*'):
    if path.is_file() and path.suffix.lower() in {'.py','.md','.txt','.json','.csv','.yaml','.yml','.ini','.env','.cfg','.ps1','.bat'}:
        try:
            text = path.read_text('utf-8', errors='ignore')
            hits = SecretScanner.scan_text_for_secrets(text)
            if hits:
                secret_hits.append({'file': str(path.relative_to(root)), 'hits': hits[:3]})
        except Exception:
            pass
print('SECRET_COUNT=' + str(len(secret_hits)))
print('SECRET_HITS=' + json.dumps(secret_hits[:20], default=str))

# Suspicious encoded / execution markers in workspace files
suspicious = []
for path in pathlib.Path(root).rglob('*'):
    if path.is_file() and path.suffix.lower() in {'.py','.md','.txt','.json','.csv','.yaml','.yml','.ini','.env','.cfg','.ps1','.bat'}:
        try:
            text = path.read_text('utf-8', errors='ignore').lower()
            markers = ['powershell', 'base64', 'certutil', 'rundll32', 'wmic', 'bitsadmin']
            hits = [m for m in markers if m in text]
            if hits:
                suspicious.append({'file': str(path.relative_to(root)), 'markers': hits[:5]})
        except Exception:
            pass
print('SUSPICIOUS_MARKERS=' + json.dumps(suspicious[:20], default=str))

# NAT / CUDA status
nat_available = importlib.util.find_spec('nat') is not None or importlib.util.find_spec('nvidia_nat') is not None
print('NAT_AVAILABLE=' + str(nat_available))
try:
    import torch
    print('CUDA_AVAILABLE=' + str(torch.cuda.is_available()))
    if torch.cuda.is_available():
        print('CUDA_DEVICE=' + str(torch.cuda.get_device_name(0)))
    else:
        print('CUDA_DEVICE=N/A')
except Exception as e:
    print('CUDA_AVAILABLE=False')
    print('CUDA_ERROR=' + str(e))

# IOC enrichment status (only simulated in project)
print('IOC_VT=' + json.dumps({"status": "simulated", "hash": "examplehashnotreal", "result": "No malicious detections (simulated)"}, default=str))
print('IOC_ABUSE=' + json.dumps({"status": "simulated", "ip": "8.8.8.8", "reputation": "clean", "score": 0}, default=str))
print('IOC_URL=' + json.dumps({"status": "simulated", "url": "https://example.com", "result": "No known threats (simulated)"}, default=str))
print('ROOT=' + root)
print('FILE_COUNT=' + str(sum(1 for _ in pathlib.Path(root).rglob('*') if _.is_file())))
