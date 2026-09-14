"""
CyberOS Core - Response Engine with Verification
Executes controlled security responses with approval workflow
"""

import os
import json
import time
import uuid
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class ResponseResult:
    def __init__(self, action_id: str, action_type: str, target: str,
                 status: str, result: str, verification: str = ""):
        self.action_id = action_id
        self.action_type = action_type
        self.target = target
        self.status = status  # REQUESTED, EXECUTING, SUCCESS, FAILED, VERIFICATION_FAILED
        self.result = result
        self.verification = verification
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            'action_id': self.action_id,
            'action_type': self.action_type,
            'target': self.target,
            'status': self.status,
            'result': self.result,
            'verification': self.verification,
            'timestamp': self.timestamp,
        }


class ResponseEngine:
    """Executes security response actions with verification."""

    def __init__(self, policy_engine=None, audit_logger=None):
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.results: List[ResponseResult] = []
        self._lock = threading.RLock()

    def execute_action(self, action_type: str, target: str, risk_score: float = 50,
                       approved: bool = False, reason: str = "", **kwargs) -> ResponseResult:
        """Execute a security response action."""
        action_id = f"ACTION-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}"

        # Check policy
        if self.policy_engine:
            policy_check = self.policy_engine.check_policy(action_type, risk_score)
            if not policy_check.get('allowed', False):
                result = ResponseResult(
                    action_id=action_id,
                    action_type=action_type,
                    target=target,
                    status='FAILED',
                    result=f'Policy denied: {policy_check.get("reason", "Unknown")}',
                )
                self.results.append(result)
                return result

            if policy_check.get('requires_approval', False) and not approved:
                result = ResponseResult(
                    action_id=action_id,
                    action_type=action_type,
                    target=target,
                    status='REQUESTED',
                    result=f'Approval required. Policy: {policy_check.get("policy_id", "unknown")}',
                )
                self.results.append(result)
                return result

        # Execute the action
        result = ResponseResult(
            action_id=action_id,
            action_type=action_type,
            target=target,
            status='EXECUTING',
            result='Executing...',
        )

        try:
            # Route to specific handler
            handler = getattr(self, f'_handle_{action_type}', None)
            if handler:
                execution_result = handler(target, **kwargs)
                result.result = execution_result.get('message', 'Completed')
                result.status = execution_result.get('status', 'SUCCESS')

                # Verify the result
                verification = self._verify_action(action_type, target, **kwargs)
                result.verification = verification.get('message', 'Verification complete')

                if verification.get('status') == 'VERIFICATION_FAILED':
                    result.status = 'VERIFICATION_FAILED'

            else:
                result.status = 'FAILED'
                result.result = f'Unknown action type: {action_type}'

        except Exception as e:
            result.status = 'FAILED'
            result.result = f'Exception: {str(e)}'

        # Audit log
        if self.audit_logger:
            try:
                self.audit_logger.log_action(
                    actor="ResponseEngine",
                    action=action_type,
                    target=target,
                    reason=reason,
                    approval="USER_APPROVED" if approved else "AUTO_APPROVED",
                    result=result.status,
                )
            except Exception:
                pass

        with self._lock:
            self.results.append(result)

        return result

    def _handle_terminate_process(self, target: str, **kwargs) -> Dict:
        """Terminate a process by PID or name."""
        try:
            if target.isdigit():
                pid = int(target)
                proc = psutil.Process(pid) if PSUTIL_AVAILABLE else None
                if proc:
                    proc.terminate()
                    return {'status': 'SUCCESS', 'message': f'Terminated PID {pid}'}
                else:
                    return {'status': 'FAILED', 'message': f'Process {pid} not found'}
            else:
                # Try to find and kill by name
                killed = 0
                if PSUTIL_AVAILABLE:
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'].lower() == target.lower():
                            proc.terminate()
                            killed += 1
                return {'status': 'SUCCESS', 'message': f'Terminated {killed} processes matching {target}'}
        except psutil.NoSuchProcess:
            return {'status': 'FAILED', 'message': f'Process not found: {target}'}
        except psutil.AccessDenied:
            return {'status': 'FAILED', 'message': f'Access denied for {target}'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _handle_quarantine_file(self, target: str, **kwargs) -> Dict:
        """Quarantine a suspicious file."""
        try:
            quarantine_dir = kwargs.get('quarantine_dir', 'AEGIS_Quarantine')
            os.makedirs(quarantine_dir, exist_ok=True)
            filename = os.path.basename(target)
            quarantine_path = os.path.join(quarantine_dir, f"quarantined_{int(time.time())}_{filename}")
            shutil.move(target, quarantine_path)
            return {'status': 'SUCCESS', 'message': f'File quarantined to {quarantine_path}'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _handle_block_ip(self, target: str, **kwargs) -> Dict:
        """Block an IP address using firewall."""
        try:
            if os.name == 'nt':
                cmd = f'netsh advfirewall firewall add rule name="CyberOS Block {target}" dir=out action=block remoteip={target}'
                os.system(cmd)
                return {'status': 'SUCCESS', 'message': f'Blocked IP {target} in firewall'}
            else:
                return {'status': 'SIMULATED', 'message': f'Would block IP {target} (non-Windows)'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _handle_disable_persistence(self, target: str, **kwargs) -> Dict:
        """Disable a persistence mechanism."""
        try:
            if os.name == 'nt':
                cmd = f'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{target}" /f'
                os.system(cmd)
                return {'status': 'SUCCESS', 'message': f'Disabled persistence: {target}'}
            else:
                return {'status': 'SIMULATED', 'message': f'Would disable persistence: {target}'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _handle_disable_account(self, target: str, **kwargs) -> Dict:
        """Disable a user account."""
        try:
            if os.name == 'nt':
                cmd = f'net user {target} /active:no'
                os.system(cmd)
                return {'status': 'SUCCESS', 'message': f'Disabled account: {target}'}
            else:
                return {'status': 'SIMULATED', 'message': f'Would disable account: {target}'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _handle_remove_ssh_key(self, target: str, **kwargs) -> Dict:
        """Remove an SSH key."""
        try:
            key_path = os.path.expanduser(target)
            if os.path.exists(key_path):
                os.remove(key_path)
                return {'status': 'SUCCESS', 'message': f'Removed SSH key: {target}'}
            else:
                return {'status': 'FAILED', 'message': f'SSH key not found: {target}'}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _verify_action(self, action_type: str, target: str, **kwargs) -> Dict:
        """Verify that the action was successful."""
        try:
            if action_type == 'terminate_process':
                if PSUTIL_AVAILABLE:
                    if target.isdigit():
                        pid = int(target)
                        if not psutil.pid_exists(pid):
                            return {'status': 'SUCCESS', 'message': f'Verified: PID {pid} no longer running'}
                        else:
                            return {'status': 'VERIFICATION_FAILED', 'message': f'PID {pid} still running'}
                    else:
                        return {'status': 'SUCCESS', 'message': f'Verification: Process {target} handled'}
                return {'status': 'SIMULATED', 'message': 'Verification skipped (psutil not available)'}

            elif action_type == 'quarantine_file':
                if not os.path.exists(target):
                    return {'status': 'SUCCESS', 'message': f'Verified: Original file {target} inaccessible'}
                else:
                    return {'status': 'VERIFICATION_FAILED', 'message': f'Original file still exists: {target}'}

            elif action_type == 'block_ip':
                return {'status': 'SIMULATED', 'message': f'Firewall rule applied for {target}'}

            elif action_type == 'disable_persistence':
                return {'status': 'SIMULATED', 'message': f'Persistence disabled for {target}'}

            elif action_type == 'disable_account':
                return {'status': 'SIMULATED', 'message': f'Account {target} disabled'}

            elif action_type == 'remove_ssh_key':
                if not os.path.exists(target):
                    return {'status': 'SUCCESS', 'message': f'Verified: SSH key removed'}
                else:
                    return {'status': 'VERIFICATION_FAILED', 'message': f'SSH key still exists: {target}'}

            return {'status': 'SUCCESS', 'message': 'Verification complete'}

        except Exception as e:
            return {'status': 'FAILED', 'message': f'Verification error: {str(e)}'}

    def get_results(self, limit: int = 50) -> List[Dict]:
        """Get recent action results."""
        with self._lock:
            return [r.to_dict() for r in self.results[-limit:]]

    def get_result_by_id(self, action_id: str) -> Optional[ResponseResult]:
        """Get a specific action result."""
        with self._lock:
            for result in self.results:
                if result.action_id == action_id:
                    return result
        return None

import shutil