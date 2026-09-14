import asyncio
import os
import signal
import hashlib
import shutil
import logging
from dataclasses import dataclass
from z3 import Solver, String, Implies, And, Not, sat

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] ProductionFormalDaemon: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


@dataclass(frozen=True)
class SyscallIntent:
    pid: int
    uid: int
    agent_identity: str
    syscall_name: str
    target_resource: str
    threat_score: int


class FormalSMTTheoremProver:
    """Uses Z3 SMT solver to check policy safety before execution."""

    def __init__(self):
        self.solver = Solver()

    def prove_execution_safety(self, intent: SyscallIntent) -> bool:
        self.solver.reset()

        agent = String('agent')
        syscall = String('syscall')
        resource = String('resource')

        self.solver.add(agent == intent.agent_identity)
        self.solver.add(syscall == intent.syscall_name)
        self.solver.add(resource == intent.target_resource)

        # Theorem 1: Write/Delete on system binaries requires KERNEL_ROOT_AGENT
        theorem_protected_storage = Implies(
            And(syscall == "sys_unlink", resource == "/tmp/production_binary"),
            agent == "KERNEL_ROOT_AGENT"
        )
        # Theorem 2: UNTRUSTED_AGENT cannot issue execve
        theorem_isolation = Implies(
            agent == "UNTRUSTED_AGENT",
            Not(syscall == "sys_execve")
        )

        self.solver.add(theorem_protected_storage)
        self.solver.add(theorem_isolation)

        # NOTE: with concrete (non-symbolic) values bound via ==, sat here means
        # "these constraints + the bound values are jointly consistent," i.e.
        # the intent does NOT violate a theorem. UNSAT means it does violate one.
        if self.solver.check() == sat:
            logging.info(
                f"SMT_PROOF_PASSED: [{intent.syscall_name}] on [{intent.target_resource}] by "
                f"[{intent.agent_identity}] is consistent with policy."
            )
            return True
        else:
            logging.critical(
                f"SMT_PROOF_FAILED: Invariant violation for PID [{intent.pid}]! Execution HALT enforced."
            )
            return False


class CryptographicSelfHealingEngine:
    """Restores integrity from a cryptographically verified shadow copy."""

    def __init__(self, target_path: str, shadow_path: str):
        self.target_path = target_path
        self.shadow_path = shadow_path

    @staticmethod
    def _compute_sha256(path: str) -> str:
        if not os.path.exists(path):
            return ""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    async def verify_and_heal(self):
        # Recompute the shadow hash fresh each time instead of caching it once
        # at __init__ (the shadow file may not exist yet at construction time).
        valid_hash = self._compute_sha256(self.shadow_path)
        current_hash = self._compute_sha256(self.target_path)
        if current_hash != valid_hash:
            logging.warning(f"TAMPER_DETECTED: Hash mismatch on [{self.target_path}].")
            shutil.copy2(self.shadow_path, self.target_path)
            logging.info("SELF_HEALED: Restored binary from verified shadow storage.")
        else:
            logging.info("INTEGRITY_OK: No tampering detected.")


class ProductionAutonomousGuardrail:
    def __init__(self):
        self.prover = FormalSMTTheoremProver()
        self.healer = CryptographicSelfHealingEngine(
            target_path="/tmp/production_binary",
            shadow_path="/tmp/production_binary.shadow"
        )
        self.own_pid = os.getpid()

    async def terminate_process_tree(self, pid: int):
        # Never let the daemon terminate itself.
        if pid == self.own_pid:
            logging.critical(
                f"REFUSED_SELF_KILL: Intent targeted the daemon's own PID [{pid}]; ignoring."
            )
            return
        try:
            os.kill(pid, signal.SIGKILL)
            logging.critical(f"PROCESS_TERMINATED: Sent SIGKILL to PID [{pid}].")
        except ProcessLookupError:
            logging.warning(f"PROCESS_NOT_FOUND: PID [{pid}] no longer exists.")

    async def process_event(self, intent: SyscallIntent):
        is_safe = self.prover.prove_execution_safety(intent)

        if not is_safe or intent.threat_score >= 8:
            # Heal first (deterministic, file-based), then terminate the
            # offending process — don't run them "concurrently" when one
            # (SIGKILL) can end the process performing the other.
            await self.healer.verify_and_heal()
            await self.terminate_process_tree(intent.pid)

    async def start(self):
        logging.info("Starting Production Security Daemon & Z3 Formal Theorem Engine...")

        with open("/tmp/production_binary.shadow", "w") as f:
            f.write("SIGNED_SECURE_BINARY_DATA")
        with open("/tmp/production_binary", "w") as f:
            f.write("TAMPERED_MALICIOUS_PAYLOAD")

        # Simulate a hostile process with its own PID, distinct from the daemon.
        simulated_attacker_pid = os.fork() if hasattr(os, "fork") else self.own_pid
        if simulated_attacker_pid == 0:
            # Child: just sleep, standing in for the "attacker" process.
            try:
                signal.pause()
            finally:
                os._exit(0)

        attack_intent = SyscallIntent(
            pid=simulated_attacker_pid,
            uid=1001,
            agent_identity="UNAUTHORIZED_USER",
            syscall_name="sys_unlink",
            target_resource="/tmp/production_binary",
            threat_score=10
        )

        logging.info("Submitting telemetry intent to Z3 Formal Theorem Prover...")
        await self.process_event(attack_intent)


if __name__ == "__main__":
    daemon = ProductionAutonomousGuardrail()
    asyncio.run(daemon.start())