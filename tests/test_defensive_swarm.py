"""Credit-free planning rules for the defensive specialist swarm."""

from cyber_os.subagents.contracts import SubagentProfile
from cyber_os.subagents.contracts import (
    SubagentStatus,
    SubagentStructuredResult,
    SubagentVerdict,
    ValidationConfidence,
)
from cyber_os.subagents.manager import SubagentManager
from cyber_os.subagents.swarm import DefensiveSwarmExecution, DefensiveSwarmPlanner, merge_swarm_evidence


def test_incident_swarm_is_bounded_to_relevant_defensive_specialists():
    plan = DefensiveSwarmPlanner().plan(
        "Several endpoints are slow and one has suspicious PowerShell network activity."
    )

    assert plan.read_only is True
    assert len(plan.profiles) <= 3
    assert SubagentProfile.INCIDENT_INVESTIGATION in plan.profiles
    assert SubagentProfile.NETWORK_ANALYSIS in plan.profiles
    assert SubagentProfile.MALWARE_ANALYSIS in plan.profiles


def test_simple_question_does_not_spend_credits_on_a_swarm():
    plan = DefensiveSwarmPlanner().plan("What is Kerberoasting?")

    assert plan.profiles == []
    assert plan.reason == "No multi-domain defensive investigation is required."


def test_requested_profiles_are_deduplicated_and_untrusted_values_rejected():
    planner = DefensiveSwarmPlanner()
    plan = planner.plan(
        "Investigate this suspicious hash",
        requested_profiles=["threat_analysis", "threat_analysis", "unknown-agent"],
    )

    assert plan.profiles == [SubagentProfile.THREAT_ANALYSIS]
    assert plan.rejected_profiles == ["unknown-agent"]


def test_swarm_execution_delegates_each_planned_specialist_once(monkeypatch):
    plan = DefensiveSwarmPlanner().plan(
        "Investigate suspicious PowerShell network activity across endpoints."
    )
    manager = SubagentManager(agent=object())
    calls = []

    def fake_delegate(profile_name, objective, parent_investigation_id, **_kwargs):
        calls.append((profile_name, objective, parent_investigation_id))
        return SubagentStructuredResult(
            subagent_id=f"sub-{profile_name}",
            profile=profile_name,
            status=SubagentStatus.COMPLETED,
            verdict=SubagentVerdict.INCONCLUSIVE,
            confidence=ValidationConfidence.LOW,
            summary="No live provider was invoked by this test.",
        )

    monkeypatch.setattr(manager, "delegate_task", fake_delegate)

    result = manager.delegate_swarm(plan, parent_investigation_id="inv-1")

    assert len(calls) == len(plan.profiles)
    assert {call[0] for call in calls} == {profile.value for profile in plan.profiles}
    assert result.completed_count == len(plan.profiles)


def test_swarm_isolates_a_failing_specialist_without_losing_the_others(monkeypatch):
    """A specialist that raises inside the thread pool must be captured as a FAILED
    result carrying its root cause, and must never discard the evidence produced by
    the specialists that succeeded alongside it."""
    plan = DefensiveSwarmPlanner().plan(
        "Investigate suspicious PowerShell network activity across endpoints."
    )
    # The scenario is only meaningful if the planner fielded more than one specialist.
    assert len(plan.profiles) >= 2

    manager = SubagentManager(agent=object())
    failing_profile = plan.profiles[0].value

    def flaky_delegate(profile_name, objective, parent_investigation_id, **_kwargs):
        if profile_name == failing_profile:
            raise RuntimeError("provider exploded mid-flight")
        return SubagentStructuredResult(
            subagent_id=f"sub-{profile_name}",
            profile=profile_name,
            status=SubagentStatus.COMPLETED,
            verdict=SubagentVerdict.INCONCLUSIVE,
            confidence=ValidationConfidence.LOW,
            summary="No live provider was invoked by this test.",
        )

    monkeypatch.setattr(manager, "delegate_task", flaky_delegate)

    execution = manager.delegate_swarm(plan, parent_investigation_id="inv-fail")

    # No specialist is dropped: every planned profile is represented, in planned order.
    assert [result.profile for result in execution.results] == [
        profile.value for profile in plan.profiles
    ]

    # Exactly one specialist failed; the rest completed and the swarm did not crash.
    assert execution.failed_count == 1
    assert execution.completed_count == len(plan.profiles) - 1

    # The failure is captured with its root cause, not silently swallowed.
    failed = next(r for r in execution.results if r.profile == failing_profile)
    assert failed.status == SubagentStatus.FAILED
    assert "provider exploded mid-flight" in (failed.error or "")
    assert any("provider exploded mid-flight" in limitation for limitation in failed.limitations)


def test_evidence_merge_preserves_conflicting_specialist_verdicts():
    plan = DefensiveSwarmPlanner().plan(
        "Investigate suspicious PowerShell network activity across endpoints."
    )
    execution = DefensiveSwarmExecution(
        plan=plan,
        results=[
            SubagentStructuredResult(
                subagent_id="sub-network",
                profile="Network Defense Specialist",
                status=SubagentStatus.COMPLETED,
                verdict=SubagentVerdict.CONFIRMED,
                confidence=ValidationConfidence.HIGH,
                summary="Observed repeated connections to the reported destination.",
                evidence_refs=["connection:42"],
            ),
            SubagentStructuredResult(
                subagent_id="sub-malware",
                profile="Malware Analysis Specialist",
                status=SubagentStatus.COMPLETED,
                verdict=SubagentVerdict.INCONCLUSIVE,
                confidence=ValidationConfidence.LOW,
                summary="No submitted binary was available for analysis.",
                limitations=["No file artifact was supplied."],
            ),
        ],
    )

    merged = merge_swarm_evidence(execution)

    assert merged.evidence_refs == ["connection:42"]
    assert merged.coverage == "incomplete"
    assert "No file artifact was supplied." in merged.limitations
    assert "inconclusive" in merged.summary.lower()


def test_evidence_merge_records_a_failed_specialist_without_dropping_confirmed_evidence():
    """A FAILED child is the exact state the failure-isolation branch produces
    (manager.delegate_swarm captures a raising specialist as FAILED). The merge
    reducer must attribute that failure in ``failed_profiles`` and keep coverage
    honest, yet it must never discard the verified evidence a sibling confirmed."""
    plan = DefensiveSwarmPlanner().plan(
        "Investigate suspicious PowerShell network activity across endpoints."
    )
    execution = DefensiveSwarmExecution(
        plan=plan,
        results=[
            SubagentStructuredResult(
                subagent_id="sub-network",
                profile="Network Defense Specialist",
                status=SubagentStatus.COMPLETED,
                verdict=SubagentVerdict.CONFIRMED,
                confidence=ValidationConfidence.HIGH,
                summary="Observed repeated connections to the reported destination.",
                evidence_refs=["connection:42"],
            ),
            SubagentStructuredResult(
                subagent_id="sub-malware",
                profile="Malware Analysis Specialist",
                status=SubagentStatus.COMPLETED,
                verdict=SubagentVerdict.INCONCLUSIVE,
                confidence=ValidationConfidence.LOW,
                summary="No submitted binary was available for analysis.",
                limitations=["No file artifact was supplied."],
            ),
            SubagentStructuredResult(
                subagent_id="sub-threat",
                profile="Threat Intel Specialist",
                status=SubagentStatus.FAILED,
                verdict=SubagentVerdict.INCONCLUSIVE,
                confidence=ValidationConfidence.LOW,
                summary="",
                error="provider exploded mid-flight",
                limitations=["Threat Intel Specialist crashed: provider exploded mid-flight"],
            ),
        ],
    )

    merged = merge_swarm_evidence(execution)

    # The confirmed specialist's evidence survives a sibling's failure.
    assert merged.evidence_refs == ["connection:42"]
    assert merged.confirmed_profiles == ["Network Defense Specialist"]
    assert merged.inconclusive_profiles == ["Malware Analysis Specialist"]

    # The failure is attributed to the right specialist, not silently dropped.
    assert merged.failed_profiles == ["Threat Intel Specialist"]

    # A failed (or inconclusive) child keeps the settlement from over-claiming.
    assert merged.coverage == "incomplete"

    # Both the generic non-completion note and the specialist's own root cause
    # reach the parent for its later evidence-bound synthesis.
    assert "Threat Intel Specialist did not complete." in merged.limitations
    assert (
        "Threat Intel Specialist crashed: provider exploded mid-flight"
        in merged.limitations
    )
    assert "No file artifact was supplied." in merged.limitations

    # The one-line settlement counts each outcome class exactly once.
    assert "1 confirmed" in merged.summary
    assert "1 inconclusive" in merged.summary
    assert "1 unavailable" in merged.summary


def test_explicit_swarm_command_routes_to_parent_owned_swarm_handler():
    from cyber_agent import CyberAgent

    agent = CyberAgent.__new__(CyberAgent)
    agent._run_defensive_swarm = lambda objective, session_id="default": f"SWARM:{objective}:{session_id}"

    assert agent._process_chat_command(
        "/swarm investigate suspicious network activity", session_id="s7"
    ) == ("SWARM:investigate suspicious network activity:s7")


def test_swarm_command_is_discoverable_in_the_composer_catalog():
    from cyber_os.assets import get_command_registry

    command = get_command_registry().get("swarm")

    assert command is not None
    assert command.argument_hint == "investigation objective"


def test_network_containment_advisor_is_read_only_and_approval_gated():
    from cyber_os.subagents.profiles import get_profile_definition

    profile = get_profile_definition(SubagentProfile.NETWORK_CONTAINMENT_ADVISOR)

    assert profile.allowed_tools == []
    assert "approval" in profile.system_prompt.lower()
    assert "firewall" in profile.system_prompt.lower()
