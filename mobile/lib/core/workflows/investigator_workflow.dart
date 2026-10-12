import '../tools/mobile_tool_definition.dart';

enum InvestigatorWorkflowPhase { foundation, consumerMvp }

enum InvestigatorNetworkPolicy {
  localOnly,
  externalRequiresEvidenceSelectionAndConsent,
}

class InvestigatorWorkflowStep {
  const InvestigatorWorkflowStep({
    required this.id,
    required this.summary,
    this.toolId,
    this.requiresUserSelection = false,
  });

  final String id;
  final String summary;
  final String? toolId;
  final bool requiresUserSelection;
}

class InvestigatorWorkflowDefinition {
  const InvestigatorWorkflowDefinition({
    required this.id,
    required this.name,
    required this.summary,
    required this.phase,
    required this.steps,
    required this.networkPolicy,
    required this.dataSensitivity,
    required this.allowedInvocationSources,
    required this.requiresUserConfirmation,
    this.requiresEvidencePreview = false,
    this.canExecuteDeviceActions = false,
  });

  final String id;
  final String name;
  final String summary;
  final InvestigatorWorkflowPhase phase;
  final List<InvestigatorWorkflowStep> steps;
  final InvestigatorNetworkPolicy networkPolicy;
  final MobileDataSensitivity dataSensitivity;
  final Set<MobileInvocationSource> allowedInvocationSources;
  final bool requiresUserConfirmation;
  final bool requiresEvidencePreview;

  /// Kept false by design: an investigator workflow cannot mutate Android.
  final bool canExecuteDeviceActions;
}
