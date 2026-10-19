import '../tools/mobile_tool_definition.dart';
import '../tools/mobile_tool_registry.dart';
import 'investigator_workflow.dart';

const investigatorWorkflowRegistryVersion = 1;

/// Bounded investigator workflows. Metadata records the required user steps;
/// runtime support is provided only by the explicitly wired mobile services.
const investigatorWorkflowRegistry = <InvestigatorWorkflowDefinition>[
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.device_posture_review',
    name: 'Device posture review',
    summary: 'Collect a baseline, evaluate local checks, then present coverage gaps.',
    phase: InvestigatorWorkflowPhase.foundation,
    steps: [
      InvestigatorWorkflowStep(id: 'baseline', summary: 'Read supported local posture fields.', toolId: 'mobile.device_baseline'),
      InvestigatorWorkflowStep(id: 'checks', summary: 'Evaluate deterministic local checks.', toolId: 'mobile.posture_check'),
      InvestigatorWorkflowStep(id: 'coverage', summary: 'Show what is and is not monitored.', toolId: 'mobile.protection_coverage_report'),
    ],
    networkPolicy: InvestigatorNetworkPolicy.localOnly,
    dataSensitivity: MobileDataSensitivity.moderate,
    allowedInvocationSources: {MobileInvocationSource.user, MobileInvocationSource.enabledLocalRule},
    requiresUserConfirmation: false,
  ),
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.application_risk_review',
    name: 'Application risk review',
    summary: 'Review visible packages and requested permission posture.',
    phase: InvestigatorWorkflowPhase.consumerMvp,
    steps: [
      InvestigatorWorkflowStep(id: 'inventory', summary: 'Read the visible package inventory.', toolId: 'mobile.visible_app_inventory', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'permissions', summary: 'Analyze selected visible apps.', toolId: 'mobile.visible_app_permission_audit', requiresUserSelection: true),
    ],
    networkPolicy: InvestigatorNetworkPolicy.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    allowedInvocationSources: {MobileInvocationSource.user},
    requiresUserConfirmation: true,
  ),
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.selected_apk_triage',
    name: 'Selected APK triage',
    summary: 'Inspect an APK selected through Android’s document picker as inert data.',
    phase: InvestigatorWorkflowPhase.consumerMvp,
    steps: [
      InvestigatorWorkflowStep(id: 'select_apk', summary: 'User chooses one APK URI.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'inspect_apk', summary: 'Run bounded static metadata and signature checks.', toolId: 'mobile.selected_apk_inspection'),
    ],
    networkPolicy: InvestigatorNetworkPolicy.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    allowedInvocationSources: {MobileInvocationSource.user},
    requiresUserConfirmation: true,
  ),
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.selected_file_triage',
    name: 'Selected file triage',
    summary: 'Compute a bounded local SHA-256 digest for one user-selected file.',
    phase: InvestigatorWorkflowPhase.consumerMvp,
    steps: [
      InvestigatorWorkflowStep(id: 'select_file', summary: 'User chooses one file URI.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'inspect_file', summary: 'Compute a bounded digest; do not extract or execute content.', toolId: 'mobile.selected_file_inspection'),
    ],
    networkPolicy: InvestigatorNetworkPolicy.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    allowedInvocationSources: {MobileInvocationSource.user},
    requiresUserConfirmation: true,
  ),
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.link_triage',
    name: 'Link triage',
    summary: 'Check a URL entered in the app; no browser or share-sheet integration is active.',
    phase: InvestigatorWorkflowPhase.consumerMvp,
    steps: [
      InvestigatorWorkflowStep(id: 'submit_url', summary: 'User enters the URL in the Tools screen.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'local_url_check', summary: 'Run local URL structure checks.', toolId: 'mobile.url_local_check'),
    ],
    networkPolicy: InvestigatorNetworkPolicy.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    allowedInvocationSources: {MobileInvocationSource.user},
    requiresUserConfirmation: true,
  ),
  InvestigatorWorkflowDefinition(
    id: 'mobile.workflow.finding_investigation',
    name: 'Finding investigation',
    summary: 'Correlate selected local findings and optionally submit selected evidence to a provider.',
    phase: InvestigatorWorkflowPhase.consumerMvp,
    steps: [
      InvestigatorWorkflowStep(id: 'select_findings', summary: 'User chooses findings/evidence references.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'local_correlation', summary: 'Create local evidence-backed explanation.', toolId: 'mobile.finding_correlate_explain'),
      InvestigatorWorkflowStep(id: 'select_external_evidence', summary: 'User selects exact evidence for external submission.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'preview_external_request', summary: 'Show provider, destination, redactions, and exact payload before sending.', requiresUserSelection: true),
      InvestigatorWorkflowStep(id: 'explicit_submit_consent', summary: 'Require a separate affirmative confirmation for this transmission.', requiresUserSelection: true),
    ],
    networkPolicy: InvestigatorNetworkPolicy.externalRequiresEvidenceSelectionAndConsent,
    dataSensitivity: MobileDataSensitivity.high,
    allowedInvocationSources: {MobileInvocationSource.user},
    requiresUserConfirmation: true,
    requiresEvidencePreview: true,
    canExecuteDeviceActions: false,
  ),
];

List<String> validateInvestigatorWorkflowRegistry() {
  final errors = <String>[];
  final ids = <String>{};
  for (final workflow in investigatorWorkflowRegistry) {
    if (!ids.add(workflow.id)) errors.add('Duplicate workflow id: ${workflow.id}');
    if (!workflow.id.startsWith('mobile.workflow.')) {
      errors.add('Non-mobile workflow id: ${workflow.id}');
    }
    if (workflow.canExecuteDeviceActions) {
      errors.add('Device action execution is forbidden in ${workflow.id}');
    }
    if (workflow.networkPolicy == InvestigatorNetworkPolicy.externalRequiresEvidenceSelectionAndConsent &&
        (!workflow.requiresEvidencePreview || !workflow.requiresUserConfirmation)) {
      errors.add('External AI workflow lacks selection, preview, or consent gates: ${workflow.id}');
    }
    for (final step in workflow.steps) {
      final toolId = step.toolId;
      if (toolId != null && !mobileToolRegistry.any((tool) => tool.id == toolId)) {
        errors.add('Unknown tool $toolId referenced by ${workflow.id}');
      }
    }
  }
  return errors;
}
