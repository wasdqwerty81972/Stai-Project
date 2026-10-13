import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/capabilities/capability_catalog.dart';
import 'package:svs_cyber_mobile/core/capabilities/capability_definition.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late CapabilityCatalog catalog;

  setUpAll(() async {
    final source = await rootBundle.loadString(capabilityCatalogAsset);
    catalog = CapabilityCatalog.fromJsonString(source);
  });

  CapabilityDefinition capability(String id) => catalog[id]!;

  const partiallyImplementedIds = {
    'AND-001',
    'AND-002',
    'AND-003',
    'AND-004',
    'AND-008',
    'AND-113',
    'AND-115',
    'AND-116',
    'AND-012',
    'AND-013',
    'AND-016',
    'AND-025',
    'AND-026',
    'AND-017',
    'AND-081',
  };

  group('capability catalogue feasibility metadata', () {
    test('preserves all ordered capability IDs and conservative runtime defaults', () {
      expect(catalog.entries, hasLength(136));

      for (var index = 0; index < catalog.entries.length; index++) {
        final entry = catalog.entries[index];
        expect(entry.id, 'AND-${(index + 1).toString().padLeft(3, '0')}');
        expect(
          entry.implementation,
          partiallyImplementedIds.contains(entry.id)
              ? CapabilityImplementationStatus.partial
              : CapabilityImplementationStatus.planned,
        );
        expect(entry.availability, CapabilityAvailability.notChecked);
        expect(entry.operation, CapabilityOperationStatus.disabled);
        expect(entry.freshness, CapabilityFreshness.neverObserved);
        expect(
          entry.backgroundExecution,
          partiallyImplementedIds.contains(entry.id)
              ? 'user_initiated_snapshot_only'
              : 'none_until_collector_exists',
        );
        expect(entry.minAndroidApi, greaterThanOrEqualTo(29));
        expect(
          entry.maxAndroidApi == null ||
              entry.maxAndroidApi! >= entry.minAndroidApi,
          isTrue,
        );
        expect(entry.collectionHealth, CapabilityCollectionHealth.notEvaluated);
        expect(entry.lastSuccessfulObservation, isNull);
        expect(entry.collectorDependency, isNotEmpty);
      }
    });

    test('records API-specific boundaries and the baseline collector dependency', () {
      expect(capability('AND-009').minAndroidApi, 30);
      expect(capability('AND-009').apiConditions.join(' '), contains('package visibility'));
      expect(capability('AND-130').apiConditions.join(' '), contains('Android 8'));
      expect(capability('AND-001').collectorDependency, 'android_device_baseline_v1');
      expect(capability('AND-024').collectorDependency, 'planned_local_derived_calculation');
    });

    test('distinguishes platform visibility, runtime permission, online service, and user access', () {
      expect(capability('AND-009').accessClass, CapabilityAccessClass.packageVisibility);
      expect(capability('AND-006').accessClass, CapabilityAccessClass.onlineService);
      expect(capability('AND-042').accessClass, CapabilityAccessClass.runtimePermission);
      expect(capability('AND-033').accessClass, CapabilityAccessClass.specialUserAccess);
      expect(capability('AND-049').accessClass, CapabilityAccessClass.userConsent);
      expect(capability('AND-129').accessClass, CapabilityAccessClass.enterprise);
      expect(capability('AND-007').accessClass, CapabilityAccessClass.unavailable);
    });

    test('uses accurate evidence and access requirements for integrity and file analysis', () {
      final integrity = capability('AND-006');
      expect(integrity.accessRequirements.join(' '), contains('backend'));
      expect(integrity.accessRequirements.join(' '), isNot(contains('package visibility')));
      expect(integrity.evidenceSource, contains('Google Play Integrity'));

      for (final id in ['AND-017', 'AND-021']) {
        final entry = capability(id);
        expect(entry.evidenceSource.toLowerCase(), contains('user-selected'));
        expect(entry.evidenceSource.toLowerCase(), contains('local'));
        expect(entry.evidenceSource, isNot(contains('Public Android system APIs')));
      }
    });

    test('describes app inventory and usage as scoped snapshots or history', () {
      final inventory = capability('AND-009');
      expect(inventory.accessRequirements.join(' '), contains('Android 11'));
      expect(inventory.accessRequirements.join(' '), contains('QUERY_ALL_PACKAGES'));
      expect(inventory.limitations.join(' '), contains('snapshot'));

      final visiblePackages = capability('AND-012');
      expect(visiblePackages.implementation, CapabilityImplementationStatus.partial);
      expect(visiblePackages.accessClass, CapabilityAccessClass.packageVisibility);
      expect(visiblePackages.collectorDependency, 'android_visible_app_inventory_v1');
      expect(visiblePackages.limitations.join(' '), contains('launchable applications'));

      final permissions = capability('AND-025');
      expect(permissions.implementation, CapabilityImplementationStatus.partial);
      expect(permissions.accessRequirements.join(' '), contains('no runtime permission'));
      expect(permissions.limitations.join(' '), contains('not evidence that an app exercised them'));

      final usage = capability('AND-033');
      expect(usage.accessRequirements.join(' '), contains('Usage Access'));
      expect(usage.limitations.join(' '), contains('historical'));
      expect(usage.limitations.join(' '), contains('real-time'));
    });

    test('states VPN, document-provider, and URL collection boundaries', () {
      final vpn = capability('AND-049');
      expect(vpn.evidenceSource, contains('TUN'));
      expect(vpn.limitations.join(' '), contains('foreground'));
      expect(vpn.limitations.join(' '), contains('attribution'));

      final file = capability('AND-073');
      expect(file.evidenceSource, contains('SAF'));
      expect(file.limitations.join(' '), contains('document providers'));

      final redirect = capability('AND-085');
      expect(redirect.accessRequirements.join(' '), contains('submit/share'));
      expect(redirect.accessRequirements.join(' '), contains('network'));

      final apkMetadata = capability('AND-017');
      expect(apkMetadata.implementation, CapabilityImplementationStatus.partial);
      expect(apkMetadata.collectorDependency, 'android_selected_apk_inspection_v1');
      expect(apkMetadata.limitations.join(' '), contains('does not establish'));

      final localUrl = capability('AND-081');
      expect(localUrl.implementation, CapabilityImplementationStatus.partial);
      expect(localUrl.collectorDependency, 'mobile_url_local_check_v1');
      expect(localUrl.limitations.join(' '), contains('does not fetch'));
    });

    test('classifies lock activity and sensitive device states by their actual access', () {
      expect(capability('AND-099').accessClass, CapabilityAccessClass.specialUserAccess);
      expect(capability('AND-099').accessRequirements.join(' '), contains('Usage Access'));
      expect(capability('AND-104').evidenceSource, contains('canRequestPackageInstalls'));
      expect(capability('AND-104').evidenceSource, contains('SVS-Cyber itself'));
      expect(capability('AND-108').accessClass, CapabilityAccessClass.runtimePermission);
      expect(capability('AND-110').evidenceSource, contains('StorageManager'));
      expect(capability('AND-119').accessClass, CapabilityAccessClass.specialUserAccess);
      expect(capability('AND-119').evidenceSource, contains('NetworkStatsManager'));
    });

    test('separates enterprise security-log roles from network-log roles', () {
      final security = capability('AND-129');
      expect(security.accessRequirements.join(' '), contains('device owner'));
      expect(security.accessRequirements.join(' '), contains('organization-owned managed profile'));
      expect(security.evidenceSource, contains('SecurityLog'));

      final network = capability('AND-130');
      expect(network.accessRequirements.join(' '), contains('profile owner'));
      expect(network.accessRequirements.join(' '), contains('work-profile-only'));
      expect(network.limitations.join(' '), contains('hard-coded IP'));

      final process = capability('AND-131');
      expect(process.limitations.join(' '), contains('not a general process monitor'));
    });
  });
}
