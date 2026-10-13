import 'package:flutter/foundation.dart';

import 'visible_application.dart';

/// The observed state of the permissions in one review group.
enum PermissionGrantState { granted, partiallyGranted, notGranted, unknown }

enum ApplicationPermissionCaveat {
  grantStateUnavailable,
  packageVisibilityMayBeFiltered,
  applicationListTruncated,
  permissionListTruncated,
  installerUnknown,
  specialAccessStateUnavailable,
}

@immutable
class ApplicationPermissionSignal {
  const ApplicationPermissionSignal({
    required this.ruleId,
    required this.ruleVersion,
    required this.groupId,
    required this.title,
    required this.requestedPermissions,
    required this.grantedPermissions,
    required this.grantState,
    required this.explanation,
  });

  final String ruleId;
  final String ruleVersion;
  final String groupId;
  final String title;
  final List<String> requestedPermissions;
  final List<String> grantedPermissions;
  final PermissionGrantState grantState;
  final String explanation;
}

@immutable
class ApplicationPermissionReview {
  const ApplicationPermissionReview({
    required this.packageName,
    required this.label,
    required this.signals,
    required this.caveats,
  });

  final String packageName;
  final String label;
  final List<ApplicationPermissionSignal> signals;
  final List<ApplicationPermissionCaveat> caveats;

  /// This analyzer reports evidence for review and does not assign a verdict.
  String? get verdict => null;
}

@immutable
class ApplicationPermissionAnalysis {
  const ApplicationPermissionAnalysis({
    required this.ruleVersion,
    required this.observedAt,
    required this.scope,
    required this.applications,
    required this.caveats,
  });

  final String ruleVersion;
  final DateTime observedAt;
  final String scope;
  final List<ApplicationPermissionReview> applications;
  final List<ApplicationPermissionCaveat> caveats;
}

/// Deterministic, local-only permission posture analysis for visible apps.
///
/// Signals describe declared permissions in selected groups. They are review
/// prompts, not claims that an application is malicious or safe.
class ApplicationPermissionAnalyzer {
  const ApplicationPermissionAnalyzer();

  static const ruleVersion = '1';
  static const _specialAccessPermissions = <String>{
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
  };

  static const _groups = <_PermissionGroup>[
    _PermissionGroup('camera_microphone', 'Camera and microphone', {
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
      'android.permission.CAPTURE_AUDIO_OUTPUT',
    }),
    _PermissionGroup('contacts', 'Contacts', {
      'android.permission.READ_CONTACTS',
      'android.permission.WRITE_CONTACTS',
      'android.permission.GET_ACCOUNTS',
    }),
    _PermissionGroup('location', 'Location', {
      'android.permission.ACCESS_COARSE_LOCATION',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_BACKGROUND_LOCATION',
    }),
    _PermissionGroup('messages', 'Messages', {
      'android.permission.READ_SMS',
      'android.permission.RECEIVE_SMS',
      'android.permission.SEND_SMS',
      'android.permission.RECEIVE_MMS',
      'android.permission.RECEIVE_WAP_PUSH',
    }),
    _PermissionGroup('call_logs', 'Call logs and phone state', {
      'android.permission.READ_CALL_LOG',
      'android.permission.WRITE_CALL_LOG',
      'android.permission.PROCESS_OUTGOING_CALLS',
      'android.permission.READ_PHONE_STATE',
      'android.permission.CALL_PHONE',
    }),
    _PermissionGroup('calendar', 'Calendar', {
      'android.permission.READ_CALENDAR',
      'android.permission.WRITE_CALENDAR',
    }),
    _PermissionGroup('nearby_devices', 'Nearby devices', {
      'android.permission.BLUETOOTH_SCAN',
      'android.permission.BLUETOOTH_CONNECT',
      'android.permission.BLUETOOTH_ADVERTISE',
      'android.permission.NEARBY_WIFI_DEVICES',
    }),
    _PermissionGroup('media_files', 'Media and files', {
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.READ_MEDIA_IMAGES',
      'android.permission.READ_MEDIA_VIDEO',
      'android.permission.READ_MEDIA_AUDIO',
      'android.permission.MANAGE_EXTERNAL_STORAGE',
    }),
    _PermissionGroup('install_packages', 'Package installation', {
      'android.permission.REQUEST_INSTALL_PACKAGES',
    }),
    _PermissionGroup('display_over_apps', 'Display over other apps', {
      'android.permission.SYSTEM_ALERT_WINDOW',
    }),
  ];

  ApplicationPermissionAnalysis analyze(VisibleApplicationCollection collection) {
    final reviews = collection.applications.map((app) {
      final declared = app.requestedPermissions.toSet();
      final granted = app.grantedPermissions.toSet();
      final signals = <ApplicationPermissionSignal>[];

      for (final group in _groups) {
        final requested = group.permissions.where(declared.contains).toList()..sort();
        if (requested.isEmpty) continue;
        final groupGranted = requested.where(granted.contains).toList(growable: false);
        final hasSpecialAccess = requested.any(_specialAccessPermissions.contains);
        final state = !app.permissionGrantStateAvailable || hasSpecialAccess
            ? PermissionGrantState.unknown
            : groupGranted.isEmpty
                ? PermissionGrantState.notGranted
                : groupGranted.length == requested.length
                    ? PermissionGrantState.granted
                    : PermissionGrantState.partiallyGranted;
        signals.add(ApplicationPermissionSignal(
          ruleId: 'APP-PERM-${group.id.toUpperCase()}',
          ruleVersion: ruleVersion,
          groupId: group.id,
          title: '${group.title} permission declared',
          requestedPermissions: List.unmodifiable(requested),
          grantedPermissions: List.unmodifiable(groupGranted),
          grantState: state,
          explanation: hasSpecialAccess
              ? '${app.label} declares ${group.title.toLowerCase()} access. Review whether this access fits the app\'s purpose. Android special app access state cannot be inferred from runtime permission flags.'
              : !app.permissionGrantStateAvailable
                  ? '${app.label} declares ${group.title.toLowerCase()} access. Review whether this access fits the app\'s purpose. Android did not provide grant state for this inventory.'
                  : '${app.label} declares ${group.title.toLowerCase()} access. Review whether this access fits the app\'s purpose; the grant state shown is limited to the permissions listed.',
        ));
      }

      final caveats = <ApplicationPermissionCaveat>{};
      if (!app.permissionGrantStateAvailable) {
        caveats.add(ApplicationPermissionCaveat.grantStateUnavailable);
      }
      if (app.requestedPermissions.any(_specialAccessPermissions.contains)) {
        caveats.add(ApplicationPermissionCaveat.specialAccessStateUnavailable);
      }
      if (collection.visibilityMayBeFiltered) {
        caveats.add(ApplicationPermissionCaveat.packageVisibilityMayBeFiltered);
      }
      if (collection.truncated) {
        caveats.add(ApplicationPermissionCaveat.applicationListTruncated);
      }
      if (collection.permissionsTruncated) {
        caveats.add(ApplicationPermissionCaveat.permissionListTruncated);
      }
      if (app.installerPackageName == null) {
        caveats.add(ApplicationPermissionCaveat.installerUnknown);
      }
      return ApplicationPermissionReview(
        packageName: app.packageName,
        label: app.label,
        signals: List.unmodifiable(signals),
        caveats: List.unmodifiable(caveats),
      );
    }).toList(growable: false);

    final caveats = <ApplicationPermissionCaveat>{};
    if (collection.visibilityMayBeFiltered) {
      caveats.add(ApplicationPermissionCaveat.packageVisibilityMayBeFiltered);
    }
    if (collection.truncated) {
      caveats.add(ApplicationPermissionCaveat.applicationListTruncated);
    }
    if (collection.permissionsTruncated) {
      caveats.add(ApplicationPermissionCaveat.permissionListTruncated);
    }
    return ApplicationPermissionAnalysis(
      ruleVersion: ruleVersion,
      observedAt: collection.observedAt,
      scope: collection.scope,
      applications: List.unmodifiable(reviews),
      caveats: List.unmodifiable(caveats),
    );
  }
}

class _PermissionGroup {
  const _PermissionGroup(this.id, this.title, this.permissions);

  final String id;
  final String title;
  final Set<String> permissions;
}





