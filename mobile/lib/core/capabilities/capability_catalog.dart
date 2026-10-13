import 'dart:convert';

import 'package:flutter/services.dart';

import 'capability_definition.dart';

const capabilityCatalogAsset = 'assets/capabilities/capabilities.json';
const _baselineCapabilityIds = {
  'AND-001',
  'AND-002',
  'AND-003',
  'AND-004',
  'AND-008',
  'AND-113',
  'AND-115',
  'AND-116',
};

const _visibleAppInventoryCapabilityIds = {
  'AND-012',
  'AND-013',
  'AND-016',
  'AND-025',
  'AND-026',
};

const _partialCapabilityIds = {
  ..._baselineCapabilityIds,
  ..._visibleAppInventoryCapabilityIds,
  'AND-017',
  'AND-081',
};

/// The bundled catalogue is metadata, not a collector or live status source.
class CapabilityCatalog {
  CapabilityCatalog._(List<CapabilityDefinition> entries)
      : entries = List<CapabilityDefinition>.unmodifiable(entries),
        _byId = Map<String, CapabilityDefinition>.unmodifiable({
          for (final entry in entries) entry.id: entry,
        });

  final List<CapabilityDefinition> entries;
  final Map<String, CapabilityDefinition> _byId;

  CapabilityDefinition? operator [](String id) => _byId[id];

  static Future<CapabilityCatalog> load({AssetBundle? bundle}) async {
    final jsonText = await (bundle ?? rootBundle).loadString(capabilityCatalogAsset);
    return fromJsonString(jsonText);
  }

  factory CapabilityCatalog.fromJsonString(String source) {
    final decoded = jsonDecode(source);
    if (decoded is! List<Object?>) {
      throw const FormatException('Capability catalogue must be a JSON array.');
    }

    final entries = decoded.map((value) {
      if (value is! Map<String, Object?>) {
        throw const FormatException('Each capability must be a JSON object.');
      }
      return CapabilityDefinition.fromJson(value);
    }).toList(growable: false);

    if (entries.length != 136) {
      throw FormatException(
        'Capability catalogue must contain 136 records; found ${entries.length}.',
      );
    }

    for (var index = 0; index < entries.length; index++) {
      final expectedId = 'AND-${(index + 1).toString().padLeft(3, '0')}';
      final entry = entries[index];
      if (entry.id != expectedId) {
        throw FormatException(
          'Capability at position $index must have id $expectedId; found ${entry.id}.',
        );
      }

      final expectedTier = index < 128
          ? CapabilityTier.consumer
          : CapabilityTier.enterprise;
      if (entry.tier != expectedTier) {
        throw FormatException('$expectedId has an invalid tier.');
      }

      final expectedImplementation = _partialCapabilityIds.contains(entry.id)
          ? CapabilityImplementationStatus.partial
          : CapabilityImplementationStatus.planned;
      if (entry.implementation != expectedImplementation ||
          entry.availability != CapabilityAvailability.notChecked ||
          entry.operation != CapabilityOperationStatus.disabled ||
          entry.freshness != CapabilityFreshness.neverObserved ||
          entry.collectionHealth != CapabilityCollectionHealth.notEvaluated ||
          entry.lastSuccessfulObservation != null) {
        throw FormatException('$expectedId contains runtime state in static metadata.');
      }
      if (entry.minAndroidApi < 29 ||
          (entry.maxAndroidApi != null &&
              entry.maxAndroidApi! < entry.minAndroidApi) ||
          entry.collectorDependency.isEmpty) {
        throw FormatException('$expectedId has invalid platform dependencies.');
      }
      final expectedBackground = _partialCapabilityIds.contains(entry.id)
          ? 'user_initiated_snapshot_only'
          : 'none_until_collector_exists';
      if (entry.backgroundExecution != expectedBackground) {
        throw FormatException('$expectedId has an invalid background execution status.');
      }
    }

    return CapabilityCatalog._(entries);
  }
}
