import 'package:flutter/material.dart';

import '../../core/capabilities/capability_catalog.dart';
import '../../core/capabilities/capability_definition.dart';
import '../../core/detection/detection_models.dart';
import '../../core/platform/mobile_security_session.dart';

class MobileCapabilitiesPage extends StatefulWidget {
  const MobileCapabilitiesPage({super.key, this.session});

  final MobileSecuritySession? session;

  @override
  State<MobileCapabilitiesPage> createState() => _MobileCapabilitiesPageState();
}

class _MobileCapabilitiesPageState extends State<MobileCapabilitiesPage> {
  late Future<CapabilityCatalog> _catalog;
  String _query = '';
  String? _selectedCategory;

  @override
  void initState() {
    super.initState();
    _catalog = CapabilityCatalog.load();
  }

  @override
  Widget build(BuildContext context) => FutureBuilder<CapabilityCatalog>(
        future: _catalog,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return const _CatalogMessage(
              icon: Icons.error_outline_rounded,
              title: 'Catalogue unavailable',
              detail: 'The bundled capability definitions could not be loaded.',
            );
          }
          if (!snapshot.hasData) {
            return const Center(child: CircularProgressIndicator());
          }

          final catalog = snapshot.data!;
          final categories = catalog.entries
              .map((entry) => entry.category)
              .toSet()
              .toList()
            ..sort();
          final normalizedQuery = _query.trim().toLowerCase();
          final entries = catalog.entries.where((entry) {
            if (_selectedCategory != null && entry.category != _selectedCategory) {
              return false;
            }
            if (normalizedQuery.isEmpty) return true;
            return <String>[
              entry.id,
              entry.name,
              entry.category,
              entry.description,
              entry.evidenceSource,
              entry.collectorDependency,
              ...entry.accessRequirements,
              ...entry.apiConditions,
              ...entry.privacyTags,
              ...entry.limitations,
            ].any((value) => value.toLowerCase().contains(normalizedQuery));
          }).toList(growable: false);

          return Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('CAPABILITY REGISTRY',
                        style: TextStyle(
                          color: Theme.of(context).colorScheme.primary,
                          fontSize: 11,
                          letterSpacing: 1.3,
                          fontWeight: FontWeight.w800,
                        )),
                    const SizedBox(height: 8),
                    Text('What can this app observe?',
                        style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                              fontWeight: FontWeight.w800,
                            )),
                    const SizedBox(height: 6),
                    Text(
                      '${catalog.entries.length} capability definitions. Catalogue entries do not mean collection is supported or active.',
                      style: const TextStyle(color: Colors.white60, height: 1.4),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      key: const Key('capability-search'),
                      onChanged: (value) => setState(() => _query = value),
                      decoration: InputDecoration(
                        prefixIcon: const Icon(Icons.search_rounded),
                        hintText: 'Search ID, category, access, or name',
                        filled: true,
                        fillColor: Theme.of(context).colorScheme.surface,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                          borderSide: BorderSide.none,
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),
                    SizedBox(
                      height: 44,
                      child: ListView(
                        key: const Key('capability-category-filters'),
                        scrollDirection: Axis.horizontal,
                        children: [
                          Padding(
                            padding: const EdgeInsets.only(right: 8),
                            child: ChoiceChip(
                              key: const Key('category-filter-all'),
                              label: const Text('All categories'),
                              selected: _selectedCategory == null,
                              onSelected: (_) => setState(() => _selectedCategory = null),
                            ),
                          ),
                          for (final category in categories)
                            Padding(
                              padding: const EdgeInsets.only(right: 8),
                              child: ChoiceChip(
                                key: Key('category-filter-$category'),
                                label: Text(category),
                                selected: _selectedCategory == category,
                                onSelected: (_) => setState(() => _selectedCategory = category),
                              ),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 4),
                    Align(
                      alignment: Alignment.centerLeft,
                      child: Text('${entries.length} shown · Consumer 128 · Enterprise 8',
                          style: const TextStyle(color: Colors.white54, fontSize: 12)),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: entries.isEmpty
                    ? const _CatalogMessage(
                        icon: Icons.search_off_rounded,
                        title: 'No matching capabilities',
                        detail: 'Try another ID, category, permission, or name.',
                      )
                    : ListView.builder(
                        padding: const EdgeInsets.fromLTRB(12, 0, 12, 24),
                        itemCount: entries.length,
                        itemBuilder: (context, index) => _CapabilityTile(
                          key: ValueKey(entries[index].id),
                          capability: entries[index],
                          event: _latestEvent(widget.session, entries[index].id),
                        ),
                      ),
              ),
            ],
          );
        },
      );
}

class _CapabilityTile extends StatelessWidget {
  const _CapabilityTile({super.key, required this.capability, this.event});

  final CapabilityDefinition capability;
  final MobileEvent? event;

  @override
  Widget build(BuildContext context) {
    final access = _label(capability.accessClass.name);
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 4, vertical: 5),
      child: ExpansionTile(
        tilePadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        title: Text(capability.name, style: const TextStyle(fontWeight: FontWeight.w700)),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 5),
          child: Text(
              '${capability.id} · ${capability.category} · $access\n'
              '${_label(capability.implementation.name)} · '
              '${_label(event?.availability ?? capability.availability.name)} · '
              '${_label(capability.operation.name)}',
              style: const TextStyle(color: Colors.white60, fontSize: 11, height: 1.4)),
        ),
        children: [
          _DetailLine(label: 'Purpose', value: capability.description),
          _DetailLine(label: 'Tier', value: _label(capability.tier.name)),
          _DetailLine(label: 'Implementation', value: _label(capability.implementation.name)),
          _DetailLine(label: 'Collection health', value: _label(capability.collectionHealth.name)),
          _DetailLine(label: 'Availability', value: _label(event?.availability ?? capability.availability.name)),
          _DetailLine(label: 'Operation', value: _label(capability.operation.name)),
          _DetailLine(label: 'Latest collection operation', value: _label(event?.operation ?? 'none')),
          _DetailLine(label: 'Evidence freshness', value: _label(event?.freshness ?? capability.freshness.name)),
          _DetailLine(label: 'Evidence source', value: capability.evidenceSource),
          _DetailLine(label: 'Access requirements', value: _joined(capability.accessRequirements)),
          _DetailLine(
            label: 'Android API range',
            value: 'API ${capability.minAndroidApi}+' +
                (capability.maxAndroidApi == null ? '' : ' through ${capability.maxAndroidApi}'),
          ),
          _DetailLine(label: 'API-specific conditions', value: _joined(capability.apiConditions)),
          _DetailLine(label: 'Collector dependency', value: capability.collectorDependency),
          _DetailLine(label: 'Privacy classification', value: _joined(capability.privacyTags)),
          _DetailLine(label: 'Derived calculation', value: capability.derived ? 'Yes' : 'No'),
          _DetailLine(label: 'Background', value: capability.backgroundExecution),
          _DetailLine(label: 'Battery impact', value: capability.batteryImpact),
          _DetailLine(
            label: 'Last successful observation',
            value: _lastSuccessfulObservation(capability, event),
          ),
          _DetailLine(label: 'Distribution restrictions', value: _joined(capability.distributionRestrictions)),
          _DetailLine(label: 'Known limits', value: _joined(capability.limitations)),
        ],
      ),
    );
  }
}

MobileEvent? _latestEvent(MobileSecuritySession? session, String capabilityId) {
  final matching = session?.events
      .where((event) => event.capabilityId == capabilityId)
      .toList(growable: false);
  if (matching == null || matching.isEmpty) return null;
  return matching.reduce((left, right) =>
      left.observedAt.isAfter(right.observedAt) ? left : right);
}

String _lastSuccessfulObservation(
  CapabilityDefinition capability,
  MobileEvent? event,
) {
  if (event != null &&
      event.availability == 'available' &&
      event.operation == 'completed') {
    return event.observedAt.toLocal().toString();
  }
  return capability.lastSuccessfulObservation?.toLocal().toString() ?? 'None recorded';
}

class _DetailLine extends StatelessWidget {
  const _DetailLine({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label.toUpperCase(),
                style: TextStyle(
                  color: Theme.of(context).colorScheme.primary,
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  letterSpacing: .7,
                )),
            const SizedBox(height: 3),
            Text(value, style: const TextStyle(color: Colors.white70, height: 1.35)),
          ],
        ),
      );
}

class _CatalogMessage extends StatelessWidget {
  const _CatalogMessage({required this.icon, required this.title, required this.detail});
  final IconData icon;
  final String title;
  final String detail;

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 40, color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 12),
              Text(title, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(detail, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white60)),
            ],
          ),
        ),
      );
}

String _joined(List<String> values) => values.isEmpty ? 'None declared' : values.join(' · ');

String _label(String value) => value
    .replaceAllMapped(RegExp(r'([a-z])([A-Z])'), (match) => '${match[1]} ${match[2]}')
    .replaceAll('_', ' ')
    .toUpperCase();
