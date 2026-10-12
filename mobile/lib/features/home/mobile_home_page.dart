import 'package:flutter/material.dart';

import '../../core/platform/mobile_security_session.dart';

class MobileHomePage extends StatefulWidget {
  const MobileHomePage({super.key, required this.session});

  final MobileSecuritySession session;

  @override
  State<MobileHomePage> createState() => _MobileHomePageState();
}

class _MobileHomePageState extends State<MobileHomePage> {
  bool _busy = false;
  String? _operation;

  Future<void> _runBaseline() async {
    setState(() {
      _busy = true;
      _operation = 'baseline';
    });
    await widget.session.collectBaseline();
    if (mounted) setState(() => _busy = false);
  }

  Future<void> _restoreJournal() async {
    setState(() {
      _busy = true;
      _operation = 'restore';
    });
    await widget.session.restoreJournal();
    if (mounted) setState(() => _busy = false);
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: widget.session,
        builder: (context, _) => _PageFrame(
          eyebrow: 'DEVICE OVERVIEW',
          title: 'Your security, at a glance.',
          subtitle: 'Local checks work without an account or AI provider.',
          children: [
            const _ModeCard(),
            const SizedBox(height: 14),
            const _SectionHeading('Point-in-time checks'),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Run a baseline when you choose. Opening the app does not start collection.',
                      style: TextStyle(color: Colors.white60, height: 1.4),
                    ),
                    const SizedBox(height: 14),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton.icon(
                        onPressed: _busy ? null : _runBaseline,
                        icon: _busy && _operation == 'baseline'
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : const Icon(Icons.play_arrow_rounded),
                        label: Text(_busy && _operation == 'baseline'
                            ? 'Checking…'
                            : 'Run device baseline'),
                      ),
                    ),
                    TextButton.icon(
                      onPressed: _busy ? null : _restoreJournal,
                      icon: const Icon(Icons.history_rounded),
                      label: Text(_busy && _operation == 'restore'
                          ? 'Restoring…'
                          : 'Restore last 24 hours'),
                    ),
                    if (widget.session.lastError case final error?) ...[
                      const SizedBox(height: 8),
                      Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                    ],
                    if (widget.session.journalStatus case final status?) ...[
                      const SizedBox(height: 4),
                      Text(
                        status.available
                            ? 'Encrypted journal: ${status.eventCount} saved events'
                            : 'Local event journal unavailable',
                        style: const TextStyle(color: Colors.white60, fontSize: 12),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 14),
            const _SectionHeading('Protection coverage'),
            const _InfoCard(
              icon: Icons.hourglass_empty_rounded,
              title: 'Monitoring is not enabled',
              detail: 'This build performs a one-time device baseline only. No continuous collectors are active.',
              badge: 'POINT-IN-TIME',
            ),
            const SizedBox(height: 14),
            const _SectionHeading('Recent local activity'),
            if (widget.session.events.isEmpty)
              const _InfoCard(
                icon: Icons.history_rounded,
                title: 'No local events yet',
                detail: 'Events appear after a supported check actually runs.',
              )
            else
              _InfoCard(
                icon: Icons.fact_check_outlined,
                title: 'Observations saved',
                detail: widget.session.events.length == 1
                    ? 'One observation saved locally.'
                    : '${widget.session.events.length} observations saved locally.',
                badge: 'LOCAL',
              ),
            if (widget.session.events.isNotEmpty && widget.session.findings.isEmpty) ...[
              const SizedBox(height: 10),
              const _InfoCard(
                icon: Icons.check_circle_outline_rounded,
                title: 'Baseline checked',
                detail: 'No finding was created from this baseline.',
              ),
            ],
          ],
        ),
      );
}

class _ModeCard extends StatelessWidget {
  const _ModeCard();

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Row(
            children: [
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: Colors.amber.withValues(alpha: .12),
                  borderRadius: BorderRadius.circular(15),
                ),
                child: const Icon(Icons.pause_circle_outline_rounded, color: Colors.amber),
              ),
              const SizedBox(width: 14),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Protection is not enabled', style: TextStyle(fontWeight: FontWeight.w700)),
                    SizedBox(height: 4),
                    Text('This app has not started monitoring.', style: TextStyle(color: Colors.white60, fontSize: 13)),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
}

class _PageFrame extends StatelessWidget {
  const _PageFrame({required this.eyebrow, required this.title, required this.subtitle, required this.children});
  final String eyebrow;
  final String title;
  final String subtitle;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => ListView(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
        children: [
          Text(eyebrow, style: TextStyle(color: Theme.of(context).colorScheme.primary, fontSize: 11, letterSpacing: 1.3, fontWeight: FontWeight.w800)),
          const SizedBox(height: 10),
          Text(title, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800, height: 1.12)),
          const SizedBox(height: 8),
          Text(subtitle, style: const TextStyle(color: Colors.white60, height: 1.45)),
          const SizedBox(height: 22),
          ...children,
        ],
      );
}

class _SectionHeading extends StatelessWidget {
  const _SectionHeading(this.title);
  final String title;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Text(title, style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700)),
      );
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({required this.icon, required this.title, required this.detail, this.badge});
  final IconData icon;
  final String title;
  final String detail;
  final String? badge;
  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: Theme.of(context).colorScheme.primary, size: 22),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Expanded(child: Text(title, style: const TextStyle(fontWeight: FontWeight.w700))),
                      if (badge != null) ...[
                        const SizedBox(width: 8),
                        Text(badge!, style: TextStyle(color: Theme.of(context).colorScheme.primary, fontSize: 9, letterSpacing: .7, fontWeight: FontWeight.w800)),
                      ],
                    ]),
                    const SizedBox(height: 5),
                    Text(detail, style: const TextStyle(color: Colors.white60, fontSize: 12, height: 1.4)),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
}
