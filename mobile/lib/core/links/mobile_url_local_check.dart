import 'package:flutter/foundation.dart';

/// A structural observation about a submitted URL. It is not a reputation or
/// malware verdict.
@immutable
class MobileUrlCheckSignal {
  const MobileUrlCheckSignal({required this.code, required this.explanation});

  final String code;
  final String explanation;
}

/// The result of a bounded, local-only URL structure check.
@immutable
class MobileUrlCheckResult {
  const MobileUrlCheckResult({
    required this.isValid,
    required this.normalizedUrl,
    required this.scheme,
    required this.host,
    required this.port,
    required this.signals,
    required this.explanation,
  });

  /// Null because structural checks cannot establish whether a URL is safe.
  String? get verdict => null;

  final bool isValid;
  final String? normalizedUrl;
  final String? scheme;
  final String? host;
  final int? port;
  final List<MobileUrlCheckSignal> signals;
  final String explanation;
}

/// Parses URL structure without resolving, fetching, opening, or redirecting it.
class MobileUrlLocalCheck {
  MobileUrlLocalCheck._();

  static const maxInputLength = 2048;

  static MobileUrlCheckResult analyze(String raw) {
    if (raw.length > maxInputLength) {
      return _invalid('input_too_long',
          'Input exceeds the $maxInputLength character limit; no URL was parsed.');
    }
    final input = raw.trim();
    if (input.isEmpty) {
      return _invalid('empty_input', 'Enter a URL to inspect its structure.');
    }

    final colon = input.indexOf(':');
    if (colon <= 0) {
      return _invalid('malformed_url', 'A URL scheme is required.');
    }
    final scheme = input.substring(0, colon).toLowerCase();
    if (scheme != 'http' && scheme != 'https') {
      return MobileUrlCheckResult(
        isValid: false,
        normalizedUrl: null,
        scheme: scheme,
        host: null,
        port: null,
        signals: const [
          MobileUrlCheckSignal(
            code: 'non_http_scheme',
            explanation: 'Only HTTP and HTTPS URL structures are inspected.',
          ),
        ],
        explanation: 'This is a non-web scheme; no destination was opened.',
      );
    }
    if (!input.startsWith(RegExp(r'^https?://', caseSensitive: false))) {
      return _invalid('malformed_url', 'HTTP URLs must include // after the scheme.',
          scheme: scheme);
    }
    if (input.contains(RegExp(r'[\u0000-\u0020\u007f]'))) {
      return _invalid('malformed_url', 'The URL contains whitespace or control characters.',
          scheme: scheme);
    }

    final Uri uri;
    try {
      uri = Uri.parse(input);
      if (!uri.hasAuthority || uri.host.isEmpty) {
        return _invalid('malformed_url', 'The URL does not contain a hostname.',
            scheme: scheme);
      }
      // Accessing port validates its syntax (and range).
      final parsedPort = uri.hasPort ? uri.port : null;
      if (parsedPort != null && (parsedPort < 1 || parsedPort > 65535)) {
        return _invalid('malformed_url', 'The URL contains an invalid port.',
            scheme: scheme);
      }
    } on FormatException {
      return _invalid('malformed_url', 'The URL could not be parsed.', scheme: scheme);
    }

    final host = uri.host.toLowerCase();
    final signals = <MobileUrlCheckSignal>[];
    if (uri.userInfo.isNotEmpty) {
      signals.add(const MobileUrlCheckSignal(
        code: 'credentials_present',
        explanation: 'The authority contains user information; it is omitted from display output.',
      ));
    }
    if (_isIpLiteral(host)) {
      signals.add(const MobileUrlCheckSignal(
        code: 'ip_literal',
        explanation: 'The hostname is an IP address literal rather than a domain name.',
      ));
    }
    if (host.codeUnits.any((unit) => unit > 127)) {
      signals.add(const MobileUrlCheckSignal(
        code: 'unicode_hostname',
        explanation: 'The hostname contains Unicode characters and may display differently across tools.',
      ));
    }
    if (host.split('.').any((label) => label.startsWith('xn--'))) {
      signals.add(const MobileUrlCheckSignal(
        code: 'punycode_hostname',
        explanation: 'The hostname contains an IDN punycode label.',
      ));
    }
    final port = uri.hasPort ? uri.port : null;
    if (port != null && !((scheme == 'http' && port == 80) ||
        (scheme == 'https' && port == 443))) {
      signals.add(MobileUrlCheckSignal(
        code: 'non_default_port',
        explanation: 'The URL specifies non-default port $port for $scheme.',
      ));
    }

    // Expose only the origin. Paths, queries, and fragments can include
    // customer identifiers, reset tokens, or other private data.
    final safeUri = Uri(
      scheme: scheme,
      host: uri.host,
      port: uri.hasPort ? uri.port : null,
      path: '/',
    );
    final normalized = safeUri.toString();
    return MobileUrlCheckResult(
      isValid: true,
      normalizedUrl: normalized,
      scheme: scheme,
      host: host,
      port: port,
      signals: List.unmodifiable(signals),
      explanation: signals.isEmpty
          ? 'URL structure parsed locally; no reputation or safety verdict is available.'
          : 'URL structure parsed locally with ${signals.length} review signal(s); no safety verdict is available.',
    );
  }

  static bool _isIpLiteral(String host) {
    if (host.contains(':')) return true; // Uri removes IPv6 brackets.
    final parts = host.split('.');
    if (parts.length != 4) return false;
    return parts.every((part) {
      final value = int.tryParse(part);
      return value != null && value >= 0 && value <= 255 &&
          (part == '0' || !part.startsWith('0'));
    });
  }

  static MobileUrlCheckResult _invalid(String code, String explanation,
      {String? scheme}) =>
      MobileUrlCheckResult(
        isValid: false,
        normalizedUrl: null,
        scheme: scheme,
        host: null,
        port: null,
        signals: [MobileUrlCheckSignal(code: code, explanation: explanation)],
        explanation: explanation,
      );
}
