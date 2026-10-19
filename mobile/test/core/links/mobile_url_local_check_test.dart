import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/links/mobile_url_local_check.dart';

void main() {
  group('MobileUrlLocalCheck', () {
    test('parses HTTP and HTTPS into safe display fields', () {
      final result = MobileUrlLocalCheck.analyze(' https://Example.com/path?q=1#part ');
      expect(result.normalizedUrl, 'https://example.com/');
      expect(result.scheme, 'https');
      expect(result.host, 'example.com');
      expect(result.signals, isEmpty);
    });

    test('limits input length and reports truncation without parsing a prefix', () {
      final result = MobileUrlLocalCheck.analyze('https://example.com/${'a' * 4096}');
      expect(result.isValid, isFalse);
      expect(result.signals.map((signal) => signal.code), contains('input_too_long'));
      expect(result.normalizedUrl, isNull);
    });

    test('detects embedded credentials but does not retain them in display fields', () {
      final result = MobileUrlLocalCheck.analyze(
          'https://alice:secret@example.com/login?token=private#reset');
      expect(result.host, 'example.com');
      expect(result.normalizedUrl, isNot(contains('secret')));
      expect(result.normalizedUrl, isNot(contains('private')));
      expect(result.normalizedUrl, isNot(contains('reset')));
      expect(result.signals.map((signal) => signal.code), contains('credentials_present'));
    });

    test('flags non-web schemes without treating them as web URLs', () {
      final result = MobileUrlLocalCheck.analyze('javascript:alert(1)');
      expect(result.isValid, isFalse);
      expect(result.signals.map((signal) => signal.code), contains('non_http_scheme'));
    });

    test('recognizes IPv4 and IPv6 literals', () {
      for (final input in ['http://192.0.2.1/', 'https://[2001:db8::1]/']) {
        final result = MobileUrlLocalCheck.analyze(input);
        expect(result.signals.map((signal) => signal.code), contains('ip_literal'));
      }
    });

    test('reports non-default ports', () {
      final result = MobileUrlLocalCheck.analyze('https://example.com:8443/');
      expect(result.signals.map((signal) => signal.code), contains('non_default_port'));
    });

    test('reports Unicode and punycode hostname indicators', () {
      final unicode = MobileUrlLocalCheck.analyze('https://münich.example/');
      expect(unicode.signals.map((signal) => signal.code), contains('unicode_hostname'));
      final punycode = MobileUrlLocalCheck.analyze('https://xn--mnich-kva.example/');
      expect(punycode.signals.map((signal) => signal.code), contains('punycode_hostname'));
    });

    test('malformed and empty input return explanatory signals', () {
      for (final input in ['', '   ', 'https://', 'http://exa mple.com']) {
        final result = MobileUrlLocalCheck.analyze(input);
        expect(result.isValid, isFalse, reason: input);
        expect(result.signals, isNotEmpty, reason: input);
        expect(result.explanation, isNotEmpty, reason: input);
      }
    });

    test('results are explicitly heuristic signals, not safety verdicts', () {
      final result = MobileUrlLocalCheck.analyze('https://example.com');
      expect(result.verdict, isNull);
      expect(result.explanation.toLowerCase(), contains('structure'));
    });
  });
}
