enum SelectedFileInspectionStatus { complete, unsupported, overLimit, timedOut }

/// Metadata from exactly one user-selected document. A hash covers the entire
/// stream only; this result makes no assessment of whether content is safe.
class SelectedFileInspection {
  const SelectedFileInspection._({
    required this.apkRequested,
    required this.status,
    required this.contentType,
    required this.byteSize,
    required this.bytesRead,
    required this.maxBytes,
    required this.sha256,
    required this.apkMetadata,
    required this.metadataTruncated,
  });

  static const byteLimit = 64 * 1024 * 1024;
  final bool apkRequested;
  final SelectedFileInspectionStatus status;
  final String? contentType;
  final int? byteSize;
  final int bytesRead;
  final int maxBytes;
  final String? sha256;
  final SelectedApkMetadata? apkMetadata;
  final bool metadataTruncated;

  factory SelectedFileInspection.fromMap(Map<String, Object?> map) {
    if (map['contractVersion'] is! int ||
        map['contractVersion'] != 1 ||
        map['apkRequested'] is! bool ||
        map['metadataTruncated'] is! bool) {
      throw const FormatException('Invalid selected file contract.');
    }
    final status = SelectedFileInspectionStatus.values
        .where((value) => value.name == map['status'])
        .firstOrNull;
    if (status == null) throw const FormatException('Unknown inspection status.');
    final size = map['byteSize'];
    final read = map['bytesRead'];
    final max = map['maxBytes'];
    final hash = _text(map['sha256'], 64);
    final contentType = _text(map['contentType'], 255);
    if (read is! int ||
        read < 0 ||
        max is! int ||
        max != byteLimit ||
        read > byteLimit + 1 ||
        (size != null && (size is! int || size < 0 || size > byteLimit)) ||
        (hash != null && !_digest.hasMatch(hash))) {
      throw const FormatException('Invalid inspection bounds or digest.');
    }
    final full = status == SelectedFileInspectionStatus.complete ||
        status == SelectedFileInspectionStatus.unsupported;
    if (full ? (size != read || hash == null) : (size != null || hash != null)) {
      throw const FormatException('Incomplete content cannot carry a full hash or size.');
    }
    if (status == SelectedFileInspectionStatus.overLimit && read != byteLimit + 1) {
      throw const FormatException('Over-limit inspection requires an observed excess byte.');
    }
    final apk = map['apkRequested']! as bool;
    final rawMetadata = map['apkMetadata'];
    final metadata = rawMetadata == null
        ? null
        : SelectedApkMetadata.fromMap(_map(rawMetadata));
    if ((!apk && (metadata != null || status == SelectedFileInspectionStatus.unsupported)) ||
        (apk && status == SelectedFileInspectionStatus.complete && metadata == null) ||
        (status != SelectedFileInspectionStatus.complete && metadata != null) ||
        (!apk && map['metadataTruncated'] == true)) {
      throw const FormatException('APK metadata contradicts inspection status.');
    }
    return SelectedFileInspection._(
      apkRequested: apk,
      status: status,
      contentType: contentType,
      byteSize: size as int?,
      bytesRead: read,
      maxBytes: max,
      sha256: hash,
      apkMetadata: metadata,
      metadataTruncated: map['metadataTruncated']! as bool,
    );
  }
}

class SelectedApkMetadata {
  const SelectedApkMetadata._({
    required this.packageName,
    required this.versionName,
    required this.versionCode,
    required this.requestedPermissions,
    required this.signatureStatus,
    required this.certificateSha256,
  });
  final String packageName;
  final String? versionName;
  final int versionCode;
  final List<String> requestedPermissions;

  /// Public PackageManager metadata availability, never a trust verdict.
  final String signatureStatus;
  final List<String> certificateSha256;

  factory SelectedApkMetadata.fromMap(Map<String, Object?> map) {
    final package = _text(map['packageName'], 255);
    final version = map['versionCode'];
    final permissions = _strings(map['requestedPermissions'], 256, 255);
    final certificates = _strings(map['certificateSha256'], 16, 64);
    final signature = map['signatureStatus'];
    if (package == null || version is! int || version < 0 ||
        !['available', 'unknown'].contains(signature) ||
        certificates.any((value) => !_digest.hasMatch(value)) ||
        (signature == 'available' ? certificates.isEmpty : certificates.isNotEmpty)) {
      throw const FormatException('Invalid APK metadata.');
    }
    return SelectedApkMetadata._(
      packageName: package,
      versionName: _text(map['versionName'], 255),
      versionCode: version,
      requestedPermissions: permissions,
      signatureStatus: signature! as String,
      certificateSha256: certificates,
    );
  }
}

final _digest = RegExp(r'^[a-f0-9]{64}$');

String? _text(Object? value, int limit) {
  if (value == null) return null;
  if (value is! String ||
      value.isEmpty ||
      value.length > limit ||
      value.runes.any((rune) => rune < 32 || rune == 127)) {
    throw const FormatException('Invalid bounded metadata text.');
  }
  return value;
}

List<String> _strings(Object? value, int limit, int textLimit) {
  if (value is! List || value.length > limit) {
    throw const FormatException('Invalid metadata list.');
  }
  return List<String>.unmodifiable(value.map((item) {
    final text = _text(item, textLimit);
    if (text == null) throw const FormatException('Null metadata list item.');
    return text;
  }));
}

Map<String, Object?> _map(Object? raw) {
  if (raw is! Map || raw.keys.any((key) => key is! String)) {
    throw const FormatException('Invalid APK metadata object.');
  }
  return raw.cast<String, Object?>();
}
