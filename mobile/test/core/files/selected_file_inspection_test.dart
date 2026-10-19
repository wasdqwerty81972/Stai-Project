import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/files/selected_file_inspection.dart';

Map<String, Object?> payload() => {
  'contractVersion': 1,
  'apkRequested': false,
  'status': 'complete',
  'contentType': 'text/plain',
  'byteSize': 3,
  'bytesRead': 3,
  'maxBytes': 67108864,
  'sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'apkMetadata': null,
  'metadataTruncated': false,
};

void main() {
  test('parses a complete file hash with exact stream size', () {
    final result = SelectedFileInspection.fromMap(payload());
    expect(result.status, SelectedFileInspectionStatus.complete);
    expect(result.byteSize, 3);
    expect(result.sha256, startsWith('ba7816bf'));
  });

  test('unsupported APK parsing retains hash without inventing metadata', () {
    final result = SelectedFileInspection.fromMap(payload()
      ..['apkRequested'] = true
      ..['status'] = 'unsupported');
    expect(result.status, SelectedFileInspectionStatus.unsupported);
    expect(result.apkMetadata, isNull);
    expect(result.sha256, isNotNull);
  });

  test('over-limit has no partial hash or invented total byte size', () {
    final result = SelectedFileInspection.fromMap(payload()
      ..['status'] = 'overLimit'
      ..['bytesRead'] = 67108865
      ..['byteSize'] = null
      ..['sha256'] = null);
    expect(result.status, SelectedFileInspectionStatus.overLimit);
    expect(result.byteSize, isNull);
    expect(result.sha256, isNull);
  });

  test('timeout preserves observed byte count without a complete digest', () {
    final result = SelectedFileInspection.fromMap(payload()
      ..['status'] = 'timedOut'
      ..['byteSize'] = null
      ..['sha256'] = null);
    expect(result.status, SelectedFileInspectionStatus.timedOut);
    expect(result.bytesRead, 3);
    expect(result.sha256, isNull);
  });

  test('valid APK carries bounded metadata and certificate fingerprints', () {
    final result = SelectedFileInspection.fromMap(payload()
      ..['apkRequested'] = true
      ..['apkMetadata'] = {
        'packageName': 'com.example.reader',
        'versionName': '1.0',
        'versionCode': 1,
        'requestedPermissions': ['android.permission.CAMERA'],
        'signatureStatus': 'available',
        'certificateSha256': [payload()['sha256']],
      });
    expect(result.apkMetadata!.packageName, 'com.example.reader');
    expect(result.apkMetadata!.requestedPermissions, ['android.permission.CAMERA']);
    expect(result.apkMetadata!.certificateSha256, hasLength(1));
  });

  test('unavailable signing metadata stays unknown', () {
    final result = SelectedFileInspection.fromMap(payload()
      ..['apkRequested'] = true
      ..['apkMetadata'] = {
        'packageName': 'com.example.reader', 'versionName': null, 'versionCode': 1,
        'requestedPermissions': [], 'signatureStatus': 'unknown',
        'certificateSha256': [],
      });
    expect(result.apkMetadata!.signatureStatus, 'unknown');
    expect(result.apkMetadata!.certificateSha256, isEmpty);
  });

  test('rejects metadata that exceeds limits or fabricates signer availability', () {
    for (final permissions in [<Object?>[null], List.filled(257, 'android.permission.CAMERA')]) {
      expect(() => SelectedFileInspection.fromMap(payload()
        ..['apkRequested'] = true
        ..['apkMetadata'] = {
          'packageName': 'com.example.reader', 'versionName': null, 'versionCode': 1,
          'requestedPermissions': permissions, 'signatureStatus': 'unknown',
          'certificateSha256': [],
        }), throwsFormatException);
    }
    expect(() => SelectedFileInspection.fromMap(payload()
      ..['apkRequested'] = true
      ..['apkMetadata'] = {
        'packageName': 'com.example.reader', 'versionName': null, 'versionCode': 1,
        'requestedPermissions': [], 'signatureStatus': 'available',
        'certificateSha256': [],
      }), throwsFormatException);
  });

  test('rejects malformed and contradictory bounded payloads', () {
    for (final invalid in [
      payload()..['contractVersion'] = 2,
      payload()..['status'] = 'safe',
      payload()..['byteSize'] = 2,
      payload()..['sha256'] = 'partial',
      payload()..['maxBytes'] = 999999999,
      payload()..['maxBytes'] = 67108864.0,
      payload()..['contractVersion'] = 1.0,
      payload()..['bytesRead'] = -1,
      payload()..['contentType'] = List.filled(300, 'x').join(),
      payload()..['status'] = 'overLimit',
      payload()..['apkRequested'] = true,
    ]) {
      expect(() => SelectedFileInspection.fromMap(invalid), throwsFormatException);
    }
  });
}
