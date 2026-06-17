library auth_totp;

import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:qr/qr.dart';

enum SecretKeyStyle { upperCase, lowerCase, upperLowerCase }

enum OTPAlgorithm { sha1, sha256, sha512 }

class OTPAuthURI {
  final String type;
  final String secret;
  final String appName;
  final String? issuer;
  final int digits;
  final OTPAlgorithm algorithm;
  final int? period;
  final int? counter;

  OTPAuthURI({
    required this.type,
    required this.secret,
    required this.appName,
    this.issuer,
    this.digits = 6,
    this.algorithm = OTPAlgorithm.sha1,
    this.period,
    this.counter,
  });
}

// Auth TOTP
class AuthTOTP {
  /// The secret is generated using the Base32 alphabet and is suitable for
  /// use in TOTP (Time-based One-Time Password) applications.
  ///
  /// * [length] : The length of the secret to generate. Must be between 16 and 255, Defaults is 32.
  /// * [autoPadding] : If true, it will create a secret with a letter by 4 sections, Defaults is false.
  /// * [secretKeyStyle] : SecretKeyStyle is used to set the case of the secret key. Defaults is upperCase.
  static String createSecret(
      {int length = 32,
      bool autoPadding = false,
      SecretKeyStyle secretKeyStyle = SecretKeyStyle.upperCase}) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 alphabet
    if (length < 16 || length > 255) {
      throw ArgumentError('The length of the secret must be 16 to 255.');
    }
    final rnd = Random.secure();
    var generatedSecret =
        List.generate(length, (_) => chars[rnd.nextInt(chars.length)]).join();
    generatedSecret =
        autoPadding ? _autoPadding(generatedSecret) : generatedSecret;

    if (secretKeyStyle == SecretKeyStyle.upperCase) {
      generatedSecret = generatedSecret.toUpperCase();
    } else if (secretKeyStyle == SecretKeyStyle.lowerCase) {
      generatedSecret = generatedSecret.toLowerCase();
    } else if (secretKeyStyle == SecretKeyStyle.upperLowerCase) {
      generatedSecret = _randomizeCase(generatedSecret);
    }
    return generatedSecret;
  }

  /// Generates cryptographically secure backup/recovery codes.
  static List<String> generateRecoveryCodes({int count = 10, int length = 10}) {
    final chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    final rnd = Random.secure();
    final codes = <String>[];

    for (int i = 0; i < count; i++) {
      var code =
          List.generate(length, (_) => chars[rnd.nextInt(chars.length)]).join();
      if (length >= 8 && length % 2 == 0) {
        final half = length ~/ 2;
        code = '${code.substring(0, half)}-${code.substring(half)}';
      }
      codes.add(code);
    }
    return codes;
  }

  /// Generates an OTP code based on the provided secret and interval.
  static String generateTOTPCode(
      {required String secretKey,
      required int interval,
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1}) {
    if (secretKey.length < 16 || secretKey.length > 255) {
      throw ArgumentError('The length of the secret must be 16 to 255.');
    }
    final time = DateTime.now().millisecondsSinceEpoch ~/ 1000 ~/ interval;
    return _generateOTP(secretKey, time, digits, algorithm);
  }

  /// Verifies a given TOTP code against a secret key.
  static bool verifyCode(
      {required String secretKey,
      required String totpCode,
      int interval = 30,
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1}) {
    secretKey = secretKey.replaceAll(RegExp(r'[ -]'), '');
    int tolerance = 1;
    for (var i = -tolerance; i <= tolerance; i++) {
      final time =
          (DateTime.now().millisecondsSinceEpoch ~/ 1000 + i * interval) ~/
              interval;
      final generatedCode = _generateOTP(secretKey, time, digits, algorithm);
      if (generatedCode == totpCode) return true;
    }
    return false;
  }

  /// Generates an HMAC-based One-Time Password (HOTP) code based on the provided secret and counter.
  static String generateHOTPCode(
      {required String secretKey,
      required int counter,
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1}) {
    if (secretKey.length < 16 || secretKey.length > 255) {
      throw ArgumentError('The length of the secret must be 16 to 255.');
    }
    return _generateOTP(secretKey, counter, digits, algorithm);
  }

  /// Verifies a given HOTP code against a secret key and a counter.
  static bool verifyHOTPCode(
      {required String secretKey,
      required String hotpCode,
      required int counter,
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1}) {
    return _generateOTP(secretKey, counter, digits, algorithm) == hotpCode;
  }

  /// Core OTP generation method (used by both TOTP and HOTP).
  static String _generateOTP(
      String secret, int counter, int digits, OTPAlgorithm algorithm) {
    secret = secret.replaceAll(RegExp(r'[ -]'), '');
    final timeBytes = Uint8List(8);
    for (int i = 7, t = counter; i >= 0; i--) {
      timeBytes[i] = t & 0xff;
      t >>= 8;
    }
    final secretBytes = _base32Decode(secret);

    Hash hashAlgo;
    switch (algorithm) {
      case OTPAlgorithm.sha256:
        hashAlgo = sha256;
        break;
      case OTPAlgorithm.sha512:
        hashAlgo = sha512;
        break;
      case OTPAlgorithm.sha1:
        hashAlgo = sha1;
        break;
    }

    final hmac = Hmac(hashAlgo, secretBytes);
    final hash = hmac.convert(timeBytes).bytes;

    final offset = hash[hash.length - 1] & 0xf;
    final binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    final code = binary % pow(10, digits).toInt();
    return code.toString().padLeft(digits, '0');
  }

  /// Decode base32 encoded string
  static List<int> _base32Decode(String base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final buffer = <int>[];
    var bits = 0;
    var value = 0;

    for (var char in base32.toUpperCase().codeUnits) {
      if (char == '='.codeUnitAt(0)) {
        break;
      }
      value = (value << 5) | base32Chars.indexOf(String.fromCharCode(char));
      bits += 5;

      if (bits >= 8) {
        buffer.add((value >> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return buffer;
  }

  /// Parses an otpauth:// URI and returns an OTPAuthURI object
  static OTPAuthURI parseURI(String uriString) {
    final uri = Uri.parse(uriString);
    if (uri.scheme != 'otpauth') {
      throw FormatException('Invalid URI scheme: ${uri.scheme}');
    }

    final type = uri.host; // totp or hotp
    final path = Uri.decodeComponent(uri.path)
        .replaceFirst('/', ''); // remove leading slash

    final params = uri.queryParameters;
    final secret = params['secret'];
    if (secret == null) {
      throw FormatException('Missing secret in URI');
    }

    final issuer = params['issuer'];
    final digits =
        params.containsKey('digits') ? int.parse(params['digits']!) : 6;

    OTPAlgorithm algorithm = OTPAlgorithm.sha1;
    if (params.containsKey('algorithm')) {
      final algoStr = params['algorithm']!.toUpperCase();
      if (algoStr == 'SHA256') {
        algorithm = OTPAlgorithm.sha256;
      } else if (algoStr == 'SHA512') {
        algorithm = OTPAlgorithm.sha512;
      }
    }

    int? period =
        params.containsKey('period') ? int.parse(params['period']!) : null;
    int? counter =
        params.containsKey('counter') ? int.parse(params['counter']!) : null;

    return OTPAuthURI(
      type: type,
      secret: secret,
      appName: path,
      issuer: issuer,
      digits: digits,
      algorithm: algorithm,
      period: period,
      counter: counter,
    );
  }

  // Generates a QR code URL for OTP authentication.
  static String getQRCodeUrl(
      {required String appName,
      required String secretKey,
      String? issuer = 'auth_otp',
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1}) {
    final queryParameters = <String, String>{
      'secret': secretKey,
      if (issuer != null) 'issuer': issuer,
      if (digits != 6) 'digits': digits.toString(),
      if (algorithm != OTPAlgorithm.sha1)
        'algorithm': algorithm.name.toUpperCase(),
    };

    final otpauthUri = Uri(
      scheme: 'otpauth',
      host: 'totp',
      path: '/$appName',
      queryParameters: queryParameters,
    );

    final qrUri = Uri.https('api.qrserver.com', '/v1/create-qr-code/', {
      'data': otpauthUri.toString(),
    });

    return qrUri.toString();
  }

  /// Generates an offline QR Code matrix (QrCode object) for the given TOTP/HOTP parameters.
  /// You can use this to draw a QR code in Flutter using CustomPainter or other UI methods.
  static QrCode generateQRMatrix(
      {required String appName,
      required String secretKey,
      String? issuer = 'auth_otp',
      int digits = 6,
      OTPAlgorithm algorithm = OTPAlgorithm.sha1,
      String type = 'totp',
      int? counter}) {
    final queryParameters = <String, String>{
      'secret': secretKey,
      if (issuer != null) 'issuer': issuer,
      if (digits != 6) 'digits': digits.toString(),
      if (algorithm != OTPAlgorithm.sha1)
        'algorithm': algorithm.name.toUpperCase(),
      if (type == 'hotp' && counter != null) 'counter': counter.toString(),
    };

    final otpauthUri = Uri(
      scheme: 'otpauth',
      host: type,
      path: '/$appName',
      queryParameters: queryParameters,
    );

    return QrCode.fromData(
        data: otpauthUri.toString(), errorCorrectLevel: QrErrorCorrectLevel.M);
  }

  static String _autoPadding(String input) {
    StringBuffer output = StringBuffer();
    for (int i = 0; i < input.length; i += 4) {
      if (i + 4 <= input.length) {
        output.write(input.substring(i, i + 4));
        if (i + 4 < input.length) {
          output.write(' ');
        }
      }
    }
    return output.toString();
  }

  static String _randomizeCase(String input) {
    final random = Random();
    StringBuffer randomizedString = StringBuffer();
    for (int i = 0; i < input.length; i++) {
      String char = input[i];
      if (random.nextBool()) {
        randomizedString.write(char.toUpperCase());
      } else {
        randomizedString.write(char.toLowerCase());
      }
    }
    return randomizedString.toString();
  }
}
