import 'package:flutter_test/flutter_test.dart';
import 'package:auth_totp/auth_totp.dart';

void main() {
  group('AuthTOTP (Core & Advanced Scenarios)', () {
    /// -----------------------------------------------------
    /// SCENARIO 1: HOTP Generation with Fixed Scenarios
    /// This proves that the algorithm matches expected outputs
    /// for a given secret and counter.
    /// -----------------------------------------------------
    test('HOTP should generate exact known values for a given secret', () {
      final secret = 'JBSWY3DPEHPK3PXP'; // Known test secret

      // Scenario A: Counter = 0
      final code0 = AuthTOTP.generateHOTPCode(secretKey: secret, counter: 0);
      print('[Scenario 1] Counter 0 -> Expected: 282760 | Actual: $code0');
      expect(code0, '282760', reason: 'Counter 0 must generate 282760');

      // Scenario B: Counter = 1
      final code1 = AuthTOTP.generateHOTPCode(secretKey: secret, counter: 1);
      print('[Scenario 1] Counter 1 -> Expected: 996554 | Actual: $code1');
      expect(code1, '996554', reason: 'Counter 1 must generate 996554');

      // Scenario C: Counter = 2
      final code2 = AuthTOTP.generateHOTPCode(secretKey: secret, counter: 2);
      print('[Scenario 1] Counter 2 -> Expected: 602287 | Actual: $code2');
      expect(code2, '602287', reason: 'Counter 2 must generate 602287');
    });

    /// -----------------------------------------------------
    /// SCENARIO 2: HOTP Verification Scenarios
    /// Proves the verify function works correctly against
    /// exact known good/bad codes.
    /// -----------------------------------------------------
    test('HOTP verification should pass/fail strictly based on counter', () {
      final secret = 'JBSWY3DPEHPK3PXP';
      final validCodeCounter0 = '282760';

      // Verify Correct Code & Counter
      final isValidCorrect = AuthTOTP.verifyHOTPCode(
          secretKey: secret, hotpCode: validCodeCounter0, counter: 0);
      print(
          '[Scenario 2] Verify Code ($validCodeCounter0) with Correct Counter (0): $isValidCorrect');
      expect(isValidCorrect, isTrue,
          reason: 'Should verify valid code at correct counter');

      // Verify Incorrect Counter (Testing counter drift failure)
      final isValidWrongCounter = AuthTOTP.verifyHOTPCode(
          secretKey: secret, hotpCode: validCodeCounter0, counter: 1);
      print(
          '[Scenario 2] Verify Code ($validCodeCounter0) with Wrong Counter (1): $isValidWrongCounter');
      expect(isValidWrongCounter, isFalse,
          reason: 'Should fail because counter 1 generates a different code');

      // Verify Incorrect Code string
      final isValidWrongCode = AuthTOTP.verifyHOTPCode(
          secretKey: secret, hotpCode: '111111', counter: 0);
      print(
          '[Scenario 2] Verify Wrong Code (111111) with Correct Counter (0): $isValidWrongCode');
      expect(isValidWrongCode, isFalse,
          reason: 'Should fail for completely wrong code string');
    });

    /// -----------------------------------------------------
    /// SCENARIO 3: TOTP Length (Digits) Support
    /// Ensure the system correctly pads or calculates
    /// both 6-digit (default) and 8-digit codes.
    /// -----------------------------------------------------
    test('TOTP should support generating 6-digit and 8-digit lengths', () {
      final secret =
          AuthTOTP.createSecret(); // Randomly generated secure secret

      // Generate 6-digit TOTP
      final code6 =
          AuthTOTP.generateTOTPCode(secretKey: secret, interval: 30, digits: 6);
      print('[Scenario 3] 6-Digit TOTP Output: $code6');
      expect(code6.length, 6,
          reason: 'Generated code must have exactly 6 characters');
      expect(int.tryParse(code6), isNotNull,
          reason: 'Generated code must be strictly numeric');

      // Generate 8-digit TOTP
      final code8 =
          AuthTOTP.generateTOTPCode(secretKey: secret, interval: 30, digits: 8);
      print('[Scenario 3] 8-Digit TOTP Output: $code8');
      expect(code8.length, 8,
          reason: 'Generated code must have exactly 8 characters');
      expect(int.tryParse(code8), isNotNull,
          reason: 'Generated code must be strictly numeric');
    });

    /// -----------------------------------------------------
    /// SCENARIO 4: TOTP Verification Tolerance
    /// Ensures `verifyCode` accurately checks time intervals.
    /// -----------------------------------------------------
    test('TOTP verification properly authenticates recent codes', () {
      final secret = AuthTOTP.createSecret();

      // Generate code for RIGHT NOW
      final currentCode =
          AuthTOTP.generateTOTPCode(secretKey: secret, interval: 30);

      // Verify
      final isValid = AuthTOTP.verifyCode(
          secretKey: secret, totpCode: currentCode, interval: 30);
      print(
          '[Scenario 4] Newly Generated TOTP ($currentCode) -> Valid? $isValid');
      expect(isValid, isTrue,
          reason: 'A newly generated code should be valid right away');
    });

    /// -----------------------------------------------------
    /// SCENARIO 5: Advanced Hash Algorithms (SHA256, SHA512)
    /// -----------------------------------------------------
    test(
        'TOTP should generate entirely different codes based on hashing algorithm',
        () {
      final secret = AuthTOTP.createSecret();

      final sha1Code = AuthTOTP.generateTOTPCode(
          secretKey: secret, interval: 30, algorithm: OTPAlgorithm.sha1);
      final sha256Code = AuthTOTP.generateTOTPCode(
          secretKey: secret, interval: 30, algorithm: OTPAlgorithm.sha256);
      final sha512Code = AuthTOTP.generateTOTPCode(
          secretKey: secret, interval: 30, algorithm: OTPAlgorithm.sha512);

      print('[Scenario 5] SHA1 Generated: $sha1Code');
      print('[Scenario 5] SHA256 Generated: $sha256Code');
      print('[Scenario 5] SHA512 Generated: $sha512Code');

      // We assert that switching the algorithm drastically alters the generated code
      expect(sha1Code, isNot(sha256Code),
          reason: 'SHA1 must not match SHA256 code output');
      expect(sha256Code, isNot(sha512Code),
          reason: 'SHA256 must not match SHA512 code output');

      // Verify works properly with advanced hashes
      expect(
          AuthTOTP.verifyCode(
              secretKey: secret,
              totpCode: sha512Code,
              algorithm: OTPAlgorithm.sha512),
          isTrue);
    });

    /// -----------------------------------------------------
    /// SCENARIO 6: Recovery Codes Formatting
    /// Ensuring backup codes are safe, split, and alphanumeric.
    /// -----------------------------------------------------
    test('Recovery codes should generate secure hyphenated blocks', () {
      final codes = AuthTOTP.generateRecoveryCodes(count: 5, length: 10);

      expect(codes.length, 5, reason: 'Must output exactly 5 requested codes');

      final firstCode = codes.first;
      print(
          '[Scenario 6] Sample Recovery Code Output: $firstCode (Total Length: ${firstCode.length})');

      // length of 10 characters split by 1 hyphen = 11 characters total
      expect(firstCode.length, 11,
          reason: 'Should be length 10 + 1 hyphen = 11 length');
      expect(firstCode.contains('-'), isTrue,
          reason: 'Should automatically format with a hyphen in the middle');
    });

    /// -----------------------------------------------------
    /// SCENARIO 7: otpauth:// URI Parsing
    /// Ensure all fields extract perfectly to a URI object.
    /// -----------------------------------------------------
    test(
        'URI Parser should extract type, secret, issuer, and advanced parameters correctly',
        () {
      final rawUri =
          'otpauth://totp/AcmeApp?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Corp&digits=8&algorithm=SHA256';
      print('[Scenario 7] Input URI: $rawUri');

      final parsedObj = AuthTOTP.parseURI(rawUri);

      print(
          '[Scenario 7] Parsed Secret: ${parsedObj.secret}, Issuer: ${parsedObj.issuer}, Algorithm: ${parsedObj.algorithm.name}');

      expect(parsedObj.type, 'totp');
      expect(parsedObj.secret, 'JBSWY3DPEHPK3PXP');
      expect(parsedObj.appName, 'AcmeApp');
      expect(parsedObj.issuer, 'Acme Corp'); // Verifies URL %20 decoding
      expect(parsedObj.digits, 8);
      expect(parsedObj.algorithm, OTPAlgorithm.sha256);
    });

    /// -----------------------------------------------------
    /// SCENARIO 8: Offline QR Code Matrix
    /// Test the creation of a local, untracked QR matrix grid.
    /// -----------------------------------------------------
    test(
        'generateQRMatrix safely generates a QrCode grid representation offline',
        () {
      final matrix = AuthTOTP.generateQRMatrix(
          appName: 'SuperSecureApp',
          secretKey: 'JBSWY3DPEHPK3PXP',
          issuer: 'MyCompany');

      print(
          '[Scenario 8] Successfully generated QR Code matrix of dimension: ${matrix.moduleCount}x${matrix.moduleCount}');

      // Should successfully construct the internal QR grid payload
      expect(matrix, isNotNull);
      expect(matrix.moduleCount > 0, isTrue,
          reason:
              'QR Code matrix should be heavily populated with grid modules');
    });
  });
}
