# auth_totp

`auth_totp` is a pure Dart package providing a straightforward and secure implementation of Time-based One-Time Passwords (TOTP). It allows generating Base32 secret keys, generating TOTP codes, and verifying codes.

## Architecture and Core Components

The logic resides in `lib/auth_totp.dart`, which exposes a single utility class, `AuthTOTP`. It operates primarily on static methods, making it simple to drop into any authentication flow.

### Key God Nodes & Functions (Based on Graphify Analysis)

The project centers around these core operations:

1. **`createSecret()`**
   Generates a secure random Base32 encoded secret key. This is typically done once per user account.
   *   Length can be customized (default 32, range 16-255).
   *   Provides a `SecretKeyStyle` to toggle `upperCase`, `lowerCase`, or `upperLowerCase`.
   *   Supports optional space padding every 4 characters (`autoPadding`).

2. **`generateTOTPCode()`**
   Generates a standard 6-digit or 8-digit TOTP code based on the current system time and the specified interval (typically 30 seconds).
   *   Length can be 6 or 8 digits using the `digits` parameter.
   *   Internally uses `Hmac` with `sha1` from the `crypto` package.
   *   Relies on an internal `_base32Decode()` function to convert the secret string into raw bytes.

3. **`verifyCode()`**
   Validates a 6-digit code against the secret key.
   *   It provides a **time tolerance** of ±1 interval (e.g., ±30 seconds) to account for slight clock skews or delays in user input.
   *   Uses the internal helper `_generateCodeAtTime()` to check neighboring time windows.

4. **`getQRCodeUrl()`**
   A helper function to generate a URL pointing to `api.qrserver.com`. This creates an `otpauth://` QR code image that users can scan with Google Authenticator, Authy, or other authenticator apps.

## Dependencies

- **`crypto`**: Used for HMAC and SHA-1 hashing operations to compute the TOTP value.
- **`dart:math`**: Supplies `Random.secure()` for cryptographically secure random generation of the secret key.
- **`dart:typed_data`**: Provides `Uint8List` and `ByteData` for byte-level manipulation of the time intervals.

## Integration Flow

1. **Setup**: The server/app generates a secret using `AuthTOTP.createSecret()` and displays a QR code to the user using `AuthTOTP.getQRCodeUrl()`.
2. **Client Config**: The user scans the QR code with their authenticator app.
3. **Verification**: During login, the user provides a code from their app. The server verifies it using `AuthTOTP.verifyCode()`.

## Development Rules

- **Changelog**: All significant changes must be documented in the `CHANGELOG.md` file.
- **Documentation**: Whenever any functional or structural changes are made, the `README.md` must be updated to reflect the new state.

## Testing

The project uses the standard Flutter testing framework. Run all tests in the root directory using:
```bash
flutter test
```
The `test/auth_totp_test.dart` file verifies the core library behaviors, including 6-digit/8-digit logic, code verifications, and `Uri` safe generation for QR codes.
