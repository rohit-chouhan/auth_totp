## 2.0.0

- **Feature**: Added support for 8-digit TOTP codes (`digits` parameter).
- **Fix**: Resolved `Unsupported operation: Int64 accessor not supported by dart2js` on web.
- **Fix**: Refactored `getQRCodeUrl` to use `Uri` for safe QR code URL generation.
- **Feature**: Added support for SHA-256 and SHA-512 via `OTPAlgorithm` enum.
- **Feature**: Added HOTP (Counter-Based OTP) generation and verification (`generateHOTPCode`, `verifyHOTPCode`).
- **Feature**: Added `generateRecoveryCodes` utility to generate alphanumeric backup codes.
- **Feature**: Added `OTPAuthURI` class and `parseURI` method to safely parse `otpauth://` URIs.
- **Feature**: Added `generateQRMatrix` using the `qr` package for offline, privacy-focused QR code generation.

## 1.0.1

- bug fixed
- `secretKeyStyle` property added to createSecret method to customized secret key style.
- `autoPadding` property added to createSecret method.
- `interval` property added to verifyCode method, to set custom time interval.
- create method length limit increased to 255

## 1.0.0

- initial release
