# Notes-X-krdrx

A local-first Android password notes app with an editable spreadsheet-style vault.

## Current MVP
- First-run master-password setup and unlock (minimum 10 characters).
- Encrypted local vault file using PBKDF2-HMAC-SHA256 + AES-256-GCM.
- Fully user-defined spreadsheet columns and rows.
- Edit cells, add/delete rows and columns, search, reveal/hide password cells, copy cell values.
- Light Tosca and Dark Tosca themes.
- No network permission and no account/server requirement.

## Security notes
- Vault contents are encrypted at rest. The master password is used to derive the encryption key with PBKDF2-HMAC-SHA256 (600,000 iterations); it is never stored.
- Forgetting the PIN means the vault cannot be decrypted. There is no recovery backdoor.
- This is an initial MVP, not an independently audited password manager. Do not use it as the sole store for critical credentials until the implementation has been reviewed and tested.
- Android screenshots are disabled while the vault is open. Clipboard contents are cleared on a best-effort basis after 30 seconds.

## Build
Open the project in Android Studio or run:

```bash
./gradlew assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`.

GitHub Actions builds a debug APK on pushes and can publish a downloadable artifact.

## License
MIT
