# KAAO Google Play Store Compliance & Release Guide

This document maps KAAO's permissions, foreground services, `VpnService` usage, and Data Safety declarations to Google Play Console policy requirements.

## 1. Data Safety Form Mapping

| Question | Answer | Rationale |
|---|---|---|
| Does your app collect or share any required user data types? | **No** (when Cloud Hash Lookup is off); **Optional SHA-256 hashes only** when user opts in | No user accounts, analytics, crash trackers, or ads. Opt-in hash lookups transmit only file SHA-256 digests to MalwareBazaar / user-supplied VirusTotal. |
| Is all data encrypted in transit? | **Yes** | `network_security_config.xml` enforces `cleartextTrafficPermitted="false"` globally with OkHttp `CertificatePinner`. |
| Does the app exclude sensitive data from cloud backup? | **Yes** | `android:allowBackup="false"`, plus `backup_rules.xml` & `data_extraction_rules.xml` excluding SQLCipher DB and Keystore wrapped keys. |

## 2. Sensitive Permission & Service Justifications

### `VpnService` (`AegisVpnService`)
- **Core Purpose:** Security & Privacy (local zero-root DNS-over-HTTPS phishing/malware/adware sinkhole + Game Mode background bandwidth firewall).
- **Disclosure:** Explicitly presented to the user before invoking `VpnService.prepare()`, runs strictly on-device without remote VPN servers or ad-monetization traffic manipulation.

### Android 14/15 `foregroundServiceType="specialUse"`
- **`AegisVpnService`:** Sustains the local TUN packet loop for split-routed RFC 8484 DoH filtering and Game Mode firewall.
- **`RealtimeMonitorService`:** Opt-in user-enabled real-time antivirus monitor registering dynamic `PackageInstallReceiver` and `Downloads` inotify `FileObserver`.
- **`GameOverlayService`:** Displays the user-initiated draggable telemetry HUD pill (ping, °C, RAM, battery) with one-tap system settings restore during active gameplay.

### Android 14/15 `foregroundServiceType="dataSync"`
- **`DeepScanForegroundService`:** Completes long-running on-device antivirus scans over installed packages and downloaded APKs reliably when the user switches apps.

### `QUERY_ALL_PACKAGES`
- **Play Policy Category:** Antivirus / Security & Device Utility.
- **Use:** Required to compute SHA-256 digests and run static APK/DEX heuristic scans, audit Stalkerware privileges, detect `CATEGORY_GAME` titles, and compute per-app storage breakdown.

### `MANAGE_EXTERNAL_STORAGE` (with Graceful MediaStore Fallback)
- **Play Policy Category:** File Management / Deep Storage Cleaner.
- **Note for Play Review:** KAAO works **without** `MANAGE_EXTERNAL_STORAGE` by falling back seamlessly to `MediaStore` (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`). If Google Play rejects `MANAGE_EXTERNAL_STORAGE` for your store listing category, you can remove that single permission line from `AndroidManifest.xml` without breaking duplicate media cleaning or app storage analysis.

### `PACKAGE_USAGE_STATS`
- **Use:** Opt-in just-in-time permission powering `StorageStatsManager` exact app data/cache breakdown and Stalkerware Usage Access auditing.

## 3. Configuring Production Signing Secrets for Play Store Releases

1. Generate your upload keystore locally (store it safely offline — **never commit it**):
   ```bash
   keytool -genkeypair -v -keystore kaao-release.jks -alias kaao-upload \
     -keyalg RSA -keysize 4096 -validity 10000
   ```
2. Base64-encode the keystore:
   ```bash
   base64 -w0 kaao-release.jks > kaao-release.jks.b64
   ```
3. In GitHub (`Settings → Secrets and variables → Actions`), add:
   - `KEYSTORE_BASE64`
   - `KEYSTORE_PASSWORD`
   - `KEY_ALIAS`
   - `KEY_PASSWORD`
4. Push a release tag (`git tag v1.0.0 && git push origin v1.0.0`) or run the **KAAO Release APK & AAB** workflow manually. When secrets are present, CI automatically signs both `KAAO-<tag>-release.apk` and `KAAO-<tag>-release.aab` (ready for Play Console upload).
