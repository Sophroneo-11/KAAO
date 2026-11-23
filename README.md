# KAAO — Android Security, Privacy, DNS Shield, Game Booster & Deep Cleaner

**KAAO** is a dark-first, zero-root Android security and device-hygiene suite built with **Kotlin 2.1**, **Jetpack Compose (Material 3)**, **Clean Architecture + MVVM + UDF**, **Hilt**, **Coroutines/StateFlow**, **Room + SQLCipher 4.6.1** (wrapped by **Android Keystore AES-256-GCM**), **DataStore**, **WorkManager**, and **Retrofit + OkHttp (CertificatePinner + Kotlinx Serialization)**.

## Core Architecture & Features

1. **Hardened Android 14/15 Foundation (Min SDK 26 / Target SDK 35)**
   - Android 14/15 `foregroundServiceType="specialUse"` (`AegisVpnService`, `RealtimeMonitorService`, `GameOverlayService`) and `foregroundServiceType="dataSync"` (`DeepScanForegroundService`), with zero `KILL_BACKGROUND_PROCESSES` gimmicks.
   - TLS-only `network_security_config.xml`, non-backed-up encrypted vaults (`backup_rules.xml` & `data_extraction_rules.xml`), adaptive monochrome-ready vector icons, and just-in-time `PermissionManager` with graceful fallbacks.

2. **Core Antivirus & Stalkerware Engine**
   - **Lock-free SHA-256 Bloom Filter** (`AtomicReference<BloomSnapshot>`) + **SQLCipher 4.6.1** encrypted threat vault wrapped by Android Keystore AES-256-GCM.
   - **Static APK / DEX / Hidden-Asset Analyzer**: binary `AndroidManifest.xml` string-pool scanner, DEX header/entropy/API heuristics, and hidden nested APK/DEX/ELF masquerading detection inside `assets/` & `res/raw/`.
   - **Active Stalkerware Privilege Auditor**: audits live Device Admins, Accessibility Services, Notification Listeners, and Usage Access holders correlated with installer provenance and hidden launcher icons.
   - **Pluggable Hash-Only Cloud Reputation**: opt-in MalwareBazaar + optional Keystore-encrypted VirusTotal v3 SHA-256 lookups over certificate-pinned TLS (raw files are never uploaded).
   - **ECDSA-P256 Definition Verification**: `SHA256withECDSA` signature check + monotonic anti-rollback protection.
   - **Real-Time Protection**: dynamic `PackageInstallReceiver`, `Downloads` inotify `FileObserver`, and API 26+ `PackageManager.getChangedPackages()` periodic WorkManager delta audit.

3. **Zero-Root `AegisVpnService`, Wi-Fi Inspector & Game Booster**
   - **Split-Routed RFC 8484 DNS-over-HTTPS Sinkhole**: routes only the virtual DNS endpoint (`10.111.222.2/32`) through TUN, filtering phishing, malware, and adware/trackers locally and forwarding allowed queries via certificate-pinned DoH (Cloudflare / Quad9) using `VpnService.protect()` sockets.
   - **Game Mode Background Bandwidth Firewall**: routes background traffic into the TUN drain while excluding the active game via `addDisallowedApplication()`.
   - **Wi-Fi Security Inspector**: detects Open/WEP/WPA/WPA2/WPA3, captive portals, Private DNS, and suspicious DNS overrides.
   - **Game Booster**: `CATEGORY_GAME` auto-detection, live thermal/battery/RAM/TCP-ping telemetry, crash-safe reversible DND/brightness/auto-sync suppression, and draggable floating HUD overlay with notification fallback.

4. **Deep Storage Cleaner**
   - **3-Stage Duplicate Finder**: exact size → 3-region partial SHA-256 → full streaming SHA-256.
   - Leftover APKs (with installed status check), temp/log files, bottom-up empty folders, large/messaging media with **MediaStore fallback**, `StorageStatsManager` per-app storage/cache breakdown, exclusion whitelist, and explicit user-confirmed safe deletion modal.

## Build & Verification

```bash
./gradlew testDebugUnitTest lintDebug assembleDebug
```
