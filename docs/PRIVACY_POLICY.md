# KAAO Privacy Policy

**Last Updated:** November 2026

KAAO is engineered on a strict **on-device-first, zero-telemetry** security architecture. We do not operate tracking analytics, advertising SDKs, or cloud user accounts, and we never upload your personal files, photos, messages, or APK binaries.

## 1. Data Processed Locally On Your Device
All core security and cleaning functions run entirely inside your Android device:
- **Antivirus & Static APK Analysis:** SHA-256 hashing, binary `AndroidManifest.xml` inspection, DEX bytecode heuristics, and hidden-asset checks run locally against an on-device SQLCipher 4.6.1 AES-256 database wrapped by Android Keystore AES-256-GCM.
- **Stalkerware Privilege Auditor:** Reads active Device Admin, Accessibility, Notification Listener, and Usage Access states locally to present guided remediation actions. No app inventory is transmitted off-device.
- **Zero-Root Aegis VPN (`VpnService`):**
  - In **DNS Shield** mode, only DNS queries routed to the local virtual DNS endpoint (`10.111.222.2`) are inspected locally against your on-device blocklist. Allowed DNS queries are forwarded using encrypted RFC 8484 DNS-over-HTTPS directly to your selected resolver (Cloudflare `1.1.1.1` or Quad9 `9.9.9.9`). KAAO never proxies, logs, or routes your non-DNS web traffic to any KAAO server.
  - In **Game Mode Firewall**, background app packets are dropped locally inside the Android TUN interface while your selected game bypasses the tunnel directly.
- **Deep Storage Cleaner:** 3-stage duplicate detection, APK/log scanning, and `StorageStatsManager` analysis happen exclusively on-device. Files are deleted **only** after explicit confirmation in the deletion modal.

## 2. Optional Opt-In Network Connections
KAAO only initiates outbound TLS connections (all protected with TLS certificate pinning) for:
1. **Signed Threat Definition Updates:** Downloading ECDSA-P256 signed threat hash & DNS blocklist bundles from the KAAO repository. No device identifiers or personal data are sent.
2. **Opt-In Hash-Only Cloud Reputation (Off by Default):** If you explicitly enable Cloud Hash Lookup in Settings, KAAO transmits **only the 64-character SHA-256 digest** of suspicious APKs/files to MalwareBazaar (`mb-api.abuse.ch`) and—only if you supply your own API key—VirusTotal (`www.virustotal.com`). Raw files and personal data are never uploaded.
3. **Game Booster TCP Ping Telemetry:** Measures socket connect latency (`ms`) to `1.1.1.1:443` or `8.8.8.8:443` while viewing the Game Booster telemetry HUD.

## 3. Data Storage, Security & Retention
- Threat signatures, custom DNS rules, recent local DNS logs (capped at 500 entries, clearable anytime), and cleaner whitelists are stored locally inside an encrypted SQLCipher 4.6.1 database excluded from cloud backups (`allowBackup="false"`).
- Optional VirusTotal API keys are encrypted via Android Keystore (`AES/GCM/NoPadding`).
- Uninstalling KAAO permanently removes all local databases and keys.

## 4. Contact
For privacy or security questions, open an issue at `https://github.com/Sophroneo-11/KAAO/issues`.
