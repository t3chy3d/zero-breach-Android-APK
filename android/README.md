# Zero Breach — Android port

Local, read-only Android scanner for the AdFection / Candiru ad-delivered
spyware campaign, ported 2026-10-30 from https://github.com/interplains/zero-breach
(desktop scanner v0.1.8, indicator set as-of 2026-10-18).

## Deliverable
- `ZeroBreach-1.0.0.apk` — package `com.zerobreach.scanner`, versionCode 1,
  versionName 1.0.0, 637 KB, minSdk 26 / targetSdk 34.
- Signed with the pinned key in `signing/zerobreach.keystore`
  (cert SHA-256 70057c60659f031ad0af47402028b119fd8d7f126dd4d1b96a341e163f162ece).
  New app, new key — it does not clash with PinPoint.
- NO `android.permission.INTERNET`. Permissions: ACCESS_NETWORK_STATE
  (read DNS config), QUERY_ALL_PACKAGES (hash installed APKs),
  READ_EXTERNAL_STORAGE (≤ Android 12), MANAGE_EXTERNAL_STORAGE
  (user-granted all-files access for the storage walk).

## Same detections, adapted to Android
Embedded indicator set is byte-identical to upstream `iocs/adfection_iocs.txt`
(SHA-256 c9801e3ba37376535a676d9938d65550bcaa5478578cb80a6dd09eb2ac402d38,
verified against the repo's published .sha256): **405 indicators —
292 domains, 111 IPs, 1 spyware-sample SHA-256, 1 vuln-driver SHA-256**,
with tier / confidence / source per indicator. Matching is a direct port of
upstream `iocs.py`: boundary matching (notcontrolium.net and
controlium.network do not match; 152.174.65.771 does not match the IP),
parent-domain pruning (noas.powerium.net is one contact, not two),
plain-text + UTF-16LE search. JVM tests of the matcher pass
(`build-manual/test/TestMain.kt`).

Checks that run on Android:
- Hosts file (/system/etc/hosts, /etc/hosts) → `configured` findings;
  indicator names blocked to 0.0.0.0/127.0.0.1 are reported as protective, not hits.
- DNS servers + Private DNS (per-network and system-wide) vs indicator IPs/domains → `configured`.
- Installed apps: every readable APK hashed vs the 2 known hashes → `on-disk`.
- Shared storage (Downloads/Documents/root, with all-files access): candidate
  files hashed (upstream extension set + apk/dex/so/jar, 120 MB cap) → `on-disk`;
  files ≤25 MB content-searched → `contacted` for browser-type artifacts,
  `referenced` otherwise.
- User-picked folder/files (SAF): same hash + content search — the way to scan
  a browser export/backup or Downloads without broad access.
- Persistence equivalents (context/notes, not findings by themselves):
  device-admin receivers, enabled accessibility services, active VPN.

Honest gaps (reported in-app, per upstream's "measured, never inferred"):
- Direct browser history/cookies/cache checks CANNOT run — Android's sandbox
  blocks reading other apps' private data. Picked-folder/file scan is the workaround.
- No queryable DNS cache/history on Android — only current DNS config is checked.
- Windows-only checks (COM persistence, HW.sys path, DNS event log) have no
  Android equivalent and are listed as gaps, not as clean.

Evidence grading, defanged indicator display, "a clean result is not a clean
bill of health", and next-step guidance follow the upstream report format.

## Build
Gradle's daemon socket is broken in this sandbox (client gets garbage from the
daemon port), so the APK was built with the equivalent manual pipeline in
`build-manual/` (same SDK/Kotlin versions as the Gradle files, which are kept
for a normal environment):
aapt2 link → kotlinc (kotlin-compiler-embeddable 2.0.21, from the PinPoint
local-repo) → D8 → zipalign → apksigner with the pinned key above.
Verified with apksigner (v2+v3 true) and aapt badging; IOC matcher JVM-tested.
Not yet run on a real device — first install on Cameron's phone is the smoke test.

Upstream code Apache-2.0; indicator data CC0 ( Citizen Lab, Confiant,
Recorded Future, Microsoft, ESET, Avast, Google TAG, Amnesty sources).
Not affiliated with or endorsed by any of them.
