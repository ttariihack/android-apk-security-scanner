# Android APK Security Scanner

A simple Android app for scanning APK files and identifying common mobile app security issues such as:

- exported components
- dangerous permissions
- cleartext traffic
- hardcoded secrets / API keys
- suspicious WebView patterns

This project is intended for authorized testing only, such as:
- your own app
- internal apps with permission
- apps in a valid bug bounty scope

## Features
- select an APK from the device
- inspect AndroidManifest.xml
- look for dangerous permissions
- detect exported components
- check cleartext traffic
- scan embedded strings for secrets or tokens
- flag risky WebView patterns

## Build in Android Studio
1. Open the repository in Android Studio.
2. Let Gradle sync.
3. Build > Build APK.
4. Install the APK to a device or emulator.
5. Open the app and choose an APK file.

## Important note
Use only with applications you own or are explicitly authorized to test. Do not use this tool to exploit, access, or exfiltrate data from third-party apps without permission.

## Project structure
- `app/src/main/java/com/example/apkscanner/MainActivity.kt` — UI + APK scanning flow
- `app/src/main/java/com/example/apkscanner/ScannerUtil.kt` — static scanning logic
- `app/src/main/res/layout/activity_main.xml` — app layout
- `app/src/main/AndroidManifest.xml` — app manifest
- `README.md` — instructions
