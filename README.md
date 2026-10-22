# Android APK Security Scanner

A lightweight Android application designed for authorized APK security analysis. The app is intended for use on:

- your own applications
- internal apps where you have explicit permission to test
- apps within a valid bug bounty scope

It performs static checks on APK contents and highlights common mobile application risks.

## Features
- Select an APK file from the device
- Read and inspect the Android manifest
- Detect dangerous permissions
- Detect exported components
- Detect cleartext traffic settings
- Scan embedded strings for potential hardcoded secrets, tokens, and API keys
- Flag risky WebView patterns
- Calculate a basic risk score and security recommendation list
- Copy scan results to the clipboard

## Build instructions
1. Open the repository in Android Studio.
2. Let Gradle sync and download dependencies.
3. Build > Build APK.
4. Install the generated APK on a physical device or emulator.
5. Open the app and select an APK to scan.

## Legal note
Use this tool only for authorized testing. Do not use it to attack or access third-party apps without permission.

## Project layout
- `app/src/main/java/com/example/apkscanner/MainActivity.kt` — app UI and orchestrates scan flow
- `app/src/main/java/com/example/apkscanner/ScannerUtil.kt` — manifest parsing and static analysis
- `app/src/main/res/layout/activity_main.xml` — main interface
- `app/src/main/AndroidManifest.xml` — app manifest

## Limitations
This is a static scanner for common issues, not a full-blown automated pentest framework. For deeper analysis, combine it with tools such as `apktool`, `jadx`, `MobSF`, `frida`, and a properly scoped testing environment.
