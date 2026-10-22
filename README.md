# Android APK Security Scanner

This repository contains a simple Android app for scanning APK files and checking common security indicators. The app is intended for legitimate, authorized security assessments only and should not be used to attack or access apps you do not own or have permission to test.

## Features
- Select an APK from the device
- Read the manifest
- Detect dangerous permissions
- Detect exported components
- Detect cleartext traffic
- Search for potential hardcoded secrets or tokens
- Check for risky WebView patterns

## Legal note
Use only for:
- your own apps
- internal apps you are authorized to test
- applications included in a valid bug bounty scope

Do not use this tool to exploit, access, or exfiltrate data from third-party apps without explicit permission.

## Build instructions
1. Open the project in Android Studio.
2. Let Gradle sync.
3. Build the app.
4. Install the APK on a test device or emulator.
5. Open the app and select an APK to scan.

## Project structure
- `app/src/main/java/com/example/apkscanner/MainActivity.kt` — main app logic
- `app/src/main/java/com/example/apkscanner/ScannerUtil.kt` — scanning routines
- `app/src/main/res/layout/activity_main.xml` — UI layout
- `app/src/main/AndroidManifest.xml` — app manifest

## Notes
This repo is a lightweight static scanner sample, not a full commercial APK security suite. For serious analysis, use additional tools such as `apktool`, `jadx`, `MobSF`, or `Frida` in a properly scoped and authorized environment.
