package com.example.apkscanner

import java.io.File
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import org.xmlpull.v1.XmlPullParserFactory

private data class ManifestFacts(
    val dangerousPermissions: List<String>,
    val exportedCount: Int,
    val debuggable: Boolean,
    val allowBackup: Boolean,
    val cleartextTraffic: Boolean,
    val backupAgent: Boolean,
    val networkSecurityConfig: Boolean,
    val exportedComponents: List<String>
)

data class Finding(
    val type: String,
    val severity: String,
    val message: String
)

data class ScanReport(
    val apkPath: String,
    val score: Int,
    val severity: String,
    val findings: List<Finding>
)

object ScannerUtil {
    private val dangerousPermissions = setOf(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW"
    )

    private val secretPatterns = listOf(
        Regex("(?i)(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|oauth[_-]?token)[:=][\\s\"']?[A-Za-z0-9._\\-]{8,}"),
        Regex("AIza[0-9A-Za-z\\-_]{35}"),
        Regex("ghp_[A-Za-z0-9]{20,}"),
        Regex("xox[baprs]-[A-Za-z0-9-]+"),
        Regex("AKIA[0-9A-Z]{16}"),
        Regex("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        Regex("(?i)(aws_access_key_id|aws_secret_access_key|db_password|password)[:=][\\s\"']?[A-Za-z0-9!@#$%^&*()_+\\-={}\\[\\]:;\"'<>?,./\\|~]{4,}")
    )

    private val webviewRiskPatterns = listOf(
        "addJavascriptInterface",
        "setJavaScriptEnabled(true)",
        "setAllowFileAccess(true)",
        "loadUrl(\"file://",
        "WebChromeClient",
        "WebViewClient"
    )

    fun buildRiskSummary(reportText: String): String {
        val scoreMatch = Regex("Risk Score: (\\d+)/100").find(reportText)
        val score = scoreMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val severity = when {
            score >= 70 -> "Critical"
            score >= 40 -> "High"
            score >= 20 -> "Medium"
            else -> "Low"
        }
        return "Risk score: $score/100 ($severity)"
    }

    fun analyzeApk(apkPath: String): ScanReport {
        val manifestText = readManifestFromApk(apkPath)
        val facts = parseManifestFacts(manifestText)
        val findings = mutableListOf<Finding>()

        if (facts.debuggable) {
            findings.add(Finding("debuggable", "high", "Application is marked debuggable=true."))
        }

        if (facts.allowBackup) {
            findings.add(Finding("allow_backup", "medium", "allowBackup=true may allow device backup exposure."))
        }

        if (facts.cleartextTraffic) {
            findings.add(Finding("cleartext_traffic", "high", "usesCleartextTraffic=true allows plaintext HTTP traffic."))
        }

        if (facts.backupAgent) {
            findings.add(Finding("backup_agent", "medium", "Backup agent is configured and may expose data."))
        }

        if (facts.exportedCount > 0) {
            findings.add(Finding("exported_components", "medium", "Found ${facts.exportedCount} exported component(s): ${facts.exportedComponents.joinToString()}"))
        }

        if (facts.dangerousPermissions.isNotEmpty()) {
            findings.add(Finding("dangerous_permissions", "medium", "Dangerous permissions present: ${facts.dangerousPermissions.joinToString()}"))
        }

        val secretMatches = scanZipForSecretMatches(apkPath)
        if (secretMatches.isNotEmpty()) {
            findings.add(Finding("hardcoded_secret", "high", secretMatches.first()))
        }

        val webMatches = scanZipForWebviewMatches(apkPath)
        if (webMatches.isNotEmpty()) {
            findings.add(Finding("webview_risk", "medium", webMatches.first()))
        }

        val score = calculateScore(findings)
        val severity = when {
            score >= 70 -> "critical"
            score >= 40 -> "high"
            score >= 20 -> "medium"
            else -> "low"
        }

        return ScanReport(apkPath, score, severity, findings)
    }

    fun recommendations(report: ScanReport): List<String> {
        val recs = mutableListOf<String>()

        if (report.findings.any { it.type == "cleartext_traffic" }) {
            recs.add("Disable cleartext traffic and enforce HTTPS/TLS for all network requests.")
        }
        if (report.findings.any { it.type == "allow_backup" }) {
            recs.add("Set allowBackup=false or protect backups with encryption and user consent.")
        }
        if (report.findings.any { it.type == "exported_components" }) {
            recs.add("Restrict exported activities/services to only what is required and validate incoming intents.")
        }
        if (report.findings.any { it.type == "hardcoded_secret" }) {
            recs.add("Move secrets to Android Keystore or secure server-side validation instead of bundle strings.")
        }
        if (report.findings.any { it.type == "dangerous_permissions" }) {
            recs.add("Request only the minimal permissions required and avoid over-scoping access.")
        }
        if (report.findings.any { it.type == "webview_risk" }) {
            recs.add("Review WebView settings to disable file access and unsafe JS bridging.")
        }
        if (recs.isEmpty()) {
            recs.add("No major issues detected. Continue secure coding practices and regular code review.")
        }

        return recs
    }

    private fun calculateScore(findings: List<Finding>): Int {
        var total = 0
        findings.forEach { finding ->
            total += when (finding.severity.lowercase()) {
                "critical" -> 30
                "high" -> 20
                "medium" -> 10
                "low" -> 5
                else -> 0
            }
        }
        return minOf(total, 100)
    }

    private fun readManifestFromApk(apkPath: String): String {
        val file = File(apkPath)
        if (!file.exists()) return ""

        ZipInputStream(file.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (entry.name == "AndroidManifest.xml") {
                    return String(zip.readBytes(), Charsets.UTF_8)
                }
                entry = zip.nextEntry
            }
        }
        return ""
    }

    private fun parseManifestFacts(manifestText: String): ManifestFacts {
        val dangerous = mutableListOf<String>()
        val exportedComponents = mutableListOf<String>()
        var exportedCount = 0
        var debuggable = false
        var allowBackup = true
        var cleartextTraffic = false
        var backupAgent = false
        var networkSecurityConfig = false

        if (manifestText.isBlank()) {
            return ManifestFacts(emptyList(), 0, false, false, false, false, false, emptyList())
        }

        try {
            val factory = XmlPullParserFactory.newInstance()
            val parser = factory.newPullParser()
            parser.setInput(manifestText.reader())

            var eventType = parser.eventType
            while (eventType != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                if (eventType == org.xmlpull.v1.XmlPullParser.START_TAG) {
                    val tag = parser.name ?: ""
                    when (tag) {
                        "uses-permission" -> {
                            val name = parser.getAttributeValue(null, "name")
                            if (name != null && dangerousPermissions.contains(name)) {
                                dangerous.add(name)
                            }
                        }
                        "application" -> {
                            debuggable = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "debuggable") == "true"
                            allowBackup = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "allowBackup") != "false"
                            cleartextTraffic = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "usesCleartextTraffic") == "true"
                            backupAgent = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "backupAgent") != null
                            networkSecurityConfig = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "networkSecurityConfig") != null
                        }
                        "activity", "service", "receiver", "provider" -> {
                            val exported = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "exported")
                            if (exported == "true") {
                                exportedCount += 1
                                exportedComponents.add(tag)
                            }
                        }
                    }
                }
                eventType = parser.next()
            }
        } catch (_: Exception) {
            // fallback: best effort only
        }

        return ManifestFacts(
            dangerousPermissions = dangerous.distinct(),
            exportedCount = exportedCount,
            debuggable = debuggable,
            allowBackup = allowBackup,
            cleartextTraffic = cleartextTraffic,
            backupAgent = backupAgent,
            networkSecurityConfig = networkSecurityConfig,
            exportedComponents = exportedComponents.distinct()
        )
    }

    private fun scanZipForSecretMatches(apkPath: String): List<String> {
        val results = mutableSetOf<String>()
        val zipFile = ZipFile(apkPath)
        val entries = zipFile.entries()

        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.isDirectory) continue
            val fileName = entry.name.lowercase()
            if (!fileName.endsWith(".xml") && !fileName.endsWith(".txt") && !fileName.endsWith(".properties") && !fileName.endsWith(".json") && !fileName.endsWith(".smali") && !fileName.endsWith(".java") && !fileName.endsWith(".kt")) {
                continue
            }

            zipFile.getInputStream(entry).use { input ->
                val text = String(input.readBytes(), Charsets.UTF_8)
                for (pattern in secretPatterns) {
                    val match = pattern.find(text)
                    if (match != null) {
                        results.add("Potential secret match: ${match.value.take(160)}")
                    }
                }
            }
        }

        return results.toList().take(5)
    }

    private fun scanZipForWebviewMatches(apkPath: String): List<String> {
        val results = mutableSetOf<String>()
        val zipFile = ZipFile(apkPath)
        val entries = zipFile.entries()

        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.isDirectory) continue
            val fileName = entry.name.lowercase()
            if (!fileName.endsWith(".xml") && !fileName.endsWith(".smali") && !fileName.endsWith(".java") && !fileName.endsWith(".kt") && !fileName.endsWith(".txt")) {
                continue
            }

            zipFile.getInputStream(entry).use { input ->
                val text = String(input.readBytes(), Charsets.UTF_8)
                for (pattern in webviewRiskPatterns) {
                    if (text.contains(pattern)) {
                        results.add("WebView risky pattern: $pattern")
                    }
                }
            }
        }

        return results.toList().take(5)
    }
}
