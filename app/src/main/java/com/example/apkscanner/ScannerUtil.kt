package com.example.apkscanner

import java.util.zip.ZipInputStream

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
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    fun findDangerousPermissions(manifestText: String): List<String> {
        return dangerousPermissions.filter { manifestText.contains(it) }
    }

    fun findExportedComponents(manifestText: String): List<String> {
        val exportedPattern = Regex("android:exported=\"true\"")
        return exportedPattern.findAll(manifestText)
            .map { "Component exported=true" }
            .toList()
    }

    fun findCleartextTraffic(manifestText: String): List<String> {
        return if (manifestText.contains("usesCleartextTraffic=\"true\"")) {
            listOf("usesCleartextTraffic=true")
        } else {
            emptyList()
        }
    }

    fun findSecretsFromApk(apkPath: String): List<String> {
        val results = mutableSetOf<String>()
        val file = java.io.File(apkPath)
        if (!file.exists()) return emptyList()

        ZipInputStream(file.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val text = String(zip.readBytes(), Charsets.UTF_8)
                    val patterns = listOf(
                        Regex("(?i)(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)[:=].{3,}"),
                        Regex("AIza[0-9A-Za-z\\-_]{35}"),
                        Regex("ghp_[A-Za-z0-9]{20,}"),
                        Regex("-----BEGIN [A-Z ]*PRIVATE KEY-----")
                    )
                    patterns.forEach { regex ->
                        regex.findAll(text).forEach { match ->
                            results.add("Potential secret match: ${match.value.take(120)}")
                        }
                    }
                }
                entry = zip.nextEntry
            }
        }

        return results.toList()
    }

    fun findWebViewRisks(apkPath: String): List<String> {
        val results = mutableSetOf<String>()
        val file = java.io.File(apkPath)
        if (!file.exists()) return emptyList()

        ZipInputStream(file.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val text = String(zip.readBytes(), Charsets.UTF_8)
                    val patterns = listOf(
                        "addJavascriptInterface",
                        "setJavaScriptEnabled(true)",
                        "setAllowFileAccess(true)",
                        "loadUrl(\"file://"
                    )
                    patterns.forEach { pattern ->
                        if (text.contains(pattern)) {
                            results.add("WebView risky pattern: $pattern")
                        }
                    }
                }
                entry = zip.nextEntry
            }
        }

        return results.toList()
    }
}
