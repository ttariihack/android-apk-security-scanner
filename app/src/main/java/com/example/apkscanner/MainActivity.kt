package com.example.apkscanner

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.example.apkscanner.databinding.ActivityMainBinding
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var apkUri: Uri? = null

    private val openDocumentLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            apkUri = uri
            binding.tvSelectedApk.text = "APK dipilih: ${uri.path}"
            try {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: SecurityException) {
                // Some devices do not allow persistable URI permission here.
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnPickApk.setOnClickListener {
            openDocumentLauncher.launch(arrayOf("application/vnd.android.package-archive"))
        }

        binding.btnScan.setOnClickListener {
            val uri = apkUri
            if (uri == null) {
                binding.tvResult.text = "Pilih APK terlebih dahulu."
                return@setOnClickListener
            }

            val report = scanApkFromUri(uri)
            binding.tvResult.text = report
        }
    }

    private fun scanApkFromUri(uri: Uri): String {
        val tempFile = File(cacheDir, "selected.apk")
        val inputStream: InputStream? = contentResolver.openInputStream(uri)
        if (inputStream == null) {
            return "Gagal membuka APK."
        }

        FileOutputStream(tempFile).use { output ->
            inputStream.copyTo(output)
        }

        val manifestText = readManifestFromApk(tempFile.absolutePath)
        val dangerousPermissions = ScannerUtil.findDangerousPermissions(manifestText)
        val exportedComponents = ScannerUtil.findExportedComponents(manifestText)
        val cleartextTraffic = ScannerUtil.findCleartextTraffic(manifestText)
        val secrets = ScannerUtil.findSecretsFromApk(tempFile.absolutePath)
        val riskyWebViews = ScannerUtil.findWebViewRisks(tempFile.absolutePath)

        val builder = StringBuilder()
        builder.append("APK: ${tempFile.absolutePath}\n")
        builder.append("== Permission berbahaya ==\n")
        if (dangerousPermissions.isEmpty()) {
            builder.append("- Tidak ada permission berbahaya terdeteksi\n")
        } else {
            dangerousPermissions.forEach { builder.append("- $it\n") }
        }

        builder.append("\n== Exported components ==\n")
        if (exportedComponents.isEmpty()) {
            builder.append("- Tidak ada component yang exported=true\n")
        } else {
            exportedComponents.forEach { builder.append("- $it\n") }
        }

        builder.append("\n== Cleartext traffic ==\n")
        if (cleartextTraffic.isEmpty()) {
            builder.append("- Tidak ada cleartext traffic di manifest\n")
        } else {
            cleartextTraffic.forEach { builder.append("- $it\n") }
        }

        builder.append("\n== Potensi secret/token ==\n")
        if (secrets.isEmpty()) {
            builder.append("- Tidak ada pattern secret/token yang terdeteksi\n")
        } else {
            secrets.forEach { builder.append("- $it\n") }
        }

        builder.append("\n== Potensi WebView risk ==\n")
        if (riskyWebViews.isEmpty()) {
            builder.append("- Tidak ada pattern WebView yang terlihat berisiko\n")
        } else {
            riskyWebViews.forEach { builder.append("- $it\n") }
        }

        return builder.toString()
    }

    private fun readManifestFromApk(apkPath: String): String {
        val apkFile = File(apkPath)
        if (!apkFile.exists()) return ""

        ZipInputStream(apkFile.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (entry.name == "AndroidManifest.xml") {
                    val bytes = zip.readBytes()
                    return String(bytes, Charsets.UTF_8)
                }
                entry = zip.nextEntry
            }
        }
        return ""
    }
}
