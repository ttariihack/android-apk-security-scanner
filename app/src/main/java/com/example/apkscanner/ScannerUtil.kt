package com.example.apkscanner

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.example.apkscanner.databinding.ActivityMainBinding
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var apkUri: Uri? = null
    private var lastReport: String = ""

    private val pickApk = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        apkUri = uri
        binding.tvSelectedApk.text = "APK dipilih: ${uri.path}"
        try {
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: SecurityException) {
            // ignore on devices that do not support this
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnPickApk.setOnClickListener {
            pickApk.launch(arrayOf("application/vnd.android.package-archive"))
        }

        binding.btnScan.setOnClickListener {
            val uri = apkUri ?: run {
                binding.tvResult.text = "Pilih APK terlebih dahulu."
                return@setOnClickListener
            }

            val report = scanApkFromUri(uri)
            lastReport = report
            binding.tvResult.text = report
            binding.tvRiskSummary.text = ScannerUtil.buildRiskSummary(report)
        }

        binding.btnCopy.setOnClickListener {
            if (lastReport.isBlank()) {
                Toast.makeText(this, "Belum ada hasil scan", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("APK Security Report", lastReport)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Hasil scan berhasil disalin", Toast.LENGTH_SHORT).show()
        }
    }

    private fun scanApkFromUri(uri: Uri): String {
        val inputStream: InputStream? = contentResolver.openInputStream(uri)
        if (inputStream == null) {
            return "Gagal membuka file APK."
        }

        val tempFile = File(cacheDir, "selected.apk")
        FileOutputStream(tempFile).use { out ->
            inputStream.copyTo(out)
        }

        val report = ScannerUtil.analyzeApk(tempFile.absolutePath)

        val builder = StringBuilder()
        builder.append("APK Path: ${report.apkPath}\n")
        builder.append("Risk Score: ${report.score}/100\n")
        builder.append("Severity: ${report.severity}\n\n")

        if (report.findings.isEmpty()) {
            builder.append("Tidak ditemukan indikasi yang terlihat berbahaya.\n")
        } else {
            report.findings.forEach { finding ->
                builder.append("[${finding.severity.uppercase()}] ${finding.type}\n")
                builder.append("- ${finding.message}\n\n")
            }
        }

        builder.append("\nRekomendasi:\n")
        builder.append(ScannerUtil.recommendations(report).joinToString(separator = "\n") { "- $it" })
        return builder.toString()
    }
}
