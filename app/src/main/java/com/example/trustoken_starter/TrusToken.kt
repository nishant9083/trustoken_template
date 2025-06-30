package com.example.trustoken_starter

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets

class TrusToken : AppCompatActivity() {
    private lateinit var btnDetectToken: Button
    private lateinit var btnLogin: Button
    private lateinit var btnSign: Button
    private lateinit var btnVerify: Button
    private lateinit var btnEncrypt: Button
    private lateinit var btnDecrypt: Button
    private lateinit var btnLogout: Button
    private lateinit var btnClear: Button
    private lateinit var btnPkcs11Functions: Button

    private lateinit var tvTokenName: TextView
    private lateinit var tvSignature: TextView
    private lateinit var tvEncryptedData: TextView

    private lateinit var edtPin: EditText
    private lateinit var edtPlainText: EditText
    private lateinit var edtPlainText2: EditText

    private var fileDescriptor: Int = 0
    private var isTokenConnected = false
    private var tokenPin: String = ""
    private var plainText: String = ""

    companion object {
        init {
            System.loadLibrary("native-lib")
        }

        private const val ACTION_USB_PERMISSION = "com.example.USB_PERMISSION"

        fun hexStringToByteArray(s: String): ByteArray {
            return s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        fun byteArrayToAsciiString(bytes: ByteArray?): String {
            return bytes?.toString(StandardCharsets.US_ASCII) ?: ""
        }
    }

    private fun isHexString(str: String): Boolean {
        return str.matches(Regex("[0-9A-Fa-f]+"))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_trus_token)

        btnDetectToken = findViewById(R.id.detect_token)
        btnLogin = findViewById(R.id.login)
        btnSign = findViewById(R.id.sign)
        btnVerify = findViewById(R.id.verify)
        btnEncrypt = findViewById(R.id.encrypt)
        btnDecrypt = findViewById(R.id.decrypt)
        btnLogout = findViewById(R.id.logout)
        btnClear = findViewById(R.id.clear_token)
        btnPkcs11Functions = findViewById(R.id.pkcs11_functions)

        tvTokenName = findViewById(R.id.token_name)
        tvSignature = findViewById(R.id.signature)
        tvEncryptedData = findViewById(R.id.cipher_text)

        edtPin = findViewById(R.id.token_pin)
        edtPlainText = findViewById(R.id.plain_text)
        edtPlainText2 = findViewById(R.id.plain_text2)

        btnDetectToken.setOnClickListener {
            fileDescriptor = detectSmartCard()
            if (libint(fileDescriptor) == 0) {
                tvTokenName.text = "Trustoken"
                isTokenConnected = true
            }
            Toast.makeText(this, "File Descriptor: $fileDescriptor", Toast.LENGTH_SHORT).show()
        }

        btnLogin.setOnClickListener {
            if (isTokenConnected && edtPin.text.toString().isNotEmpty()) {
                tokenPin = edtPin.text.toString()
                println("Token Pin: $tokenPin")
                val res = login(tokenPin)
                println("Login Response: $res")
                Toast.makeText(this, res, Toast.LENGTH_LONG).show()
            }
        }

        btnSign.setOnClickListener {
            if (isTokenConnected && edtPlainText.text.toString().isNotEmpty()) {
                plainText = edtPlainText.text.toString()
                tvSignature.text = signData()
            } else {
                Toast.makeText(this, "Fill all the required fields", Toast.LENGTH_SHORT).show()
            }
        }

        btnVerify.setOnClickListener {
            if(tvSignature.text.toString().isNotEmpty() && isHexString(tvSignature.text.toString()))
                tvSignature.text = verify(tvSignature.text.toString(), edtPlainText.text.toString())
        }

        btnEncrypt.setOnClickListener {
            if (isTokenConnected && edtPlainText2.text.toString().isNotEmpty()) {
                plainText = edtPlainText2.text.toString()
                tvEncryptedData.text = encrypt()
            }
        }

        btnDecrypt.setOnClickListener {
            if (isTokenConnected && tvEncryptedData.text.toString().isNotEmpty() && isHexString(tvEncryptedData.text.toString()))
            tvEncryptedData.text = byteArrayToAsciiString(hexStringToByteArray(decrypt(tvEncryptedData.text.toString())))
        }

        btnLogout.setOnClickListener {
            val res = logout()
            Toast.makeText(this,res , Toast.LENGTH_LONG).show()
        }

        btnClear.setOnClickListener {
            edtPin.text.clear()
            edtPlainText.text.clear()
            edtPlainText2.text.clear()
            tvSignature.text = ""
            tvEncryptedData.text = ""
        }

        btnPkcs11Functions.setOnClickListener {
            val intent = Intent(this, PKCS11FunctionsActivity::class.java)
            startActivity(intent)
        }
    }

    private fun detectSmartCard(): Int {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager?
        usbManager?.deviceList?.values?.forEach { device ->
            if (isSmartCardReader(device)) {
                val flag = if (Build.VERSION.SDK_INT >= 33) PendingIntent.FLAG_IMMUTABLE else 0
                val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), flag)
                usbManager.requestPermission(device, permissionIntent)
                if (usbManager.hasPermission(device)) {
                    return getFileDescriptor(usbManager, device)
                }
            }
        }
        return -1
    }

    private fun isSmartCardReader(device: UsbDevice): Boolean {
        return if (device.vendorId == 10381 && device.productId == 64) {
            tvTokenName.text = "Trustoken"
            true
        } else false
    }

    private fun getFileDescriptor(manager: UsbManager, device: UsbDevice): Int {
        return manager.openDevice(device)?.fileDescriptor ?: -1
    }

    fun getPlainText(): String {
        return plainText
    }

    external fun libint(int: Int): Int
    external fun login(tokenPin: String): String
    external fun signData(): String
    external fun verify(string: String, plainText: String): String
    external fun encrypt(): String
    external fun decrypt(string: String): String
    external fun logout(): String
}
