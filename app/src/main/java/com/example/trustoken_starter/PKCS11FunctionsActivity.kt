package com.example.trustoken_starter

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.example.trustoken_starter.TrusToken.Companion.ACTION_USB_PERMISSION

class PKCS11FunctionsActivity : AppCompatActivity() {
    private lateinit var spinner: Spinner
    private lateinit var pinInput: EditText
    private lateinit var executeButton: Button
    private lateinit var outputText: TextView

    private val functionList = listOf(
        // Initialization and info functions
        "C_Initialize",
        "C_GetFunctionList",
        "C_GetInfo",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_GetMechanismList",
        "C_GetMechanismInfo",

        // Session management
        "C_OpenSession",
        "C_GetSessionInfo",
        "C_Login",
        "C_Logout",
        "C_CloseSession",
        "C_CloseAllSessions",

        // Token/PIN management
        "C_InitToken",
        "C_InitPIN",
        "C_SetPIN",

        // Random number generation
        "C_SeedRandom",
        "C_GenerateRandom",

        // Object management
        "C_CreateObject",
        "C_CopyObject",
        "C_DestroyObject",
        "C_GetObjectSize",
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_FindObjectsInit",
        "C_FindObjects",
        "C_FindObjectsFinal",

        // Key management
        "C_GenerateKeyPair",
        "C_GenerateKey",
        "C_UnwrapKey",
        "C_DeriveKey",

        // Digest operations
        "C_DigestInit",
        "C_Digest",
        "C_DigestUpdate",
        "C_DigestFinal",
        "C_DigestKey",

        // Sign/Verify operations
        "C_SignInit",
        "C_Sign",
        "C_SignUpdate",
        "C_SignFinal",
        "C_VerifyInit",
        "C_Verify",
        "C_SignRecoverInit",
        "C_SignRecover",

        // Encrypt/Decrypt operations
        "C_EncryptInit",
        "C_Encrypt",
        "C_DecryptInit",
        "C_Decrypt",

        // Combined operations
        "C_SignEncryptUpdate",
        "C_DecryptVerifyUpdate",
        "C_DigestEncryptUpdate",
        "C_DecryptDigestUpdate",

        // State management
        "C_GetOperationState",
        "C_SetOperationState",

        // Event handling
        "C_WaitForSlotEvent",

        // Cleanup
        "C_Finalize"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pkcs11_functions)

        // Initialize views
        spinner = findViewById(R.id.spinner_functions)
//        pinInput = findViewById(R.id.et_pin)
        executeButton = findViewById(R.id.btn_execute)
        outputText = findViewById(R.id.tv_output)

        // Set up spinner adapter
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            functionList
        )
        spinner.adapter = adapter

        // Set up execute button click listener
        executeButton.setOnClickListener {
            val selectedFunction = spinner.selectedItem.toString()
//            val pin = pinInput.text.toString()

            // Show execution in progress
            outputText.text = "Executing $selectedFunction...\n"

            // Execute the selected function
            executeFunction(selectedFunction, "123456")
        }
    }

    private fun executeFunction(functionName: String, pin: String) {
//        val fileDescriptor = detectSmartCard()
//        Toast.makeText(this, "File Descriptor: $fileDescriptor", Toast.LENGTH_SHORT).show()

        val result = testFunctions(functionName)
        println(result);

        // Display the result
        outputText.text = "$functionName result:\n$result"
    }

    fun detectSmartCard(): Int {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager?
        usbManager?.deviceList?.values?.forEach { device ->
            if (isSmartCardReader(device)) {
                val flag = if (Build.VERSION.SDK_INT >= 33) PendingIntent.FLAG_IMMUTABLE else 0
                val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(
                    ACTION_USB_PERMISSION
                ), flag)
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
            true
        } else false
    }

    private fun getFileDescriptor(manager: UsbManager, device: UsbDevice): Int {
        return manager.openDevice(device)?.fileDescriptor ?: -1
    }

    // Native function declarations
    external fun testFunctions(functionName: String): String
    external fun connectToken(fileDescriptor: Int): Int

    companion object {
        init {
            System.loadLibrary("native-lib")
        }
    }
}
