#include <jni.h>
#include <string>
#include <vector>
#include <dlfcn.h>
#include "cryptoki.h"
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <iostream>
#include <stdexcept>
#define LOG_TAG "MyLib"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Forward declarations for pointer cleanup
void cleanUp();

// Function pointer typedefs remain unchanged.
typedef int(*Connect_usb)(int, int, int);

typedef CK_RV (*Initialize)(CK_VOID_PTR);

typedef CK_RV (*GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);

typedef CK_RV (*OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);

typedef CK_RV (*Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);

typedef CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);

typedef CK_RV (*FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);

typedef CK_RV (*GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);

typedef CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);

typedef CK_RV (*SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

typedef CK_RV (*Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

typedef CK_RV (*VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

typedef CK_RV (*Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);

typedef CK_RV (*EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

typedef CK_RV (*Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

typedef CK_RV (*DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

typedef CK_RV (*Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

typedef CK_RV (*Logout)(CK_SESSION_HANDLE);

typedef CK_RV (*CloseSession)(CK_SESSION_HANDLE);

typedef CK_RV (*Finalize)(CK_VOID_PTR);

// Global variables (consider encapsulating these in a class in a real application)
bool isInitialized = false;
CK_SESSION_HANDLE hhSession = 0;
CK_OBJECT_HANDLE hPrivate = 0; // Handle for a private key.
CK_OBJECT_HANDLE hObject = 0;
CK_ULONG ulObjectCount = 0;
void *dlhandle = nullptr;
CK_BYTE *signature = new CK_BYTE[256];
CK_ULONG sigLen = 256;
CK_BYTE *encrypted = nullptr;
CK_BYTE *decrypted = nullptr;
CK_ULONG encLen = 0, decLen = 0;

// Global variables for plain text (be careful with globals in multi-threaded contexts)
const char *plain_data = nullptr;
const char *plain_data_encrypt = nullptr;

std::string certToHex(CK_BYTE_PTR data, CK_ULONG len) {
    std::stringstream ss;
    ss << std::hex;
    for (CK_ULONG i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return ss.str();
}
std::vector<CK_BYTE> hexStringToBytes(const std::string& hexString) {
    std::vector<CK_BYTE> bytes;

    // Ensure the hex string has an even length
    if (hexString.length() % 2 != 0) {
        LOGE("Invalid hex string length %d", hexString.length());
        return bytes;
    }

    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        CK_BYTE byte = static_cast<CK_BYTE>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

void cleanUp() {
    if (dlhandle != nullptr) {
        dlclose(dlhandle);
        dlhandle = nullptr;
    }
    // Free any allocated memory if needed
    if (encrypted) {
        delete[] encrypted;
        encrypted = nullptr;
    }
    if (decrypted) {
        delete[] decrypted;
        decrypted = nullptr;
    }
    hhSession = 0;
    // Reset other globals if needed
}

// Helper to log an error with an optional error code and clean up before returning.
jstring logErrorAndCleanup(JNIEnv *env, const char *msg, CK_RV rv = CKR_OK) {
    if (rv != CKR_OK) {
        LOGE("%s (rv = 0x%lX)", msg, static_cast<unsigned long>(rv));
    } else {
        LOGE("%s", msg);
    }
    cleanUp();
    return env->NewStringUTF(msg);
}

// Helper function to load the library only once.
void *getLibraryHandle() {
    if (dlhandle == nullptr) {
        dlhandle = dlopen("libtrustokenso.so", RTLD_NOW);
        if (dlhandle == nullptr) {
            __android_log_print(ANDROID_LOG_ERROR, "MyLib", "dlopen failed: %s", dlerror());
        }
    }
    return dlhandle;
}

CK_RV initializePKCS11() {
    if (isInitialized) {
        return CKR_OK;
    }
    auto c_initialize = (Initialize) dlsym(dlhandle, "C_Initialize");
    if (!c_initialize) {
        return CKR_FUNCTION_REJECTED;
    }
    CK_RV rv = c_initialize(nullptr);
    if (rv != CKR_OK) {
        return rv;
    }
    isInitialized = true;
    return CKR_OK;
}

CK_RV openSession(const char *token_pin, JNIEnv *env, jstring jStr) {

    if (hhSession != 0) {
        return CKR_OK;
    }

    CK_RV rv = initializePKCS11();

    LOGE("%s", "initializing");
    if (rv != CKR_OK) {
        logErrorAndCleanup(env, "Failed to initialize pkcs#11", rv);
        env->ReleaseStringUTFChars(jStr, token_pin);
        std::cerr << "Failed to initialize PKCS#11" << rv << std::endl;
        return rv;
    }
    LOGE("%s","initialized");


    auto getSlotList = (GetSlotList) dlsym(dlhandle, "C_GetSlotList");

    CK_ULONG no_of_slots = 0;

    getSlotList(TRUE, nullptr, &no_of_slots);
    CK_SLOT_ID slotlist[no_of_slots];
    rv = getSlotList(CK_TRUE, slotlist, &no_of_slots);
//    try {
//        LOGE("getSlotList called");
//        LOGE("getSlotList returned");
//    }
//    catch (const std::exception& e) {
//        LOGE("Exception caught: %s", e.what());
//        logErrorAndCleanup(env, "Failed to get slot list", CKR_ARGUMENTS_BAD);
//        env->ReleaseStringUTFChars(jStr, token_pin);
//        std::cerr << "Failed to get slot list" << CKR_ARGUMENTS_BAD << std::endl;
//        return CKR_ARGUMENTS_BAD;
//    }
    LOGE("no of slots %lu", no_of_slots);
//    if (no_of_slots == 0) {
//        printf("No slots found with tokens inserted\n");
//        logErrorAndCleanup(env, "No slots found with tokens inserted", CKR_SLOT_ID_INVALID);
//        return CKR_SLOT_ID_INVALID;
//    }
//    LOGE("openSession called");
//    //logErrorAndCleanup(env, "tokens inserted", CKR_OK);
////    CK_SLOT_ID slotlist[no_of_slots];
    if (rv != CKR_OK) {
        logErrorAndCleanup(env, "Failed to get slot list", rv);
        env->ReleaseStringUTFChars(jStr, token_pin);
        std::cerr << "Failed to get slot list" << rv << std::endl;
        return rv;
    }
    LOGE("slotlist[0] %lu", slotlist[0]);
//    LOGE("slot count %lu", no_of_slots);


    auto c_openSession = (OpenSession) dlsym(dlhandle, "C_OpenSession");

    if ( !c_openSession) {
        logErrorAndCleanup(env, "Failed to find required symbols", CKR_FUNCTION_REJECTED);
        env->ReleaseStringUTFChars(jStr, token_pin);
        std::cerr << "Failed to find required symbols" << std::endl;
        return CKR_FUNCTION_REJECTED;
    }

    CK_SESSION_HANDLE session;
    rv = c_openSession(slotlist[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                       &session);
    if (rv != CKR_OK) {
        logErrorAndCleanup(env, "Failed to open session", rv);
        env->ReleaseStringUTFChars(jStr, token_pin);
        std::cerr << "Failed to open session" << rv << std::endl;
        return rv;
    }
    hhSession = session;
    std::cout << "opened session" << std::endl;
    return CKR_OK;
}


extern "C" {

JNIEXPORT jint JNICALL
Java_com_example_trustoken_1starter_TrusToken_libint(JNIEnv *env, jobject mainActivityInstance,
                                                     jint fileDescriptor) {
    if (getLibraryHandle() == nullptr) {
        return -1;
    }
    LOGE("fileDescriptor: %d", fileDescriptor);
    auto Connect_usb_test = (Connect_usb) dlsym(dlhandle, "Connect_usb");
    if (Connect_usb_test == nullptr) {
        LOGE("dlsym(Connect_usb) failed: %s", dlerror());
        cleanUp();
        return -1;
    }
    int* productId = nullptr;
    int* vendorId = nullptr;
    LOGE("Program is reaching till here fileDescriptor: %d", fileDescriptor);
    try {
        int ret = Connect_usb_test(10381, 64, fileDescriptor);

        LOGE("Program successfully connected usb :Connect_usb returned: %d", ret);
        return ret;
    } catch (...) {
        LOGE("Exception in Connect_usb");
        return -1;
    }
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_login(JNIEnv *env, jobject mainActivityInstance,
                                                    jstring jStr) {


    // Get token_pin from jstring and ensure it is released later.
    const char *token_pin = env->GetStringUTFChars(jStr, nullptr);
    if (!token_pin) {
        return env->NewStringUTF("Failed to get token_pin");
    }

    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }

    LOGE("%s", token_pin);
    CK_RV rv = openSession(token_pin, env, jStr);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to initialize", rv);
    }
    LOGE("%s","Login called");
    auto c_login = (Login) dlsym(dlhandle, "C_Login");
    if (!c_login) {
        return logErrorAndCleanup(env, "Failed to find C_Login symbol");
    }

    rv = c_login(hhSession, CKU_USER, (CK_BYTE_PTR) token_pin, strlen(token_pin));
//    env->ReleaseStringUTFChars(jStr, token_pin);  // Always release the string
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to login", rv);
    }

    return env->NewStringUTF("Login Success");
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_readCertificate(JNIEnv *env,
                                                              jobject mainActivityInstance) {
    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }

    auto c_findObjectsInit = (FindObjectsInit) dlsym(dlhandle, "C_FindObjectsInit");
    auto c_findObjects = (FindObjects) dlsym(dlhandle, "C_FindObjects");
    auto c_getAttributeValue = (GetAttributeValue) dlsym(dlhandle, "C_GetAttributeValue");
    auto c_findObjectsFinal = (FindObjectsFinal) dlsym(dlhandle, "C_FindObjectsFinal");

    if (!c_findObjectsInit || !c_findObjects || !c_findObjectsFinal || !c_getAttributeValue) {
        return logErrorAndCleanup(env, "Failed to find symbols");
    }

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_ATTRIBUTE certTemplate[] = {
            {CKA_CLASS,            &certClass, sizeof(certClass)},
            {CKA_CERTIFICATE_TYPE, &certType,  sizeof(certType)}
    };

    CK_RV rv = c_findObjectsInit(hhSession, certTemplate, 2);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to initialize object search", rv);
    }

    CK_OBJECT_HANDLE certObj;
    CK_ULONG objCount = 0;
    rv = c_findObjects(hhSession, &certObj, 1, &objCount);
    if (rv != CKR_OK || objCount == 0) {
        c_findObjectsFinal(hhSession);
        return logErrorAndCleanup(env, "Failed to find certificate object", rv);
    }

    rv = c_findObjectsFinal(hhSession);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to finalize object search", rv);
    }

    CK_ATTRIBUTE certValueTemplate[] = {
            {CKA_VALUE, NULL_PTR, 0}
    };

    rv = c_getAttributeValue(hhSession, certObj, certValueTemplate, 1);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to get certificate value size", rv);
    }

    // Allocate memory for the certificate value.
    auto certValue = (CK_BYTE_PTR) malloc(certValueTemplate[0].ulValueLen);
    if (certValue == nullptr) {
        return logErrorAndCleanup(env, "Failed to allocate memory for certificate value");
    }

    certValueTemplate[0].pValue = certValue;
    rv = c_getAttributeValue(hhSession, certObj, certValueTemplate, 1);
    if (rv != CKR_OK) {
        free(certValue);
        return logErrorAndCleanup(env, "Failed to get certificate value", rv);
    }

    std::string hexCertValue = certToHex(certValue, certValueTemplate[0].ulValueLen);
    free(certValue);

    return env->NewStringUTF(hexCertValue.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_logout(JNIEnv *env, jobject thiz) {
    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }

    auto logout = (Logout) dlsym(dlhandle, "C_Logout");
    auto closeSession = (CloseSession) dlsym(dlhandle, "C_CloseSession");
    auto finalize = (Finalize) dlsym(dlhandle, "C_Finalize");

    if (!logout || !closeSession || !finalize) {
        return logErrorAndCleanup(env, "Failed to find symbols");
    }

    CK_RV rv = logout(hhSession);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to logout", rv);
    }

    rv = closeSession(hhSession);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to close session", rv);
    }
    hhSession = 0;

//    rv = finalize(NULL_PTR);
//    if (rv != CKR_OK) {
//        return logErrorAndCleanup(env, "Failed to finalize", rv);
//    }

//    cleanUp();
    return env->NewStringUTF("Logged out Successfully");
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_signData(JNIEnv *env, jobject mainActivityInstance) {

    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }

    // Retrieve plain text from TrusToken.
    jclass mainActivityCls = env->GetObjectClass(mainActivityInstance);
    jmethodID jmethodId_PlainText = env->GetMethodID(mainActivityCls, "getPlainText",
                                                     "()Ljava/lang/String;");
    if (jmethodId_PlainText == nullptr) {
        return env->NewStringUTF("Failed to retrieve plain text method");
    }

    auto jPlainText = (jstring) env->CallObjectMethod(mainActivityInstance, jmethodId_PlainText);
    if (jPlainText == nullptr) {
        return env->NewStringUTF("Plain text not provided");
    }
    plain_data = env->GetStringUTFChars(jPlainText, nullptr);
    if (plain_data == nullptr) {
        return env->NewStringUTF("Failed to get plain text");
    }

    // Obtain required function pointers.
    auto c_findObjectsInit = (FindObjectsInit) dlsym(dlhandle, "C_FindObjectsInit");
    auto c_findObjects = (FindObjects) dlsym(dlhandle, "C_FindObjects");
    auto c_getAttributeValue = (GetAttributeValue) dlsym(dlhandle, "C_GetAttributeValue");
    auto findObjectsFinal = (FindObjectsFinal) dlsym(dlhandle, "C_FindObjectsFinal");
    auto signInit = (SignInit) dlsym(dlhandle, "C_SignInit");
    Sign sign = (Sign) dlsym(dlhandle, "C_Sign");

    if (!c_findObjectsInit || !c_findObjects || !findObjectsFinal || !c_getAttributeValue ||
        !signInit || !sign) {
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to find required symbols");
    }

    // Search for a private key object.
    CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE templPriv[] = {{CKA_CLASS, &keyClassPriv, sizeof(keyClassPriv)}};
    CK_ULONG templPrivateSize = sizeof(templPriv) / sizeof(CK_ATTRIBUTE);

    CK_RV rv = c_findObjectsInit(hhSession, templPriv, templPrivateSize);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to initiate find objects", rv);
    }

    rv = c_findObjects(hhSession, &hObject, 1, &ulObjectCount);
    if (rv != CKR_OK || ulObjectCount == 0) {
        findObjectsFinal(hhSession);
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to find private key object", rv);
    }

    // Read an attribute (e.g. label) to confirm the object.
    CK_UTF8CHAR label[32];
    CK_ATTRIBUTE readtemplPrivate[] = {{CKA_LABEL, label, sizeof(label)}};
    rv = c_getAttributeValue(hhSession, hObject, readtemplPrivate, 1);
    if (rv == CKR_OK) {
        hPrivate = hObject;
    } else {
        findObjectsFinal(hhSession);
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to read private key object", rv);
    }
    rv = findObjectsFinal(hhSession);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to finalize find objects", rv);
    }

    // Initialize signing.
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
    rv = signInit(hhSession, &mech, hPrivate);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jPlainText, plain_data);
        return logErrorAndCleanup(env, "Failed to initialize signing", rv);
    }

    rv = sign(hhSession, (CK_BYTE *) plain_data, strlen(plain_data), signature, &sigLen);
    // Release the plain text regardless of sign result.
    env->ReleaseStringUTFChars(jPlainText, plain_data);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to sign the data", rv);
    }

    // Convert the signature to a hex string.
    std::string hexSignature;
    char hexBuffer[3];
    for (CK_ULONG i = 0; i < sigLen; ++i) {
        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", signature[i]);
        hexSignature.append(hexBuffer);
    }
    LOGE("signature length %lu", sigLen);

    return env->NewStringUTF(hexSignature.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_verify(JNIEnv *env, jobject thiz, jstring jsig, jstring data) {
    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }
    const char *sign = env->GetStringUTFChars(jsig, nullptr);
    if (sign == nullptr) {
        return env->NewStringUTF("Failed to get signature");
    }
    const char *plain_text = env->GetStringUTFChars(data, nullptr);
    if (plain_text == nullptr) {
        return env->NewStringUTF("Failed to get plain text");
    }
    std::vector<CK_BYTE> originalSignature = hexStringToBytes(sign);
    if (originalSignature.empty()) {
        return env->NewStringUTF("Invalid signature format");
    }
    CK_BYTE* signaturePtr = originalSignature.data();
    CK_ULONG signatureLen = originalSignature.size();
    LOGE("signature length %lu", signatureLen);


    auto verifyInit = (VerifyInit) dlsym(dlhandle, "C_VerifyInit");
    auto verify = (Verify) dlsym(dlhandle, "C_Verify");

//    if (signature == NULL_PTR) {
//        return env->NewStringUTF("Signature not found");
//    }

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
    CK_RV rv = verifyInit(hhSession, &mech, 5000);
    if (rv != CKR_OK) {
        return logErrorAndCleanup(env, "Failed to initialize verify", rv);
    }

    rv = verify(hhSession, (CK_BYTE_PTR) plain_text, strlen(plain_text), signaturePtr, sigLen);
    if (rv != CKR_OK) {
        return env->NewStringUTF("Verification failed");
    }

    return env->NewStringUTF("Verified");
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_encrypt(JNIEnv *env, jobject mainActivityInstance
) {

    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }
    // Retrieve plain text for encryption.
    jclass mainActivityCls = env->GetObjectClass(mainActivityInstance);
    jmethodID jmethodId_PlainText = env->GetMethodID(mainActivityCls, "getPlainText",
                                                     "()Ljava/lang/String;");
    if (jmethodId_PlainText == nullptr) {
        return env->NewStringUTF("Failed to retrieve plain text method");
    }

    auto jPlainText = (jstring) env->CallObjectMethod(mainActivityInstance, jmethodId_PlainText);
    if (jPlainText == nullptr) {
        return env->NewStringUTF("Plain text not provided");
    }
    plain_data_encrypt = env->GetStringUTFChars(jPlainText, nullptr);
    if (plain_data_encrypt == nullptr) {
        return env->NewStringUTF("Failed to get plain text for encryption");
    }

    // Get encryption functions.
    auto encryptInit = (EncryptInit) dlsym(dlhandle, "C_EncryptInit");
    auto encrypt = (Encrypt) dlsym(dlhandle, "C_Encrypt");
    if (!encryptInit || !encrypt) {
        env->ReleaseStringUTFChars(jPlainText, plain_data_encrypt);
        return logErrorAndCleanup(env, "Failed to find encryption symbols");
    }

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
    CK_RV rv = encryptInit(hhSession, &mech, 5000);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jPlainText, plain_data_encrypt);
        return logErrorAndCleanup(env, "Failed to initialize encryption", rv);
    }

    // First call to determine required buffer size.
    rv = encrypt(hhSession, (CK_BYTE_PTR) plain_data_encrypt, strlen(plain_data_encrypt), NULL,
                 &encLen);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jPlainText, plain_data_encrypt);
        return logErrorAndCleanup(env, "Failed to get encryption buffer size", rv);
    }

    encrypted = new CK_BYTE[encLen];
    rv = encrypt(hhSession, (CK_BYTE_PTR) plain_data_encrypt, strlen(plain_data_encrypt), encrypted,
                 &encLen);
    env->ReleaseStringUTFChars(jPlainText, plain_data_encrypt);
    if (rv != CKR_OK) {
        delete[] encrypted;
        encrypted = nullptr;
        return logErrorAndCleanup(env, "Failed to encrypt data", rv);
    }

    // Convert encrypted data to hex.
    std::string hexEncryptedData;
    char hexBuffer[3];
    for (CK_ULONG i = 0; i < encLen; ++i) {
        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", encrypted[i]);
        hexEncryptedData.append(hexBuffer);
    }

    return env->NewStringUTF(hexEncryptedData.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_TrusToken_decrypt(JNIEnv *env, jobject thiz, jstring jStr) {
    if (getLibraryHandle() == nullptr) {
        return env->NewStringUTF("Failed to load library");
    }
    const char *encrypted_data = env->GetStringUTFChars(jStr, nullptr);
    if (encrypted_data == nullptr) {
        return env->NewStringUTF("Failed to get encrypted data");
    }

    // Convert hex string to byte array
    size_t encrypted_data_len = strlen(encrypted_data) / 2;
    encrypted = new CK_BYTE[encrypted_data_len];
    for (size_t i = 0; i < encrypted_data_len; ++i) {
        sscanf(&encrypted_data[2 * i], "%2hhx", &encrypted[i]);
    }
    encLen = encrypted_data_len;

    auto decryptInit = (DecryptInit) dlsym(dlhandle, "C_DecryptInit");
    auto decrypt = (Decrypt) dlsym(dlhandle, "C_Decrypt");
    if (!decryptInit || !decrypt) {
        env->ReleaseStringUTFChars(jStr, encrypted_data);
        return logErrorAndCleanup(env, "Failed to find decryption symbols");
    }

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
    CK_RV rv = decryptInit(hhSession, &mech, hPrivate);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jStr, encrypted_data);
        return logErrorAndCleanup(env, "Failed to initialize decryption", rv);
    }

    // First call to get the size required.
    rv = decrypt(hhSession, encrypted, encLen, nullptr, &decLen);
    if (rv != CKR_OK) {
        env->ReleaseStringUTFChars(jStr, encrypted_data);
        return logErrorAndCleanup(env, "Failed to get decryption buffer size", rv);
    }

    decrypted = new CK_BYTE[decLen];
    rv = decrypt(hhSession, encrypted, encLen, decrypted, &decLen);
    env->ReleaseStringUTFChars(jStr, encrypted_data);
    if (rv != CKR_OK) {
        delete[] decrypted;
        decrypted = nullptr;
        return logErrorAndCleanup(env, "Failed to decrypt data", rv);
    }

    // Convert decrypted data to hex.
    std::string hexDecryptedData;
    char hexBuffer[3];
    for (CK_ULONG i = 0; i < decLen; ++i) {
        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", decrypted[i]);
        hexDecryptedData.append(hexBuffer);
    }

    return env->NewStringUTF(hexDecryptedData.c_str());
}

// Forward declarations of functions from pkcs11_test.cpp

extern int connect_usb(int file_descriptor);

// Initialization and general info functions
extern void testInitialize();
extern void testGetFunctionList();
extern void testGetInfo();
extern void testGetSlotList();
extern void testGetSlotInfo();
extern void testGetTokenInfo();
extern void testGetMechanismList();
extern void testGetMechanismInfo();

// Session management functions
extern void testOpenSession();
extern void testGetSessionInfo();
extern void testLogin();
extern void testLogout();
extern void testCloseSession();
extern void testCloseAllSessions();

// Token/PIN management functions
extern void testInitToken();
extern void testInitPIN();
extern void testSetPIN();

// Random number generation functions
extern void testSeedRandom();
extern void testGenerateRandom();

// Object management functions
extern void testCreateObject();
extern void testCopyObject();
extern void testDestroyObject();
extern void testGetObjectSize();
extern void testGetAttributeValue();
extern void testSetAttributeValue();
extern void testFindObjectsInit();
extern void testFindObjects();
extern void testFindObjectsFinal();

// Key management functions
extern void testGenerateKeyPair();
extern void testGenerateKey();
extern void testUnwrapKey();
extern void testDeriveKey();

// Digest/hash operations
extern void testDigest();
extern void testDigestInit();
extern void testDigestUpdate();
extern void testDigestFinal();
extern void testDigestKey();

// Sign/verify operations
extern void testSign();
extern void testSignInit();
extern void testSignUpdate();
extern void testSignFinal();
extern void testVerify();
extern void testVerifyInit();
extern void testSignRecoverInit();
extern void testSignRecover();

// Encrypt/decrypt operations
extern void testEncrypt();
extern void testEncryptInit();
extern void testDecrypt();
extern void testDecryptInit();

// Combined operations
extern void testSignEncryptUpdate();
extern void testDecryptVerifyUpdate();
extern void testDigestEncryptUpdate();
extern void testDecryptDigestUpdate();

// State management
extern void testGetOperationState();
extern void testSetOperationState();

// Event handling
extern void testWaitForSlotEvent();

// Cleanup
extern void testFinalize();
extern void resetState();
extern void init();

// Helper class to capture stdout to a string
// Helper class to capture stdout to a string
class StdoutCapture {
private:
    std::stringstream buffer;
    std::streambuf* oldCout;

public:
    StdoutCapture() {
        oldCout = std::cout.rdbuf(buffer.rdbuf());
        buffer.str("");  // Clear buffer on construction
        buffer.clear();  // Clear flags
    }

    ~StdoutCapture() {
        std::cout.rdbuf(oldCout);
    }

    std::string getString() {
        return buffer.str();
    }

    void clearBuffer() {
        buffer.str("");
        buffer.clear();
    }
};

int initCalled = 0;
// JNI function implementations for PKCS11FunctionsActivity
JNIEXPORT jstring JNICALL
Java_com_example_trustoken_1starter_PKCS11FunctionsActivity_testFunctions(JNIEnv *env, jobject thiz,
                                                                          jstring jFunctionName) {
    StdoutCapture capture;
    if(initCalled == 0){
        init();
        initCalled = 1;
    }
    const char* functionName = env->GetStringUTFChars(jFunctionName, nullptr);
    try {
        resetState(); // Make sure we start clean
        capture.clearBuffer();
//        int res = connect_usb(file_descriptor);
//        LOGE("connect_usb returned %d", res);

        if (strcmp(functionName, "C_Initialize") == 0) testInitialize();
        else if (strcmp(functionName, "C_GetFunctionList") == 0) testGetFunctionList();
        else if (strcmp(functionName, "C_GetInfo") == 0) testGetInfo();
        else if (strcmp(functionName, "C_GetSlotList") == 0) testGetSlotList();
        else if (strcmp(functionName, "C_GetSlotInfo") == 0) testGetSlotInfo();
        else if (strcmp(functionName, "C_GetTokenInfo") == 0) testGetTokenInfo();
        else if (strcmp(functionName, "C_GetMechanismList") == 0) testGetMechanismList();
        else if (strcmp(functionName, "C_GetMechanismInfo") == 0) testGetMechanismInfo();
        else if (strcmp(functionName, "C_OpenSession") == 0) testOpenSession();
        else if (strcmp(functionName, "C_GetSessionInfo") == 0) testGetSessionInfo();
        else if (strcmp(functionName, "C_Login") == 0) testLogin();
        else if (strcmp(functionName, "C_Logout") == 0) testLogout();
        else if (strcmp(functionName, "C_CloseSession") == 0) testCloseSession();
        else if (strcmp(functionName, "C_CloseAllSessions") == 0) testCloseAllSessions();
        else if (strcmp(functionName, "C_InitToken") == 0) testInitToken();
        else if (strcmp(functionName, "C_InitPIN") == 0) testInitPIN();
        else if (strcmp(functionName, "C_SetPIN") == 0) testSetPIN();
        else if (strcmp(functionName, "C_SeedRandom") == 0) testSeedRandom();
        else if (strcmp(functionName, "C_GenerateRandom") == 0) testGenerateRandom();
        else if (strcmp(functionName, "C_CreateObject") == 0) testCreateObject();
        else if (strcmp(functionName, "C_CopyObject") == 0) testCopyObject();
        else if (strcmp(functionName, "C_DestroyObject") == 0) testDestroyObject();
        else if (strcmp(functionName, "C_GetObjectSize") == 0) testGetObjectSize();
        else if (strcmp(functionName, "C_GetAttributeValue") == 0) testGetAttributeValue();
        else if (strcmp(functionName, "C_SetAttributeValue") == 0) testSetAttributeValue();
        else if (strcmp(functionName, "C_FindObjectsInit") == 0) testFindObjectsInit();
        else if (strcmp(functionName, "C_FindObjects") == 0) testFindObjects();
        else if (strcmp(functionName, "C_FindObjectsFinal") == 0) testFindObjectsFinal();
        else if (strcmp(functionName, "C_GenerateKeyPair") == 0) testGenerateKeyPair();
        else if (strcmp(functionName, "C_GenerateKey") == 0) testGenerateKey();
        else if (strcmp(functionName, "C_UnwrapKey") == 0) testUnwrapKey();
        else if (strcmp(functionName, "C_DeriveKey") == 0) testDeriveKey();
        else if (strcmp(functionName, "C_DigestInit") == 0) testDigestInit();
        else if (strcmp(functionName, "C_Digest") == 0) testDigest();
        else if (strcmp(functionName, "C_DigestUpdate") == 0) testDigestUpdate();
        else if (strcmp(functionName, "C_DigestFinal") == 0) testDigestFinal();
        else if (strcmp(functionName, "C_DigestKey") == 0) testDigestKey();
        else if (strcmp(functionName, "C_SignInit") == 0) testSignInit();
        else if (strcmp(functionName, "C_Sign") == 0) testSign();
        else if (strcmp(functionName, "C_SignUpdate") == 0) testSignUpdate();
        else if (strcmp(functionName, "C_SignFinal") == 0) testSignFinal();
        else if (strcmp(functionName, "C_VerifyInit") == 0) testVerifyInit();
        else if (strcmp(functionName, "C_Verify") == 0) testVerify();
        else if (strcmp(functionName, "C_SignRecoverInit") == 0) testSignRecoverInit();
        else if (strcmp(functionName, "C_SignRecover") == 0) testSignRecover();
        else if (strcmp(functionName, "C_EncryptInit") == 0) testEncryptInit();
        else if (strcmp(functionName, "C_Encrypt") == 0) testEncrypt();
        else if (strcmp(functionName, "C_DecryptInit") == 0) testDecryptInit();
        else if (strcmp(functionName, "C_Decrypt") == 0) testDecrypt();
        else if (strcmp(functionName, "C_GetOperationState") == 0) testGetOperationState();
        else if (strcmp(functionName, "C_SetOperationState") == 0) testSetOperationState();
        else if (strcmp(functionName, "C_SignEncryptUpdate") == 0) testSignEncryptUpdate();
        else if (strcmp(functionName, "C_DecryptVerifyUpdate") == 0) testDecryptVerifyUpdate();
        else if (strcmp(functionName, "C_DigestEncryptUpdate") == 0) testDigestEncryptUpdate();
        else if (strcmp(functionName, "C_DecryptDigestUpdate") == 0) testDecryptDigestUpdate();
        else if (strcmp(functionName, "C_WaitForSlotEvent") == 0) testWaitForSlotEvent();
        else if (strcmp(functionName, "C_Finalize") == 0) testFinalize();
        else capture.getString().append("Unknown function");
        env->ReleaseStringUTFChars(jFunctionName, functionName);
        return env->NewStringUTF(capture.getString().c_str());
    } catch (const std::exception& e) {
        std::string error = "Exception during testInitialize: ";
        error += e.what();
        LOGE("%s", error.c_str());
        return env->NewStringUTF(error.c_str());
    } catch (...) {
        LOGE("Unknown exception during testInitialize");
        return env->NewStringUTF("Unknown exception occurred during testInitialize");
    }
}


JNIEXPORT jint JNICALL
Java_com_example_trustoken_1starter_PKCS11FunctionsActivity_connectToken(JNIEnv *env, jobject thiz,
                                                              jint file_descriptor) {
    int res = connect_usb(file_descriptor);
    LOGE("connect_usb returned %d", res);
    return res;
}
} // extern "C"
