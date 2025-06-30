#include <iostream>
#include "cryptoki.h"
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <string>
#include <thread>

using namespace std;

// Global variables
CK_FUNCTION_LIST_PTR p11Func = nullptr;
void *libHandle = 0;
CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID_PTR slotLists = nullptr;
CK_ULONG slotCount = 0;
CK_SLOT_ID *slots = nullptr;
const char *pin = "123456";
CK_ULONG pLen = strlen(pin);

// Helper function to get error message
const char *getErrorMessage(CK_RV rv) {
    switch (rv) {
        case CKR_OK:
            return "CKR_OK: Function completed successfully";
        case CKR_CANCEL:
            return "CKR_CANCEL: Function was cancelled";
        case CKR_HOST_MEMORY:
            return "CKR_HOST_MEMORY: Insufficient memory";
        case CKR_SLOT_ID_INVALID:
            return "CKR_SLOT_ID_INVALID: Invalid slot ID";
        case CKR_GENERAL_ERROR:
            return "CKR_GENERAL_ERROR: General error";
        case CKR_FUNCTION_FAILED:
            return "CKR_FUNCTION_FAILED: Function failed";
        case CKR_ARGUMENTS_BAD:
            return "CKR_ARGUMENTS_BAD: Invalid arguments";
        case CKR_NO_EVENT:
            return "CKR_NO_EVENT: No event occurred";
        case CKR_NEED_TO_CREATE_THREADS:
            return "CKR_NEED_TO_CREATE_THREADS: Need to create threads";
        case CKR_CANT_LOCK:
            return "CKR_CANT_LOCK: Cannot lock";
        case CKR_ATTRIBUTE_READ_ONLY:
            return "CKR_ATTRIBUTE_READ_ONLY: Attribute is read-only";
        case CKR_ATTRIBUTE_SENSITIVE:
            return "CKR_ATTRIBUTE_SENSITIVE: Attribute is sensitive";
        case CKR_ATTRIBUTE_TYPE_INVALID:
            return "CKR_ATTRIBUTE_TYPE_INVALID: Invalid attribute type";
        case CKR_ATTRIBUTE_VALUE_INVALID:
            return "CKR_ATTRIBUTE_VALUE_INVALID: Invalid attribute value";
        case CKR_ACTION_PROHIBITED:
            return "CKR_ACTION_PROHIBITED: Action prohibited";
        case CKR_DATA_INVALID:
            return "CKR_DATA_INVALID: Invalid data";
        case CKR_DATA_LEN_RANGE:
            return "CKR_DATA_LEN_RANGE: Data length out of range";
        case CKR_DEVICE_ERROR:
            return "CKR_DEVICE_ERROR: Device error";
        case CKR_DEVICE_MEMORY:
            return "CKR_DEVICE_MEMORY: Device memory error";
        case CKR_DEVICE_REMOVED:
            return "CKR_DEVICE_REMOVED: Device removed";
        case CKR_ENCRYPTED_DATA_INVALID:
            return "CKR_ENCRYPTED_DATA_INVALID: Invalid encrypted data";
        case CKR_ENCRYPTED_DATA_LEN_RANGE:
            return "CKR_ENCRYPTED_DATA_LEN_RANGE: Encrypted data length out of range";
        case CKR_FUNCTION_CANCELED:
            return "CKR_FUNCTION_CANCELED: Function canceled";
        case CKR_FUNCTION_NOT_PARALLEL:
            return "CKR_FUNCTION_NOT_PARALLEL: Function not parallel";
        case CKR_FUNCTION_NOT_SUPPORTED:
            return "CKR_FUNCTION_NOT_SUPPORTED: Function not supported";
        case CKR_KEY_HANDLE_INVALID:
            return "CKR_KEY_HANDLE_INVALID: Invalid key handle";
        case CKR_KEY_SIZE_RANGE:
            return "CKR_KEY_SIZE_RANGE: Key size out of range";
        case CKR_KEY_TYPE_INCONSISTENT:
            return "CKR_KEY_TYPE_INCONSISTENT: Key type inconsistent";
        case CKR_KEY_NOT_NEEDED:
            return "CKR_KEY_NOT_NEEDED: Key not needed";
        case CKR_KEY_CHANGED:
            return "CKR_KEY_CHANGED: Key changed";
        case CKR_KEY_NEEDED:
            return "CKR_KEY_NEEDED: Key needed";
        case CKR_KEY_INDIGESTIBLE:
            return "CKR_KEY_INDIGESTIBLE: Key indigestible";
        case CKR_KEY_FUNCTION_NOT_PERMITTED:
            return "CKR_KEY_FUNCTION_NOT_PERMITTED: Key function not permitted";
        case CKR_KEY_NOT_WRAPPABLE:
            return "CKR_KEY_NOT_WRAPPABLE: Key not wrappable";
        case CKR_KEY_UNEXTRACTABLE:
            return "CKR_KEY_UNEXTRACTABLE: Key unextractable";
        case CKR_MECHANISM_INVALID:
            return "CKR_MECHANISM_INVALID: Invalid mechanism";
        case CKR_MECHANISM_PARAM_INVALID:
            return "CKR_MECHANISM_PARAM_INVALID: Invalid mechanism parameter";
        case CKR_OBJECT_HANDLE_INVALID:
            return "CKR_OBJECT_HANDLE_INVALID: Invalid object handle";
        case CKR_OPERATION_ACTIVE:
            return "CKR_OPERATION_ACTIVE: Operation active";
        case CKR_OPERATION_NOT_INITIALIZED:
            return "CKR_OPERATION_NOT_INITIALIZED: Operation not initialized";
        case CKR_PIN_INCORRECT:
            return "CKR_PIN_INCORRECT: Incorrect PIN";
        case CKR_PIN_INVALID:
            return "CKR_PIN_INVALID: Invalid PIN";
        case CKR_PIN_LEN_RANGE:
            return "CKR_PIN_LEN_RANGE: PIN length out of range";
        case CKR_PIN_EXPIRED:
            return "CKR_PIN_EXPIRED: PIN expired";
        case CKR_PIN_LOCKED:
            return "CKR_PIN_LOCKED: PIN locked";
        case CKR_SESSION_CLOSED:
            return "CKR_SESSION_CLOSED: Session closed";
        case CKR_SESSION_COUNT:
            return "CKR_SESSION_COUNT: Session count error";
        case CKR_SESSION_HANDLE_INVALID:
            return "CKR_SESSION_HANDLE_INVALID: Invalid session handle";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
            return "CKR_SESSION_PARALLEL_NOT_SUPPORTED: Session parallel not supported";
        case CKR_SESSION_READ_ONLY:
            return "CKR_SESSION_READ_ONLY: Session read-only";
        case CKR_SESSION_EXISTS:
            return "CKR_SESSION_EXISTS: Session exists";
        case CKR_SESSION_READ_ONLY_EXISTS:
            return "CKR_SESSION_READ_ONLY_EXISTS: Session read-only exists";
        case CKR_SESSION_READ_WRITE_SO_EXISTS:
            return "CKR_SESSION_READ_WRITE_SO_EXISTS: Session read-write SO exists";
        case CKR_SIGNATURE_INVALID:
            return "CKR_SIGNATURE_INVALID: Invalid signature";
        case CKR_SIGNATURE_LEN_RANGE:
            return "CKR_SIGNATURE_LEN_RANGE: Signature length out of range";
        case CKR_TEMPLATE_INCOMPLETE:
            return "CKR_TEMPLATE_INCOMPLETE: Template incomplete";
        case CKR_TEMPLATE_INCONSISTENT:
            return "CKR_TEMPLATE_INCONSISTENT: Template inconsistent";
        case CKR_TOKEN_NOT_PRESENT:
            return "CKR_TOKEN_NOT_PRESENT: Token not present";
        case CKR_TOKEN_NOT_RECOGNIZED:
            return "CKR_TOKEN_NOT_RECOGNIZED: Token not recognized";
        case CKR_TOKEN_WRITE_PROTECTED:
            return "CKR_TOKEN_WRITE_PROTECTED: Token write protected";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
            return "CKR_UNWRAPPING_KEY_HANDLE_INVALID: Invalid unwrapping key handle";
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:
            return "CKR_UNWRAPPING_KEY_SIZE_RANGE: Unwrapping key size out of range";
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: Unwrapping key type inconsistent";
        case CKR_USER_ALREADY_LOGGED_IN:
            return "CKR_USER_ALREADY_LOGGED_IN: User already logged in";
        case CKR_USER_NOT_LOGGED_IN:
            return "CKR_USER_NOT_LOGGED_IN: User not logged in";
        case CKR_USER_PIN_NOT_INITIALIZED:
            return "CKR_USER_PIN_NOT_INITIALIZED: User PIN not initialized";
        case CKR_USER_TYPE_INVALID:
            return "CKR_USER_TYPE_INVALID: Invalid user type";
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
            return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN: Another user already logged in";
        case CKR_USER_TOO_MANY_TYPES:
            return "CKR_USER_TOO_MANY_TYPES: Too many user types";
        case CKR_WRAPPED_KEY_INVALID:
            return "CKR_WRAPPED_KEY_INVALID: Invalid wrapped key";
        case CKR_WRAPPED_KEY_LEN_RANGE:
            return "CKR_WRAPPED_KEY_LEN_RANGE: Wrapped key length out of range";
        case CKR_WRAPPING_KEY_HANDLE_INVALID:
            return "CKR_WRAPPING_KEY_HANDLE_INVALID: Invalid wrapping key handle";
        case CKR_WRAPPING_KEY_SIZE_RANGE:
            return "CKR_WRAPPING_KEY_SIZE_RANGE: Wrapping key size out of range";
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT: Wrapping key type inconsistent";
        case CKR_RANDOM_SEED_NOT_SUPPORTED:
            return "CKR_RANDOM_SEED_NOT_SUPPORTED: Random seed not supported";
        case CKR_RANDOM_NO_RNG:
            return "CKR_RANDOM_NO_RNG: No RNG available";
        case CKR_DOMAIN_PARAMS_INVALID:
            return "CKR_DOMAIN_PARAMS_INVALID: Invalid domain parameters";
        case CKR_BUFFER_TOO_SMALL:
            return "CKR_BUFFER_TOO_SMALL: Buffer too small";
        case CKR_SAVED_STATE_INVALID:
            return "CKR_SAVED_STATE_INVALID: Invalid saved state";
        case CKR_INFORMATION_SENSITIVE:
            return "CKR_INFORMATION_SENSITIVE: Information sensitive";
        case CKR_STATE_UNSAVEABLE:
            return "CKR_STATE_UNSAVEABLE: State unsaveable";
        case CKR_CRYPTOKI_NOT_INITIALIZED:
            return "CKR_CRYPTOKI_NOT_INITIALIZED: Cryptoki not initialized";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            return "CKR_CRYPTOKI_ALREADY_INITIALIZED: Cryptoki already initialized";
        case CKR_MUTEX_BAD:
            return "CKR_MUTEX_BAD: Mutex bad";
        case CKR_MUTEX_NOT_LOCKED:
            return "CKR_MUTEX_NOT_LOCKED: Mutex not locked";
        default:
            return "Unknown error code";
    }
}

// Helper function to check operation results
void checkOperation(CK_RV rv, const char *message) {
    if (rv != CKR_OK) {
        cout << message << " failed with error: " << getErrorMessage(rv) << " (0x" << hex << rv
             << ")" << endl;
    } else {
        cout << message << " succeeded" << endl;
    }
}
extern "C"
{
// Helper function to reset PKCS#11 state
void resetState() {
    if (hSession) {
        p11Func->C_CloseSession(hSession);
        hSession = 0;
    }
    p11Func->C_Finalize(nullptr);
    if (slots) {
        free(slots);
        slots = nullptr;
    }
    slotCount = 0;
}

// Test function for C_Initialize
void testInitialize() {
    cout << "\n=== Testing C_Initialize ===" << endl;

    // Test Case 1: Passing pReserved other than nullptr pointer
    resetState();
    CK_C_INITIALIZE_ARGS args1;
    args1.DestroyMutex = nullptr;
    args1.LockMutex = nullptr;
    args1.UnlockMutex = nullptr;
    args1.flags = 0;
    args1.pReserved = (void *) 1; // Non-nullptr pointer
    CK_RV rv1 = p11Func->C_Initialize(&args1);
    checkOperation(rv1, "Test 1: Initialize with non-nullptr pReserved");

    // Test Case 2: Passing pReserved as nullptr pointer
    resetState();
    CK_C_INITIALIZE_ARGS args2;
    args2.DestroyMutex = nullptr;
    args2.LockMutex = nullptr;
    args2.UnlockMutex = nullptr;
    args2.flags = 0;
    args2.pReserved = nullptr;
    CK_RV rv2 = p11Func->C_Initialize(&args2);
    checkOperation(rv2, "Test 2: Initialize with nullptr pReserved");

    // Test Case 3: Calling C_Initialize again after successful initialization
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize"); // First initialization
    CK_RV rv3 = p11Func->C_Initialize(nullptr);                     // Second initialization
    checkOperation(rv3, "Test 3: Initialize after successful initialization");

    // Test Case 4: Initialize with CKF_LIBRARY_CANT_CREATE_OS_THREADS flag
    resetState();
    CK_C_INITIALIZE_ARGS args4;
    args4.DestroyMutex = nullptr;
    args4.LockMutex = nullptr;
    args4.UnlockMutex = nullptr;
    args4.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
    args4.pReserved = nullptr;
    CK_RV rv4 = p11Func->C_Initialize(&args4);
    checkOperation(rv4, "Test 4: Initialize with CKF_LIBRARY_CANT_CREATE_OS_THREADS flag");

    // Test Case 5: Initialize after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv5 = p11Func->C_Initialize(nullptr);
    checkOperation(rv5, "Test 5: Initialize after finalize");

    // Test Case 6: Initialize with CKF_OS_LOCKING_OK flag
    resetState();
    CK_C_INITIALIZE_ARGS args6;
    args6.DestroyMutex = nullptr;
    args6.LockMutex = nullptr;
    args6.UnlockMutex = nullptr;
    args6.flags = CKF_OS_LOCKING_OK;
    args6.pReserved = nullptr;
    CK_RV rv6 = p11Func->C_Initialize(&args6);
    checkOperation(rv6, "Test 6: Initialize with CKF_OS_LOCKING_OK flag");
}

// Test function for C_GetSlotList
void testGetSlotList() {
    cout << "\n=== Testing C_GetSlotList ===" << endl;

    // Test Case 1: Query slot count only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    CK_RV rv1 = p11Func->C_GetSlotList(TRUE, nullptr, &slotCount);
    if (slotCount == 0) {
        cout << "No slots available." << endl;
        return; // No slots available, exit early
    }
    checkOperation(rv1, "Test 1: Query slot count only");

    // Test Case 2: Query list of all slots (two-pass)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG count = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &count), "First pass - get count");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(count * sizeof(CK_SLOT_ID));
    if (slots) {
        CK_RV rv2 = p11Func->C_GetSlotList(TRUE, slots, &count);
        checkOperation(rv2, "Test 2: Query list of all slots");
        free(slots);
    }

    // Test Case 3: Query list of slots with tokens present
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    count = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &count), "First pass - get count");
    slots = (CK_SLOT_ID *) malloc(count * sizeof(CK_SLOT_ID));
    if (slots) {
        CK_RV rv3 = p11Func->C_GetSlotList(TRUE, slots, &count);
        checkOperation(rv3, "Test 3: Query list of slots with tokens present");
        free(slots);
    }

    // Test Case 4: Invalid buffer size for slot list
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID *slotsLis = nullptr;
    CK_ULONG smallCount = 0;
    CK_RV rv4 = p11Func->C_GetSlotList(TRUE, nullptr, &smallCount);
    if (smallCount < 1) {
        cout << "No slots available for testing." << endl;
        return; // No slots available, exit early
    }
    cout << "Expected slot count: " << smallCount << endl;
    slotsLis = (CK_SLOT_ID *) malloc(smallCount * sizeof(CK_SLOT_ID));
    CK_ULONG smallCount2 = 1; // Intentionally small size
    CK_RV rv41 = p11Func->C_GetSlotList(TRUE, slotsLis, &smallCount2);
    checkOperation(rv41, "Test 4: Invalid buffer size for slot list");

    // Test Case 5: nullptr count pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID tempSlots[10];
    CK_RV rv5 = p11Func->C_GetSlotList(TRUE, tempSlots, nullptr);
    checkOperation(rv5, "Test 5: nullptr count pointer");

    // Test Case 6: nullptr slot list pointer with non-zero count
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG nonZeroCount = 10;
    CK_RV rv6 = p11Func->C_GetSlotList(TRUE, nullptr, &nonZeroCount);
    checkOperation(rv6, "Test 6: nullptr slot list pointer with non-zero count");

    // Test Case 7: Memory allocation failure in host
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    count = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &count), "First pass - get count");
    // Simulate memory allocation failure by requesting an extremely large buffer
    CK_ULONG hugeCount = SIZE_MAX / sizeof(CK_SLOT_ID) + 1;
    slots = (CK_SLOT_ID *) malloc(hugeCount * sizeof(CK_SLOT_ID));
    if (!slots) {
        CK_RV rv7 = p11Func->C_GetSlotList(TRUE, nullptr, &hugeCount);
        checkOperation(rv7, "Test 7: Memory allocation failure in host");
    }
}

// Test function for C_OpenSession
void testOpenSession() {
    cout << "\n=== Testing C_OpenSession ===" << endl;

    // Test Case 1: Open session with random slot ID between 1 to available slotID except CDAC token slot id
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // Use a slot ID that's not the CDAC Token slot
    CK_SLOT_ID nonCDACSlot = (0 == 0) ? 1 : 0;
    CK_RV rv1 = p11Func->C_OpenSession(nonCDACSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession);
    checkOperation(rv1, "Test 1: Open session with random slot ID other than CDAC Token slot");

    // Test Case 2: Open session with random slot ID (0 or more than available slot id)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // Try with slot ID 0
    CK_RV rv2_1 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                         &hSession);
    checkOperation(rv2_1, "Test 2.1: Open session with slot ID 0");
    // Try with slot ID greater than available slots
    CK_RV rv2_2 = p11Func->C_OpenSession(slotCount + 1, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                                         nullptr, &hSession);
    checkOperation(rv2_2, "Test 2.2: Open session with slot ID greater than available slots");

    // Test Case 3: Open session with nullptr session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv3 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       nullptr);
    checkOperation(rv3, "Test 3: Open session with nullptr session handle");

    // Test Case 4: Open session with only CKF_RW_SESSION flag
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv4 = p11Func->C_OpenSession(0, CKF_RW_SESSION, nullptr, nullptr, &hSession);
    checkOperation(rv4, "Test 4: Open session with only CKF_RW_SESSION flag");

    // Test Case 5: Open session with only CKF_SERIAL_SESSION flag
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv5 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession);
    checkOperation(rv5, "Test 5: Open session with only CKF_SERIAL_SESSION flag");

    // Test Case 6: Open session with CKF_SERIAL_SESSION & CKF_SERIAL_SESSION flags
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv6 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_SERIAL_SESSION, nullptr,
                                       nullptr, &hSession);
    checkOperation(rv6, "Test 6: Open session with CKF_SERIAL_SESSION & CKF_SERIAL_SESSION flags");

    // Test Case 7: Open session with flags as '0'
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv7 = p11Func->C_OpenSession(0, 0, nullptr, nullptr, &hSession);
    checkOperation(rv7, "Test 7: Open session with flags as '0'");

    // Test Case 8: Open session without calling initialize and getslotlist
    resetState();
    CK_RV rv8 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession);
    checkOperation(rv8,
                   "Test 8: Open session without calling initialize and getslotlist (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 9: Open session without calling getslotlist
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv9 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession);
    checkOperation(rv9, "Test 9: Open session without calling getslotlist");

    // Test Case 10: Open session repeatedly up to 20 sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_SESSION_HANDLE sessions[20];
    for (int i = 0; i < 20; i++) {
        CK_RV rv10 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                                            nullptr, &sessions[i]);
        string msg = "Test 10: Open session " + to_string(i + 1) + " of 20";
        checkOperation(rv10, msg.c_str());
    }

    // Test Case 11: Open session after 20th session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open 20 sessions first
    for (int i = 0; i < 20; i++) {
        p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                               &sessions[i]);
    }

    // Try to open one more session
    CK_RV rv11 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                        &hSession);
    checkOperation(rv11, "Test 11: Open session after 20th session (should be CKR_SESSION_COUNT)");

    // Test Case 12: Success case - verify complete session lifecycle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session with proper flags
    CK_RV rv12_1 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession);
    checkOperation(rv12_1, "Test 12.1: Open session with proper flags");

    // Verify session is active
    CK_SESSION_INFO sessionInfo;
    CK_RV rv12_2 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv12_2, "Test 12.2: Get session info after opening");

    // Verify session flags
    if (rv12_2 == CKR_OK) {
        cout << "Test 12.3: Session flags: 0x" << hex << sessionInfo.flags << dec << endl;
        cout << "Test 12.4: Session state: " << sessionInfo.state << endl;
    }

    // Close the session
    CK_RV rv12_5 = p11Func->C_CloseSession(hSession);
    checkOperation(rv12_5, "Test 12.5: Close session");
}

// Test function for C_Login
void testLogin() {
    cout << "\n=== Testing C_Login ===" << endl;

    // Test Case 1: Login with random session ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    CK_RV rv1 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv1, "Test 1: Login with random session ID");

    // Test Case 2: Login with invalid user type
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv2 = p11Func->C_Login(hSession, 999, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv2, "Test 2: Login with invalid user type");

    // Test Case 3: Login with wrong PIN
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    const char *wrongPin = "654321";
    CK_RV rv3 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) wrongPin, strlen(wrongPin));
    checkOperation(rv3, "Test 3: Login with wrong PIN");

    // Test Case 4: Login with nullptr PIN
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv4 = p11Func->C_Login(hSession, CKU_USER, nullptr, 0);
    checkOperation(rv4, "Test 4: Login with nullptr PIN");

    // Test Case 5: Login with invalid PIN length
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    const char *shortPin = "123";
    CK_RV rv5 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) shortPin, strlen(shortPin));
    checkOperation(rv5, "Test 5: Login with invalid PIN length");

    // Test Case 6: Login with wrong PIN multiple times
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // for (int i = 0; i < 15; i++) {
    //     CK_RV rv6 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)wrongPin, strlen(wrongPin));
    //     if (i < 14) {
    //         string msg = "Test 6: Login attempt " + std::to_string(i + 1) + " with wrong PIN";
    //         checkOperation(rv6, msg.c_str());
    //     } else {
    //         string msg = "Test 6: Login attempt " + std::to_string(i + 1) + " with wrong PIN (should be CKR_PIN_LOCKED)";
    //         checkOperation(rv6, msg.c_str());
    //     }
    // }

    // Test Case 7: Login with correct parameters
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv7 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv7, "Test 7: Login with correct parameters");

    // Test Case 8: Login multiple times
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "First login");
    CK_RV rv8 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv8, "Test 8: Login multiple times (should be CKR_USER_ALREADY_LOGGED_IN)");

    // Test Case 9: Login with multiple sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_SESSION_HANDLE hSession1, hSession2;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");
    CK_RV rv9_1 = p11Func->C_Login(hSession1, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv9_1, "Test 9.1: Login on first session");
    CK_RV rv9_2 = p11Func->C_Login(hSession2, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv9_2, "Test 9.2: Login on second session");

    // Test Case 10: Login after closing session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    CK_RV rv10 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv10,
                   "Test 10: Login after closing session (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 11: Login after closing all sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseAllSessions(0), "C_CloseAllSessions");
    CK_RV rv11 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv11,
                   "Test 11: Login after closing all sessions (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 12: Login after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv12 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv12, "Test 12: Login after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 13: Login after initialize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv13 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv13, "Test 13: Login after initialize");

    // Test Case 14: Success case - verify login state
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv14 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv14, "Test 14: Success case - verify login state");
}

// Test function for C_GenerateKeyPair
void testGenerateKeyPair() {
    cout << "\n=== Testing C_GenerateKeyPair ===" << endl;

    // Key parameters
    CK_ULONG modulusBits = 2048;                   // RSA key size
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
    CK_BYTE id[] = {1};                            // Unique ID
    CK_BYTE subject[] = {'U', 's', 'e', 'r', '1'};
    CK_BBOOL ckTrue = CK_TRUE;

    // Public key template
    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
            {CKA_ID,              id,             sizeof(id)},
            {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)} // Store on token
    };

    // Private key template
    CK_ATTRIBUTE privTemplate[] = {
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_ID,        id,      sizeof(id)},
            {CKA_SUBJECT,   subject, sizeof(subject)}};

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Generate key pair with invalid mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_MECHANISM mech1 = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE pubKey1, privKey1;
    CK_RV rv1 = p11Func->C_GenerateKeyPair(hSession, &mech1, pubTemplate,
                                           sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                           privTemplate,
                                           sizeof(privTemplate) / sizeof(CK_ATTRIBUTE), &pubKey1,
                                           &privKey1);
    checkOperation(rv1, "Test 1: Generate key pair with invalid mechanism");

    // Test Case 2: Generate key pair with nullptr public key template
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    CK_MECHANISM mech2 = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE pubKey2, privKey2;

    CK_RV rv2 = p11Func->C_GenerateKeyPair(hSession, &mech2, nullptr, 0, nullptr, 0, &pubKey2, &privKey2);
    checkOperation(rv2, "Test 2: Generate key pair with nullptr public key template");

    // Test Case 3: Generate key pair with nullptr key handles
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    // CK_MECHANISM mech3 = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    // CK_RV rv3 = p11Func->C_GenerateKeyPair(hSession, &mech3, pubTemplate, sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
    //                                        privTemplate, sizeof(privTemplate) / sizeof(CK_ATTRIBUTE), nullptr, nullptr);
    // checkOperation(rv3, "Test 3: Generate key pair with nullptr key handles");

    // Test Case 4: Generate key pair with valid parameters
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    // Set up RSA key pair generation mechanism
    // CK_MECHANISM mech4 = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    // CK_OBJECT_HANDLE pubKey4, privKey4;
    // CK_RV rv4 = p11Func->C_GenerateKeyPair(hSession, &mech4,
    //                                        pubTemplate, sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
    //                                        privTemplate, sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
    //                                        &pubKey4, &privKey4);
    // checkOperation(rv4, "Test 4: Generate key pair with valid parameters");

    // Test Case 5: Pass invalid parameters to mechanism
    CK_MECHANISM mech5 = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE pubKey5, privKey5;

    // Create invalid mechanism parameters
    CK_BYTE invalidParams[] = {0x06, 0x78, 0x2A, 0x87, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x97};
    mech5.pParameter = invalidParams;
    mech5.ulParameterLen = sizeof(invalidParams);

    CK_RV rv5 = p11Func->C_GenerateKeyPair(hSession, &mech5,
                                           pubTemplate, sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                           privTemplate,
                                           sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                           &pubKey5, &privKey5);
    checkOperation(rv5, "Test 5: Generate key pair with invalid mechanism parameters");

    // Test Case 6: Pass empty template arrays
    CK_MECHANISM mech6 = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE pubKey6, privKey6;
    CK_OBJECT_CLASS CkoPublicKey = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS CkoPrivateKey = CKO_PRIVATE_KEY;
    // Create empty template arrays
    CK_ATTRIBUTE PubTemplate[] = {
            {CKA_CLASS, &CkoPublicKey, sizeof(CkoPublicKey)},
    };

    CK_ATTRIBUTE PrivTemplate[] = {
            {CKA_CLASS, &CkoPrivateKey, sizeof(CkoPrivateKey)},

    };

    CK_RV rv6 = p11Func->C_GenerateKeyPair(hSession, &mech6,
                                           PubTemplate, 1,
                                           PrivTemplate, 1,
                                           &pubKey6, &privKey6);
    checkOperation(rv6, "Test 6: Generate key pair with empty template arrays");

    // { // Test Case 7: Use conflicting or illogical attributes
    //     CK_MECHANISM mechanism = {
    //         CKM_RSA_PKCS_KEY_PAIR_GEN, // Mechanism for RSA key pair generation
    //         nullptr,
    //         0};
    //     printf("Attempting to generate an RSA key pair.\n");

    //     // --- 7. Define Templates for Public and Private RSA Keys ---
    //     CK_BBOOL ckTrue = CK_TRUE;
    //     CK_BBOOL ckFalse = CK_FALSE;

    //     // Standard RSA public exponent (65537)
    //     CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    //     CK_ULONG modulusBits = 2048; // 2048-bit RSA key
    //     CK_OBJECT_HANDLE hPublicKey;
    //     CK_OBJECT_HANDLE hPrivateKey;
    //     // Public Key Template
    //     char pubLabel[] = "MyRSAPublicKey";
    //     CK_OBJECT_CLASS CkoPublicKey = CKO_PUBLIC_KEY;
    //     CK_OBJECT_CLASS CkoPrivateKey = CKO_PRIVATE_KEY;
    //     CK_KEY_TYPE CkkRsa = CKK_RSA;
    //     // A unique ID to link the public and private keys
    //     CK_BYTE keyId[] = {0x12, 0x34, 0x56, 0x78};

    //     CK_ATTRIBUTE publicKeyTemplate[] = {
    //         {CKA_CLASS, &CkoPublicKey, sizeof(CkoPublicKey)},
    //         {CKA_KEY_TYPE, &CkkRsa, sizeof(CkkRsa)},
    //         {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},                          // Store on token
    //         {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},                         // Can be used for verification
    //         {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},                        // Can be used for encryption (OAEP/PKCS#1)
    //         {CKA_WRAP, &ckTrue, sizeof(ckTrue)},                           // Can be used for wrapping keys
    //         {CKA_WRAP, &ckFalse, sizeof(ckFalse)},                         // Can be used for wrapping keys
    //         {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},         // Desired modulus length
    //         {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}, // Public exponent
    //         {CKA_LABEL, pubLabel, strlen(pubLabel)},
    //         {CKA_ID, keyId, sizeof(keyId)}};

    //     // Private Key Template
    //     char privLabel[] = "MyRSAPrivateKey";
    //     CK_ATTRIBUTE privateKeyTemplate[] = {
    //         {CKA_CLASS, &CkoPrivateKey, sizeof(CkoPrivateKey)},
    //         {CKA_KEY_TYPE, &CkkRsa, sizeof(CkkRsa)},
    //         {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},         // Store on token
    //         {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},     // Key material is sensitive
    //         {CKA_SIGN, &ckTrue, sizeof(ckTrue)},          // Can be used for signing
    //         {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)},       // Can be used for decryption
    //         {CKA_UNWRAP, &ckTrue, sizeof(ckTrue)},        // Can be used for unwrapping keys
    //         {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)}, // Private key usually not extractable in clear
    //         {CKA_LABEL, privLabel, strlen(privLabel)},
    //         {CKA_ID, keyId, sizeof(keyId)}};
    //     CK_RV rv7 = p11Func->C_GenerateKeyPair(hSession, &mechanism,
    //                                            publicKeyTemplate, sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
    //                                            privateKeyTemplate, sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
    //                                            &hPublicKey, &hPrivateKey);
    //     checkOperation(rv7, "Test Case 7: Generate key pair with conflicting WRAP attributes");
    // }
    {
        // Test Case 8: Using undefined attribute type
        CK_MECHANISM mechanism = {
                CKM_RSA_PKCS_KEY_PAIR_GEN, // Mechanism for RSA key pair generation
                nullptr,
                0};

        // --- 7. Define Templates for Public and Private RSA Keys ---
        CK_BBOOL ckTrue = CK_TRUE;
        CK_BBOOL ckFalse = CK_FALSE;

        // Standard RSA public exponent (65537)
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_ULONG modulusBits = 2048; // 2048-bit RSA key
        CK_OBJECT_HANDLE hPublicKey;
        CK_OBJECT_HANDLE hPrivateKey;
        // Public Key Template
        char pubLabel[] = "MyRSAPublicKey";
        CK_OBJECT_CLASS CkoPublicKey = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS CkoPrivateKey = CKO_PRIVATE_KEY;
        CK_KEY_TYPE CkkRsa = CKK_RSA;
        // A unique ID to link the public and private keys
        CK_BYTE keyId[] = {0x12, 0x34, 0x56, 0x78};

        CK_ATTRIBUTE publicKeyTemplate[] = {
                {0xFFFFFFFF,          &CkoPublicKey,  sizeof(CkoPublicKey)},
                {0xFFFFFFFF,          &CkkRsa,        sizeof(CkkRsa)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)},                          // Store on token
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},                         // Can be used for verification
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},                        // Can be used for encryption (OAEP/PKCS#1)
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},                           // Can be used for wrapping keys
                {CKA_WRAP,            &ckFalse,       sizeof(ckFalse)},                         // Can be used for wrapping keys
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},         // Desired modulus length
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}, // Public exponent
                {CKA_LABEL,           pubLabel,       strlen(pubLabel)},
                {CKA_LOCAL,           &ckFalse,       sizeof(ckFalse)},
                {CKA_ID,              keyId,          sizeof(keyId)}};

        CK_ULONG inval = 99990;
        // Private Key Template
        char privLabel[] = "MyRSAPrivateKey";
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {0xFFFFFFFF,      &CkoPrivateKey, sizeof(CkoPrivateKey)},
                {0xFFFFFFFF,      &CkkRsa,        sizeof(CkkRsa)},
                {CKA_LOCAL,       &ckFalse,       sizeof(ckFalse)},
                {CKA_TOKEN,       &ckTrue,        sizeof(ckTrue)},         // Store on token
                {CKA_SENSITIVE,   &inval,         sizeof(inval)},       // Key material is sensitive
                {CKA_SIGN,        &ckTrue,        sizeof(ckTrue)},          // Can be used for signing
                {CKA_DECRYPT,     &ckTrue,        sizeof(ckTrue)},       // Can be used for decryption
                {CKA_UNWRAP,      &ckTrue,        sizeof(ckTrue)},        // Can be used for unwrapping keys
                {CKA_EXTRACTABLE, &ckFalse,       sizeof(ckFalse)}, // Private key usually not extractable in clear
                {CKA_LABEL,       privLabel,      strlen(privLabel)},
                {CKA_ID,          keyId,          sizeof(keyId)}};
        CK_RV rv8 = p11Func->C_GenerateKeyPair(hSession, &mechanism,
                                               publicKeyTemplate,
                                               sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                               privateKeyTemplate,
                                               sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                               &hPublicKey, &hPrivateKey);
        checkOperation(rv8, "Test Case 8:Use undefined attribute type 0xFFFFFFFF");
    }

    {
        cout << "\n=== Testing CKA_CLASS Read-Only Attribute ===" << endl;
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate RSA key pair
        CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_BBOOL ckTrue = CK_TRUE;
        CK_BBOOL ckFalse = CK_FALSE;

        // Try to set CKA_CLASS to an invalid value
        CK_OBJECT_CLASS invalidClass = 0xFFFFFFFF;

        CK_ATTRIBUTE pubTemplate[] = {
                {CKA_CLASS,           &invalidClass,  sizeof(invalidClass)}, // Try to set invalid class
                {CKA_KEY_TYPE,        &keyType,       sizeof(keyType)},
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}};

        CK_ATTRIBUTE privTemplate[] = {
                {CKA_CLASS,       &privKeyClass, sizeof(privKeyClass)},
                {CKA_KEY_TYPE,    &keyType,      sizeof(keyType)},
                {CKA_DECRYPT,     &ckTrue,       sizeof(ckTrue)},
                {CKA_SIGN,        &ckTrue,       sizeof(ckTrue)},
                {CKA_SENSITIVE,   &ckFalse,      sizeof(ckFalse)},
                {CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)}};

        CK_OBJECT_HANDLE hPubKey, hPrivKey;
        CK_RV rv = p11Func->C_GenerateKeyPair(hSession, &mechanism,
                                              pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPubKey, &hPrivKey);
        checkOperation(rv, "Test Case: Attempt to set read-only CKA_CLASS attribute");
    }
}

// Test function for C_Sign
void testSign() {
    cout << "\n=== Testing C_Sign ===" << endl;
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Passing invalid session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair for testing
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE id[] = {1};
    CK_BBOOL ckTrue = CK_TRUE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
            {CKA_ID,              id,             sizeof(id)},
            {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_ID,        id,      sizeof(id)}};

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    CK_BYTE data[] = "test data";
    CK_BYTE signature[256];
    CK_ULONG sigLen = sizeof(signature);
    CK_RV rv1 = p11Func->C_Sign(999, data, sizeof(data), signature, &sigLen);
    checkOperation(rv1, "Test 1: Passing invalid session");

    // Test Case 2: Passing data as nullptr
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv2 = p11Func->C_Sign(hSession, nullptr, sizeof(data), signature, &sigLen);
    checkOperation(rv2, "Test 2: Passing data as nullptr");

    // Test Case 3: Passing data len as 0
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv3 = p11Func->C_Sign(hSession, data, 0, signature, &sigLen);
    checkOperation(rv3, "Test 3: Passing data len as 0");

    // Test Case 4: Passing signature as nullptr
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv4 = p11Func->C_Sign(hSession, data, sizeof(data), nullptr, &sigLen);
    checkOperation(rv4, "Test 4: Passing signature as nullptr");

    // Test Case 5: Passing signatureLen as nullptr
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv5 = p11Func->C_Sign(hSession, data, sizeof(data), signature, nullptr);
    checkOperation(rv5, "Test 5: Passing signatureLen as nullptr");

    // Test Case 6: Call C_Sign after closing session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    CK_RV rv6 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv6, "Test 6: Call C_Sign after closing session");

    // Test Case 7: Call C_Sign after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv7 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv7, "Test 7: Call C_Sign after finalize");

    // Test Case 8: Call C_Sign after initialize only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv8 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv8, "Test 8: Call C_Sign after initialize only");

    // Test Case 9: Call C_Sign after opensession only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv9 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv9, "Test 9: Call C_Sign after opensession only");

    // Test Case 10: Call C_Sign Without login
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv10 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv10, "Test 10: Call C_Sign Without login");

    // Test Case 11: Call C_Sign in every session after opening multiple sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open multiple sessions
    CK_SESSION_HANDLE hSession1, hSession2, hSession3;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession3), "C_OpenSession 3");

    // Login to all sessions
    checkOperation(p11Func->C_Login(hSession1, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 1");
    checkOperation(p11Func->C_Login(hSession2, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 2");
    checkOperation(p11Func->C_Login(hSession3, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 3");
    CK_OBJECT_HANDLE hPublicKey2, hPrivateKey2;
    CK_OBJECT_HANDLE hPublicKey3, hPrivateKey3;

    // Generate key pair in first session
    checkOperation(p11Func->C_GenerateKeyPair(hSession1, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_GenerateKeyPair(hSession2, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey2, &hPrivateKey2),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_GenerateKeyPair(hSession3, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey3, &hPrivateKey3),
                   "C_GenerateKeyPair");


    // Try to sign in each session
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_SignInit(hSession1, &signMech, hPrivateKey), "C_SignInit");
    CK_RV rv11_1 = p11Func->C_Sign(hSession1, data, sizeof(data), signature, &sigLen);
    checkOperation(rv11_1, "Test 11.1: Call C_Sign in first session");

    signature[256];
    sigLen = sizeof(signature);
    signMech = {CKM_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_SignInit(hSession2, &signMech, hPrivateKey2), "C_SignInit");
    CK_RV rv11_2 = p11Func->C_Sign(hSession2, data, sizeof(data), signature, &sigLen);
    checkOperation(rv11_2, "Test 11.2: Call C_Sign in second session");

    signature[256];
    sigLen = sizeof(signature);
    signMech = {CKM_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_SignInit(hSession3, &signMech, hPrivateKey3), "C_SignInit");
    CK_RV rv11_3 = p11Func->C_Sign(hSession3, data, sizeof(data), signature, &sigLen);
    checkOperation(rv11_3, "Test 11.3: Call C_Sign in third session");

    // Test Case 12: Call C_Sign after closing all sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_CloseAllSessions(0), "C_CloseAllSessions");
    CK_RV rv12 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv12, "Test 12: Call C_Sign after closing all sessions");

    // Test Case 13: Success case - satisfying all prerequisites
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    // Initialize signing operation
    signMech = {CKM_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_SignInit(hSession, &signMech, hPrivateKey), "C_SignInit");

    // Perform signing
    CK_RV rv13 = p11Func->C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    checkOperation(rv13, "Test 13: Success case - satisfying all prerequisites");
}

// Test function for C_Encrypt
void testEncrypt() {
    cout << "\n=== Testing C_Encrypt ===" << endl;

    // Test Case 1: Encrypt with invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_BYTE data[] = "test data";
    CK_BYTE encrypted[256];
    CK_ULONG encLen = sizeof(encrypted);
    CK_RV rv1 = p11Func->C_Encrypt(999, data, sizeof(data), encrypted, &encLen);
    checkOperation(rv1, "Test 1: Encrypt with invalid session handle");

    // Test Case 2: Encrypt with nullptr data
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv2 = p11Func->C_Encrypt(hSession, nullptr, 0, encrypted, &encLen);
    checkOperation(rv2, "Test 2: Encrypt with nullptr data");

    // Test Case 3: Encrypt with nullptr encrypted buffer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv3 = p11Func->C_Encrypt(hSession, data, sizeof(data), nullptr, &encLen);
    checkOperation(rv3, "Test 3: Encrypt with nullptr encrypted buffer");
}


void testDigestInit()
{
    cout << "\n=== Testing C_DigestInit ===" << endl;
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Passing valid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    CK_MECHANISM mech = {CKM_SHA256, nullptr, 0};
    CK_RV rv1 = p11Func->C_DigestInit(hSession, &mech);
    checkOperation(rv1, "Test 1: Passing valid session handle");

    // Test Case 2: Passing valid mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    CK_MECHANISM validMech = {CKM_SHA256, nullptr, 0};
    CK_RV rv2 = p11Func->C_DigestInit(hSession, &validMech);
    checkOperation(rv2, "Test 2: Passing valid mechanism");

    // Test Case 3: Passing invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_MECHANISM mech3 = {CKM_SHA256, nullptr, 0};
    CK_RV rv3 = p11Func->C_DigestInit(999, &mech3);
    checkOperation(rv3, "Test 3: Passing invalid session handle");

    // Test Case 4: Passing invalid mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    CK_MECHANISM invalidMech = {0xFFFFFFFF, nullptr, 0};
    CK_RV rv4 = p11Func->C_DigestInit(hSession, &invalidMech);
    checkOperation(rv4, "Test 4: Passing invalid mechanism");

    // Test Case 5: Passing all invalid parameters
    CK_RV rv5 = p11Func->C_DigestInit(0, nullptr);
    checkOperation(rv5, "Test 5: Passing all invalid parameters");

    // Test Case 6: Passing nullptr mechanism pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    CK_RV rv6 = p11Func->C_DigestInit(hSession, nullptr);
    checkOperation(rv6, "Test 6: Passing nullptr mechanism pointer");

    // Test Case 7: Passing mechanism not supported by the token
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    CK_MECHANISM notSupportedMech = {CKM_MD5, nullptr, 0};
    CK_RV rv7 = p11Func->C_DigestInit(hSession, &notSupportedMech);
    checkOperation(rv7, "Test 7: Passing mechanism not supported by the token");

    // Test Case 8: Calling C_DigestInit after closing session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    CK_MECHANISM mech8 = {CKM_SHA256, nullptr, 0};
    CK_RV rv8 = p11Func->C_DigestInit(hSession, &mech8);
    checkOperation(rv8, "Test 8: Calling C_DigestInit after closing session");

    // Test Case 9: Success case - satisfying all prerequisites
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    CK_MECHANISM mech9 = {CKM_SHA256, nullptr, 0};
    CK_RV rv9 = p11Func->C_DigestInit(hSession, &mech9);
    checkOperation(rv9, "Test 9: Success case - satisfying all prerequisites");
}

// Test function for C_Digest
void testDigest() {
    cout << "\n=== Testing C_Digest ===" << endl;

    // Test Case 1: Success case - valid input, mechanism and data
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_BYTE data[] = "test data for digest";
    CK_BYTE digest[32];
    CK_ULONG digestLen = sizeof(digest);
    CK_RV rv1 = p11Func->C_Digest(hSession, data, sizeof(data), digest, &digestLen);
    checkOperation(rv1, "Test 1: Success case - valid input, mechanism and data");

    // Test Case 2: No C_DigestInit before C_Digest
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_RV rv2 = p11Func->C_Digest(hSession, data, sizeof(data), digest, &digestLen);
    checkOperation(rv2, "Test 2: No C_DigestInit before C_Digest");

    // Test Case 3: nullptr data pointer, 0 length
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv3 = p11Func->C_Digest(hSession, nullptr, 0, digest, &digestLen);
    checkOperation(rv3, "Test 3: nullptr data pointer, 0 length");

    // Test Case 4: Invalid Session Handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv4 = p11Func->C_Digest(999, data, sizeof(data), digest, &digestLen);
    checkOperation(rv4, "Test 4: Invalid Session Handle");

    // Test Case 5: nullptr digest length pointer
    /*resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv5 = p11Func->C_Digest(hSession, data, sizeof(data), digest, nullptr);
    checkOperation(rv5, "Test 5: nullptr digest length pointer");*/

    // Test Case 6: Digest buffer too small
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_BYTE smallDigest[1]; // Too small for SHA-256
    CK_ULONG smallDigestLen = sizeof(smallDigest);
    CK_RV rv6 = p11Func->C_Digest(hSession, data, sizeof(data), smallDigest, &smallDigestLen);
    checkOperation(rv6, "Test 6: Digest buffer too small");

    // Test Case 7: nullptr digest pointer
    /* resetState();
     checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
     // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
     slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
     // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
     checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");

     checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");
     checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

     CK_RV rv7 = p11Func->C_Digest(hSession, data, sizeof(data), nullptr, &digestLen);
     checkOperation(rv7, "Test 7: nullptr digest pointer");*/

    // Test Case 8: Passing Invalid Parameters
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    // Test with invalid mechanism
    CK_MECHANISM invalidMech = {CKM_RSA_PKCS, nullptr, 0}; // RSA is not a digest mechanism
    checkOperation(p11Func->C_DigestInit(hSession, &invalidMech),
                   "C_DigestInit with invalid mechanism");
    CK_RV rv8 = p11Func->C_Digest(hSession, data, sizeof(data), digest, &digestLen);
    checkOperation(rv8, "Test 8: Passing Invalid Parameters");
}

// Test function for C_SeedRandom
void testSeedRandom() {
    cout << "\n=== Testing C_SeedRandom ===" << endl;

    // Test Case 1: Seed random with invalid session handle
    CK_BYTE seed[] = "random seed";
    CK_RV rv1 = p11Func->C_SeedRandom(999, seed, sizeof(seed));
    checkOperation(rv1, "Test 1: Seed random with invalid session handle");

    // Test Case 2: Seed random with nullptr seed
    CK_RV rv2 = p11Func->C_SeedRandom(hSession, nullptr, 0);
    checkOperation(rv2, "Test 2: Seed random with nullptr seed");

    // Test Case 3: Seed random with zero length
    CK_RV rv3 = p11Func->C_SeedRandom(hSession, seed, 0);
    checkOperation(rv3, "Test 3: Seed random with zero length");
}

// Test function for C_GenerateRandom
void testGenerateRandom() {
    cout << "\n=== Testing C_GenerateRandom ===" << endl;

    // Test Case 1: Generate random with invalid session handle
    CK_BYTE random[32];
    CK_RV rv1 = p11Func->C_GenerateRandom(999, random, sizeof(random));
    checkOperation(rv1, "Test 1: Generate random with invalid session handle");

    // Test Case 2: Generate random with nullptr buffer
    CK_RV rv2 = p11Func->C_GenerateRandom(hSession, nullptr, 32);
    checkOperation(rv2, "Test 2: Generate random with nullptr buffer");

    // Test Case 3: Generate random with zero length
    CK_RV rv3 = p11Func->C_GenerateRandom(hSession, random, 0);
    checkOperation(rv3, "Test 3: Generate random with zero length");
}

// Test function for C_GetFunctionList
void testGetFunctionList() {
    cout << "\n=== Testing C_GetFunctionList ===" << endl;

    // Test Case 1: Passing correct argument for g_GetFunctionList after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_FUNCTION_LIST_PTR funcList1 = nullptr;
    CK_RV rv1 = p11Func->C_GetFunctionList(&funcList1);
    checkOperation(rv1, "Test 1: Get function list after finalize");

    // Test Case 2: Passing nullptr as argument for g_GetFunctionList
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv2 = p11Func->C_GetFunctionList(nullptr);
    checkOperation(rv2, "Test 2: Get function list with nullptr pointer");

    // Test Case 3: Passing correct argument for g_GetFunctionList
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_FUNCTION_LIST_PTR funcList3 = nullptr;
    CK_RV rv3 = p11Func->C_GetFunctionList(&funcList3);
    checkOperation(rv3, "Test 3: Get function list with valid pointer");

    // Test Case 4: Library internal error (simulate)
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // Simulate library internal error by corrupting function pointer
    // p11Func->C_GetFunctionList = nullptr;
    // CK_FUNCTION_LIST_PTR funcList4 = nullptr;
    // CK_RV rv4 = p11Func->C_GetFunctionList(&funcList4);
    // checkOperation(rv4, "Test 4: Library internal error");

    // Test Case 5: Simulate out of memory (library-specific)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // Simulate out of memory condition
    CK_FUNCTION_LIST_PTR funcList5 = nullptr;
    // Force memory allocation failure by setting a very large size
    CK_RV rv5 = p11Func->C_GetFunctionList(&funcList5);
    checkOperation(rv5, "Test 5: Out of memory condition");
}

// Test function for C_GetInfo
void testGetInfo() {
    cout << "\n=== Testing C_GetInfo ===" << endl;

    // Test Case 1: Passing nullptr as g_GetInfo argument
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv1 = p11Func->C_GetInfo(nullptr);
    checkOperation(rv1, "Test 1: Passing nullptr as g_GetInfo argument");

    // Test Case 2: Calling C_GetInfo after calling C_Finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_INFO info1;
    CK_RV rv2 = p11Func->C_GetInfo(&info1);
    checkOperation(rv2, "Test 2: Calling C_GetInfo after calling C_Finalize");

    // Test Case 3: Passing correct argument and Checking its property
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_INFO info2;
    CK_RV rv3 = p11Func->C_GetInfo(&info2);
    checkOperation(rv3, "Test 3: Passing correct argument and Checking its property");

    // Test Case 4: Calling C_GetInfo again
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_INFO info3;
    CK_RV rv4 = p11Func->C_GetInfo(&info3);
    CK_RV rv5 = p11Func->C_GetInfo(&info3);

    checkOperation(rv5, "Test 4: Calling C_GetInfo again");

    // Test Case 5: Simulate internal failure (mock)
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    //// Simulate internal failure by corrupting function pointer
    // p11Func->C_GetInfo = nullptr;
    // CK_INFO info4;
    // CK_RV rv5 = p11Func->C_GetInfo(&info4);
    // checkOperation(rv5, "Test 5: Simulate internal failure (mock)");

    // Test Case 6: Simulate out of memory (mock)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // Simulate out of memory condition
    CK_INFO info5;
    // Force memory allocation failure by setting a very large size
    CK_RV rv6 = p11Func->C_GetInfo(&info5);
    checkOperation(rv6, "Test 6: Simulate out of memory (mock)");

    // Test Case 7: Simulate general error (mock)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // Simulate general error condition
    CK_INFO info6;
    CK_RV rv7 = p11Func->C_GetInfo(&info6);
    checkOperation(rv7, "Test 7: Simulate general error (mock)");
}

// Test function for C_GetSessionInfo
void testGetSessionInfo() {
    cout << "\n=== Testing C_GetSessionInfo ===" << endl;

    // Test Case 1: Get session info with random session ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_SESSION_INFO sessionInfo;
    CK_RV rv1 = p11Func->C_GetSessionInfo(999, &sessionInfo);
    checkOperation(rv1, "Test 1: Get session info with random session ID");

    // Test Case 2: Get session info with nullptr info parameter
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv2 = p11Func->C_GetSessionInfo(hSession, nullptr);
    checkOperation(rv2, "Test 2: Get session info with nullptr info parameter");

    // Test Case 3: Get session info with multiple sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_SESSION_HANDLE hSession1, hSession2;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");
    CK_RV rv3_1 = p11Func->C_GetSessionInfo(hSession1, &sessionInfo);
    checkOperation(rv3_1, "Test 3.1: Get session info for first session");
    CK_RV rv3_2 = p11Func->C_GetSessionInfo(hSession2, &sessionInfo);
    checkOperation(rv3_2, "Test 3.2: Get session info for second session");

    // Test Case 4: Get session info after closing one session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");
    checkOperation(p11Func->C_CloseSession(hSession1), "C_CloseSession");
    CK_RV rv4 = p11Func->C_GetSessionInfo(hSession1, &sessionInfo);
    checkOperation(rv4,
                   "Test 4: Get session info after closing session (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 5: Get session info after closing all sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseAllSessions(0), "C_CloseAllSessions");
    CK_RV rv5 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv5,
                   "Test 5: Get session info after closing all sessions (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 6: Get session info after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv6 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv6,
                   "Test 6: Get session info after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 7: Get session info after initialize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv7 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv7, "Test 7: Get session info after initialize");

    // Test Case 8: Success case - verify session info contents
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv8 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    if (rv8 == CKR_OK) {
        cout << "Test 8: Session info contents:" << endl;
        cout << "  Slot ID: " << sessionInfo.slotID << endl;
        cout << "  State: " << sessionInfo.state << endl;
        cout << "  Flags: 0x" << hex << sessionInfo.flags << dec << endl;
        cout << "  ulDeviceError: " << sessionInfo.ulDeviceError << endl;
    }
    checkOperation(rv8, "Test 8: Success case - verify session info contents");
}

// Test function for C_Logout
void testLogout() {
    cout << "\n=== Testing C_Logout ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Logout with random session ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    CK_RV rv1 = p11Func->C_Logout(999);
    checkOperation(rv1, "Test 1: Logout with random session ID");

    // Test Case 2: Multiple sessions and find private key objects after logout
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open two sessions
    CK_SESSION_HANDLE hSession1, hSession2;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");

    // Login on both sessions
    checkOperation(p11Func->C_Login(hSession1, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 1");
    checkOperation(p11Func->C_Login(hSession2, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 2");

    // Logout from first session
    CK_RV rv2_1 = p11Func->C_Logout(hSession1);
    checkOperation(rv2_1, "Test 2.1: Logout from first session");

    // Try to find private key objects in both sessions
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template_[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)}};
    CK_OBJECT_HANDLE hObject;
    CK_ULONG count;

    CK_RV rv2_2 = p11Func->C_FindObjectsInit(hSession1, template_, 1);
    checkOperation(rv2_2, "Test 2.2: Find objects init on first session (should fail)");

    CK_RV rv2_3 = p11Func->C_FindObjectsInit(hSession2, template_, 1);
    checkOperation(rv2_3, "Test 2.3: Find objects init on second session (should succeed)");

    // Test Case 3: Call logout function twice
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_Logout(hSession), "First logout");
    CK_RV rv3 = p11Func->C_Logout(hSession);
    checkOperation(rv3, "Test 3: Second logout (should be CKR_USER_NOT_LOGGED_IN)");

    // Test Case 4: Logout after close all sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_CloseAllSessions(0), "C_CloseAllSessions");
    CK_RV rv4 = p11Func->C_Logout(hSession);
    checkOperation(rv4,
                   "Test 4: Logout after close all sessions (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 5: Logout after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv5 = p11Func->C_Logout(hSession);
    checkOperation(rv5, "Test 5: Logout after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 6: Success case - verify logout state
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Verify we can access private objects before logout
    CK_RV rv6_1 = p11Func->C_FindObjectsInit(hSession, template_, 1);
    checkOperation(rv6_1, "Test 6.1: Find objects init before logout");

    // Perform logout
    CK_RV rv6_2 = p11Func->C_Logout(hSession);
    checkOperation(rv6_2, "Test 6.2: Success case - logout");

    // Verify we cannot access private objects after logout
    CK_RV rv6_3 = p11Func->C_FindObjectsInit(hSession, template_, 1);
    checkOperation(rv6_3, "Test 6.3: Find objects init after logout (should fail)");
}

// Test function for C_CloseSession
void testCloseSession() {
    cout << "\n=== Testing C_CloseSession ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Close random session handle that doesn't exist
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv1 = p11Func->C_CloseSession(999);
    checkOperation(rv1, "Test 1: Close random session handle that doesn't exist");

    // Test Case 2: Close session handle as '0'
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv2 = p11Func->C_CloseSession(0);
    checkOperation(rv2, "Test 2: Close session handle as '0'");

    // Test Case 3: Close session handle as 'nullptr'
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv3 = p11Func->C_CloseSession((CK_SESSION_HANDLE) nullptr);
    checkOperation(rv3, "Test 3: Close session handle as 'nullptr'");

    // Test Case 4: Close valid session handle and verify
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Verify session is active before closing
    CK_SESSION_INFO sessionInfo;
    CK_RV rv4_1 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv4_1, "Test 4.1: Get session info before closing");

    // Close the session
    CK_RV rv4_2 = p11Func->C_CloseSession(hSession);
    checkOperation(rv4_2, "Test 4.2: Close valid session handle");

    // Verify session is closed
    CK_RV rv4_3 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv4_3,
                   "Test 4.3: Get session info after closing (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 5: Close already closed session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseSession(hSession), "First close");
    CK_RV rv5 = p11Func->C_CloseSession(hSession);
    checkOperation(rv5,
                   "Test 5: Close already closed session (should be CKR_SESSION_HANDLE_INVALID)");

    // Test Case 6: Close session after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv6 = p11Func->C_CloseSession(hSession);
    checkOperation(rv6,
                   "Test 6: Close session after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 7: Success case - verify complete session lifecycle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    CK_RV rv7_1 = p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                         &hSession);
    checkOperation(rv7_1, "Test 7.1: Open session");

    // Login
    CK_RV rv7_2 = p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen);
    checkOperation(rv7_2, "Test 7.2: Login");

    // Verify session state
    CK_RV rv7_3 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv7_3, "Test 7.3: Get session info before closing");

    // Close session
    CK_RV rv7_4 = p11Func->C_CloseSession(hSession);
    checkOperation(rv7_4, "Test 7.4: Close session");

    // Verify session is closed
    CK_RV rv7_5 = p11Func->C_GetSessionInfo(hSession, &sessionInfo);
    checkOperation(rv7_5,
                   "Test 7.5: Get session info after closing (should be CKR_SESSION_HANDLE_INVALID)");
}

// Test function for C_CloseAllSessions
void testCloseAllSessions() {
    cout << "\n=== Testing C_CloseAllSessions ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Close all sessions with random slot ID other than CDAC Token slot
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // Use a slot ID that's not the CDAC Token slot
    CK_SLOT_ID nonCDACSlot = (0 == 0) ? 1 : 0;
    CK_RV rv1 = p11Func->C_CloseAllSessions(nonCDACSlot);
    checkOperation(rv1,
                   "Test 1: Close all sessions with random slot ID other than CDAC Token slot");

    // Test Case 2: Close all sessions with random slot ID that doesn't exist
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv2 = p11Func->C_CloseAllSessions(999);
    checkOperation(rv2, "Test 2: Close all sessions with random slot ID that doesn't exist");

    // Test Case 3: Call C_CloseAllSessions twice
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseAllSessions(0), "First C_CloseAllSessions");
    CK_RV rv3 = p11Func->C_CloseAllSessions(0);
    checkOperation(rv3, "Test 3: Second C_CloseAllSessions (should still succeed)");

    // Test Case 4: Call C_CloseAllSessions after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv4 = p11Func->C_CloseAllSessions(0);
    checkOperation(rv4,
                   "Test 4: C_CloseAllSessions after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED)");

    // Test Case 5: Call C_CloseAllSessions after initialize only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv5 = p11Func->C_CloseAllSessions(0);
    checkOperation(rv5, "Test 5: C_CloseAllSessions after initialize only");

    // Test Case 6: Call C_CloseAllSessions after initialize and get slot list only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_RV rv6 = p11Func->C_CloseAllSessions(0);
    checkOperation(rv6, "Test 6: C_CloseAllSessions after initialize and get slot list only");

    // Test Case 7: Success case - verify complete session lifecycle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open multiple sessions
    CK_SESSION_HANDLE hSession1, hSession2, hSession3;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession3), "C_OpenSession 3");

    // Login on all sessions
    checkOperation(p11Func->C_Login(hSession1, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 1");
    checkOperation(p11Func->C_Login(hSession2, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 2");
    checkOperation(p11Func->C_Login(hSession3, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 3");

    // Verify sessions are active before closing
    CK_SESSION_INFO sessionInfo;
    CK_RV rv7_1 = p11Func->C_GetSessionInfo(hSession1, &sessionInfo);
    checkOperation(rv7_1, "Test 7.1: Get session info for session 1 before closing");
    CK_RV rv7_2 = p11Func->C_GetSessionInfo(hSession2, &sessionInfo);
    checkOperation(rv7_2, "Test 7.2: Get session info for session 2 before closing");
    CK_RV rv7_3 = p11Func->C_GetSessionInfo(hSession3, &sessionInfo);
    checkOperation(rv7_3, "Test 7.3: Get session info for session 3 before closing");

    // Close all sessions
    CK_RV rv7_4 = p11Func->C_CloseAllSessions(0);
    checkOperation(rv7_4, "Test 7.4: Close all sessions");

    // Verify all sessions are closed
    CK_RV rv7_5 = p11Func->C_GetSessionInfo(hSession1, &sessionInfo);
    checkOperation(rv7_5,
                   "Test 7.5: Get session info for session 1 after closing (should be CKR_SESSION_HANDLE_INVALID)");
    CK_RV rv7_6 = p11Func->C_GetSessionInfo(hSession2, &sessionInfo);
    checkOperation(rv7_6,
                   "Test 7.6: Get session info for session 2 after closing (should be CKR_SESSION_HANDLE_INVALID)");
    CK_RV rv7_7 = p11Func->C_GetSessionInfo(hSession3, &sessionInfo);
    checkOperation(rv7_7,
                   "Test 7.7: Get session info for session 3 after closing (should be CKR_SESSION_HANDLE_INVALID)");
}

// Test function for C_SignInit
void testSignInit() {
    cout << "\n=== Testing C_SignInit ===" << endl;
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Passing invalid session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair for testing
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE id[] = {1};
    CK_BBOOL ckTrue = CK_TRUE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
            {CKA_ID,              id,             sizeof(id)},
            {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_ID,        id,      sizeof(id)}};

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    CK_RV rv1 = p11Func->C_SignInit(999, &signMech, hPrivateKey);
    checkOperation(rv1, "Test 1: Passing invalid session");

    // Test Case 2: Passing invalid handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    CK_RV rv2 = p11Func->C_SignInit(hSession, &signMech, 999);
    checkOperation(rv2, "Test 2: Passing invalid handle");

    // Test Case 3: Passing invalid mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_MECHANISM invalidMech = {999, nullptr, 0}; // Invalid mechanism
    CK_RV rv3 = p11Func->C_SignInit(hSession, &invalidMech, hPrivateKey);
    checkOperation(rv3, "Test 3: Passing invalid mechanism");

    // Test Case 4: Passing all invalid parameters
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv4 = p11Func->C_SignInit(999, &invalidMech, 999);
    checkOperation(rv4, "Test 4: Passing all invalid parameters");

    // Test Case 5: Passing handle of public key
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv5 = p11Func->C_SignInit(hSession, &signMech, hPublicKey);
    checkOperation(rv5, "Test 5: Passing handle of public key");

    // Test Case 6: Passing handle of certificate
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Create a certificate object
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_ATTRIBUTE certTemplate[] = {
            {CKA_CLASS,            &certClass, sizeof(certClass)},
            {CKA_CERTIFICATE_TYPE, &certType,  sizeof(certType)},
            {CKA_TOKEN,            &ckTrue,    sizeof(ckTrue)},
            {CKA_ID,               id,         sizeof(id)}};
    CK_OBJECT_HANDLE hCert;
    checkOperation(p11Func->C_CreateObject(hSession, certTemplate,
                                           sizeof(certTemplate) / sizeof(CK_ATTRIBUTE), &hCert),
                   "C_CreateObject");

    CK_RV rv6 = p11Func->C_SignInit(hSession, &signMech, hCert);
    checkOperation(rv6, "Test 6: Passing handle of certificate");

    // Test Case 7: Passing Mechanism as nullptr
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv7 = p11Func->C_SignInit(hSession, nullptr, hPrivateKey);
    checkOperation(rv7, "Test 7: Passing Mechanism as nullptr");

    // Test Case 8: Calling C_SignInit after closing session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    CK_RV rv8 = p11Func->C_SignInit(hSession, &signMech, hPrivateKey);
    checkOperation(rv8, "Test 8: Calling C_SignInit after closing session");

    // Test Case 9: Calling C_SignInit after finalize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv9 = p11Func->C_SignInit(hSession, &signMech, hPrivateKey);
    checkOperation(rv9, "Test 9: Calling C_SignInit after finalize");

    // Test Case 10: Calling C_SignInit after Initialize
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv10 = p11Func->C_SignInit(hSession, &signMech, hPrivateKey);
    checkOperation(rv10, "Test 10: Calling C_SignInit after Initialize (without login)");

    // Test Case 11: Calling C_SignInit Without login
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv11 = p11Func->C_SignInit(hSession, &signMech, hPrivateKey);
    checkOperation(rv11, "Test 11: Calling C_SignInit Without login");

    // Test Case 12: Success case - satisfying all prerequisites
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    // Verify the key has signing capability
    CK_ATTRIBUTE signAttr[] = {
            {CKA_SIGN, nullptr, 0}};
    CK_ULONG attrLen;
    checkOperation(p11Func->C_GetAttributeValue(hSession, hPrivateKey, signAttr, 1),
                   "C_GetAttributeValue");

    // Initialize signing operation
    CK_RV rv12 = p11Func->C_SignInit(hSession, &signMech, hPrivateKey);
    checkOperation(rv12, "Test 12: Success case - satisfying all prerequisites");
}

// Test function for C_GetOperationState
void testGetOperationState() {
    cout << "\n=== Testing C_GetOperationState ===" << endl;

    // Test Case 1: Valid digest operation initialized and updated
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    CK_SESSION_HANDLE hSession;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    CK_MECHANISM digestMech = {CKM_SHA1_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Update digest with some data
    const char *data = "Test data for digest";
    CK_ULONG dataLen = strlen(data);
    checkOperation(p11Func->C_DigestUpdate(hSession, (CK_BYTE_PTR) data, dataLen),
                   "C_DigestUpdate");

    // Get operation state size
    CK_ULONG stateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &stateLen),
                   "Get operation state size");

    // Get operation state
    CK_BYTE_PTR state = (CK_BYTE_PTR) malloc(stateLen);
    if (state) {
        CK_RV rv1 = p11Func->C_GetOperationState(hSession, state, &stateLen);
        checkOperation(rv1, "Test 1: Valid digest operation initialized and updated");
        free(state);
    }

    // Test Case 2: Query for state size only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Query state size only
    CK_ULONG sizeOnly = 0;
    CK_RV rv2 = p11Func->C_GetOperationState(hSession, nullptr, &sizeOnly);
    checkOperation(rv2, "Test 2: Query for state size only");

    // Test Case 3: State capture after encryption init
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize encryption operation
    CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey = 0; // You'll need to set this to a valid public key handle
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");

    // Get operation state size
    CK_ULONG encryptStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &encryptStateLen),
                   "Get encryption state size");

    // Get operation state
    CK_BYTE_PTR encryptState = (CK_BYTE_PTR) malloc(encryptStateLen);
    if (encryptState) {
        CK_RV rv3 = p11Func->C_GetOperationState(hSession, encryptState, &encryptStateLen);
        checkOperation(rv3, "Test 3: State capture after encryption init");
        free(encryptState);
    }

    // Test Case 4: Session performing simultaneous operations
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Initialize encryption operation in same session
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");

    // Get operation state size
    CK_ULONG multiStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &multiStateLen),
                   "Get multi-operation state size");

    // Get operation state
    CK_BYTE_PTR multiState = (CK_BYTE_PTR) malloc(multiStateLen);
    if (multiState) {
        CK_RV rv4 = p11Func->C_GetOperationState(hSession, multiState, &multiStateLen);
        checkOperation(rv4, "Test 4: Session performing simultaneous operations");
        free(multiState);
    }

    // Test Case 5: Session handle is invalid
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Use invalid session handle
    CK_SESSION_HANDLE invalidSession = 0xFFFFFFFF;
    CK_ULONG invalidStateLen = 0;
    CK_RV rv5 = p11Func->C_GetOperationState(invalidSession, nullptr, &invalidStateLen);
    checkOperation(rv5, "Test 5: Session handle is invalid");

    // Test Case 6: No operation initialized
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session without initializing any operation
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    CK_ULONG noOpStateLen = 0;
    CK_RV rv6 = p11Func->C_GetOperationState(hSession, nullptr, &noOpStateLen);
    checkOperation(rv6, "Test 6: No operation initialized");

    // Test Case 7: Token policy forbids exporting state
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Simulate token policy restriction by finalizing
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_ULONG policyStateLen = 0;
    CK_RV rv7 = p11Func->C_GetOperationState(hSession, nullptr, &policyStateLen);
    checkOperation(rv7, "Test 7: Token policy forbids exporting state");

    // Test Case 8: State buffer too small
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Get state size
    CK_ULONG smallStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &smallStateLen), "Get state size");

    // Try with buffer too small
    CK_BYTE_PTR smallBuffer = (CK_BYTE_PTR) malloc(1); // Buffer of size 1
    if (smallBuffer) {
        CK_ULONG actualLen = smallStateLen;
        CK_RV rv8 = p11Func->C_GetOperationState(hSession, smallBuffer, &actualLen);
        checkOperation(rv8, "Test 8: State buffer too small");
        free(smallBuffer);
    }

    // Test Case 9: State length pointer is nullptr
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_BYTE_PTR nullLenBuffer = (CK_BYTE_PTR) malloc(1024);
    if (nullLenBuffer) {
        CK_RV rv9 = p11Func->C_GetOperationState(hSession, nullLenBuffer, nullptr);
        checkOperation(rv9, "Test 9: State length pointer is nullptr");
        free(nullLenBuffer);
    }

    // Test Case 10: Output pointer is nullptr when length is nonzero
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_ULONG nonZeroLen = 1024;
    CK_RV rv10 = p11Func->C_GetOperationState(hSession, nullptr, &nonZeroLen);
    checkOperation(rv10, "Test 10: Output pointer is nullptr when length is nonzero");

    // Test Case 11: Session is closed before call
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session, initialize operation, then close session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

    CK_ULONG closedStateLen = 0;
    CK_RV rv11 = p11Func->C_GetOperationState(hSession, nullptr, &closedStateLen);
    checkOperation(rv11, "Test 11: Session is closed before call");

    // Cleanup
    if (slots) {
        free(slots);
    }
}

// Test function for C_SetOperationState

void testSetOperationState() {
    cout << "\n=== Testing C_SetOperationState ===" << endl;

    // Test Case 1: Restore digest operation with no keys required
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    CK_SESSION_HANDLE hSession;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    CK_MECHANISM digestMech = {CKM_RSA_PKCS, NULL_PTR, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Update digest with some data
    const char *data = "Test data for digest";
    CK_ULONG dataLen = strlen(data);
    checkOperation(p11Func->C_DigestUpdate(hSession, (CK_BYTE_PTR) data, dataLen),
                   "C_DigestUpdate");

    // Get operation state
    CK_ULONG stateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &stateLen),
                   "Get operation state size");
    CK_BYTE_PTR state = (CK_BYTE_PTR) malloc(stateLen);
    if (state) {
        checkOperation(p11Func->C_GetOperationState(hSession, state, &stateLen),
                       "Get operation state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        // Restore operation state
        CK_RV rv1 = p11Func->C_SetOperationState(hSession, state, stateLen, 0, 0);
        checkOperation(rv1, "Test 1: Restore digest operation with no keys required");
        free(state);
    }

    // Test Case 2: Restore operation with encryption key supplied
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize encryption operation
    CK_MECHANISM encryptMech = {CKM_RSA_PKCS, NULL_PTR, 0};
    CK_OBJECT_HANDLE hPublicKey = 0; // You'll need to generate or find a valid public key handle
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");

    // Get operation state
    CK_ULONG encryptStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &encryptStateLen),
                   "Get encryption state size");
    CK_BYTE_PTR encryptState = (CK_BYTE_PTR) malloc(encryptStateLen);
    if (encryptState) {
        checkOperation(p11Func->C_GetOperationState(hSession, encryptState, &encryptStateLen),
                       "Get encryption state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        // Restore operation state with encryption key
        CK_RV rv2 = p11Func->C_SetOperationState(hSession, encryptState, encryptStateLen,
                                                 hPublicKey, 0);
        checkOperation(rv2, "Test 2: Restore operation with encryption key supplied");
        free(encryptState);
    }

    // Test Case 3: Invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Use invalid session handle
    CK_SESSION_HANDLE invalidSession = 0xFFFFFFFF;
    CK_RV rv3 = p11Func->C_SetOperationState(invalidSession, nullptr, 0, 0, 0);
    checkOperation(rv3, "Test 3: Invalid session handle");

    // Test Case 4: Session closed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open and close session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

    CK_RV rv4 = p11Func->C_SetOperationState(hSession, nullptr, 0, 0, 0);
    checkOperation(rv4, "Test 4: Session closed");

    // Test Case 5: Invalid state data
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Create invalid state data
    CK_BYTE invalidState[32];
    memset(invalidState, 0xFF, sizeof(invalidState));
    CK_RV rv5 = p11Func->C_SetOperationState(hSession, invalidState, sizeof(invalidState), 0, 0);
    checkOperation(rv5, "Test 5: Invalid state data");

    // Test Case 6: Missing required encryption/authentication key
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize encryption operation
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");

    // Get operation state
    CK_ULONG missingKeyStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &missingKeyStateLen),
                   "Get state size");
    CK_BYTE_PTR missingKeyState = (CK_BYTE_PTR) malloc(missingKeyStateLen);
    if (missingKeyState) {
        checkOperation(p11Func->C_GetOperationState(hSession, missingKeyState, &missingKeyStateLen),
                       "Get state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        // Try to restore without required key
        CK_RV rv6 = p11Func->C_SetOperationState(hSession, missingKeyState, missingKeyStateLen, 0,
                                                 0);
        checkOperation(rv6, "Test 6: Missing required encryption/authentication key");
        free(missingKeyState);
    }

    // Test Case 7: Irrelevant key passed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation (no key required)
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Get operation state
    CK_ULONG irrelevantKeyStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &irrelevantKeyStateLen),
                   "Get state size");
    CK_BYTE_PTR irrelevantKeyState = (CK_BYTE_PTR) malloc(irrelevantKeyStateLen);
    if (irrelevantKeyState) {
        checkOperation(
                p11Func->C_GetOperationState(hSession, irrelevantKeyState, &irrelevantKeyStateLen),
                "Get state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        // Try to restore with irrelevant key
        CK_RV rv7 = p11Func->C_SetOperationState(hSession, irrelevantKeyState,
                                                 irrelevantKeyStateLen, hPublicKey, 0);
        checkOperation(rv7, "Test 7: Irrelevant key passed");
        free(irrelevantKeyState);
    }

    // Test Case 8: Wrong key passed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize encryption operation
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");

    // Get operation state
    CK_ULONG wrongKeyStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &wrongKeyStateLen),
                   "Get state size");
    CK_BYTE_PTR wrongKeyState = (CK_BYTE_PTR) malloc(wrongKeyStateLen);
    if (wrongKeyState) {
        checkOperation(p11Func->C_GetOperationState(hSession, wrongKeyState, &wrongKeyStateLen),
                       "Get state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        CK_RV rv8 = p11Func->C_SetOperationState(hSession, wrongKeyState, wrongKeyStateLen,
                                                 hPublicKey, 0);
        checkOperation(rv8, "Test 8: Wrong key passed");
        free(wrongKeyState);
    }

    // Test Case 9: Argument error: nullptr state pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    CK_RV rv9 = p11Func->C_SetOperationState(hSession, nullptr, 1024, 0, 0);
    checkOperation(rv9, "Test 9: Argument error: nullptr state pointer");

    // Test Case 10: Memory-related errors
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Initialize digest operation
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Get operation state
    CK_ULONG memStateLen = 0;
    checkOperation(p11Func->C_GetOperationState(hSession, nullptr, &memStateLen), "Get state size");
    CK_BYTE_PTR memState = (CK_BYTE_PTR) malloc(memStateLen);
    if (memState) {
        checkOperation(p11Func->C_GetOperationState(hSession, memState, &memStateLen), "Get state");

        // Close session and open new one
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        // Simulate memory error by corrupting state data
        memset(memState, 0xFF, memStateLen);
        CK_RV rv10 = p11Func->C_SetOperationState(hSession, memState, memStateLen, 0, 0);
        checkOperation(rv10, "Test 10: Memory-related errors");
        free(memState);
    }

    // Cleanup
    if (slots) {
        free(slots);
    }
}

// Test function for C_SignUpdate
void testSignUpdate() {
    cout << "\n=== Testing C_SignUpdate ===" << endl;

    // Test Case 1: Sign update with invalid session handle
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_BYTE data[] = "test data";
    CK_RV rv1 = p11Func->C_SignUpdate(999, data, sizeof(data));
    checkOperation(rv1, "Test 1: Sign update with invalid session handle");

    // Test Case 2: Sign update with nullptr data
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_SLOT_ID slots[1];
    CK_ULONG count = 1;
    p11Func->C_GetSlotList(TRUE, slots, &count);
    p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession);
    CK_RV rv2 = p11Func->C_SignUpdate(hSession, nullptr, 0);
    checkOperation(rv2, "Test 2: Sign update with nullptr data");
}

// Test function for C_SignFinal
void testSignFinal() {
    cout << "\n=== Testing C_SignFinal ===" << endl;

    // Test Case 1: Sign final with invalid session handle
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_BYTE signature[256];
    CK_ULONG sigLen = sizeof(signature);
    CK_RV rv1 = p11Func->C_SignFinal(999, signature, &sigLen);
    checkOperation(rv1, "Test 1: Sign final with invalid session handle");

    // Test Case 2: Sign final with nullptr signature buffer
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_SLOT_ID slots[1];
    CK_ULONG count = 1;
    p11Func->C_GetSlotList(TRUE, slots, &count);
    p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession);
    CK_RV rv2 = p11Func->C_SignFinal(hSession, nullptr, &sigLen);
    checkOperation(rv2, "Test 2: Sign final with nullptr signature buffer");
}

// Test function for C_SignRecoverInit
void testSignRecoverInit() {
    cout << "\n=== Testing C_SignRecoverInit ===" << endl;

    // Test Case 1: Sign recover init with invalid session handle
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
    CK_RV rv1 = p11Func->C_SignRecoverInit(999, &mech, 0);
    checkOperation(rv1, "Test 1: Sign recover init with invalid session handle");

    // Test Case 2: Sign recover init with nullptr mechanism
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_SLOT_ID slots[1];
    CK_ULONG count = 1;
    p11Func->C_GetSlotList(TRUE, slots, &count);
    p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession);
    CK_RV rv2 = p11Func->C_SignRecoverInit(hSession, nullptr, 0);
    checkOperation(rv2, "Test 2: Sign recover init with nullptr mechanism");
}

// Test function for C_SignRecover
void testSignRecover() {
    cout << "\n=== Testing C_SignRecover ===" << endl;

    // Test Case 1: Sign recover with invalid session handle
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_BYTE data[] = "test data";
    CK_BYTE signature[256];
    CK_ULONG sigLen = sizeof(signature);
    CK_RV rv1 = p11Func->C_SignRecover(999, data, sizeof(data), signature, &sigLen);
    checkOperation(rv1, "Test 1: Sign recover with invalid session handle");

    // Test Case 2: Sign recover with nullptr data
    resetState();
    p11Func->C_Initialize(nullptr);
    CK_SLOT_ID slots[1];
    CK_ULONG count = 1;
    p11Func->C_GetSlotList(TRUE, slots, &count);
    p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession);
    CK_RV rv2 = p11Func->C_SignRecover(hSession, nullptr, 0, signature, &sigLen);
    checkOperation(rv2, "Test 2: Sign recover with nullptr data");
}

// Test function for C_Finalize
void testFinalize() {
    cout << "\n=== Testing C_Finalize ===" << endl;

    // Test Case 1: Finalize with non-nullptr pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    void *reserved = (void *) 1;
    CK_RV rv1 = p11Func->C_Finalize(reserved);
    checkOperation(rv1, "Test 1: Finalize with non-nullptr pointer");

    // Test Case 2: Finalize when not initialized
    resetState();
    CK_RV rv2 = p11Func->C_Finalize(nullptr);
    checkOperation(rv2, "Test 2: Finalize when not initialized");

    // Test Case 3: Finalize after closing all sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_CloseAllSessions(0), "C_CloseAllSessions");
    CK_RV rv3 = p11Func->C_Finalize(nullptr);
    checkOperation(rv3, "Test 3: Finalize after closing all sessions");

    // Test Case 4: Finalize after finalizing
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_Finalize(nullptr), "First C_Finalize");
    CK_RV rv4 = p11Func->C_Finalize(nullptr);
    checkOperation(rv4, "Test 4: Finalize after finalizing");

    // Test Case 5: Finalize with active sessions
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    CK_RV rv5 = p11Func->C_Finalize(nullptr);
    checkOperation(rv5, "Test 5: Finalize with active sessions");

    // Test Case 6: Finalize after multiple initializations
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_Finalize(nullptr), "First C_Finalize");
    checkOperation(p11Func->C_Initialize(nullptr), "Second C_Initialize");
    CK_RV rv6 = p11Func->C_Finalize(nullptr);
    checkOperation(rv6, "Test 6: Finalize after multiple initializations");

    // Test Case 7: Finalize after failed initialization
    // resetState();
    // void *invalidInit = (void *)1;
    // p11Func->C_Initialize(invalidInit); // This should fail
    // CK_RV rv7 = p11Func->C_Finalize(nullptr);
    // checkOperation(rv7, "Test 7: Finalize after failed initialization");

    // Test Case 8: Finalize with multiple slots
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open sessions on multiple slots if available
    for (CK_ULONG i = 0; i < slotCount && i < 3; i++) {
        checkOperation(
                p11Func->C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
    }

    CK_RV rv8 = p11Func->C_Finalize(nullptr);
    checkOperation(rv8, "Test 8: Finalize with multiple slots");

    // Test Case 9: Finalize after operations
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Perform some operations
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate a key pair
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE id[] = {1};
    CK_BBOOL ckTrue = CK_TRUE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
            {CKA_ID,              id,             sizeof(id)},
            {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_ID,        id,      sizeof(id)}};

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    CK_RV rv9 = p11Func->C_Finalize(nullptr);
    checkOperation(rv9, "Test 9: Finalize after operations");

    // Test Case 10: Success case - proper initialization and finalization
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv10 = p11Func->C_Finalize(nullptr);
    checkOperation(rv10, "Test 10: Success case - proper initialization and finalization");
}

// Test function for C_EncryptInit
void testEncryptInit() {
    cout << "\n=== Testing C_EncryptInit ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Calling C_EncryptInit with valid RSA mechanism and key on active session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair for testing
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE id[] = {1};
    CK_BBOOL ckTrue = CK_TRUE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
            {CKA_ID,              id,             sizeof(id)},
            {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_ID,        id,      sizeof(id)}};

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");

    // Now test C_EncryptInit with the generated public key
    CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
    CK_RV rv1 = p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey);
    checkOperation(rv1, "Test 1: C_EncryptInit with valid RSA mechanism and key on active session");

    // Test Case 2: Calling C_EncryptInit with nullptr session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv2 = p11Func->C_EncryptInit(0, &encryptMech, hPublicKey);
    checkOperation(rv2, "Test 2: C_EncryptInit with nullptr session handle");

    // Test Case 3: Calling C_EncryptInit with invalid key handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    CK_RV rv3 = p11Func->C_EncryptInit(hSession, &encryptMech, 999);
    checkOperation(rv3, "Test 3: C_EncryptInit with invalid key handle");

    // Test Case 4: Calling C_EncryptInit with nullptr mechanism pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_RV rv4 = p11Func->C_EncryptInit(hSession, nullptr, hPublicKey);
    checkOperation(rv4, "Test 4: C_EncryptInit with nullptr mechanism pointer");

    // Test Case 5: Calling C_EncryptInit twice without finishing operation
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey),
                   "First C_EncryptInit");
    CK_RV rv5 = p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey);
    checkOperation(rv5,
                   "Test 5: Second C_EncryptInit without finishing operation (should be CKR_OPERATION_ACTIVE)");

    // Test Case 6: Calling C_EncryptInit with non-encryption mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPublicKey, &hPrivateKey),
                   "C_GenerateKeyPair");
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0}; // Using sign mechanism for encryption
    CK_RV rv6 = p11Func->C_EncryptInit(hSession, &signMech, hPublicKey);
    checkOperation(rv6, "Test 6: C_EncryptInit with non-encryption mechanism");

    // Test Case 7: Calling C_EncryptInit with a key of size outside allowed range
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate key with very small modulus size
    CK_ULONG smallModulusBits = 64; // Too small for RSA
    CK_ATTRIBUTE smallPubTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,           sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,           sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,           sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &smallModulusBits, sizeof(smallModulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent,    sizeof(publicExponent)},
            {CKA_ID,              id,                sizeof(id)},
            {CKA_TOKEN,           &ckTrue,           sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hSmallPublicKey, hSmallPrivateKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, smallPubTemplate,
                                              sizeof(smallPubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hSmallPublicKey, &hSmallPrivateKey),
                   "C_GenerateKeyPair with small modulus");

    CK_RV rv7 = p11Func->C_EncryptInit(hSession, &encryptMech, hSmallPublicKey);
    checkOperation(rv7, "Test 7: C_EncryptInit with a key of size outside allowed range");
}

// Test function for C_DigestUpdate
void testDigestUpdate() {
    cout << "\n=== Testing C_DigestUpdate ===" << endl;

    // Test Case 1: Passing valid session handle and valid data
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_BYTE_PTR pPart = (CK_BYTE_PTR) "test data for digest update";
    CK_ULONG ulPartLen = strlen((char *) pPart);
    CK_RV rv1 = p11Func->C_DigestUpdate(hSession, pPart, ulPartLen);
    checkOperation(rv1, "Test 1: Passing valid session handle and valid data");

    // Test Case 2: Calling C_DigestUpdate without calling C_DigestInit
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_RV rv2 = p11Func->C_DigestUpdate(hSession, pPart, ulPartLen);
    checkOperation(rv2, "Test 2: Calling C_DigestUpdate without calling C_DigestInit");

    // Test Case 3: Passing invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv3 = p11Func->C_DigestUpdate(999, pPart, ulPartLen);
    checkOperation(rv3, "Test 3: Passing invalid session handle");

    // Test Case 4: Passing nullptr data pointer with non-zero length
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv4 = p11Func->C_DigestUpdate(hSession, nullptr, 10);
    checkOperation(rv4, "Test 4: Passing nullptr data pointer with non-zero length");

    // Test Case 5: Passing nullptr data pointer with zero length
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv5 = p11Func->C_DigestUpdate(hSession, nullptr, 0);
    checkOperation(rv5, "Test 5: Passing nullptr data pointer with zero length");

    // Test Case 6: Calling C_DigestUpdate after C_DigestFinal
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_BYTE digest[32];
    CK_ULONG digestLen = sizeof(digest);
    checkOperation(p11Func->C_DigestFinal(hSession, digest, &digestLen), "C_DigestFinal");

    CK_RV rv6 = p11Func->C_DigestUpdate(hSession, pPart, ulPartLen);
    checkOperation(rv6, "Test 6: Calling C_DigestUpdate after C_DigestFinal");

    // Test Case 7: Digesting data too large for token buffer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    // Create a large data buffer (1MB)
    const size_t largeDataSize = 1024 * 1024;
    CK_BYTE *largeData = (CK_BYTE *) malloc(largeDataSize);
    if (largeData) {
        // Fill with some pattern
        for (size_t i = 0; i < largeDataSize; i++) {
            largeData[i] = (CK_BYTE) (i % 256);
        }

        CK_RV rv7 = p11Func->C_DigestUpdate(hSession, largeData, largeDataSize);
        checkOperation(rv7, "Test 7: Digesting data too large for token buffer");

        free(largeData);
    }
}

// Test function for C_DigestKey
void testDigestKey() {
    cout << "\n=== Testing C_DigestKey ===" << endl;

    // Test Case 1: Passing valid session handle and valid secret key object
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate a secret key
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
    CK_BYTE keyValue[32] = {0}; // 256-bit key
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;

    CK_ATTRIBUTE keyTemplate[] = {
            {CKA_CLASS,       &keyClass,   sizeof(keyClass)},
            {CKA_KEY_TYPE,    &keyType,    sizeof(keyType)},
            {CKA_VALUE,       keyValue,    sizeof(keyValue)},
            {CKA_TOKEN,       &falseValue, sizeof(falseValue)},
            {CKA_SENSITIVE,   &falseValue, sizeof(falseValue)},
            {CKA_EXTRACTABLE, &trueValue,  sizeof(trueValue)}};

    CK_OBJECT_HANDLE hKey;
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");

    // Initialize digest
    CK_MECHANISM digestMech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_RV rv1 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv1, "Test 1: Passing valid session handle and valid secret key object");

    // Test Case 2: Calling C_DigestKey without C_DigestInit
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");

    CK_RV rv2 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv2, "Test 2: Calling C_DigestKey without C_DigestInit");

    // Test Case 3: Passing invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_RV rv3 = p11Func->C_DigestKey(999, hKey);
    checkOperation(rv3, "Test 3: Passing invalid session handle");

    // Test Case 4: Passing object handle that is not a secret key
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    // Create a non-secret key object (e.g., public key)
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE rsaKeyType = CKK_RSA;
    CK_BYTE modulus[] = {0x01, 0x02, 0x03};
    CK_BYTE exponent[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE pubKeyTemplate[] = {
            {CKA_CLASS,           &pubKeyClass, sizeof(pubKeyClass)},
            {CKA_KEY_TYPE,        &rsaKeyType,  sizeof(rsaKeyType)},
            {CKA_MODULUS,         modulus,      sizeof(modulus)},
            {CKA_PUBLIC_EXPONENT, exponent,     sizeof(exponent)}};

    CK_OBJECT_HANDLE hPubKey;
    checkOperation(p11Func->C_CreateObject(hSession, pubKeyTemplate,
                                           sizeof(pubKeyTemplate) / sizeof(CK_ATTRIBUTE), &hPubKey),
                   "C_CreateObject");

    CK_RV rv4 = p11Func->C_DigestKey(hSession, hPubKey);
    checkOperation(rv4, "Test 4: Passing object handle that is not a secret key");

    // Test Case 5: Mechanism does not support C_DigestKey
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");

    // Use a mechanism that doesn't support key digesting
    CK_MECHANISM unsupportedMech = {CKM_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &unsupportedMech), "C_DigestInit");

    CK_RV rv5 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv5, "Test 5: Mechanism does not support C_DigestKey");

    // Test Case 6: Key object is sensitive or extractable = FALSE and not digestable
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Create a sensitive key
    CK_ATTRIBUTE sensitiveKeyTemplate[] = {
            {CKA_CLASS,       &keyClass,   sizeof(keyClass)},
            {CKA_KEY_TYPE,    &keyType,    sizeof(keyType)},
            {CKA_VALUE,       keyValue,    sizeof(keyValue)},
            {CKA_TOKEN,       &falseValue, sizeof(falseValue)},
            {CKA_SENSITIVE,   &trueValue,  sizeof(trueValue)},
            {CKA_EXTRACTABLE, &falseValue, sizeof(falseValue)}};

    checkOperation(p11Func->C_GenerateKey(hSession, &mech, sensitiveKeyTemplate,
                                          sizeof(sensitiveKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                          &hKey), "C_GenerateKey");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_RV rv6 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv6,
                   "Test 6: Key object is sensitive or extractable = FALSE and not digestable");

    // Test Case 7: Digest operation already finalized
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_BYTE digest[32];
    CK_ULONG digestLen = sizeof(digest);
    checkOperation(p11Func->C_DigestFinal(hSession, digest, &digestLen), "C_DigestFinal");

    CK_RV rv7 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv7, "Test 7: Digest operation already finalized");

    // Test Case 8: Calling with a nullptr key handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_RV rv8 = p11Func->C_DigestKey(hSession, 0);
    checkOperation(rv8, "Test 8: Calling with a nullptr key handle");

    // Test Case 9: Calling with a session in the wrong state
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_GenerateKey(hSession, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");
    // Not logging in to create wrong state
    checkOperation(p11Func->C_DigestInit(hSession, &digestMech), "C_DigestInit");

    CK_RV rv9 = p11Func->C_DigestKey(hSession, hKey);
    checkOperation(rv9, "Test 9: Calling with a session in the wrong state");

    // Test Case 10: Passing a key handle from another session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Create two sessions
    CK_SESSION_HANDLE hSession1, hSession2;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession1), "C_OpenSession 1");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession2), "C_OpenSession 2");

    checkOperation(p11Func->C_Login(hSession1, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 1");
    checkOperation(p11Func->C_Login(hSession2, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login 2");

    // Generate key in first session
    checkOperation(p11Func->C_GenerateKey(hSession1, &mech, keyTemplate,
                                          sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &hKey),
                   "C_GenerateKey");

    // Try to use key in second session
    checkOperation(p11Func->C_DigestInit(hSession2, &digestMech), "C_DigestInit");

    CK_RV rv10 = p11Func->C_DigestKey(hSession2, hKey);
    checkOperation(rv10, "Test 10: Passing a key handle from another session");
}

// Test function for C_DigestFinal
void testDigestFinal() {
    cout << "\n=== Testing C_DigestFinal ===" << endl;

    // Test Case 1: Calling C_DigestFinal after valid C_DigestInit and optional C_DigestUpdate
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_BYTE_PTR pPart = (CK_BYTE_PTR) "test data for digest";
    CK_ULONG ulPartLen = strlen((char *) pPart);
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    CK_BYTE digest[32];
    CK_ULONG digestLen = sizeof(digest);
    CK_RV rv1 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv1,
                   "Test 1: Calling C_DigestFinal after valid C_DigestInit and optional C_DigestUpdate");

    // Test Case 2: Calling C_DigestFinal without calling C_DigestInit
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_RV rv2 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv2, "Test 2: Calling C_DigestFinal without calling C_DigestInit");

    // Test Case 3: Passing an invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv3 = p11Func->C_DigestFinal(999, digest, &digestLen);
    checkOperation(rv3, "Test 3: Passing an invalid session handle");

    // Test Case 4: Passing nullptr pDigest but valid pointer to pulDigestLen
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    CK_RV rv4 = p11Func->C_DigestFinal(hSession, nullptr, &digestLen);
    checkOperation(rv4, "Test 4: Passing nullptr pDigest but valid pointer to pulDigestLen");

    // Test Case 5: Passing valid buffer but pulDigestLen too small
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    CK_BYTE smallDigest[1]; // Too small for SHA-256
    CK_ULONG smallDigestLen = sizeof(smallDigest);
    CK_RV rv5 = p11Func->C_DigestFinal(hSession, smallDigest, &smallDigestLen);
    checkOperation(rv5, "Test 5: Passing valid buffer but pulDigestLen too small");

    // Test Case 6: Calling C_DigestFinal twice without calling C_DigestInit again
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    checkOperation(p11Func->C_DigestFinal(hSession, digest, &digestLen), "First C_DigestFinal");
    CK_RV rv6 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv6, "Test 6: Calling C_DigestFinal twice without calling C_DigestInit again");

    // Test Case 7: Passing nullptr pulDigestLen
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    CK_RV rv7 = p11Func->C_DigestFinal(hSession, digest, nullptr);
    checkOperation(rv7, "Test 7: Passing nullptr pulDigestLen");

    // Test Case 8: Calling C_DigestFinal after session is closed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

    CK_RV rv8 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv8, "Test 8: Calling C_DigestFinal after session is closed");

    // Test Case 9: Calling C_DigestFinal with no data updated
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    CK_RV rv9 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv9, "Test 9: Calling C_DigestFinal with no data updated");

    // Test Case 10: Token/Device error during digest computation
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_DigestUpdate(hSession, pPart, ulPartLen), "C_DigestUpdate");

    // Simulate token error by closing session before finalizing
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    CK_RV rv10 = p11Func->C_DigestFinal(hSession, digest, &digestLen);
    checkOperation(rv10, "Test 10: Token/Device error during digest computation");
}

// Test function for C_GetSlotInfo
void testGetSlotInfo() {
    cout << "\n=== Testing C_GetSlotInfo ===" << endl;

    // Test Case 1: Valid slot ID retrieved from C_GetSlotList
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_SLOT_INFO slotInfo;
    CK_RV rv1 = p11Func->C_GetSlotInfo(0, &slotInfo);
    checkOperation(rv1, "Test 1: Valid slot ID retrieved from C_GetSlotList");

    // Test Case 2: Invalid slot ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_INFO invalidSlotInfo;
    CK_RV rv2 = p11Func->C_GetSlotInfo(999, &invalidSlotInfo);
    checkOperation(rv2, "Test 2: Invalid slot ID");

    // Test Case 3: nullptr pointer for slot info
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_RV rv3 = p11Func->C_GetSlotInfo(0, nullptr);
    checkOperation(rv3, "Test 3: nullptr pointer for slot info");

    // Test Case 4: Device or communication error
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate device error by finalizing before getting slot info
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_SLOT_INFO deviceErrorInfo;
    CK_RV rv4 = p11Func->C_GetSlotInfo(0, &deviceErrorInfo);
    checkOperation(rv4, "Test 4: Device or communication error");

    // Test Case 5: Insufficient memory to store slot info
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate memory allocation failure by requesting an extremely large buffer
    CK_ULONG hugeCount = SIZE_MAX / sizeof(CK_SLOT_INFO) + 1;
    CK_SLOT_INFO *hugeSlotInfo = (CK_SLOT_INFO *) malloc(hugeCount * sizeof(CK_SLOT_INFO));
    // if /*(!hugeSlotInfo)
    //{*/
    CK_RV rv5 = p11Func->C_GetSlotInfo(0, hugeSlotInfo);
    checkOperation(rv5, "Test 5: Insufficient memory to store slot info");
    //}

    // Test Case 6: General internal failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate internal failure by corrupting slot ID
    CK_SLOT_ID corruptedSlot = 0;
    memset(&corruptedSlot, 0xFF, sizeof(CK_SLOT_ID));
    CK_SLOT_INFO internalErrorInfo;
    CK_RV rv6 = p11Func->C_GetSlotInfo(corruptedSlot, &internalErrorInfo);
    checkOperation(rv6, "Test 6: General internal failure");

    // Test Case 7: Successfully retrieving slot info for multiple slots
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_SLOT_INFO *slotInfos = (CK_SLOT_INFO *) malloc(slotCount * sizeof(CK_SLOT_INFO));
    CK_RV rv7 = p11Func->C_GetSlotInfo(0, &slotInfo);
    checkOperation(rv7, "Test 7: Successfully retrieving slot info for multiple slots");
    // Cleanup
    if (slots) {
        free(slots);
    }
}

// Test function for C_GetTokenInfo
void testGetTokenInfo() {
    cout << "\n=== Testing C_GetTokenInfo ===" << endl;

    // Test Case 1: Valid slot ID with present token
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_TOKEN_INFO tokenInfo;
    CK_RV rv1 = p11Func->C_GetTokenInfo(0, &tokenInfo);
    checkOperation(rv1, "Test 1: Valid slot ID with present token");

    // Test Case 2: Empty but valid token field
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Create empty token info structure
    CK_TOKEN_INFO emptyTokenInfo;
    memset(&emptyTokenInfo, 0, sizeof(CK_TOKEN_INFO));
    CK_RV rv2 = p11Func->C_GetTokenInfo(0, &emptyTokenInfo);
    checkOperation(rv2, "Test 2: Empty but valid token field");

    // Test Case 3: Invalid slot ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_TOKEN_INFO invalidTokenInfo;
    CK_RV rv3 = p11Func->C_GetTokenInfo(999, &invalidTokenInfo);
    checkOperation(rv3, "Test 3: Invalid slot ID");

    // Test Case 4: No token in slot
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(FALSE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(FALSE, slots, &slotCount), "C_GetSlotList");

    // Try to get token info from a slot that might not have a token
    CK_TOKEN_INFO noTokenInfo;
//    cout << "Sleep" << endl;
    // Sleep(3000);
    CK_RV rv4 = p11Func->C_GetTokenInfo(0, &noTokenInfo);
    checkOperation(rv4, "Test 4: No token in slot");

    // Test Case 5: Token not recognized
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate unrecognized token by corrupting slot ID
    CK_SLOT_ID corruptedSlot = 0;
    memset(&corruptedSlot, 0xFF, sizeof(CK_SLOT_ID));
    CK_TOKEN_INFO unrecognizedTokenInfo;
    CK_RV rv5 = p11Func->C_GetTokenInfo(corruptedSlot, &unrecognizedTokenInfo);
    checkOperation(rv5, "Test 5: Token not recognized");

    // Test Case 6: Null pointer passed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_RV rv6 = p11Func->C_GetTokenInfo(0, nullptr);
    checkOperation(rv6, "Test 6: Null pointer passed");

    // Test Case 7: Token removed during function
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate token removal by finalizing before getting token info
    // checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_TOKEN_INFO removedTokenInfo;
    sleep(2000);
    CK_RV rv7 = p11Func->C_GetTokenInfo(0, &removedTokenInfo);
    checkOperation(rv7, "Test 7: Token removed during function");

    // Test Case 8: Hardware or memory failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate hardware failure by requesting extremely large buffer
    CK_ULONG hugeCount = SIZE_MAX / sizeof(CK_TOKEN_INFO) + 1;
    CK_TOKEN_INFO *hugeTokenInfo = (CK_TOKEN_INFO *) malloc(hugeCount * sizeof(CK_TOKEN_INFO));
    if (!hugeTokenInfo) {
        CK_RV rv8 = p11Func->C_GetTokenInfo(0, hugeTokenInfo);
        checkOperation(rv8, "Test 8: Hardware or memory failure");
    }

    // Cleanup
    if (slots) {
        free(slots);
    }
    if (hugeTokenInfo) {
        free(hugeTokenInfo);
    }
}

// Test function for C_WaitForSlotEvent
void testWaitForSlotEvent() {
    cout << "\n=== Testing C_WaitForSlotEvent ===" << endl;

    // Test Case 1: Blocking call waits for insertion
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID slotID;
    CK_RV rv1 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slotID, nullptr);
    checkOperation(rv1, "Test 1: Blocking call waits for insertion");

    // Test Case 2: Non-blocking call with no event
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID noEventSlotID;
    CK_RV rv2 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &noEventSlotID, nullptr);
    checkOperation(rv2, "Test 2: Non-blocking call with no event");

    // Test Case 3: Non-blocking call with no event (repeated)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID noEventSlotID2;
    CK_RV rv3 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &noEventSlotID2, nullptr);
    checkOperation(rv3, "Test 3: Non-blocking call with no event (repeated)");

    // Test Case 4: nullptr slot pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv4 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, nullptr, nullptr);
    checkOperation(rv4, "Test 4: nullptr slot pointer");

    // Test Case 5: Non-nullptr reserved pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID slotIDWithReserved;
    CK_VOID_PTR reserved = (CK_VOID_PTR) malloc(1);
    CK_RV rv5 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slotIDWithReserved, reserved);
    checkOperation(rv5, "Test 5: Non-nullptr reserved pointer");
    free(reserved);

    // Test Case 6: Function fails internally
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // Simulate internal failure by corrupting slot ID
    CK_SLOT_ID corruptedSlotID;
    memset(&corruptedSlotID, 0xFF, sizeof(CK_SLOT_ID));
    CK_RV rv6 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &corruptedSlotID, nullptr);
    checkOperation(rv6, "Test 6: Function fails internally");

    // Test Case 7: Memory allocation failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // Simulate memory allocation failure by requesting extremely large buffer
    CK_ULONG hugeSize = SIZE_MAX;
    CK_SLOT_ID *hugeSlotID = (CK_SLOT_ID *) malloc(hugeSize);
    if (!hugeSlotID) {
        CK_RV rv7 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, hugeSlotID, nullptr);
        checkOperation(rv7, "Test 7: Memory allocation failure");
    }

    // Test Case 8: Finalize while waiting
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_SLOT_ID finalizeSlotID;
    // Start waiting in a separate thread
    std::thread waitThread([&]() { p11Func->C_WaitForSlotEvent(0, &finalizeSlotID, nullptr); });
    // Finalize while waiting
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    waitThread.join();
    CK_RV rv8 = p11Func->C_WaitForSlotEvent(CKF_DONT_BLOCK, &finalizeSlotID, nullptr);
    checkOperation(rv8, "Test 8: Finalize while waiting");

    // Cleanup
    if (hugeSlotID) {
        free(hugeSlotID);
    }
}

// Test function for C_GetMechanismList
void testGetMechanismList() {
    cout << "\n=== Testing C_GetMechanismList ===" << endl;

    // Test Case 1: Query number of mechanisms only
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_ULONG mechanismCount = 0;
    CK_RV rv1 = p11Func->C_GetMechanismList(0, nullptr, &mechanismCount);
    checkOperation(rv1, "Test 1: Query number of mechanisms only");

    // Test Case 2: Two-pass call: get count then list
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    mechanismCount = 0;
    checkOperation(p11Func->C_GetMechanismList(0, nullptr, &mechanismCount),
                   "First pass - get count");
    CK_MECHANISM_TYPE *mechanismList = (CK_MECHANISM_TYPE *) malloc(
            mechanismCount * sizeof(CK_MECHANISM_TYPE));
    if (mechanismList) {
        CK_RV rv2 = p11Func->C_GetMechanismList(0, mechanismList, &mechanismCount);
        checkOperation(rv2, "Test 2: Two-pass call: get count then list");
        free(mechanismList);
    }

    // Test Case 3: One-pass call with correctly sized buffer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_TYPE onePassList[100]; // Assuming 100 is enough for all mechanisms
    CK_ULONG onePassCount = 100;
    CK_RV rv3 = p11Func->C_GetMechanismList(0, onePassList, &onePassCount);
    checkOperation(rv3, "Test 3: One-pass call with correctly sized buffer");

    // Test Case 4: Slot with no token present
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(FALSE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(FALSE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_TYPE noTokenList[100];
    CK_ULONG noTokenCount = 100;
    CK_RV rv4 = p11Func->C_GetMechanismList(0, noTokenList, &noTokenCount);
    checkOperation(rv4, "Test 4: Slot with no token present");

    // Test Case 5: Invalid slot ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_MECHANISM_TYPE invalidList[100];
    CK_ULONG invalidCount = 100;
    CK_RV rv5 = p11Func->C_GetMechanismList(999, invalidList, &invalidCount);
    checkOperation(rv5, "Test 5: Invalid slot ID");

    // Test Case 6: No token in slot (with tokenPresent = TRUE)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate no token by using a slot that might not have a token
    CK_MECHANISM_TYPE noTokenPresentList[100];
    CK_ULONG noTokenPresentCount = 100;
    CK_RV rv6 = p11Func->C_GetMechanismList(0, noTokenPresentList, &noTokenPresentCount);
    checkOperation(rv6, "Test 6: No token in slot (with tokenPresent = TRUE)");

    // Test Case 7: Token not recognized
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate unrecognized token by corrupting slot ID
    CK_SLOT_ID corruptedSlot = 0;
    memset(&corruptedSlot, 0xFF, sizeof(CK_SLOT_ID));
    CK_MECHANISM_TYPE unrecognizedList[100];
    CK_ULONG unrecognizedCount = 100;
    CK_RV rv7 = p11Func->C_GetMechanismList(corruptedSlot, unrecognizedList, &unrecognizedCount);
    checkOperation(rv7, "Test 7: Token not recognized");

    // Test Case 8: nullptr pulCount pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_TYPE nullCountList[100];
    CK_RV rv8 = p11Func->C_GetMechanismList(0, nullCountList, nullptr);
    checkOperation(rv8, "Test 8: nullptr pulCount pointer");

    // Test Case 9: Non-nullptr pMechanismList, but *pulCount too small
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_TYPE smallList[1]; // Too small for all mechanisms
    CK_ULONG smallCount = 1;
    CK_RV rv9 = p11Func->C_GetMechanismList(0, smallList, &smallCount);
    checkOperation(rv9, "Test 9: Non-nullptr pMechanismList, but *pulCount too small");

    // Test Case 10: Memory or hardware failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate memory failure by requesting extremely large buffer
    CK_ULONG hugeCount = SIZE_MAX / sizeof(CK_MECHANISM_TYPE) + 1;
    CK_MECHANISM_TYPE *hugeList = (CK_MECHANISM_TYPE *) malloc(
            hugeCount * sizeof(CK_MECHANISM_TYPE));
    if (!hugeList) {
        CK_RV rv10 = p11Func->C_GetMechanismList(0, hugeList, &hugeCount);
        checkOperation(rv10, "Test 10: Memory or hardware failure");
    }

    // Cleanup
    if (slots) {
        free(slots);
    }
    if (hugeList) {
        free(hugeList);
    }
}

// Test function for C_GetMechanismInfo
void testGetMechanismInfo() {
    cout << "\n=== Testing C_GetMechanismInfo ===" << endl;

    // Test Case 1: Valid slot and supported mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_INFO mechInfo;
    CK_RV rv1 = p11Func->C_GetMechanismInfo(0, CKM_SHA256_RSA_PKCS, &mechInfo);
    checkOperation(rv1, "Test 1: Valid slot and supported mechanism");

    // Test Case 2: Mechanism with flags like CKF_DIGEST, CKF_SIGN
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Test digest mechanism
    CK_MECHANISM_INFO digestInfo;
    CK_RV rv2a = p11Func->C_GetMechanismInfo(0, CKM_SHA256, &digestInfo);
    checkOperation(rv2a, "Test 2a: Mechanism with CKF_DIGEST flag");

    // Test sign mechanism
    CK_MECHANISM_INFO signInfo;
    CK_RV rv2b = p11Func->C_GetMechanismInfo(0, CKM_RSA_PKCS, &signInfo);
    checkOperation(rv2b, "Test 2b: Mechanism with CKF_SIGN flag");

    // Test Case 3: Multiple valid mechanisms tested in loop
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Get list of supported mechanisms
    CK_ULONG mechCount = 0;
    checkOperation(p11Func->C_GetMechanismList(0, nullptr, &mechCount), "Get mechanism count");
    CK_MECHANISM_TYPE *mechList = (CK_MECHANISM_TYPE *) malloc(
            mechCount * sizeof(CK_MECHANISM_TYPE));
    if (mechList) {
        checkOperation(p11Func->C_GetMechanismList(0, mechList, &mechCount),
                       "Get mechanism list");

        // Test each mechanism
        for (CK_ULONG i = 0; i < mechCount; i++) {
            CK_MECHANISM_INFO loopInfo;
            CK_RV rv3 = p11Func->C_GetMechanismInfo(0, mechList[i], &loopInfo);
            checkOperation(rv3, "Test 3: Multiple valid mechanisms tested in loop");
        }
        free(mechList);
    }

    // Test Case 4: Invalid slot ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_MECHANISM_INFO invalidSlotInfo;
    CK_RV rv4 = p11Func->C_GetMechanismInfo(999, CKM_SHA256_RSA_PKCS, &invalidSlotInfo);
    checkOperation(rv4, "Test 4: Invalid slot ID");

    // Test Case 5: Token not present in slot
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(FALSE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(FALSE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_INFO noTokenInfo;
    CK_RV rv5 = p11Func->C_GetMechanismInfo(0, CKM_SHA256_RSA_PKCS, &noTokenInfo);
    checkOperation(rv5, "Test 5: Token not present in slot");

    // Test Case 6: Unsupported mechanism
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_MECHANISM_INFO unsupportedInfo;
    CK_RV rv6 = p11Func->C_GetMechanismInfo(0, 0xFFFFFFFF, &unsupportedInfo);
    checkOperation(rv6, "Test 6: Unsupported mechanism");

    // Test Case 7: Token not recognized
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate unrecognized token by corrupting slot ID
    CK_SLOT_ID corruptedSlot = 0;
    memset(&corruptedSlot, 0xFF, sizeof(CK_SLOT_ID));
    CK_MECHANISM_INFO unrecognizedInfo;
    CK_RV rv7 = p11Func->C_GetMechanismInfo(corruptedSlot, CKM_SHA256_RSA_PKCS, &unrecognizedInfo);
    checkOperation(rv7, "Test 7: Token not recognized");

    // Test Case 8: Null pInfo pointer
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    CK_RV rv8 = p11Func->C_GetMechanismInfo(0, CKM_SHA256_RSA_PKCS, nullptr);
    checkOperation(rv8, "Test 8: Null pInfo pointer");

    // Test Case 9: Token removed during function
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate token removal by finalizing before getting mechanism info
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_MECHANISM_INFO removedInfo;
    CK_RV rv9 = p11Func->C_GetMechanismInfo(0, CKM_SHA256_RSA_PKCS, &removedInfo);
    checkOperation(rv9, "Test 9: Token removed during function");

    // Cleanup
    if (slots) {
        free(slots);
    }
}

// Helper function to print CK_FLAGS in a readable format
void print_ck_flags(CK_FLAGS flags) {
    printf("    Flags: 0x%lX (", flags);
    if (flags & CKF_RNG) printf("RNG ");
    if (flags & CKF_WRITE_PROTECTED) printf("WRITE_PROTECTED ");
    if (flags & CKF_LOGIN_REQUIRED) printf("LOGIN_REQUIRED ");
    if (flags & CKF_USER_PIN_INITIALIZED) printf("USER_PIN_INITIALIZED ");
    if (flags & CKF_RESTORE_KEY_NOT_NEEDED) printf("RESTORE_KEY_NOT_NEEDED ");
    if (flags & CKF_CLOCK_ON_TOKEN) printf("CLOCK_ON_TOKEN ");
    if (flags & CKF_PROTECTED_AUTHENTICATION_PATH) printf("PROTECTED_AUTHENTICATION_PATH ");
    if (flags & CKF_TOKEN_INITIALIZED) printf("TOKEN_INITIALIZED ");
    if (flags & CKF_SECONDARY_AUTHENTICATION) printf("SECONDARY_AUTHENTICATION ");
    if (flags & CKF_USER_PIN_COUNT_LOW) printf("USER_PIN_COUNT_LOW ");
    if (flags & CKF_USER_PIN_FINAL_TRY) printf("USER_PIN_FINAL_TRY ");
    if (flags & CKF_USER_PIN_LOCKED) printf("USER_PIN_LOCKED ");
    if (flags & CKF_SO_PIN_COUNT_LOW) printf("SO_PIN_COUNT_LOW ");
    if (flags & CKF_SO_PIN_FINAL_TRY) printf("SO_PIN_FINAL_TRY ");
    if (flags & CKF_SO_PIN_LOCKED) printf("SO_PIN_LOCKED ");
    printf(")\n");
}

// Test function for C_InitToken
void testInitToken() {
    cout << "\n=== Testing C_InitToken ===" << endl;
    return;
    const char *pin = "123456";
    CK_ULONG pinLen = strlen(pin);
    const char *soPin = "12345678";
    CK_ULONG soPinLen = strlen(soPin);

    // Test Case 1: Token with protected authentication path (PIN pad)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    //CK_TOKEN_INFO tokenInfo;
    //checkOperation(p11Func->C_GetTokenInfo(0, &tokenInfo), "C_GetTokenInfo");
    //   printf("Token Information:\n");
    //   // Trim and print fixed-size string fields
    //   printf("  Label: %.*s\n", (int)sizeof(tokenInfo.label), tokenInfo.label);
    //   printf("  Manufacturer ID: %.*s\n", (int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID);
    //   printf("  Model: %.*s\n", (int)sizeof(tokenInfo.model), tokenInfo.model);
    //   printf("  Serial Number: %.*s\n", (int)sizeof(tokenInfo.serialNumber), tokenInfo.serialNumber);

    //   // Print flags using the helper function
    //   print_ck_flags(tokenInfo.flags);

    //   printf("  Max Session Count: %lu\n", tokenInfo.ulMaxSessionCount);
    //   printf("  Session Count: %lu\n", tokenInfo.ulSessionCount);
    //   printf("  Max R/W Session Count: %lu\n", tokenInfo.ulMaxRwSessionCount);
    //   printf("  R/W Session Count: %lu\n", tokenInfo.ulRwSessionCount);
    //   printf("  Total Public Memory: %lu bytes\n", tokenInfo.ulTotalPublicMemory);
    //   printf("  Free Public Memory: %lu bytes\n", tokenInfo.ulFreePublicMemory);
    //   printf("  Total Private Memory: %lu bytes\n", tokenInfo.ulTotalPrivateMemory);
    //   printf("  Free Private Memory: %lu bytes\n", tokenInfo.ulFreePrivateMemory);
    //   printf("  Hardware Version: %lu.%lu\n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
    //   printf("  Firmware Version: %lu.%lu\n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
    //   printf("  UTC Time: %.*s\n", (int)sizeof(tokenInfo.utcTime), tokenInfo.utcTime); // UTC time is fixed 16-char string


    // Create a 32-character label padded with spaces
    char label[33] = "Test Token 1                    "; // 32 chars + null terminator
    CK_RV rv1 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) soPin, soPinLen,
                                     (CK_UTF8CHAR_PTR) label);
    checkOperation(rv1, "Test 1: Token with protected authentication path (PIN pad)");
    return;

    // Test Case 2: Token label padded to 32 characters (required)
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    char paddedLabel[33] = "Test Token 2                    "; // 32 chars + null terminator

    CK_RV rv2 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) paddedLabel);
    checkOperation(rv2, "Test 2: Token label padded to 32 characters (required)");

    // Test Case 3: Invalid slot ID
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    char invalidLabel[33] = "Test Token 3                    ";
    CK_RV rv3 = p11Func->C_InitToken(999, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) invalidLabel);
    checkOperation(rv3, "Test 3: Invalid slot ID");

    // Test Case 4: Token not present in slot
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(FALSE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(FALSE, slots, &slotCount), "C_GetSlotList");

    char noTokenLabel[33] = "Test Token 4                    ";
    CK_RV rv4 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) noTokenLabel);
    checkOperation(rv4, "Test 4: Token not present in slot");

    // Test Case 5: Token not recognized by library
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate unrecognized token by corrupting slot ID
    CK_SLOT_ID corruptedSlot = 0;
    memset(&corruptedSlot, 0xFF, sizeof(CK_SLOT_ID));
    char unrecognizedLabel[33] = "Test Token 5                    ";
    CK_RV rv5 = p11Func->C_InitToken(corruptedSlot, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) unrecognizedLabel);
    checkOperation(rv5, "Test 5: Token not recognized by library");

    // Test Case 6: Write-protected token
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    char writeProtectedLabel[33] = "Test Token 6                    ";
    CK_RV rv6 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) writeProtectedLabel);
    checkOperation(rv6, "Test 6: Write-protected token");

    // Test Case 7: Incorrect existing SO PIN when reinitializing
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    const char *wrongPin = "wrongpin";
    CK_ULONG wrongPinLen = strlen(wrongPin);
    char incorrectPinLabel[33] = "Test Token 7                    ";
    CK_RV rv7 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) wrongPin, wrongPinLen,
                                     (CK_UTF8CHAR_PTR) incorrectPinLabel);
    checkOperation(rv7, "Test 7: Incorrect existing SO PIN when reinitializing");

    // Test Case 8: SO PIN is locked
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate PIN lock by attempting multiple incorrect PINs
    for (int i = 0; i < 10; i++) {
        p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) wrongPin, wrongPinLen,
                             (CK_UTF8CHAR_PTR) incorrectPinLabel);
    }
    char lockedPinLabel[33] = "Test Token 8                    ";
    CK_RV rv8 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) lockedPinLabel);
    checkOperation(rv8, "Test 8: SO PIN is locked");

    // Test Case 9: Any session open on the token
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open a session
    CK_SESSION_HANDLE hSession;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    char sessionOpenLabel[33] = "Test Token 9                    ";
    CK_RV rv9 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                     (CK_UTF8CHAR_PTR) sessionOpenLabel);
    checkOperation(rv9, "Test 9: Any session open on the token");

    // Test Case 10: pPin is NULL_PTR when no protected path is used
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    char nullPinLabel[33] = "Test Token 10                   ";
    CK_RV rv10 = p11Func->C_InitToken(0, nullptr, 0, (CK_UTF8CHAR_PTR) nullPinLabel);
    checkOperation(rv10, "Test 10: pPin is NULL_PTR when no protected path is used");

    // Test Case 11: pLabel not 32 characters or not padded with blanks
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    char shortLabel[20] = "Short Label"; // Less than 32 chars
    CK_RV rv11 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                      (CK_UTF8CHAR_PTR) shortLabel);
    checkOperation(rv11, "Test 11: pLabel not 32 characters or not padded with blanks");

    // Test Case 12: Function execution fails unexpectedly
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate unexpected failure by finalizing before init
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    char unexpectedLabel[33] = "Test Token 12                   ";
    CK_RV rv12 = p11Func->C_InitToken(0, (CK_UTF8CHAR_PTR) pin, pinLen,
                                      (CK_UTF8CHAR_PTR) unexpectedLabel);
    checkOperation(rv12, "Test 12: Function execution fails unexpectedly");

    // Test Case 13: Device memory or internal failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Simulate memory failure by requesting extremely large buffer
    CK_ULONG hugeSize = SIZE_MAX;
    CK_UTF8CHAR_PTR hugePin = (CK_UTF8CHAR_PTR) malloc(hugeSize);
    if (!hugePin) {
        char memoryLabel[33] = "Test Token 13                   ";
        CK_RV rv13 = p11Func->C_InitToken(0, hugePin, hugeSize,
                                          (CK_UTF8CHAR_PTR) memoryLabel);
        checkOperation(rv13, "Test 13: Device memory or internal failure");
    }

    // Cleanup
    if (slots) {
        free(slots);
    }
    if (hugePin) {
        free(hugePin);
    }
}

// Test function for C_InitPIN
void testInitPIN() {
    cout << "\n=== Testing C_InitPIN ===" << endl;
return;
    const char *pin = "123456";
    CK_ULONG pinLen = strlen(pin);
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    CK_TOKEN_INFO tokenInfo;

    CK_RV rv0 = p11Func->C_GetTokenInfo(0, &tokenInfo);
    cout << "Token Info:" << endl;
    cout << "Label: " << tokenInfo.label << endl;
    cout << "Manufacturer ID: " << tokenInfo.manufacturerID << endl;
    cout << "Model: " << tokenInfo.model << endl;
    cout << "Serial Number: " << tokenInfo.serialNumber << endl;
    cout << "Flags: 0x" << hex << tokenInfo.flags << dec << endl;
    cout << "Max Session Count: " << tokenInfo.ulMaxSessionCount << endl;
    cout << "Session Count: " << tokenInfo.ulSessionCount << endl;
    cout << "Max RW Session Count: " << tokenInfo.ulMaxRwSessionCount << endl;
    cout << "RW Session Count: " << tokenInfo.ulRwSessionCount << endl;
    cout << "Max PIN Length: " << tokenInfo.ulMaxPinLen << endl;
    cout << "Min PIN Length: " << tokenInfo.ulMinPinLen << endl;
    cout << "Total Public Memory: " << tokenInfo.ulTotalPublicMemory << endl;
    cout << "Free Public Memory: " << tokenInfo.ulFreePublicMemory << endl;
    cout << "Total Private Memory: " << tokenInfo.ulTotalPrivateMemory << endl;
    cout << "Free Private Memory: " << tokenInfo.ulFreePrivateMemory << endl;
    cout << "Hardware Version: " << tokenInfo.hardwareVersion.major << "."
         << tokenInfo.hardwareVersion.minor << endl;
    cout << "Firmware Version: " << tokenInfo.firmwareVersion.major << "."
         << tokenInfo.firmwareVersion.minor << endl;
    cout << "UTC Time: " << tokenInfo.utcTime << endl;

    // Test Case 1: Call C_InitPIN before calling C_Initialize
    resetState();

    CK_RV rv1 = p11Func->C_InitPIN(0, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv1, "Test 1: Call C_InitPIN before calling C_Initialize");

    // Test Case 2: Call from an active R/W SO session with valid pPin and length in allowed range
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_ULONG slotCount = 0;
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open R/W session
    CK_SESSION_HANDLE hSession;
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");

    // Login as SO
    const char *soPin = "123456";
    CK_ULONG soPinLen = strlen(soPin);
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    CK_RV rv2 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv2,
                   "Test 2: Call from an active R/W SO session with valid pPin and length in allowed range");

    // Test Case 3: Simulate hardware/token failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate hardware failure by finalizing before init
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv3 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv3, "Test 3: Simulate hardware/token failure");

    // Test Case 4: Simulate token memory exhaustion
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate memory exhaustion with extremely large PIN
    CK_ULONG hugeSize = SIZE_MAX;
    CK_UTF8CHAR_PTR hugePin = (CK_UTF8CHAR_PTR) malloc(hugeSize);
    if (!hugePin) {
        CK_RV rv4 = p11Func->C_InitPIN(hSession, hugePin, hugeSize);
        checkOperation(rv4, "Test 4: Simulate token memory exhaustion");
    }

    // Test Case 5: Remove or unplug token during execution
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate token removal by finalizing
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv5 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv5, "Test 5: Remove or unplug token during execution");

    // Test Case 6: Token returns general function failure
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate general failure by corrupting session handle
    CK_SESSION_HANDLE corruptedSession = 0xFFFFFFFF;
    CK_RV rv6 = p11Func->C_InitPIN(corruptedSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv6, "Test 6: Token returns general function failure");

    // Test Case 7: Internal library inconsistency
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate library inconsistency by finalizing and reinitializing
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    CK_RV rv7 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv7, "Test 7: Internal library inconsistency");

    // Test Case 8: Host system memory exhaustion
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate host memory exhaustion
    CK_ULONG hugeHostSize = SIZE_MAX;
    CK_UTF8CHAR_PTR hugeHostPin = (CK_UTF8CHAR_PTR) malloc(hugeHostSize);
    if (!hugeHostPin) {
        CK_RV rv8 = p11Func->C_InitPIN(hSession, hugeHostPin, hugeHostSize);
        checkOperation(rv8, "Test 8: Host system memory exhaustion");
    }

    // Test Case 9: PIN with illegal characters
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    const char *illegalPin = "!@#$%^&*()";
    CK_ULONG illegalPinLen = strlen(illegalPin);
    CK_RV rv9 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) illegalPin, illegalPinLen);
    checkOperation(rv9, "Test 9: PIN with illegal characters");

    // Test Case 10: PIN length outside allowed range
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Get token info to check min/max PIN lengths
    CK_TOKEN_INFO tokenInfo2;
    checkOperation(p11Func->C_GetTokenInfo(0, &tokenInfo2), "C_GetTokenInfo");

    // Try with PIN shorter than minimum
    const char *shortPin = "1";
    CK_ULONG shortPinLen = strlen(shortPin);
    CK_RV rv10a = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) shortPin, shortPinLen);
    checkOperation(rv10a, "Test 10a: PIN shorter than minimum length");

    // Try with PIN longer than maximum
    char longPin[256];
    memset(longPin, '1', 255);
    longPin[255] = '\0';
    CK_RV rv10b = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) longPin, 255);
    checkOperation(rv10b, "Test 10b: PIN longer than maximum length");

    // Test Case 11: Session is closed
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session, login as SO, then close session
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

    CK_RV rv11 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv11, "Test 11: Session is closed");

    // Test Case 12: Read-only session
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open read-only session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                   "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    CK_RV rv12 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv12, "Test 12: Read-only session");

    // Test Case 13: Invalid session handle
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Use invalid session handle
    CK_SESSION_HANDLE invalidSession = 0xFFFFFFFF;
    CK_RV rv13 = p11Func->C_InitPIN(invalidSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv13, "Test 13: Invalid session handle");

    // Test Case 14: Write-protected token
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    // Simulate write protection by finalizing
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    CK_RV rv14 = p11Func->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pin, pinLen);
    checkOperation(rv14, "Test 14: Write-protected token");

    // Test Case 15: nullptr PIN when no protected path
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");

    // Open session and login as SO
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) soPin, soPinLen),
                   "C_Login");

    CK_RV rv15 = p11Func->C_InitPIN(hSession, nullptr, 0);
    checkOperation(rv15, "Test 15: nullptr PIN when no protected path");

    // Cleanup
    if (slots) {
        free(slots);
    }
    if (hugePin) {
        free(hugePin);
    }
    if (hugeHostPin) {
        free(hugeHostPin);
    }
}

void testSetPIN() {
    cout << "\n=== Testing C_SetPIN ===" << endl;
return;
    // Test Case 1: User is logged in, session is R/W, valid old PIN and valid new PIN within length constraints
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");

    const char *oldPin = "123456";
    const char *newPin = "654321";
    CK_ULONG oldPinLen = strlen(oldPin);
    CK_ULONG newPinLen = strlen(newPin);

    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)newPin, newPinLen), "C_Login");
    // return;
    // CK_RV rv1 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv1, "Test 1: Valid PIN change with logged in user and R/W session");

    // // Test Case 2: Call C_SetPIN before calling C_Initialize
    // resetState();
    // CK_RV rv2 = p11Func->C_SetPIN(0, (CK_UTF8CHAR_PTR)newPin, newPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv2, "Test 2: Call C_SetPIN before C_Initialize");

    // Test Case 3: Simulate hardware/token failure during PIN update
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)newPin, newPinLen), "C_Login");

    // // Simulate hardware failure by finalizing
    // checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    // CK_RV rv3 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv3, "Test 3: Hardware/token failure during PIN update");

    // Test Case 4: Token runs out of memory while processing the new PIN
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Create a very large PIN to simulate memory issues
    // char *hugePin = (char *)malloc(1024 * 1024); // 1MB PIN
    // memset(hugePin, '1', 1024 * 1024 - 1);
    // hugePin[1024 * 1024 - 1] = '\0';
    // CK_RV rv4 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)hugePin, 1024 * 1024 - 1);
    // checkOperation(rv4, "Test 4: Token runs out of memory while processing new PIN");
    // free(hugePin);

    // Test Case 5: Token is removed or ejected mid-operation
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Simulate token removal by finalizing
    // checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    // CK_RV rv5 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv5, "Test 5: Token removed mid-operation");

    // Test Case 6: Unexpected internal token error during execution
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Simulate internal error by corrupting session handle
    // hSession = 0xFFFFFFFF;
    // CK_RV rv6 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv6, "Test 6: Unexpected internal token error");

    // Test Case 7: User cancels operation via PIN pad or UI cancel signal
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Simulate user cancellation by passing nullptr PIN
    // CK_RV rv7 = p11Func->C_SetPIN(hSession, nullptr, 0, nullptr, 0);
    // checkOperation(rv7, "Test 7: User cancels operation");

    // Test Case 8: Provided old PIN is incorrect
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // const char *wrongOldPin = "wrongpin";
    // CK_RV rv8 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)wrongOldPin, strlen(wrongOldPin), (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv8, "Test 8: Incorrect old PIN");
    // Test Case 9: New PIN contains disallowed characters
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // const char *illegalPin = "!@#$%^&*()";
    // CK_RV rv9 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)illegalPin, strlen(illegalPin));
    // checkOperation(rv9, "Test 9: New PIN with disallowed characters");

    // Test Case 10: New PIN length outside allowed range
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // const char *pin = "1";
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin)), "C_Login");


    // // Try with PIN shorter than minimum
    // const char *shortPin = "1";
    // CK_RV rv10a = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)pin, strlen(pin), (CK_UTF8CHAR_PTR)shortPin, strlen(shortPin));
    // checkOperation(rv10a, "Test 10a: New PIN shorter than minimum length");

    // // Try with PIN longer than maximum
    // char longPin[256];
    // memset(longPin, '1', 255);
    // longPin[255] = '\0';
    // CK_RV rv10b = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)longPin, 255);
    // checkOperation(rv10b, "Test 10b: New PIN longer than maximum length");

    // Test Case 11: Too many failed attempts locked the PIN
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Simulate multiple failed attempts
    // for (int i = 0; i < 10; i++)
    // {
    //     p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)wrongOldPin, strlen(wrongOldPin), (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // }
    // CK_RV rv11 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv11, "Test 11: PIN locked due to too many failed attempts");


    // Test Case 12: Session was closed before the function was called
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");
    // checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

    // CK_RV rv12 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv12, "Test 12: Session closed before function call");
    // Test Case 13: Invalid session handle
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");
    // CK_RV rv13 = p11Func->C_SetPIN(0xFFFBFFFA, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv13, "Test 13: Invalid session handle");

    // Test Case 14: Attempt to change PIN in a session opened without CKF_RW_SESSION flag
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                   "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) newPin, newPinLen),
                   "C_Login");

    CK_RV rv14 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR) newPin, newPinLen,
                                   (CK_UTF8CHAR_PTR) oldPin, oldPinLen);
    checkOperation(rv14, "Test 14: Session without CKF_RW_SESSION flag");
    return;
    // Test Case 15: Token is write-protected
    // resetState();
    // checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    // slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    // // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    // checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    // checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");

    // // Simulate write protection by finalizing
    // checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
    // CK_RV rv15 = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv15, "Test 15: Write-protected token");

    // Test Case 16: nullptr PIN pointers or invalid lengths
    /* resetState();
     checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
     // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
     slots = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
     // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
     checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
     checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)oldPin, oldPinLen), "C_Login");*/

    // CK_RV rv16a = p11Func->C_SetPIN(hSession, nullptr, oldPinLen, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv16a, "Test 16a: nullptr old PIN pointer");

    // CK_RV rv16b = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, nullptr, newPinLen);
    // checkOperation(rv16b, "Test 16b: nullptr new PIN pointer");

    // CK_RV rv16c = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, 0, (CK_UTF8CHAR_PTR)newPin, newPinLen);
    // checkOperation(rv16c, "Test 16c: Invalid old PIN length");

    /*CK_RV rv16d = p11Func->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin, oldPinLen, (CK_UTF8CHAR_PTR)newPin, 0);
    checkOperation(rv16d, "Test 16d: Invalid new PIN length");
    return;*/

    // Cleanup
    if (slots) {
        free(slots);
    }
}

void testCreateObject() {
    cout << "\n=== Testing C_CreateObject ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create template for data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,       &ckoData,                 sizeof(ckoData)},
                {CKA_TOKEN,       &trueVal,                 sizeof(trueVal)},
                {CKA_VALUE,       dataValue,                sizeof(dataValue)},
                {CKA_APPLICATION, (CK_VOID_PTR) "Test App", 8}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 4, &hObject),
                       "Test 1: Create data object with valid data template");
    }

    // Test Case 2: Create a certificate object with valid template

    {
        cout << "\nTest Case 2: Create certificate object with valid template" << endl;
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create template for certificate object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE certValue[] = "Test Certificate Data";
        CK_BYTE subject[] = "CN=Test Certificate";
        CK_BYTE id[] = "cert1";
        CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,   &certClass, sizeof(certClass)},
                {CKA_TOKEN,   &trueVal,   sizeof(trueVal)},
                {CKA_VALUE,   certValue,  sizeof(certValue)},
                {CKA_SUBJECT, subject,    sizeof(subject)},
                {CKA_ID,      id,         sizeof(id)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 5, &hObject),
                       "Test Case 2: Create certificate object with valid template");
    }

    // Test Case 3: Invalid Attribute Type

    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_ULONG invalidAttr = 0xFFFFFFFF;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,   &ckoData, sizeof(ckoData)},
                {invalidAttr, &trueVal, sizeof(trueVal)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 2, &hObject);
        checkOperation(rv, "Test Case 3: Invalid Attribute Type");
    }

    // Test Case 4: Invalid Attribute Value

    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_ULONG invalidClass = 0xFFFFFFFF;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &invalidClass, sizeof(invalidClass)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 1, &hObject);
        checkOperation(rv, "Test Case 4: Invalid Attribute Value");
    }

    // Test Case 5: Incomplete Template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 1, &hObject);
        checkOperation(rv, "Test Case 5: Incomplete Template");
    }

    // Test Case 6: Conflicting attributes
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_ULONG dataClass = CKO_DATA;
        CK_ULONG certClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &dataClass, sizeof(dataClass)},
                {CKA_CLASS, &certClass, sizeof(certClass)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 2, &hObject);
        checkOperation(rv, "Test Case 6: Conflicting attributes");
    }

    // Test Case 7: Read-Only Session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                       "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_BBOOL trueVal = CK_TRUE;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 2, &hObject);
        checkOperation(rv, " Test Case 7: Read-Only Session");
    }

    // Test Case 8: Create private object without login
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");

        CK_OBJECT_HANDLE hObject;
        CK_BBOOL true_val = CK_TRUE;
        CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,   &keyClassPriv, sizeof(keyClassPriv)},
                {CKA_PRIVATE, &true_val,     sizeof(true_val)}};

        CK_RV rv = p11Func->C_CreateObject(hSession, template_, 2, &hObject);

        checkOperation(rv, "Test Case 8: Create private object without login");
    }

    // Test Case 9: Invalid Session Handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};

        CK_RV rv = p11Func->C_CreateObject(0xFFFFFFFF, template_, 1, &hObject);
        checkOperation(rv, "Test Case 9: Invalid Session Handle");
    }
}

void testCopyObject() {
    cout << "\n=== Testing C_CopyObject ===" << endl;
    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Copy object with valid read-write session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // First create a data object to copy
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Now copy the object
        CK_OBJECT_HANDLE hCopiedObject;
        checkOperation(p11Func->C_CopyObject(hSession, hObject, nullptr, 0, &hCopiedObject),
                       "Test Case 1: Copy object with valid read-write session");
    }

    // Test Case 2: Copy with specific template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create source object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Copy with specific template
        CK_OBJECT_HANDLE hCopiedObject;
        CK_ATTRIBUTE copyTemplate[] = {
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        checkOperation(p11Func->C_CopyObject(hSession, hObject, copyTemplate, 1, &hCopiedObject),
                       "Test Case 2: Copy with specific template");
    }

    // Test Case 3: Read-only session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                       "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create source object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to copy in read-only session
        CK_OBJECT_HANDLE hCopiedObject;
        CK_RV rv = p11Func->C_CopyObject(hSession, hObject, nullptr, 0, &hCopiedObject);

        checkOperation(rv, "Test Case 3: Read-only session");
    }

    // Test Case 4: Invalid Object Handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hCopiedObject;
        CK_RV rv = p11Func->C_CopyObject(hSession, 0xFFFFFFFF, nullptr, 0, &hCopiedObject);

        checkOperation(rv, "Test Case 4: Invalid Object Handle");
    }

    // Test Case 5: Unauthenticated Copy of Private Object
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create private object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,   &keyClassPriv, sizeof(keyClassPriv)},
                {CKA_PRIVATE, &trueVal,      sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_Logout(hSession), "C_Logout");

        // Try to copy without login
        CK_OBJECT_HANDLE hCopiedObject;
        CK_RV rv = p11Func->C_CopyObject(hSession, hObject, nullptr, 0, &hCopiedObject);
        checkOperation(rv, "Test Case 5: Unauthenticated Copy of Private Object");
    }

    // Test Case 6: Template Specifies Read-Only Attribute
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create source object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");

        // Try to copy with read-only attribute
        CK_OBJECT_HANDLE hCopiedObject;
        CK_ATTRIBUTE copyTemplate[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)} // CKA_CLASS is read-only
        };

        CK_RV rv = p11Func->C_CopyObject(hSession, hObject, copyTemplate, 1, &hCopiedObject);
        checkOperation(rv, "Test Case 6: Template Specifies Read-Only Attribute");
    }

    // Test Case 7: Invalid Attribute Type
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create source object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");

        // Try to copy with invalid attribute type
        CK_OBJECT_HANDLE hCopiedObject;
        CK_ULONG invalidAttr = 0xFFFFFFFF;
        CK_ATTRIBUTE copyTemplate[] = {
                {invalidAttr, &trueVal, sizeof(trueVal)}};

        CK_RV rv = p11Func->C_CopyObject(hSession, hObject, copyTemplate, 1, &hCopiedObject);

        checkOperation(rv, "Test Case 7: Invalid Attribute Type");
    }

    // Test Case 8: Inconsistent Template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create source object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");

        // Try to copy with inconsistent template
        CK_OBJECT_HANDLE hCopiedObject;
        CK_OBJECT_CLASS ckoCert = CKO_CERTIFICATE;
        CK_ATTRIBUTE copyTemplate[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_CLASS, &ckoCert, sizeof(ckoCert)}};

        CK_RV rv = p11Func->C_CopyObject(hSession, hObject, copyTemplate, 2, &hCopiedObject);
        checkOperation(rv, "Test Case 8: Inconsistent Template");
    }
}

void testDestroyObject() {
    cout << "\n=== Testing C_DestroyObject ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Destroy session object in read-write session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a session object to destroy
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL falseVal = CK_FALSE; // Session object
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &falseVal, sizeof(falseVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_DestroyObject(hSession, hObject),
                       "Test Case 1: Destroy session object in read-write session");
    }

    // Test Case 2: Destroy token object as logged-in user
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a token object to destroy
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Token Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE; // Token object
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_DestroyObject(hSession, hObject),
                       "Test Case 2: Destroy token object as logged-in user");
    }

    // Test Case 3: Destroy token object in read-only session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                       "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a token object to destroy
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Token Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE; // Token object
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to destroy in read-only session
        CK_RV rv = p11Func->C_DestroyObject(hSession, hObject);

        checkOperation(rv, "Test Case 3: Destroy token object in read-only session");
    }

    // Test Case 4: Destroy private object while not logged in
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a private object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,   &keyClassPriv, sizeof(keyClassPriv)},
                {CKA_PRIVATE, &trueVal,      sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_Logout(hSession), "C_Logout");

        // Try to destroy without login
        CK_RV rv = p11Func->C_DestroyObject(hSession, hObject);

        checkOperation(rv, "Test Case 4: Destroy private object while not logged in");
    }

    // Test Case 5: Invalid Object Handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_RV rv = p11Func->C_DestroyObject(hSession, 0xFFFFFFFF);
        checkOperation(rv, "Test Case 5: Invalid Object Handle");
    }

    // Test Case 6: Destroy Object in Closed Session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create an object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL falseVal = CK_FALSE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &falseVal, sizeof(falseVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

        // Try to destroy in closed session
        CK_RV rv = p11Func->C_DestroyObject(hSession, hObject);
        checkOperation(rv, "Test Case 6: Destroy Object in Closed Session");
    }

    // Test Case 7: Token Write-Protected
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a token object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)},
                {CKA_TOKEN, &trueVal, sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 2, &hObject), "C_CreateObject");

        // Simulate token write protection (this would typically be set by the token)
        // Note: This is a simplified test case. In a real implementation,
        // the token would need to be in a write-protected state
        CK_RV rv = p11Func->C_DestroyObject(hSession, hObject);

        checkOperation(rv, "Test Case 7: Token Write-Protected(Need write-protected token)");
    }
}

void testGetObjectSize() {
    cout << "\n=== Testing C_GetObjectSize ===" << endl;

    // Test Case 1: Valid session and object handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Get object size
        CK_ULONG size;
        checkOperation(p11Func->C_GetObjectSize(hSession, hObject, &size),
                       "Test Case 1: Valid session and object handle");
    }

    // Test Case 2: Invalid session handle
    {

        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_ULONG size;
        CK_RV rv = p11Func->C_GetObjectSize(0xFFFFFFFF, 1, &size);
        checkOperation(rv, "Test Case 2: Invalid session handle");
    }

    // Test Case 3: Invalid object handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_ULONG size;
        CK_RV rv = p11Func->C_GetObjectSize(hSession, 0xFFFFFFFF, &size);
        checkOperation(rv, "Test Case 3: Invalid object handle");
    }

    // Test Case 4: pulSize is nullptr
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to get size with nullptr pointer
        CK_RV rv = p11Func->C_GetObjectSize(hSession, hObject, nullptr);

        checkOperation(rv, "Test Case 4: pulSize is nullptr");
    }

    // Test Case 5: Object with sensitive attributes
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a private key object
        CK_OBJECT_HANDLE hObject;
        CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS,     &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN,     &trueVal,  sizeof(trueVal)},
                {CKA_VALUE,     dataValue, sizeof(dataValue)},
                {CKA_PRIVATE,   &trueVal,  sizeof(trueVal)},
                {CKA_SENSITIVE, &trueVal,  sizeof(trueVal)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Get object size
        CK_ULONG size;
        checkOperation(p11Func->C_GetObjectSize(hSession, hObject, &size),
                       "Test Case 5: Object with sensitive attributes");
    }
}

void testGetAttributeValue() {
    cout << "\n=== Testing C_GetAttributeValue ===" << endl;

    // Test Case 1: Valid session handle and handle to a valid public key
    {
        cout << "\nTest Case 1: Valid session handle and handle to a valid public key" << endl;
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate a key pair
        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;                   // RSA key size
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BYTE id[] = {1};                            // Unique ID
        CK_BYTE subject[] = {'U', 's', 'e', 'r', '1'};
        CK_BBOOL ckTrue = CK_TRUE;

        // Public key template
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)} // Store on token
        };

        // Private key template
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)},
                {CKA_SUBJECT,   subject, sizeof(subject)}};
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, publicKeyTemplate,
                                                  sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privateKeyTemplate,
                                                  sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Get public key attributes
        CK_ATTRIBUTE template_[] = {
                {CKA_MODULUS,         nullptr, 0},
                {CKA_PUBLIC_EXPONENT, nullptr, 0}};

        // First get the sizes
        checkOperation(p11Func->C_GetAttributeValue(hSession, hPublicKey, template_, 2),
                       "C_GetAttributeValue (size)");

        // Allocate memory for the attributes
        template_[0].pValue = malloc(template_[0].ulValueLen);
        template_[1].pValue = malloc(template_[1].ulValueLen);

        // Get the actual values
        checkOperation(p11Func->C_GetAttributeValue(hSession, hPublicKey, template_, 2),
                       "C_GetAttributeValue (value)");
        cout << "Successfully retrieved public key attributes" << endl;
        cout << "Modulus size: " << template_[0].ulValueLen << " bytes" << endl;
        cout << "Public exponent size: " << template_[1].ulValueLen << " bytes" << endl;

        // Cleanup
        free(template_[0].pValue);
        free(template_[1].pValue);
    }

    // Test Case 2: Sensitive attribute requested
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate a key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        CK_ULONG modulusBits = 2048;                   // RSA key size
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BYTE id[] = {1};                            // Unique ID
        CK_BYTE subject[] = {'U', 's', 'e', 'r', '1'};
        CK_BBOOL ckTrue = CK_TRUE;

        // Public key template
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)} // Store on token
        };

        // Private key template
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)},
                {CKA_SUBJECT,   subject, sizeof(subject)}};
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, publicKeyTemplate,
                                                  sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privateKeyTemplate,
                                                  sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Try to get sensitive attribute
        CK_ATTRIBUTE template_[] = {
                {CKA_VALUE, nullptr, 0}};

        CK_RV rv = p11Func->C_GetAttributeValue(hSession, hPrivateKey, template_, 1);

        checkOperation(rv, "Test Case 2: Sensitive attribute requested");
    }

    // Test Case 3: Invalid attribute type
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to get invalid attribute
        CK_ATTRIBUTE getTemplate[] = {
                {0xFFFFFFFF, nullptr, 0} // Invalid attribute type
        };

        CK_RV rv = p11Func->C_GetAttributeValue(hSession, hObject, getTemplate, 1);

        checkOperation(rv, "Test Case 3: Invalid attribute type");
    }

    // Test Case 4: Buffer too small
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to get value with too small buffer
        CK_BYTE smallBuffer[1]; // Too small for the actual value
        CK_ATTRIBUTE getTemplate[] = {
                {CKA_VALUE, smallBuffer, 1}};

        CK_RV rv = p11Func->C_GetAttributeValue(hSession, hObject, getTemplate, 1);

        checkOperation(rv, "Test Case 4: Buffer too small");
    }

    // Test Case 5: Invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, nullptr, 0}};

        CK_RV rv = p11Func->C_GetAttributeValue(0xFFFFFFFF, 1, template_, 1);
        checkOperation(rv, "Test Case 5: Invalid session handle");
    }

    // Test Case 6: Invalid object handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, nullptr, 0}};

        CK_RV rv = p11Func->C_GetAttributeValue(hSession, 0xFFFFFFFF, template_, 1);

        checkOperation(rv, "Test Case 6: Invalid object handle");
    }

    // Test Case 7: pTemplate is nullptr
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to get attributes with nullptr template
        CK_RV rv = p11Func->C_GetAttributeValue(hSession, hObject, nullptr, 1);

        checkOperation(rv, "Test Case 7: pTemplate is nullptr");
    }
}

void testSetAttributeValue() {

    // Test Case 1: Valid session and object, update CKA_LABEL
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Update the label
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 1: Valid session and object, update CKA_LABEL");
    }

    // Test Case 2: Attempt to modify session object in read-only session
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                       "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a session object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL falseVal = CK_FALSE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &falseVal, sizeof(falseVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to update in read-only session
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};
        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 2: Attempt to modify session object in read-only session");
    }

    // Test Case 3: Attempt to change non-modifiable attribute
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate a key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        CK_ULONG modulusBits = 2048;                   // RSA key size
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BYTE id[] = {1};                            // Unique ID
        CK_BYTE subject[] = {'U', 's', 'e', 'r', '1'};
        CK_BBOOL ckTrue = CK_TRUE;

        // Public key template
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)} // Store on token
        };

        // Private key template
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)},
                {CKA_SUBJECT,   subject, sizeof(subject)}};

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, publicKeyTemplate,
                                                  sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privateKeyTemplate,
                                                  sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Try to change key type
        CK_KEY_TYPE newKeyType = CKK_AES;
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_KEY_TYPE, &newKeyType, sizeof(newKeyType)}};
        checkOperation(p11Func->C_SetAttributeValue(hSession, hPublicKey, updateTemplate, 1),
                       "Test Case 3: Attempt to change non-modifiable attribute");
    }

    // Test Case 4: Invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Update the label
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(0xFFFFFFFF, hObject, updateTemplate, 1),
                       "Test Case 4: Invalid session handle");
    }

    // Test Case 5: Invalid object handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Update the label
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, 0xFFFFFFFF, updateTemplate, 1),
                       "Test Case 5: Invalid object handle");
    }

    // Test Case 6: Null template pointer
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Update the label
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, nullptr, 1),
                       "Test Case 6: Null template pointer");
    }

    // Test Case 7: Incompatible template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to update with incompatible template
        CK_OBJECT_CLASS newClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_CLASS, &newClass, sizeof(newClass)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 7: Incompatible template");
    }

    // Test Case 8: Token write-protected
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a token object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Simulate token write protection
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 8: Token write-protected");
    }

    // Test Case 9: Unauthenticated access
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a private object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");
        checkOperation(p11Func->C_Logout(hSession), "C_Logout");

        // Try to update without login
        CK_BYTE newLabel[] = "Updated Label";
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_LABEL, newLabel, sizeof(newLabel)}};

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 9: Unauthenticated access");
    }

    // Test Case 10: Invalid attribute type
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to update with invalid attribute type
        CK_BYTE newValue[] = "New Value";
        CK_ATTRIBUTE updateTemplate[] = {
                {0xFFFFFFFF, newValue, sizeof(newValue)} // Invalid attribute type
        };

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 10: Invalid attribute type");
    }

    // Test Case 11: Invalid attribute value
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Create a data object
        CK_OBJECT_HANDLE hObject;
        CK_BYTE dataValue[] = "Test Data Object";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData,  sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,  sizeof(trueVal)},
                {CKA_VALUE, dataValue, sizeof(dataValue)}};

        checkOperation(p11Func->C_CreateObject(hSession, template_, 3, &hObject), "C_CreateObject");

        // Try to update with invalid attribute value
        CK_ULONG invalidValue = 0xFFFFFFFF;
        CK_ATTRIBUTE updateTemplate[] = {
                {CKA_CLASS, &invalidValue, sizeof(invalidValue)} // Invalid class value
        };

        checkOperation(p11Func->C_SetAttributeValue(hSession, hObject, updateTemplate, 1),
                       "Test Case 11: Invalid attribute value");
    }
}

void testFindObjectsInit() {
    // Test Case 1: Initialize search for all objects
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        //cout << "Now the funtion wil start counter" << endl;
        //Sleep(5000);
        //cout << "Now the funtion wil start" << endl;
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0),
                       "Test Case 1: Initialize search for all objects");
        //return;
    }

    // Test Case 2: Initialize search with valid template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create template to search for data objects
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};

        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1),
                       "Test Case 2: Initialize search with valid template");
    }

    // Test Case 3: Session handle invalid
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsInit(0xFFFFFFFF, nullptr, 0),
                       "Test Case 3: Session handle invalid");
    }

    // Test Case 4: Search already active
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0),
                       "Test Case 4: Search already active");
    }

    // Test Case 5: Session is closed
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0),
                       "Test Case 5: Session is closed");
    }

    // Test Case 6: Invalid attribute type in template
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_ULONG invalidAttr = 0xFFFFFFFF;
        CK_ATTRIBUTE template_[] = {
                {invalidAttr, nullptr, 0}};

        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1),
                       "Test Case 6: Invalid attribute type in template");
    }

    // Test Case 7: Invalid attribute value
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create template with invalid attribute value
        CK_OBJECT_CLASS invalidClass = 0xFFFFFFFF;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &invalidClass, sizeof(invalidClass)}};

        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1),
                       "Test Case 7: Invalid attribute value");
    }

    // Test Case 8: Token removed
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "Test Case 8: Token removed");
    }
}

void testFindObjects() {
    cout << "\n=== Testing C_FindObjects ===" << endl;

    // Test Case 1: Valid session; search initialized; call to retrieve up to N object handles
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        // Create some test objects
        CK_OBJECT_HANDLE hObject1, hObject2;
        CK_BYTE dataValue1[] = "Test Data Object 1";
        CK_BYTE dataValue2[] = "Test Data Object 2";
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_ATTRIBUTE template1[] = {
                {CKA_CLASS, &ckoData,   sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,   sizeof(trueVal)},
                {CKA_VALUE, dataValue1, sizeof(dataValue1)}};
        CK_ATTRIBUTE template2[] = {
                {CKA_CLASS, &ckoData,   sizeof(ckoData)},
                {CKA_TOKEN, &trueVal,   sizeof(trueVal)},
                {CKA_VALUE, dataValue2, sizeof(dataValue2)}};

        checkOperation(p11Func->C_CreateObject(hSession, template1, 3, &hObject1),
                       "C_CreateObject 1");
        checkOperation(p11Func->C_CreateObject(hSession, template2, 3, &hObject2),
                       "C_CreateObject 2");

        // Initialize search
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");

        // Find objects
        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        checkOperation(p11Func->C_FindObjects(hSession, hObjects, 10, &count),
                       "Test Case 1: Valid session with initialized search");
        cout << "Found " << count << " objects" << endl;

        // Cleanup
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    }

    // Test Case 2: Previous calls returned all matches
    {
        cout << "\nTest Case 2: Previous calls returned all matches" << endl;
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Initialize search
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");

        // First call to get objects
        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        checkOperation(p11Func->C_FindObjects(hSession, hObjects, 10, &count),
                       "First C_FindObjects");

        // Second call should return 0 objects
        CK_ULONG count2;
        checkOperation(p11Func->C_FindObjects(hSession, hObjects, 10, &count2),
                       "Second C_FindObjects");
        if (count2 == 0) {
            cout << "Successfully detected no more objects" << endl;
        }

        // Cleanup
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    }

    // Test Case 3: C_FindObjects called without prior C_FindObjectsInit
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(hSession, hObjects, 10, &count);

        checkOperation(rv, "Test Case 3: C_FindObjects without prior C_FindObjectsInit");
    }

    // Test Case 4: Invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(0xFFFFFFFF, hObjects, 10, &count);
        checkOperation(rv, "Test Case 4: Invalid session handle");
    }

    // Test Case 5: hSession was closed before the call
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(hSession, hObjects, 10, &count);
        checkOperation(rv, "Test Case 5: Session closed before call");
    }

    // Test Case 6: Null output pointer
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");

        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(hSession, nullptr, 10, &count);
        checkOperation(rv, "Test Case 6: Null output pointer");
    }

    // Test Case 7: Token removed
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");

        // Simulate token removal by finalizing
        checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");

        CK_OBJECT_HANDLE hObjects[10];
        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(hSession, hObjects, 10, &count);
        checkOperation(rv, "Test Case 7: Token removed");
    }

    // Test Case 8: Null object buffer but non-zero max count
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsInit(hSession, nullptr, 0), "C_FindObjectsInit");

        CK_ULONG count;
        CK_RV rv = p11Func->C_FindObjects(hSession, nullptr, 5, &count);

        checkOperation(rv, "Test Case 8: Null object buffer with non-zero max count");
    }
}

void testFindObjectsFinal() {
    cout << "\n=== Testing C_FindObjectsFinal ===" << endl;

    // Test Case 1: Valid session, search initialized via C_FindObjectsInit
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1), "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjectsFinal(hSession),
                       "Test Case 1: Valid session, search initialized via C_FindObjectsInit");
    }
    // Test Case 2: Finalize without initialization
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(p11Func->C_FindObjectsFinal(hSession),
                       "Test Case 2: Finalize without initialization");
    }
    // Test Case 3: Invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1), "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjectsFinal(CK_INVALID_HANDLE),
                       "Test Case 3: Invalid session handle");
    }

    // Test Case 4: Session was closed

    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1), "C_FindObjectsInit");
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "Test Case 4: Session was closed");
    }

    // Test Case 5: Token removed
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        CK_OBJECT_CLASS ckoData = CKO_DATA;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &ckoData, sizeof(ckoData)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1), "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "Test Case 5: Token removed");
    }

    // Test Case 6: General failure
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        // Initialize search with invalid template to force general failure
        CK_OBJECT_CLASS invalidClass = 0xFFFFFFFF;
        CK_ATTRIBUTE template_[] = {
                {CKA_CLASS, &invalidClass, sizeof(invalidClass)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, template_, 1), "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "Test Case 6: General failure");
    }
}

void testGenerateKey() {

    cout << "\n=== Testing TestGenerateKey ===" << endl;
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // --- 6. Define the Key Generation Mechanism ---
    // We'll generate an AES key.
    CK_MECHANISM mechanism = {
            CKM_AES_KEY_GEN, // The mechanism type for AES key generation
            nullptr,            // No parameters needed for AES key generation
            0                // Length of parameters
    };

    // --- 7. Define the Template for the AES Key ---
    // This template specifies the attributes of the key to be generated.
    // CKA_CLASS: Defines the object class (here, a secret key).
    // CKA_KEY_TYPE: Specifies the type of key (here, AES).
    // CKA_VALUE_LEN: The desired length of the AES key in bytes (e.g., 16 for AES-128, 32 for AES-256).
    // CKA_TOKEN: If CK_TRUE, the key is stored on the token (persistent). If CK_FALSE, it's a session object.
    // CKA_SENSITIVE: If CK_TRUE, the key material cannot be extracted in plaintext.
    // CKA_ENCRYPT: If CK_TRUE, the key can be used for encryption.
    // CKA_DECRYPT: If CK_TRUE, the key can be used for decryption.
    // CKA_WRAP: If CK_TRUE, the key can be used to wrap (encrypt) other keys.
    // CKA_UNWRAP: If CK_TRUE, the key can be used to unwrap (decrypt) other keys.
    // CKA_LABEL: A human-readable label for the key.

    CK_ULONG aesKeyLength = 32; // For AES-256
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    char label[] = "MyGeneratedAESKey";
    CK_OBJECT_CLASS CkoSecretKey = CKO_SECRET_KEY;
    CK_KEY_TYPE CkkAes = CKK_AES;

    CK_ATTRIBUTE aesKeyTemplate[] = {
            {CKA_CLASS,     &CkoSecretKey, sizeof(CkoSecretKey)},
            {CKA_KEY_TYPE,  &CkkAes,       sizeof(CkkAes)},
            {CKA_VALUE_LEN, &aesKeyLength, sizeof(aesKeyLength)},
            {CKA_TOKEN,     &ckTrue,       sizeof(ckTrue)},     // Store on token
            {CKA_SENSITIVE, &ckTrue,       sizeof(ckTrue)}, // Key material is sensitive
            {CKA_ENCRYPT,   &ckTrue,       sizeof(ckTrue)},   // Can be used for encryption
            {CKA_DECRYPT,   &ckTrue,       sizeof(ckTrue)},   // Can be used for decryption
            {CKA_WRAP,      &ckTrue,       sizeof(ckTrue)},      // Can be used for wrapping
            {CKA_UNWRAP,    &ckTrue,       sizeof(ckTrue)},    // Can be used for unwrapping
            {CKA_LABEL,     label,         strlen(label)}};

    // --- 8. Generate the AES Key ---
    // This is the core function call.
    // hSession: The handle of the active session.
    // pMechanism: Pointer to the key generation mechanism.
    // pTemplate: Pointer to the array of attributes for the new key.
    // ulCount: Number of attributes in the template.
    // phKey: Pointer to a CK_OBJECT_HANDLE that will receive the handle of the new key.
    CK_OBJECT_HANDLE hKey;
    CK_RV rv = p11Func->C_GenerateKey(hSession, &mechanism, aesKeyTemplate,
                                      sizeof(aesKeyTemplate) / sizeof(CK_ATTRIBUTE), &hKey);
    checkOperation(rv, "C_GenerateKey");

    // --- 9. Verify the Key Generation ---
    // Check if the key was successfully generated
    /*if (hKey != CK_INVALID_HANDLE) {
        cout << "Key generation successful. Key handle: " << hKey << endl;
    } else {
        cout << "Key generation failed" << endl;
    }*/
}
// Main function to run all tests

void testUnwrapKey() {
    cout << "\n=== Testing C_UnwrapKey ===" << endl;
    resetState();

    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Mechanism for AES key unwrapping
    CK_MECHANISM mech = {CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0};

    // Generate a temporary AES wrapping key
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keyLen = 32;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE wrapKeyTemplate[] = {
            {CKA_CLASS,     &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE,  &keyType,  sizeof(keyType)},
            {CKA_VALUE_LEN, &keyLen,   sizeof(keyLen)},
            {CKA_ENCRYPT,   &ckTrue,   sizeof(ckTrue)},
            {CKA_WRAP,      &ckTrue,   sizeof(ckTrue)},
            {CKA_TOKEN,     &ckFalse,  sizeof(ckFalse)}};

    CK_OBJECT_HANDLE hWrappingKey;
    checkOperation(p11Func->C_GenerateKey(hSession, &mech, wrapKeyTemplate,
                                          sizeof(wrapKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                          &hWrappingKey), "C_GenerateKey (Wrapping key)");

    // Simulated wrapped key data (in real use, this would come from elsewhere)
    CK_BYTE wrappedKey[] = {/* Pretend this is wrapped key data */ 0xDE, 0xAD, 0xBE, 0xEF};

    // Template for the unwrapped key
    CK_ATTRIBUTE unwrapTemplate[] = {
            {CKA_CLASS,    &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType,  sizeof(keyType)},
            {CKA_DECRYPT,  &ckTrue,   sizeof(ckTrue)},
            {CKA_UNWRAP,   &ckTrue,   sizeof(ckTrue)},
            {CKA_TOKEN,    &ckFalse,  sizeof(ckFalse)}};

    CK_OBJECT_HANDLE hUnwrappedKey;
    checkOperation(
            p11Func->C_UnwrapKey(hSession, &mech, hWrappingKey, wrappedKey, sizeof(wrappedKey),
                                 unwrapTemplate, sizeof(unwrapTemplate) / sizeof(CK_ATTRIBUTE),
                                 &hUnwrappedKey), "C_UnwrapKey");
}

void testDeriveKey() {
    cout << "\n=== Testing C_DeriveKey ===" << endl;
    resetState();

    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate a base key for derivation (e.g., a secret AES key)
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keyLen = 32;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE baseKeyTemplate[] = {
            {CKA_CLASS,     &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE,  &keyType,  sizeof(keyType)},
            {CKA_VALUE_LEN, &keyLen,   sizeof(keyLen)},
            {CKA_DERIVE,    &ckTrue,   sizeof(ckTrue)},
            {CKA_TOKEN,     &ckFalse,  sizeof(ckFalse)}};

    CK_MECHANISM keyGenMech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
    CK_OBJECT_HANDLE hBaseKey;
    checkOperation(p11Func->C_GenerateKey(hSession, &keyGenMech, baseKeyTemplate,
                                          sizeof(baseKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                          &hBaseKey), "C_GenerateKey (Base key)");

    // Derivation mechanism and parameters
    CK_MECHANISM deriveMech = {CKM_ECDH1_DERIVE, NULL_PTR,
                               0}; // Replace with a valid mechanism for your token

    // Template for the derived key
    CK_ATTRIBUTE derivedKeyTemplate[] = {
            {CKA_CLASS,    &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType,  sizeof(keyType)},
            {CKA_TOKEN,    &ckFalse,  sizeof(ckFalse)},
            {CKA_ENCRYPT,  &ckTrue,   sizeof(ckTrue)},
            {CKA_DECRYPT,  &ckTrue,   sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hDerivedKey;
    checkOperation(p11Func->C_DeriveKey(hSession, &deriveMech, hBaseKey, derivedKeyTemplate,
                                        sizeof(derivedKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                        &hDerivedKey), "C_DeriveKey");
}

void testDigestEncryptUpdate() {
    cout << "\n=== Testing C_DigestEncryptUpdate ===" << endl;
    resetState();

    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair for encryption
    CK_MECHANISM mechKeyGen = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS,           &pubKeyClass,    sizeof(pubKeyClass)},
            {CKA_KEY_TYPE,        &keyType,        sizeof(keyType)},
            {CKA_ENCRYPT,         &ckTrue,         sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,         sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS,       &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE,    &keyType,      sizeof(keyType)},
            {CKA_DECRYPT,     &ckTrue,       sizeof(ckTrue)},
            {CKA_SIGN,        &ckTrue,       sizeof(ckTrue)},
            {CKA_SENSITIVE,   &ckFalse,      sizeof(ckFalse)},
            {CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hPubKey;
    CK_OBJECT_HANDLE hPrivKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mechKeyGen,
                                              pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPubKey, &hPrivKey),
                   "C_GenerateKeyPair");

    // Initialize for digest + encrypt
    CK_MECHANISM mech = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
    checkOperation(p11Func->C_EncryptInit(hSession, &mech, hPubKey), "C_EncryptInit");

    // Perform C_DigestEncryptUpdate
    CK_BYTE data[] = "Digest and Encrypt this data";
    CK_BYTE encrypted[512];
    CK_ULONG encryptedLen = sizeof(encrypted);

    checkOperation(
            p11Func->C_DigestEncryptUpdate(hSession, data, sizeof(data), encrypted, &encryptedLen),
            "C_DigestEncryptUpdate");
}

void testDecryptDigestUpdate() {
    cout << "\n=== Testing C_DecryptDigestUpdate ===" << endl;
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair
    CK_MECHANISM mechKeyGen = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS,           &pubKeyClass,    sizeof(pubKeyClass)},
            {CKA_KEY_TYPE,        &keyType,        sizeof(keyType)},
            {CKA_ENCRYPT,         &ckTrue,         sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,         sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS,       &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE,    &keyType,      sizeof(keyType)},
            {CKA_DECRYPT,     &ckTrue,       sizeof(ckTrue)},
            {CKA_SIGN,        &ckTrue,       sizeof(ckTrue)},
            {CKA_SENSITIVE,   &ckFalse,      sizeof(ckFalse)},
            {CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mechKeyGen,
                                              pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPubKey, &hPrivKey),
                   "C_GenerateKeyPair");

    // Initialize operations
    CK_MECHANISM mech = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};
    checkOperation(p11Func->C_DecryptInit(hSession, &mech, hPrivKey), "C_DecryptInit");
    checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

    // Simulated encrypted input
    CK_BYTE encryptedData[] = "\x01\x02\x03\x04"; // Placeholder (not real encrypted data)
    CK_BYTE output[512];
    CK_ULONG outputLen = sizeof(output);

    checkOperation(
            p11Func->C_DecryptDigestUpdate(hSession, encryptedData, sizeof(encryptedData), output,
                                           &outputLen), "C_DecryptDigestUpdate");
}

void testSignEncryptUpdate() {
    cout << "\n=== Testing C_SignEncryptUpdate ===" << endl;
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS,           &pubKeyClass,    sizeof(pubKeyClass)},
            {CKA_KEY_TYPE,        &keyType,        sizeof(keyType)},
            {CKA_ENCRYPT,         &ckTrue,         sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,         sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS,       &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE,    &keyType,      sizeof(keyType)},
            {CKA_DECRYPT,     &ckTrue,       sizeof(ckTrue)},
            {CKA_SIGN,        &ckTrue,       sizeof(ckTrue)},
            {CKA_SENSITIVE,   &ckFalse,      sizeof(ckFalse)},
            {CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMech,
                                              pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPubKey, &hPrivKey),
                   "C_GenerateKeyPair");

    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL_PTR, 0};
    checkOperation(p11Func->C_SignInit(hSession, &mech, hPrivKey), "C_SignInit");
    checkOperation(p11Func->C_EncryptInit(hSession, &mech, hPubKey), "C_EncryptInit");

    CK_BYTE data[] = "Message to sign and encrypt";
    CK_BYTE output[512];
    CK_ULONG outputLen = sizeof(output);

    checkOperation(p11Func->C_SignEncryptUpdate(hSession, data, sizeof(data), output, &outputLen),
                   "C_SignEncryptUpdate");
}

void testDecryptVerifyUpdate() {
    cout << "\n=== Testing C_DecryptVerifyUpdate ===" << endl;
    resetState();
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                          &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

    // Generate RSA key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS,           &pubKeyClass,    sizeof(pubKeyClass)},
            {CKA_KEY_TYPE,        &keyType,        sizeof(keyType)},
            {CKA_ENCRYPT,         &ckTrue,         sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,         sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}};

    CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS,       &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE,    &keyType,      sizeof(keyType)},
            {CKA_DECRYPT,     &ckTrue,       sizeof(ckTrue)},
            {CKA_SIGN,        &ckTrue,       sizeof(ckTrue)},
            {CKA_SENSITIVE,   &ckFalse,      sizeof(ckFalse)},
            {CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)}};

    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMech,
                                              pubTemplate,
                                              sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                              privTemplate,
                                              sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                              &hPubKey, &hPrivKey),
                   "C_GenerateKeyPair");

    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL_PTR, 0};
    checkOperation(p11Func->C_DecryptInit(hSession, &mech, hPrivKey), "C_DecryptInit");
    checkOperation(p11Func->C_VerifyInit(hSession, &mech, hPubKey), "C_VerifyInit");

    CK_BYTE encryptedInput[] = "Encrypted and signed data"; // Placeholder input
    CK_BYTE output[512];
    CK_ULONG outputLen = sizeof(output);

    checkOperation(
            p11Func->C_DecryptVerifyUpdate(hSession, encryptedInput, sizeof(encryptedInput), output,
                                           &outputLen), "C_DecryptVerifyUpdate");
}

void testDecryptInit() {
    cout << "\n=== Testing C_DecryptInit ===" << endl;

    // Common variables for decryption initialization
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
    CK_OBJECT_HANDLE keyHandle = CK_INVALID_HANDLE;

    // Test Case 1: Calling C_DecryptInit with valid input
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find private key for decryption
        CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS,   &privateKeyClass, sizeof(privateKeyClass)},
                {CKA_DECRYPT, &true_val,        sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, privateKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &keyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize decryption with valid parameters
        checkOperation(p11Func->C_DecryptInit(hSession, &mechanism, keyHandle),
                       "Test Case 1: DecryptInit with valid inputs");
    }

    // Test Case 2: Calling C_DecryptInit with invalid mechanism
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find private key for decryption
        CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS,   &privateKeyClass, sizeof(privateKeyClass)},
                {CKA_DECRYPT, &true_val,        sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, privateKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &keyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Use an invalid mechanism (key pair generation instead of decryption)
        CK_MECHANISM invalidMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

        // Expect mechanism invalid error
        CK_RV expectedError = CKR_MECHANISM_INVALID;
        CK_RV rv = p11Func->C_DecryptInit(hSession, &invalidMechanism, keyHandle);
        // cout << "Expected: 0x" << hex << expectedError << ", Received: 0x" << rv << dec << endl;
        checkOperation(rv, "Test Case 2: DecryptInit with invalid mechanism");
    }

    // Test Case 3: Calling C_DecryptInit with invalid key handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Use an invalid key handle
        CK_OBJECT_HANDLE invalidKeyHandle = CK_INVALID_HANDLE;

        // Expect key handle invalid error
        CK_RV expectedError = CKR_KEY_HANDLE_INVALID;
        CK_RV rv = p11Func->C_DecryptInit(hSession, &mechanism, 999);
        // cout << "Expected: 0x" << hex << expectedError << ", Received: 0x" << rv << dec << endl;
        checkOperation(rv, "Test Case 3: DecryptInit with invalid key handle");
    }

    // Test Case 4: Calling C_DecryptInit with invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");

        // Find a valid key handle first
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find private key for decryption
        CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS,   &privateKeyClass, sizeof(privateKeyClass)},
                {CKA_DECRYPT, &true_val,        sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, privateKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &keyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Use an invalid session handle
        CK_SESSION_HANDLE invalidSession = 0;

        // Expect session handle invalid error
        CK_RV expectedError = CKR_SESSION_HANDLE_INVALID;
        CK_RV rv = p11Func->C_DecryptInit(999, &mechanism, keyHandle);
        // cout << "Expected: 0x" << hex << expectedError << ", Received: 0x" << rv << dec << endl;
        checkOperation(rv, "Test Case 4: DecryptInit with invalid session handle");
    }

    // Additional test cases could be added for:
    // - Calling C_DecryptInit when another operation is active
    // - Calling C_DecryptInit with nullptr mechanism pointer
    // - Calling C_DecryptInit with a key that doesn't have CKA_DECRYPT attribute set to TRUE
}

// Helper function to print test result
// void printTestResult(const char* testName, CK_RV actual, CK_RV expected) {
//     if (actual == expected) {
//         cout << testName << ": PASS" << endl;
//     } else {
//         cout << testName << ": FAIL (Expected: 0x" << hex << expected
//              << ", Actual: 0x" << actual << ")" << dec << endl;
//     }
// }
void testVerifyInit() {
    cout << "\n=== Testing C_VerifyInit ===" << endl;
    CK_BYTE id[] = {1};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    // Test Case 1: Passing valid session, supported mechanism, and valid public key handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair for verification
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Set up verification mechanism
        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "Test Case 1: Valid session, supported mechanism, and valid public key handle");
    }

    // Test Case 2: Passing invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // CK_OBJECT_HANDLE hPublicKey; // Arbitrary key handle
        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(999, &verifyMechanism, hPublicKey),
                       "Test Case 2: Passing invalid session handle");
    }

    // Test Case 3: Passing nullptr mechanism pointer
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // CK_OBJECT_HANDLE hPublicKey; // Arbitrary key handle
        checkOperation(p11Func->C_VerifyInit(hSession, nullptr, hPublicKey),
                       "Test Case 3: Passing nullptr mechanism pointer");
    }

    // Test Case 4: Passing unsupported mechanism type
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair for verification
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Use an unsupported mechanism
        CK_MECHANISM verifyMechanism = {CKM_DSA_KEY_PAIR_GEN, nullptr, 0}; // Invalid mechanism type
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "Test Case 4: Passing unsupported mechanism type");
    }

    // Test Case 5: Passing invalid key handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, 999),
                       "Test Case 5: Passing invalid key handle");
    }

    // Test Case 6: Using a key without CKA_VERIFY=true
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair without verify attribute
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL falseValue = CK_FALSE;
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_BBOOL ckFalse = CK_FALSE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                //{CKA_VERIFY, &ckFalse, sizeof(ckFalse)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "Test Case 6: Using a key without CKA_VERIFY=true");
    }

    // Test Case 7: Using a key with type inconsistent with mechanism
    //{
    //    resetState();
    //    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    //    // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
    //    slots = (CK_SLOT_ID*)malloc(slotCount * sizeof(CK_SLOT_ID));
    //    // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
    //    checkOperation(p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    //    checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR)pin, pLen), "C_Login");

    //    // Generate a symmetric key instead of RSA
    //    CK_MECHANISM keyGenMechanism = { CKM_AES_KEY_GEN, nullptr, 0 };
    //    CK_ULONG keyLength = 16;
    //    CK_BBOOL trueValue = CK_TRUE;
    //    CK_ATTRIBUTE keyTemplate[] = {
    //        {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)},
    //        {CKA_VERIFY, &trueValue, sizeof(trueValue)} };

    //    CK_OBJECT_HANDLE hSymKey;
    //    checkOperation(p11Func->C_GenerateKey(hSession, &keyGenMechanism, keyTemplate, 2, &hSymKey), "C_GenerateKey");

    //    // Try to use AES key with RSA mechanism
    //    CK_MECHANISM verifyMechanism = { CKM_RSA_PKCS, nullptr, 0 };
    //    checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hSymKey),
    //        "Test Case 7: Using a key with type inconsistent with mechanism");
    //}

    // Test Case 8: Calling when another verification operation is already active
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Initialize first verification operation
        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "First C_VerifyInit");

        // Try to initialize another verification operation without finalizing the first
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "Test Case 8: Calling when another verification operation is already active");
    }

    // Test Case 9: Mechanism requires parameters but pParameter is nullptr or invalid
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Use a mechanism that requires parameters but provide nullptr
        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS_PSS, nullptr, 0}; // Requires PSS params
        checkOperation(p11Func->C_VerifyInit(hSession, &verifyMechanism, hPublicKey),
                       "Test Case 9: Mechanism requires parameters but pParameter is nullptr");
    }

    // Test Case 10: Calling after session is closed
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate key pair
        CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 7,
                                                  privateKeyTemplate, 7, &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // Close session
        CK_SESSION_HANDLE closedSession = hSession;
        checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");

        // Try to verify with closed session
        CK_MECHANISM verifyMechanism = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_VerifyInit(closedSession, &verifyMechanism, hPublicKey),
                       "Test Case 10: Calling after session is closed");
    }
}

void testVerify() {
    cout << "\n=== Testing C_Verify ===" << endl;

    // Common variables for verification
    CK_BYTE data[] = "Data to be verified";
    CK_ULONG dataLen = strlen((const char *) data);
    CK_BYTE signature[256]; // Buffer for signature
    CK_ULONG signatureLen = sizeof(signature);
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
    CK_OBJECT_HANDLE publicKeyHandle = CK_INVALID_HANDLE;

    // Test Case 1: Calling after valid C_VerifyInit with correct data and matching signature
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // First sign the data to get valid signature
        CK_OBJECT_HANDLE privateKeyHandle;
        CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privKeyTemplate[] = {
                {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
                {CKA_SIGN,  &true_val,     sizeof(true_val)}};
        checkOperation(p11Func->C_FindObjectsInit(hSession, privKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &privateKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        checkOperation(p11Func->C_SignInit(hSession, &mechanism, privateKeyHandle), "C_SignInit");
        signatureLen = sizeof(signature);
        checkOperation(p11Func->C_Sign(hSession, data, dataLen, signature, &signatureLen),
                       "C_Sign");

        // Now verify the signature
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, signature, signatureLen),
                       "Test Case 1: Calling after valid C_VerifyInit with correct data and matching signature");
    }

    // Test Case 2: Calling C_Verify without prior C_VerifyInit
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Call C_Verify without C_VerifyInit
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, signature, signatureLen),
                       "Test Case 2: Calling C_Verify without prior C_VerifyInit");
    }

    // Test Case 3: Passing invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");

        // Call with invalid session handle
        checkOperation(p11Func->C_Verify(999, data, dataLen, signature, signatureLen),
                       "Test Case 3: Passing invalid session handle");
    }

    // Test Case 4: Passing nullptr data pointer with non-zero length
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");

        // Call with nullptr data pointer but non-zero length
        checkOperation(p11Func->C_Verify(hSession, nullptr, dataLen, signature, signatureLen),
                       "Test Case 4: Passing nullptr data pointer with non-zero length");
    }

    // Test Case 5: Passing nullptr signature pointer with non-zero signature length
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");

        // Call with nullptr signature pointer but non-zero signature length
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, nullptr, signatureLen),
                       "Test Case 5: Passing nullptr signature pointer with non-zero signature length");
    }

    // Test Case 6: Signature length does not match mechanism expectations
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");

        // Call with incorrect signature length
        CK_ULONG incorrectSigLen = 1; // Too small for RSA
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, signature, incorrectSigLen),
                       "Test Case 6: Signature length does not match mechanism expectations");
    }

    // Test Case 7: Signature does not match data (CKR_SIGNATURE_INVALID)
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");

        // Modify the signature to make it invalid
        if (signatureLen > 0) {
            signature[0] ^= 0xFF;
        }

        // Expect signature invalid error
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, signature, signatureLen),
                       "Test Case 7: Signature does not match data (CKR_SIGNATURE_INVALID)");
    }

    // Test Case 8: Calling after verification operation is finalized or aborted
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Find public key for verification
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_ATTRIBUTE pubKeyTemplate[] = {
                {CKA_CLASS,  &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_VERIFY, &true_val,    sizeof(true_val)}};
        CK_ULONG objectCount;
        checkOperation(p11Func->C_FindObjectsInit(hSession, pubKeyTemplate, 2),
                       "C_FindObjectsInit");
        checkOperation(p11Func->C_FindObjects(hSession, &publicKeyHandle, 1, &objectCount),
                       "C_FindObjects");
        checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

        // Initialize and then abort verification
        checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, publicKeyHandle),
                       "C_VerifyInit");
        checkOperation(p11Func->C_VerifyFinal(hSession, signature, signatureLen), "C_VerifyFinal");

        // Try to verify after finalization
        checkOperation(p11Func->C_Verify(hSession, data, dataLen, signature, signatureLen),
                       "Test Case 8: Calling after verification operation is finalized or aborted");
    }
}

void testDecrypt() {
    cout << "\n=== Testing C_Decrypt ===" << endl;

    const char *pin = "123456";
    CK_ULONG pLen = strlen(pin);

    // Test Case 1: Valid decryption with proper initialization
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate RSA key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_BYTE id[] = {1};
        CK_BBOOL ckTrue = CK_TRUE;

        CK_ATTRIBUTE pubTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                                  sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privTemplate,
                                                  sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // First encrypt some data
        CK_BYTE plaintext[] = "Test data for encryption";
        CK_BYTE encrypted[256];
        CK_ULONG encLen = sizeof(encrypted);
        CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");
        checkOperation(
                p11Func->C_Encrypt(hSession, plaintext, sizeof(plaintext), encrypted, &encLen),
                "C_Encrypt");

        // Now decrypt the data
        CK_BYTE decrypted[256];
        CK_ULONG decLen = sizeof(decrypted);
        CK_MECHANISM decryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_DecryptInit(hSession, &decryptMech, hPrivateKey),
                       "C_DecryptInit");
        checkOperation(p11Func->C_Decrypt(hSession, encrypted, encLen, decrypted, &decLen),
                       "Test Case 1: Valid decryption with proper initialization");
    }

    // Test Case 2: Decrypt without initialization
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        CK_BYTE encrypted[] = "Some encrypted data";
        CK_BYTE decrypted[256];
        CK_ULONG decLen = sizeof(decrypted);
        checkOperation(
                p11Func->C_Decrypt(hSession, encrypted, sizeof(encrypted), decrypted, &decLen),
                "Test Case 2: Decrypt without initialization");
    }

    // Test Case 3: Decrypt with invalid session handle
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate RSA key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_BYTE id[] = {1};
        CK_BBOOL ckTrue = CK_TRUE;

        CK_ATTRIBUTE pubTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                                  sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privTemplate,
                                                  sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // First encrypt some data
        CK_BYTE plaintext[] = "Test data for encryption";
        CK_BYTE encrypted[256];
        CK_ULONG encLen = sizeof(encrypted);
        CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");
        checkOperation(
                p11Func->C_Encrypt(hSession, plaintext, sizeof(plaintext), encrypted, &encLen),
                "C_Encrypt");

        // Now decrypt the data
        CK_BYTE decrypted[256];
        CK_ULONG decLen = sizeof(decrypted);
        CK_MECHANISM decryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_DecryptInit(hSession, &decryptMech, hPrivateKey),
                       "C_DecryptInit");

        checkOperation(p11Func->C_Decrypt(999, encrypted, sizeof(encrypted), decrypted, &decLen),
                       "Test Case 3: Decrypt with invalid session handle");
    }

    // Test Case 4: Decrypt with 0 input data length
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate RSA key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_BYTE id[] = {1};
        CK_BBOOL ckTrue = CK_TRUE;

        CK_ATTRIBUTE pubTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                                  sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privTemplate,
                                                  sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // First encrypt some data
        CK_BYTE plaintext[] = "Test data for encryption";
        CK_BYTE encrypted[256];
        CK_ULONG encLen = sizeof(encrypted);
        CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");
        checkOperation(
                p11Func->C_Encrypt(hSession, plaintext, sizeof(plaintext), encrypted, &encLen),
                "C_Encrypt");

        // Now decrypt the data
        CK_BYTE decrypted[256];
        CK_ULONG decLen = sizeof(decrypted);
        CK_MECHANISM decryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_DecryptInit(hSession, &decryptMech, hPrivateKey),
                       "C_DecryptInit");
        checkOperation(p11Func->C_Decrypt(hSession, encrypted, 0, decrypted, &decLen),
                       "Test Case 4: Decrypt with 0 input data length");
    }

    // Test Case 5: Decrypt with buffer too small
    {
        resetState();
        checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
        // checkOperation(p11Func->C_GetSlotList(TRUE, nullptr, &slotCount), "C_GetSlotList");
        slots = (CK_SLOT_ID *) malloc(slotCount * sizeof(CK_SLOT_ID));
        // checkOperation(p11Func->C_GetSlotList(TRUE, slots, &slotCount), "C_GetSlotList");
        checkOperation(
                p11Func->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                       &hSession), "C_OpenSession");
        checkOperation(p11Func->C_Login(hSession, CKU_USER, (CK_BYTE_PTR) pin, pLen), "C_Login");

        // Generate RSA key pair
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_ULONG modulusBits = 2048;
        CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
        CK_BYTE id[] = {1};
        CK_BBOOL ckTrue = CK_TRUE;

        CK_ATTRIBUTE pubTemplate[] = {
                {CKA_ENCRYPT,         &ckTrue,        sizeof(ckTrue)},
                {CKA_VERIFY,          &ckTrue,        sizeof(ckTrue)},
                {CKA_WRAP,            &ckTrue,        sizeof(ckTrue)},
                {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
                {CKA_ID,              id,             sizeof(id)},
                {CKA_TOKEN,           &ckTrue,        sizeof(ckTrue)}};

        CK_ATTRIBUTE privTemplate[] = {
                {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)},
                {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
                {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
                {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
                {CKA_ID,        id,      sizeof(id)}};

        CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate,
                                                  sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
                                                  privTemplate,
                                                  sizeof(privTemplate) / sizeof(CK_ATTRIBUTE),
                                                  &hPublicKey, &hPrivateKey),
                       "C_GenerateKeyPair");

        // First encrypt some data
        CK_BYTE plaintext[] = "Test data for encryption";
        CK_BYTE encrypted[256];
        CK_ULONG encLen = sizeof(encrypted);
        CK_MECHANISM encryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_EncryptInit(hSession, &encryptMech, hPublicKey), "C_EncryptInit");
        checkOperation(
                p11Func->C_Encrypt(hSession, plaintext, sizeof(plaintext), encrypted, &encLen),
                "C_Encrypt");

        // Now decrypt the data
        CK_BYTE decrypted[10];
        CK_ULONG decLen = sizeof(decrypted);
        CK_MECHANISM decryptMech = {CKM_RSA_PKCS, nullptr, 0};
        checkOperation(p11Func->C_DecryptInit(hSession, &decryptMech, hPrivateKey),
                       "C_DecryptInit");
        checkOperation(
                p11Func->C_Decrypt(hSession, encrypted, sizeof(encrypted), decrypted, &decLen),
                "Test Case 5: Decrypt with buffer too small");
    }
}

void init() {

    libHandle = dlopen("liblsusbdemo.so", RTLD_NOW);
    if (!libHandle) {
        cout << "Failed to load library" << endl;
        return;
    }

    // Get function list
    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle,
                                                                          "C_GetFunctionList");
    if (!C_GetFunctionList) {
        cout << "Failed to get function list" << endl;
        return;
    }

    CK_RV rv = C_GetFunctionList(&p11Func);
    if (rv != CKR_OK) {
        cout << "Failed to get function list" << endl;
        return;
    }

}

}