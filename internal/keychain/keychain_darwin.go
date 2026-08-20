//go:build darwin

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef broker_string(const char *value, size_t length) {
  return CFStringCreateWithBytes(
      kCFAllocatorDefault, (const UInt8 *)value, length,
      kCFStringEncodingUTF8, false);
}

static CFMutableDictionaryRef broker_query(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen) {
  CFStringRef serviceValue = broker_string(service, serviceLen);
  CFStringRef accountValue = broker_string(account, accountLen);
  if (serviceValue == NULL || accountValue == NULL) {
    if (serviceValue != NULL) CFRelease(serviceValue);
    if (accountValue != NULL) CFRelease(accountValue);
    return NULL;
  }

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  if (query != NULL) {
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceValue);
    CFDictionarySetValue(query, kSecAttrAccount, accountValue);
  }
  CFRelease(serviceValue);
  CFRelease(accountValue);
  return query;
}

static OSStatus broker_keychain_get(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen,
    void **data, size_t *dataLen) {
  CFMutableDictionaryRef query = broker_query(
      service, serviceLen, account, accountLen);
  if (query == NULL) return errSecAllocate;
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching(query, &result);
  CFRelease(query);
  if (status != errSecSuccess) return status;
  if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
    if (result != NULL) CFRelease(result);
    return errSecInternalError;
  }

  CFDataRef value = (CFDataRef)result;
  CFIndex length = CFDataGetLength(value);
  void *copy = malloc((size_t)length);
  if (copy == NULL && length > 0) {
    CFRelease(result);
    return errSecAllocate;
  }
  if (length > 0) memcpy(copy, CFDataGetBytePtr(value), (size_t)length);
  CFRelease(result);
  *data = copy;
  *dataLen = (size_t)length;
  return errSecSuccess;
}

static OSStatus broker_keychain_set(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen,
    const char *value, size_t valueLen) {
  CFMutableDictionaryRef query = broker_query(
      service, serviceLen, account, accountLen);
  if (query == NULL) return errSecAllocate;
  CFDataRef valueData = CFDataCreate(
      kCFAllocatorDefault, (const UInt8 *)value, valueLen);
  if (valueData == NULL) {
    CFRelease(query);
    return errSecAllocate;
  }

  CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  if (attributes == NULL) {
    CFRelease(valueData);
    CFRelease(query);
    return errSecAllocate;
  }
  CFDictionarySetValue(attributes, kSecValueData, valueData);
  OSStatus status = SecItemUpdate(query, attributes);
  CFRelease(attributes);

  if (status == errSecItemNotFound) {
    CFDictionarySetValue(query, kSecValueData, valueData);
    status = SecItemAdd(query, NULL);
  }

  CFRelease(valueData);
  CFRelease(query);
  return status;
}

static void broker_keychain_free(void *data, size_t dataLen) {
  if (data != NULL) {
    memset(data, 0, dataLen);
    free(data);
  }
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

var ErrNotFound = errors.New("keychain item not found")

func Get(service, account string) (string, error) {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))

	var data unsafe.Pointer
	var dataLen C.size_t
	status := C.broker_keychain_get(
		cs, C.size_t(len(service)), ca, C.size_t(len(account)), &data, &dataLen,
	)
	if status == C.errSecItemNotFound {
		return "", ErrNotFound
	}
	if status != C.errSecSuccess {
		return "", fmt.Errorf("read macOS Keychain item: OSStatus %d", int32(status))
	}
	defer C.broker_keychain_free(data, dataLen)
	return C.GoStringN((*C.char)(data), C.int(dataLen)), nil
}

func Set(service, account, value string) error {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	cv := C.CString(value)
	defer func() {
		C.memset(unsafe.Pointer(cv), 0, C.size_t(len(value)))
		C.free(unsafe.Pointer(cv))
	}()

	status := C.broker_keychain_set(
		cs, C.size_t(len(service)), ca, C.size_t(len(account)), cv, C.size_t(len(value)),
	)
	if status != C.errSecSuccess {
		return fmt.Errorf("write macOS Keychain item: OSStatus %d", int32(status))
	}
	return nil
}
