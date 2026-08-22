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

static CFMutableDictionaryRef broker_sync_query(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen, int syncMode) {
  CFMutableDictionaryRef query = broker_query(service, serviceLen, account, accountLen);
  if (query == NULL) return NULL;
  CFDictionarySetValue(query, kSecAttrSynchronizable,
      syncMode == 1 ? kCFBooleanTrue : kCFBooleanFalse);
  return query;
}

static OSStatus broker_keychain_add(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen,
    const char *label, size_t labelLen,
    const void *value, size_t valueLen, int synchronized) {
  CFMutableDictionaryRef query = broker_sync_query(
      service, serviceLen, account, accountLen, synchronized);
  if (query == NULL) return errSecAllocate;
  CFStringRef labelValue = broker_string(label, labelLen);
  CFDataRef valueData = CFDataCreate(kCFAllocatorDefault, value, valueLen);
  if (labelValue == NULL || valueData == NULL) {
    if (labelValue != NULL) CFRelease(labelValue);
    if (valueData != NULL) CFRelease(valueData);
    CFRelease(query);
    return errSecAllocate;
  }
  CFDictionarySetValue(query, kSecAttrLabel, labelValue);
  CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);
  CFDictionarySetValue(query, kSecValueData, valueData);
  OSStatus status = SecItemAdd(query, NULL);
  CFRelease(labelValue);
  CFRelease(valueData);
  CFRelease(query);
  return status;
}

static OSStatus broker_keychain_get_exact(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen, int synchronized,
    void **data, size_t *dataLen) {
  CFMutableDictionaryRef query = broker_sync_query(
      service, serviceLen, account, accountLen, synchronized);
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
  if (copy == NULL && length > 0) { CFRelease(result); return errSecAllocate; }
  if (length > 0) memcpy(copy, CFDataGetBytePtr(value), (size_t)length);
  CFRelease(result);
  *data = copy;
  *dataLen = (size_t)length;
  return errSecSuccess;
}

static OSStatus broker_keychain_delete_exact(
    const char *service, size_t serviceLen,
    const char *account, size_t accountLen, int synchronized) {
  CFMutableDictionaryRef query = broker_sync_query(
      service, serviceLen, account, accountLen, synchronized);
  if (query == NULL) return errSecAllocate;
  OSStatus status = SecItemDelete(query);
  CFRelease(query);
  return status;
}

static OSStatus broker_keychain_list(
    const char *service, size_t serviceLen, void **resultOut) {
  CFStringRef serviceValue = broker_string(service, serviceLen);
  if (serviceValue == NULL) return errSecAllocate;
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  if (query == NULL) { CFRelease(serviceValue); return errSecAllocate; }
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, serviceValue);
  CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
  CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching(query, &result);
  CFRelease(serviceValue);
  CFRelease(query);
  if (status == errSecSuccess) *resultOut = (void *)result;
  return status;
}

static CFIndex broker_list_count(void *result) {
  if (result == NULL) return 0;
  CFTypeRef value = (CFTypeRef)result;
  if (CFGetTypeID(value) == CFArrayGetTypeID()) return CFArrayGetCount((CFArrayRef)value);
  return CFGetTypeID(value) == CFDictionaryGetTypeID() ? 1 : 0;
}

static CFDictionaryRef broker_list_item(void *result, CFIndex index) {
  CFTypeRef value = (CFTypeRef)result;
  if (CFGetTypeID(value) == CFArrayGetTypeID())
    return (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)value, index);
  return index == 0 ? (CFDictionaryRef)value : NULL;
}

static OSStatus broker_list_copy_item(void *result, CFIndex index,
    void **account, size_t *accountLen, void **data, size_t *dataLen,
    int *synchronized) {
  CFDictionaryRef item = broker_list_item(result, index);
  if (item == NULL) return errSecInternalError;
  CFStringRef accountValue = (CFStringRef)CFDictionaryGetValue(item, kSecAttrAccount);
  CFDataRef dataValue = (CFDataRef)CFDictionaryGetValue(item, kSecValueData);
  if (accountValue == NULL || dataValue == NULL) return errSecInternalError;
  CFIndex maximum = CFStringGetMaximumSizeForEncoding(
      CFStringGetLength(accountValue), kCFStringEncodingUTF8) + 1;
  char *accountCopy = malloc((size_t)maximum);
  if (accountCopy == NULL || !CFStringGetCString(accountValue, accountCopy, maximum,
      kCFStringEncodingUTF8)) { if (accountCopy != NULL) free(accountCopy); return errSecAllocate; }
  CFIndex length = CFDataGetLength(dataValue);
  void *dataCopy = malloc((size_t)length);
  if (dataCopy == NULL && length > 0) { free(accountCopy); return errSecAllocate; }
  if (length > 0) memcpy(dataCopy, CFDataGetBytePtr(dataValue), (size_t)length);
  *account = accountCopy;
  *accountLen = strlen(accountCopy);
  *data = dataCopy;
  *dataLen = (size_t)length;
  CFTypeRef syncValue = CFDictionaryGetValue(item, kSecAttrSynchronizable);
  *synchronized = syncValue == kCFBooleanTrue ? 1 : 0;
  return errSecSuccess;
}

static void broker_list_release(void *result) {
  if (result != NULL) CFRelease((CFTypeRef)result);
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

var (
	ErrNotFound      = errors.New("keychain item not found")
	ErrAlreadyExists = errors.New("keychain item already exists")
)

type Item struct {
	Account        string
	Data           []byte
	Synchronizable bool
}

func Add(service, account, label string, data []byte, synchronizable bool) error {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	var dataPointer unsafe.Pointer
	if len(data) > 0 {
		dataPointer = unsafe.Pointer(&data[0])
	}
	status := C.broker_keychain_add(cs, C.size_t(len(service)), ca, C.size_t(len(account)),
		cl, C.size_t(len(label)), dataPointer, C.size_t(len(data)), boolInt(synchronizable))
	if status == C.errSecDuplicateItem {
		return ErrAlreadyExists
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("create macOS Keychain item: OSStatus %d", int32(status))
	}
	return nil
}

func GetExact(service, account string, synchronizable bool) ([]byte, error) {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	var data unsafe.Pointer
	var dataLen C.size_t
	status := C.broker_keychain_get_exact(cs, C.size_t(len(service)), ca, C.size_t(len(account)),
		C.int(boolInt(synchronizable)), &data, &dataLen)
	if status == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("read macOS Keychain item: OSStatus %d", int32(status))
	}
	defer C.broker_keychain_free(data, dataLen)
	return C.GoBytes(data, C.int(dataLen)), nil
}

func DeleteExact(service, account string, synchronizable bool) error {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	status := C.broker_keychain_delete_exact(cs, C.size_t(len(service)), ca, C.size_t(len(account)), C.int(boolInt(synchronizable)))
	if status == C.errSecItemNotFound {
		return ErrNotFound
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("delete macOS Keychain item: OSStatus %d", int32(status))
	}
	return nil
}

func List(service string) ([]Item, error) {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	var result unsafe.Pointer
	status := C.broker_keychain_list(cs, C.size_t(len(service)), &result)
	if status == C.errSecItemNotFound {
		return []Item{}, nil
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("list macOS Keychain items: OSStatus %d", int32(status))
	}
	defer C.broker_list_release(result)
	count := int(C.broker_list_count(result))
	items := make([]Item, 0, count)
	for index := 0; index < count; index++ {
		var account, data unsafe.Pointer
		var accountLen, dataLen C.size_t
		var synchronized C.int
		status := C.broker_list_copy_item(result, C.CFIndex(index), &account, &accountLen, &data, &dataLen, &synchronized)
		if status != C.errSecSuccess {
			for i := range items {
				clear(items[i].Data)
			}
			return nil, fmt.Errorf("read listed macOS Keychain item: OSStatus %d", int32(status))
		}
		item := Item{Account: C.GoStringN((*C.char)(account), C.int(accountLen)), Data: C.GoBytes(data, C.int(dataLen)), Synchronizable: synchronized == 1}
		C.broker_keychain_free(account, accountLen)
		C.broker_keychain_free(data, dataLen)
		items = append(items, item)
	}
	return items, nil
}

func boolInt(value bool) C.int {
	if value {
		return 1
	}
	return 0
}
