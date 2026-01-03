# coding = 'utf-8'
# winreg.h

from typing import NoReturn
from method.System.errcheck import *
from method.System.sdkddkver import *
from method.System.winusutypes import *
from method.System.public_dll import advapi32
from method.System.wtypesbase import LPSECURITY_ATTRIBUTES, PFILETIME
from method.System.winnt import SECURITY_INFORMATION, PSECURITY_DESCRIPTOR

_WIN32_WINNT = WIN32_WINNT

RRF_RT_REG_NONE = 0x00000001
RRF_RT_REG_SZ = 0x00000002
RRF_RT_REG_EXPAND_SZ = 0x00000004
RRF_RT_REG_BINARY = 0x00000008
RRF_RT_REG_DWORD = 0x00000010
RRF_RT_REG_MULTI_SZ = 0x00000020
RRF_RT_REG_QWORD = 0x00000040

RRF_RT_DWORD = (RRF_RT_REG_BINARY | RRF_RT_REG_DWORD)
RRF_RT_QWORD = (RRF_RT_REG_BINARY | RRF_RT_REG_QWORD)
RRF_RT_ANY = 0x0000ffff

if _WIN32_WINNT >= 0x0A00:
    RRF_SUBKEY_WOW6464KEY = 0x00010000
    RRF_SUBKEY_WOW6432KEY = 0x00020000
    RRF_WOW64_MASK = 0x00030000

RRF_NOEXPAND = 0x10000000
RRF_ZEROONFAILURE = 0x20000000

REG_PROCESS_APPKEY = 0x00000001

REGSAM = ACCESS_MASK = DWORD
LSTATUS = LONG

HKEY_CLASSES_ROOT: int = HKEY(ULONG_PTR(LONG(0x80000000).value).value).value
HKEY_CURRENT_USER: int = HKEY(ULONG_PTR(LONG(0x80000001).value).value).value
HKEY_LOCAL_MACHINE: int = HKEY(ULONG_PTR(LONG(0x80000002).value).value).value
HKEY_USERS: int = HKEY(ULONG_PTR(LONG(0x80000003).value).value).value
HKEY_PERFORMANCE_DATA: int = HKEY(ULONG_PTR(LONG(0x80000004).value).value).value
HKEY_PERFORMANCE_TEXT: int = HKEY(ULONG_PTR(LONG(0x80000050).value).value).value
HKEY_PERFORMANCE_NLSTEXT: int = HKEY(ULONG_PTR(LONG(0x80000060).value).value).value
HKEY_CURRENT_CONFIG: int = HKEY(ULONG_PTR(LONG(0x80000005).value).value).value
HKEY_DYN_DATA: int = HKEY(ULONG_PTR(LONG(0x80000006).value).value).value
HKEY_CURRENT_USER_LOCAL_SETTINGS: int = HKEY(ULONG_PTR(LONG(0x80000007).value).value).value

PROVIDER_KEEPS_VALUE_LENGTH = 0x1

class val_context(Structure):
    _fields_ = [
        ('valuelen', INT),
        ('value_context', LPVOID),
        ('val_buff_ptr', LPVOID)
    ]

PVALCONTEXT = POINTER(val_context)

class pvalueA(Structure):
    _fields_ = [
        ('pv_valuename', LPSTR),
        ('pv_valuelen', INT),
        ('pv_value_context', LPVOID),
        ('pv_type', DWORD)
    ]

PVALUEA = pvalueA
PPVALUEA = POINTER(PVALUEA)

class pvalueW(Structure):
    _fields_ = [
        ('pv_valuename', LPWSTR),
        ('pv_valuelen', INT),
        ('pv_value_context', LPVOID),
        ('pv_type', DWORD)
    ]

PVALUEW = pvalueW
PPVALUEW = POINTER(PVALUEW)

PVALUE = PVALUEW if UNICODE else PVALUEA
PPVALUE = PPVALUEW if UNICODE else PPVALUEA

QUERYHANDLER = CFUNCTYPE(DWORD, LPVOID, PVALCONTEXT, DWORD, LPVOID, DWORD, DWORD)
PQUERYHANDLER = POINTER(QUERYHANDLER)

class provider_info(Structure):
    _fields_ = [
        ('pi_R0_1val', PQUERYHANDLER),
        ('pi_R0_allvals', PQUERYHANDLER),
        ('pi_R3_1val', PQUERYHANDLER),
        ('pi_R3_allvals', PQUERYHANDLER),
        ('pi_flags', DWORD),
        ('pi_key_context', LPVOID)
    ]

REG_PROVIDER = provider_info
PPROVIDER = POINTER(provider_info)

class value_entA(Structure):
    _fields_ = [
        ('ve_valuename', LPSTR),
        ('ve_valuelen', DWORD),
        ('ve_valueptr', DWORD_PTR),
        ('ve_type', DWORD)
    ]

VALENTA = value_entA
PVALENTA = POINTER(VALENTA)

class value_entW(Structure):
    _fields_ = [
        ('ve_valuename', LPWSTR),
        ('ve_valuelen', DWORD),
        ('ve_valueptr', DWORD_PTR),
        ('ve_type', DWORD)
    ]

VALENTW = value_entW
PVALENTW = POINTER(VALENTW)

VALENT = VALENTW if UNICODE else VALENTA
PVALENT = PVALENTW if UNICODE else PVALENTA

WIN31_CLASS = NULL

REG_MUI_STRING_TRUNCATE = 0x00000001

REG_SECURE_CONNECTION = 1

def RegOverridePredefKey(hKey, hNewHKey, errcheck: bool = True):
    RegOverridePredefKey = advapi32.RegOverridePredefKey
    RegOverridePredefKey.argtypes = [HKEY, HKEY]
    RegOverridePredefKey.restype = LONG
    res = RegOverridePredefKey(hKey, hNewHKey)
    return winreg_to_errcheck(res, errcheck)


def RegOpenUserClassesRoot(hToken, dwOptions, samDesired, phkResult, errcheck: bool = True):
    RegOpenUserClassesRoot = advapi32.RegOpenUserClassesRoot
    RegOpenUserClassesRoot.argtypes = [
        HANDLE,
        DWORD,
        REGSAM,
        PHKEY
    ]
    
    RegOpenUserClassesRoot.restype = LSTATUS
    res = RegOpenUserClassesRoot(hToken, dwOptions, samDesired, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegOpenCurrentUser(samDesired, phkResult, errcheck: bool = True):
    RegOpenCurrentUser = advapi32.RegOpenCurrentUser
    RegOpenCurrentUser.argtypes = [REGSAM, PHKEY]
    RegOpenCurrentUser.restype = LONG
    res = RegOpenCurrentUser(samDesired, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegDisablePredefinedCache(errcheck: bool = True):
    RegDisablePredefinedCache = advapi32.RegDisablePredefinedCache
    RegDisablePredefinedCache.restype = LSTATUS
    res = RegDisablePredefinedCache()
    return winreg_to_errcheck(res, errcheck)


def RegDisablePredefinedCacheEx(errcheck: bool = True):
    RegDisablePredefinedCacheEx = advapi32.RegDisablePredefinedCacheEx
    RegDisablePredefinedCacheEx.restype = LSTATUS
    res = RegDisablePredefinedCacheEx()
    return winreg_to_errcheck(res, errcheck)


def RegConnectRegistry(lpMachineName, hKey, phkResult, unicode: bool = True, errcheck: bool = True):
    RegConnectRegistry = (advapi32.RegConnectRegistryW 
                          if unicode else advapi32.RegConnectRegistryA
    )

    RegConnectRegistry.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        HKEY,
        PHKEY
    ]

    RegConnectRegistry.restype = LONG
    res = RegConnectRegistry(lpMachineName, hKey, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegConnectRegistryEx(lpMachineName, hKey, Flags, phkResult, unicode: bool = True, errcheck: bool = True):
    RegConnectRegistryEx = (advapi32.RegConnectRegistryExW 
                            if unicode else advapi32.RegConnectRegistryExA
    )

    RegConnectRegistryEx.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        HKEY,
        ULONG,
        PHKEY
    ]
    
    RegConnectRegistryEx.restype = LONG
    res = RegConnectRegistryEx(lpMachineName, hKey, Flags, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegCreateKey(hKey, lpSubKey, phkResult, unicode: bool = True, errcheck: bool = True):
    RegCreateKey = (advapi32.RegCreateKeyW if unicode else advapi32.RegCreateKeyA)
    RegCreateKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        PHKEY
    ]

    RegCreateKey.restype = LONG
    res = RegCreateKey(hKey, lpSubKey, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegDeleteKey(hKey, lpSubKey, unicode: bool = True, errcheck: bool = True):
    RegDeleteKey = (advapi32.RegDeleteKeyW if unicode else advapi32.RegDeleteKeyA)
    RegDeleteKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegDeleteKey.restype = LONG
    res = RegDeleteKey(hKey, lpSubKey)
    return winreg_to_errcheck(res, errcheck)


def RegDisableReflectionKey(hBase, errcheck: bool = True):
    RegDisableReflectionKey = advapi32.RegDisableReflectionKey
    RegDisableReflectionKey.argtypes = [HKEY]
    RegDisableReflectionKey.restype = LONG
    res = RegDisableReflectionKey(hBase)
    return winreg_to_errcheck(res, errcheck)


def RegEnableReflectionKey(hBase, errcheck: bool = True):
    RegEnableReflectionKey = advapi32.RegEnableReflectionKey
    RegEnableReflectionKey.argtypes = [HKEY]
    RegEnableReflectionKey.restype = LONG
    res = RegEnableReflectionKey(hBase)
    return winreg_to_errcheck(res, errcheck)


def RegQueryReflectionKey(hBase, bIsReflectionDisabled, errcheck: bool = True):
    RegQueryReflectionKey = advapi32.RegQueryReflectionKey
    RegQueryReflectionKey.argtypes = [HKEY, WINBOOL]
    RegQueryReflectionKey.restype = LONG
    res = RegQueryReflectionKey(hBase, bIsReflectionDisabled)
    return winreg_to_errcheck(res, errcheck)


def RegEnumKey(hKey, dwIndex, lpName, cchName, unicode: bool = True, errcheck: bool = True):
    RegEnumKey = (advapi32.RegEnumKeyW if unicode else advapi32.RegEnumKeyA)
    RegEnumKey.argtypes = [
        HKEY,
        DWORD,
        (LPCWSTR if unicode else LPCSTR),
        DWORD
    ]

    RegEnumKey.restype = LONG
    res = RegEnumKey(hKey, dwIndex, lpName, cchName)
    return winreg_to_errcheck(res, errcheck)


def RegFlushKey(hKey, errcheck: bool = True):
    RegFlushKey = advapi32.RegFlushKey
    RegFlushKey.argtypes = [HKEY]
    RegFlushKey.restype = LONG
    res = RegFlushKey(hKey)
    return winreg_to_errcheck(res, errcheck)


def RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor, errcheck: bool = True):
    RegGetKeySecurity = advapi32.RegGetKeySecurity
    RegGetKeySecurity.argtypes = [
        HKEY,
        SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
        LPDWORD
    ]

    RegGetKeySecurity.restype = LONG
    res = RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor)
    return winreg_to_errcheck(res, errcheck)


def RegLoadKey(hKey, lpSubKey, lpFile, unicode: bool = True, errcheck: bool = True):
    RegLoadKey = (advapi32.RegLoadKeyW if unicode else advapi32.RegLoadKeyA)
    RegLoadKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegLoadKey.restype = LONG
    res = RegLoadKey(hKey, lpSubKey, lpFile)
    return winreg_to_errcheck(res, errcheck)


def RegOpenKey(hKey, lpSubKey, phkResult, unicode: bool = True, errcheck: bool = True):
    RegOpenKey = (advapi32.RegOpenKeyW if unicode else advapi32.RegOpenKeyA)
    RegOpenKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        PHKEY
    ]

    RegOpenKey.restype = LONG
    res = RegOpenKey(hKey, lpSubKey, phkResult)
    return winreg_to_errcheck(res, errcheck)


def RegQueryValue(hKey, lpSubKey, lpData, lpcbData, unicode: bool = True, errcheck: bool = True):
    RegQueryValue = (advapi32.RegQueryValueW if unicode else advapi32.RegQueryValueA)
    RegQueryValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        PLONG
    ]

    RegQueryValue.restype = LONG
    res = RegQueryValue(hKey, lpSubKey, lpData, lpcbData)
    return winreg_to_errcheck(res, errcheck)


def RegQueryMultipleValues(hKey, val_list, num_vals, lpValueBuf, ldwTotsize, unicode: bool = True, errcheck: bool = True):
    RegQueryMultipleValues = (advapi32.RegQueryMultipleValuesW if unicode else advapi32.RegQueryMultipleValuesA)
    RegQueryMultipleValues.argtypes = [
        HKEY,
        (PVALENTW if unicode else PVALENTA),
        DWORD,
        (LPWSTR if unicode else LPSTR),
        LPDWORD
    ]

    RegQueryMultipleValues.restype = LONG
    res = RegQueryMultipleValues(
        hKey,
        val_list,
        num_vals,
        lpValueBuf,
        ldwTotsize
    )

    return winreg_to_errcheck(res, errcheck)


def RegReplaceKey(hKey, lpSubKey, lpNewFile, lpOldFile, unicode: bool = True, errcheck: bool = True):
    RegReplaceKey = (advapi32.RegReplaceKeyW if unicode else advapi32.RegReplaceKeyA)
    RegReplaceKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegReplaceKey.restype = LONG
    res = RegReplaceKey(hKey, lpSubKey, lpNewFile, lpOldFile)
    return winreg_to_errcheck(res, errcheck)


def RegRestoreKey(hKey, lpFile, dwFlags, unicode: bool = True, errcheck: bool = True):
    RegRestoreKey = (advapi32.RegRestoreKeyW if unicode else advapi32.RegRestoreKeyA)
    RegRestoreKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD
    ]

    RegRestoreKey.restype = LONG
    res = RegRestoreKey(hKey, lpFile, dwFlags)
    return winreg_to_errcheck(res, errcheck)


def RegSaveKey(hKey, lpFile, lpSecurityAttributes, unicode: bool = True, errcheck: bool = True):
    RegSaveKey = (advapi32.RegSaveKeyW if unicode else advapi32.RegSaveKeyA)
    RegSaveKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        LPSECURITY_ATTRIBUTES
    ]

    RegSaveKey.restype = LONG
    res = RegSaveKey(hKey, lpFile, lpSecurityAttributes)
    return winreg_to_errcheck(res, errcheck)


def RegSetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, errcheck: bool = True):
    RegSetKeySecurity = advapi32.RegSetKeySecurity
    RegSetKeySecurity.argtypes = [
        HKEY,
        SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR
    ]

    RegSetKeySecurity.restype = LONG
    res = RegSetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor)
    return winreg_to_errcheck(res, errcheck)


def RegSetValue(hKey, lpSubKey, dwType, lpData, cbData, unicode: bool = True, errcheck: bool = True):
    RegSetValue = (advapi32.RegSetValueW if unicode else advapi32.RegSetValueA)
    RegSetValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        (LPCWSTR if unicode else LPCSTR),
        DWORD
    ]

    RegSetValue.restype = LONG
    res = RegSetValue(
        hKey,
        lpSubKey,
        dwType,
        lpData,
        cbData
    )

    return winreg_to_errcheck(res, errcheck)


def RegUnLoadKey(hKey, lpSubKey, unicode: bool = True, errcheck: bool = True):
    RegUnLoadKey = (advapi32.RegUnLoadKeyW if unicode else advapi32.RegUnLoadKeyA)
    RegUnLoadKey.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegUnLoadKey.restype = LONG
    res = RegUnLoadKey(hKey, lpSubKey)
    return winreg_to_errcheck(res, errcheck)


def InitiateSystemShutdown(
    lpMachineName: str | bytes, 
    lpMessage: str | bytes, 
    dwTimeout: int, 
    bForceAppsClosed: bool, 
    bRebootAfterShutdown: bool,
    unicode: bool = True,
    errcheck: bool = True
) -> NoReturn:
    
    InitiateSystemShutdown = (advapi32.InitiateSystemShutdownW 
                              if unicode else advapi32.InitiateSystemShutdownA
    )

    InitiateSystemShutdown.argtypes = [
        (LPWSTR if unicode else LPSTR),
        (LPWSTR if unicode else LPSTR),
        DWORD,
        WINBOOL,
        WINBOOL
    ]

    InitiateSystemShutdown.restype = WINBOOL
    res = InitiateSystemShutdown(
        lpMachineName, 
        lpMessage, 
        dwTimeout, 
        bForceAppsClosed, 
        bRebootAfterShutdown,
    )

    return win32_to_errcheck(res, errcheck)    


def AbortSystemShutdown(lpMachineName, unicode: bool = True, errcheck: bool = True):
    AbortSystemShutdown = (advapi32.AbortSystemShutdownW if unicode else advapi32.AbortSystemShutdownA)
    AbortSystemShutdown.argtypes = [(LPWSTR if unicode else LPSTR)]
    AbortSystemShutdown.restype = WINBOOL
    res = AbortSystemShutdown(lpMachineName)
    return win32_to_errcheck(res, errcheck)


from method.System.reason import *

REASON_SWINSTALL = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_INSTALLATION
REASON_HWINSTALL = SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_INSTALLATION
REASON_SERVICEHANG = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_HUNG
REASON_UNSTABLE = SHTDN_REASON_MAJOR_SYSTEM | SHTDN_REASON_MINOR_UNSTABLE
REASON_SWHWRECONF = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIG
REASON_OTHER = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER
REASON_UNKNOWN = SHTDN_REASON_UNKNOWN
REASON_LEGACY_API = SHTDN_REASON_LEGACY_API
REASON_PLANNED_FLAG = SHTDN_REASON_FLAG_PLANNED

MAX_SHUTDOWN_TIMEOUT = 10*365*24*60*60


def InitiateSystemShutdownEx(
    lpMachineName: str, 
    lpMessage: str, 
    dwTimeout: int, 
    bForceAppsClosed: bool, 
    bRebootAfterShutdown: bool, 
    dwReason: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> NoReturn:
    
    InitiateSystemShutdownEx = (advapi32.InitiateSystemShutdownExW 
                                if unicode else advapi32.InitiateSystemShutdownExA
    )

    InitiateSystemShutdownEx.argtypes = [
        (LPWSTR if unicode else LPSTR),
        (LPWSTR if unicode else LPSTR),
        DWORD,
        WINBOOL,
        WINBOOL,
        DWORD
    ]

    InitiateSystemShutdownEx.restype = WINBOOL
    res = InitiateSystemShutdownEx(
        lpMachineName, 
        lpMessage, 
        dwTimeout, 
        bForceAppsClosed, 
        bRebootAfterShutdown, 
        dwReason
    )

    return win32_to_errcheck(res, errcheck)


def RegSaveKeyEx(hKey, lpFile, lpSecurityAttributes, Flags, unicode: bool = True, errcheck: bool = True):
    RegSaveKeyEx = (advapi32.RegSaveKeyExW if unicode else advapi32.RegSaveKeyExA)
    RegSaveKeyEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        LPSECURITY_ATTRIBUTES,
        DWORD
    ]

    RegSaveKeyEx.restype = LONG
    res = RegSaveKeyEx(hKey, lpFile, lpSecurityAttributes, Flags)
    return winreg_to_errcheck(res, errcheck)

def Wow64Win32ApiEntry(dwFuncNumber, dwFlag, dwRes, errcheck: bool = True):
    Wow64Win32ApiEntry = advapi32.Wow64Win32ApiEntry
    Wow64Win32ApiEntry.argtypes = [
        DWORD,
        DWORD,
        DWORD
    ]

    Wow64Win32ApiEntry.restype = LONG
    res = Wow64Win32ApiEntry(dwFuncNumber, dwFlag, dwRes)
    return winreg_to_errcheck(res, errcheck)


def RegCopyTree(hKeySrc, lpSubKey, hKeyDest, unicode: bool = True, errcheck: bool = True):
    RegCopyTree = (advapi32.RegCopyTreeW if unicode else advapi32.RegCopyTreeA)
    RegCopyTree.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        HKEY
    ]

    RegCopyTree.restype = LONG
    res = RegCopyTree(hKeySrc, lpSubKey, hKeyDest)
    return winreg_to_errcheck(res, errcheck)


def RegCreateKeyTransacted(
    hKey, 
    lpSubKey, 
    Reserved, 
    lpClass, 
    dwOptions, 
    samDesired, 
    lpSecurityAttributes,
    phkResult,
    lpdwDisposition,
    hTransaction,
    pExtendedParemeter,
    unicode: bool = True,
    errcheck: bool = True
):

    RegCreateKeyTransacted = (advapi32.RegCreateKeyTransactedW 
                              if unicode else advapi32.RegCreateKeyTransactedA
    )

    RegCreateKeyTransacted.argtypes =[
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        (LPWSTR if unicode else LPSTR),
        DWORD,
        REGSAM,
        LPSECURITY_ATTRIBUTES,
        PHKEY,
        LPDWORD,
        HANDLE,
        PVOID
    ]

    RegCreateKeyTransacted.restype = LONG
    res = RegCreateKeyTransacted(
        hKey, 
        lpSubKey, 
        Reserved, 
        lpClass, 
        dwOptions, 
        samDesired, 
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition,
        hTransaction,
        pExtendedParemeter   
    )

    return winreg_to_errcheck(res, errcheck)


def RegDeleteKeyTransacted(
    hKey,
    lpSubKey,
    samDesired,
    Reserved,
    hTransaction,
    pExtendedParameter,
    unicode: bool = True,
    errcheck: bool = True
):

    RegDeleteKeyTransacted = (advapi32.RegDeleteKeyTransactedW if unicode else advapi32.RegDeleteKeyTransactedA)
    RegDeleteKeyTransacted.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        REGSAM,
        DWORD,
        HANDLE,
        PVOID
    ]

    RegDeleteKeyTransacted.restype = LONG
    res = RegDeleteKeyTransacted(
        hKey,
        lpSubKey,
        samDesired,
        Reserved,
        hTransaction,
        pExtendedParameter
    )

    return winreg_to_errcheck(res, errcheck)


def RegDeleteKeyValue(
    hKey,
    lpSubKey,
    lpValueName,
    unicode: bool = True,
    errcheck: bool = True
): 
    
    RegDeleteKeyValue = (advapi32.RegDeleteKeyValueW if unicode else advapi32.RegDeleteKeyValueA)
    RegDeleteKeyValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegDeleteKeyValue.restype = LONG
    res = RegDeleteKeyValue(
        hKey,
        lpSubKey,
        lpValueName
    )
    return winreg_to_errcheck(res, errcheck)


def RegLoadAppKey(
    lpFile,
    phkResult,
    samDesired,
    dwOptions,
    Reserved,
    unicode: bool = True,
    errcheck: bool = True
):
    RegLoadAppKey = (advapi32.RegLoadAppKeyW if unicode else advapi32.RegLoadAppKeyA)
    RegLoadAppKey.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        PHKEY,
        REGSAM,
        DWORD,
        DWORD
    ]

    RegLoadAppKey.restype = LONG
    res = RegLoadAppKey(
        lpFile,
        phkResult,
        samDesired,
        dwOptions,
        Reserved
    )

    return winreg_to_errcheck(res, errcheck)


def RegLoadMUIString(
    hKey,
    pszValue,
    pszOutBuf,
    cbOutBuf,
    pcbData,
    Flags,
    pszDirectory,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegLoadMUIString = (advapi32.RegLoadMUIStringW if unicode else advapi32.RegLoadMUIStringA)
    RegLoadMUIString.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        DWORD,
        LPDWORD,
        DWORD,
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegLoadMUIString.restype = LONG
    res = RegLoadMUIString(
        hKey,
        pszValue,
        pszOutBuf,
        cbOutBuf,
        pcbData,
        Flags,
        pszDirectory
    )

    return winreg_to_errcheck(res, errcheck)


def RegOpenKeyTransacted(
    hKey, 
    lpSubKey, 
    ulOptions, 
    samDesired, 
    phkResult,
    hTransaction,
    pExtendedParemeter,
    unicode: bool = True,
    errcheck: bool = True
):

    RegOpenKeyTransacted = (advapi32.RegOpenKeyTransactedW if unicode else advapi32.RegOpenKeyTransactedA)
    RegOpenKeyTransacted.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        REGSAM,
        LPSECURITY_ATTRIBUTES,
        PHKEY,
        HANDLE,
        PVOID
    ]

    RegOpenKeyTransacted.restype = LONG
    res = RegOpenKeyTransacted(
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult,
        hTransaction,
        pExtendedParemeter
    )

    return winreg_to_errcheck(res, errcheck)


def RegRenameKey(
    hKey,
    lpSubKeyName,
    lpNewKeyName,
    errcheck: bool = True
):
    RegRenameKey = advapi32.RegRenameKey
    RegRenameKey.argtypes = [
        HKEY,
        LPCWSTR,
        LPCWSTR
    ]

    RegRenameKey.restype = LONG
    res = RegRenameKey(hKey, lpSubKeyName, lpNewKeyName)
    return winreg_to_errcheck(res, errcheck)


def RegSetKeyValue(
    hKey,
    lpSubKey,
    lpValueName,
    dwType,
    lpData,
    cbData,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegSetKeyValue = (advapi32.RegSetKeyValueW if unicode else advapi32.RegSetKeyValueA)
    RegSetKeyValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        LPCVOID,
        DWORD
    ]

    RegSetKeyValue.restype = LONG
    res = RegSetKeyValue(
        hKey,
        lpSubKey,
        lpValueName,
        dwType,
        lpData,
        cbData
    )

    return winreg_to_errcheck(res, errcheck)


SHUTDOWN_FORCE_OTHERS = 0x00000001
SHUTDOWN_FORCE_SELF = 0x00000002
SHUTDOWN_RESTART = 0x00000004
SHUTDOWN_POWEROFF = 0x00000008
SHUTDOWN_NOREBOOT = 0x00000010
SHUTDOWN_GRACE_OVERRIDE = 0x00000020
SHUTDOWN_INSTALL_UPDATES = 0x00000040
SHUTDOWN_RESTARTAPPS = 0x00000080
SHUTDOWN_SKIP_SVC_PRESHUTDOWN = 0x00000100
SHUTDOWN_HYBRID = 0x00000200
SHUTDOWN_RESTART_BOOTOPTIONS = 0x00000400
SHUTDOWN_SOFT_REBOOT = 0x00000800
SHUTDOWN_MOBILE_UI = 0x00001000
SHUTDOWN_ARSO = 0x00002000


def InitiateShutdown(
    lpMachineName: str | bytes,
    lpMessage: str | bytes,
    dwGracePeriod: int,
    dwShutdownFlags: int,
    dwReason: int,
    unicode: bool = True,
    errcheck: bool = True
) -> NoReturn:
    
    InitiateShutdown = (advapi32.InitiateShutdownW if unicode else advapi32.InitiateShutdownA)
    InitiateShutdown.argtypes = [
        (LPWSTR if unicode else LPSTR),
        (LPWSTR if unicode else LPSTR),
        DWORD,
        DWORD,
        DWORD
    ]

    InitiateShutdown.restype = DWORD
    res = InitiateShutdown(
        lpMachineName,
        lpMessage,
        dwGracePeriod,
        dwShutdownFlags,
        dwReason
    )

    return winreg_to_errcheck(res, errcheck)


def CheckForHiberboot(pHiberboot, bClearFlag, errcheck: bool = True):
    CheckForHiberboot = advapi32.CheckForHiberboot
    CheckForHiberboot.argtypes = [
        PBOOLEAN,
        BOOLEAN
    ]

    CheckForHiberboot.restype = DWORD
    res = CheckForHiberboot(pHiberboot, bClearFlag)
    return winreg_to_errcheck(res, errcheck)


def RegCloseKey(hKey, errcheck: bool = True):
    RegCloseKey = advapi32.RegCloseKey
    RegCloseKey.argtypes = [HKEY]
    RegCloseKey.restype = LONG
    res = RegCloseKey(hKey)
    return winreg_to_errcheck(res, errcheck)


def RegCreateKeyEx(
    hKey,
    lpSubKey,
    Reserved,
    lpClass,
    dwOptions,
    samDesired,
    lpSecurityAttributes,
    phkResult,
    lpdwDisposition,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegCreateKeyEx = (advapi32.RegCreateKeyExW if unicode else advapi32.RegCreateKeyExA)
    RegCreateKeyEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        (LPWSTR if unicode else LPSTR),
        DWORD,
        REGSAM,
        LPSECURITY_ATTRIBUTES,
        PHKEY,
        LPDWORD
    ]

    RegCreateKeyEx.restype = LONG
    res = RegCreateKeyEx(
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition
    )

    return winreg_to_errcheck(res, errcheck)


def RegDeleteKeyEx(
    hKey,
    lpSubKey,
    samDesired,
    Reserved,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegDeleteKeyEx = (advapi32.RegDeleteKeyExW if unicode else advapi32.RegDeleteKeyExA)
    RegDeleteKeyEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        REGSAM,
        DWORD
    ]

    RegDeleteKeyEx.restype = LONG
    res = RegDeleteKeyEx(
        hKey,
        lpSubKey,
        samDesired,
        Reserved
    )

    return winreg_to_errcheck(res, errcheck)


def RegDeleteValue(hKey, lpValueName, unicode: bool = True, errcheck: bool = True):
    RegDeleteValue = (advapi32.RegDeleteValueW if unicode else advapi32.RegDeleteValueA)
    RegDeleteValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegDeleteValue.restype = LONG
    res = RegDeleteValue(hKey, lpValueName)
    return winreg_to_errcheck(res, errcheck)


def RegEnumKeyEx(
    hKey,
    dwIndex,
    lpName,
    lpcchName,
    lpReserved,
    lpClass,
    lpcchClass,
    lpftLastWriteTime,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegEnumKeyEx = (advapi32.RegEnumKeyExW if unicode else advapi32.RegEnumKeyExA)
    RegEnumKeyEx.argtypes = [
        HKEY,
        DWORD,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        LPDWORD,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        PFILETIME
    ]

    RegEnumKeyEx.restype = LONG
    res = RegEnumKeyEx(
        hKey,
        dwIndex,
        lpName,
        lpcchName,
        lpReserved,
        lpClass,
        lpcchClass,
        lpftLastWriteTime
    )

    return winreg_to_errcheck(res, errcheck)


def RegEnumValue(
    hKey,
    dwIndex,
    lpValueName,
    lpcchValueName,
    lpReserved,
    lpType,
    lpData,
    lpcbData,
    unicode: bool = True,
    errcheck: bool = True
):

    RegEnumValue = (advapi32.RegEnumValueW if unicode else advapi32.RegEnumValueA)
    RegEnumValue.argtypes = [
        HKEY,
        DWORD,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPBYTE,
        LPDWORD
    ]

    RegEnumValue.restype = LONG
    res = RegEnumValue(
        hKey,
        dwIndex,
        lpValueName,
        lpcchValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    )

    return winreg_to_errcheck(res, errcheck)


def RegGetValue(
    hKey,
    lpSubKey,
    lpValue,
    dwFlags,
    pdwType,
    pvData,
    pcbData,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegGetValue = (advapi32.RegGetValueW if unicode else advapi32.RegGetValueA)
    RegGetValue.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        LPDWORD,
        PVOID,
        LPDWORD
    ]

    RegGetValue.restype = LONG
    res = RegGetValue(
        hKey,
        lpSubKey,
        lpValue,
        dwFlags,
        pdwType,
        pvData,
        pcbData
    )

    return winreg_to_errcheck(res, errcheck)


def RegNotifyChangeKeyValue(
    hKey,
    bWatchSubtree,
    dwNotifyFilter,
    hEvent,
    fAsynchronous,
    errcheck: bool = True
):
    
    RegNotifyChangeKeyValue = advapi32.RegNotifyChangeKeyValue
    RegNotifyChangeKeyValue.argtypes = [
        HKEY,
        WINBOOL,
        DWORD,
        HANDLE,
        WINBOOL
    ]

    RegNotifyChangeKeyValue.restype = LONG
    res = RegNotifyChangeKeyValue(
        hKey,
        bWatchSubtree,
        dwNotifyFilter,
        hEvent,
        fAsynchronous
    )

    return winreg_to_errcheck(res, errcheck)


def RegOpenKeyEx(
    hKey,
    lpSubKey,
    ulOptions,
    samDesired,
    phkResult,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegOpenKeyEx = (advapi32.RegOpenKeyExW if unicode else advapi32.RegOpenKeyExA)
    RegOpenKeyEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        REGSAM,
        PHKEY
    ]

    RegOpenKeyEx.restype = LONG
    res = RegOpenKeyEx(
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    )

    return winreg_to_errcheck(res, errcheck)


def RegQueryInfoKey(
    hKey,
    lpClass,
    lpcchClass,
    lpReserved,
    lpcSubKeys,
    lpcbMaxSubKeyLen,
    lpcbMaxClassLen,
    lpcValues,
    lpcbMaxValueNameLen,
    lpcbMaxValueLen,
    lpcbSecurityDescriptor,
    lpftLastWriteTime,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegQueryInfoKey = (advapi32.RegQueryInfoKeyW if unicode else advapi32.RegQueryInfoKeyA)
    RegQueryInfoKey.argtypes = [
        HKEY,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        PFILETIME
    ]

    RegQueryInfoKey.restype = LONG
    res = RegQueryInfoKey(
        hKey,
        lpClass,
        lpcchClass,
        lpReserved,
        lpcSubKeys,
        lpcbMaxSubKeyLen,
        lpcbMaxClassLen,
        lpcValues,
        lpcbMaxValueNameLen,
        lpcbMaxValueLen,
        lpcbSecurityDescriptor,
        lpftLastWriteTime
    )

    return winreg_to_errcheck(res, errcheck)


def RegQueryValueEx(
    hKey,
    lpValueName,
    lpReserved,
    lpType,
    lpData,
    lpcbData,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegQueryValueEx = (advapi32.RegQueryValueExW if unicode else advapi32.RegQueryValueExA)
    RegQueryValueEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        LPDWORD,
        LPDWORD,
        LPBYTE,
        LPDWORD,
    ]

    RegQueryValueEx.restype = LONG
    res = RegQueryValueEx(
        hKey,
        lpValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    )

    return winreg_to_errcheck(res, errcheck)


def RegSetValueEx(
    hKey,
    lpValueName,
    Reserved,
    dwType,
    lpData,
    cbData,
    unicode: bool = True,
    errcheck: bool = True
):
    
    RegSetValueEx = (advapi32.RegSetValueExW if unicode else advapi32.RegSetValueExA)
    RegSetValueEx.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        DWORD,
        BYTE,
        DWORD
    ]

    RegSetValueEx.restype = LONG
    res = RegSetValueEx(
        hKey,
        lpValueName,
        Reserved,
        dwType,
        lpData,
        cbData
    )

    return winreg_to_errcheck(res, errcheck)


def RegDeleteTree(hKey, lpSubKey, unicode: bool = True, errcheck: bool = True):
    RegDeleteTree = (advapi32.RegDeleteTreeW if unicode else advapi32.RegDeleteTreeA)
    RegDeleteTree.argtypes = [
        HKEY,
        (LPCWSTR if unicode else LPCSTR)
    ]

    RegDeleteTree.restype = LONG
    res = RegDeleteTree(hKey, lpSubKey)
    return winreg_to_errcheck(res, errcheck)

