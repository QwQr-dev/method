# coding = 'utf-8'
# synchapi.h

import time as _time
from method.System.winnt import *
from method.System.sdkddkver import *
from method.System.minwinbase import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

SRWLOCK_INIT = RTL_SRWLOCK_INIT
INIT_ONCE_STATIC_INIT = RTL_RUN_ONCE_INIT
INIT_ONCE_CHECK_ONLY = RTL_RUN_ONCE_CHECK_ONLY
INIT_ONCE_ASYNC = RTL_RUN_ONCE_ASYNC
INIT_ONCE_INIT_FAILED = RTL_RUN_ONCE_INIT_FAILED
INIT_ONCE_CTX_RESERVED_BITS = RTL_RUN_ONCE_CTX_RESERVED_BITS
CONDITION_VARIABLE_INIT = RTL_CONDITION_VARIABLE_INIT
CONDITION_VARIABLE_LOCKMODE_SHARED = RTL_CONDITION_VARIABLE_LOCKMODE_SHARED
MUTEX_MODIFY_STATE = MUTANT_QUERY_STATE
MUTEX_ALL_ACCESS = MUTANT_ALL_ACCESS

SRWLOCK = RTL_SRWLOCK
PSRWLOCK = POINTER(SRWLOCK)
INIT_ONCE = RTL_RUN_ONCE
PINIT_ONCE = PRTL_RUN_ONCE
LPINIT_ONCE = PRTL_RUN_ONCE

PINIT_ONCE_FN = POINTER(WINAPI(WINBOOL, PINIT_ONCE, PVOID, PVOID))
CONDITION_VARIABLE = RTL_CONDITION_VARIABLE
PCONDITION_VARIABLE = POINTER(CONDITION_VARIABLE)


def EnterCriticalSection(lpCriticalSection):
    EnterCriticalSection = kernel32.EnterCriticalSection
    EnterCriticalSection.argtypes = [LPCRITICAL_SECTION]
    EnterCriticalSection.restype = VOID
    EnterCriticalSection(lpCriticalSection)


def LeaveCriticalSection(lpCriticalSection):
    LeaveCriticalSection = kernel32.LeaveCriticalSection
    LeaveCriticalSection.argtypes = [LPCRITICAL_SECTION]
    LeaveCriticalSection.restype = VOID
    LeaveCriticalSection(lpCriticalSection)


def TryEnterCriticalSection(lpCriticalSection, errcheck: bool = True):
    TryEnterCriticalSection = kernel32.TryEnterCriticalSection
    TryEnterCriticalSection.argtypes = [LPCRITICAL_SECTION]
    TryEnterCriticalSection.restype = WINBOOL
    res = TryEnterCriticalSection(lpCriticalSection)
    return win32_to_errcheck(res, errcheck)


def DeleteCriticalSection(lpCriticalSection):
    DeleteCriticalSection = kernel32.DeleteCriticalSection
    DeleteCriticalSection.argtypes = [LPCRITICAL_SECTION]
    DeleteCriticalSection.restype = VOID
    DeleteCriticalSection(lpCriticalSection)


def SetEvent(hEvent: int, errcheck: bool = True):
    SetEvent = kernel32.SetEvent
    SetEvent.argtypes = [HANDLE]
    SetEvent.restype = WINBOOL
    res = SetEvent(hEvent)
    return win32_to_errcheck(res, errcheck)


def ResetEvent(hEvent: int, errcheck: bool = True):
    ResetEvent = kernel32.ResetEvent
    ResetEvent.argtypes = [HANDLE]
    ResetEvent.restype = WINBOOL
    res = ResetEvent(hEvent)
    return win32_to_errcheck(res, errcheck)


def ReleaseSemaphore(hSemaphore: int, lReleaseCount: int, lpPreviousCount, errcheck: bool = True):
    ReleaseSemaphore = kernel32.ReleaseSemaphore
    ReleaseSemaphore.argtypes = [HANDLE, LONG, LPLONG]
    ReleaseSemaphore.restype = WINBOOL
    res = ReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount)
    return win32_to_errcheck(res, errcheck)


def ReleaseMutex(hMutex: int, errcheck: bool = True):
    ReleaseMutex = kernel32.ReleaseMutex
    ReleaseMutex.argtypes = [HANDLE]
    ReleaseMutex.restype = WINBOOL
    res = ReleaseMutex(hMutex)
    return win32_to_errcheck(res, errcheck)


def WaitForSingleObjectEx(hHandle: int, dwMilliseconds: int, bAlertable: bool):
    WaitForSingleObjectEx = kernel32.WaitForSingleObjectEx
    WaitForSingleObjectEx.argtypes = [HANDLE, DWORD, WINBOOL]
    WaitForSingleObjectEx.restype = DWORD
    res = WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable)
    return res


def WaitForMultipleObjectsEx(nCount: int, lpHandles, bWaitAll: int, dwMilliseconds: int, bAlertable: bool):
    WaitForMultipleObjectsEx = kernel32.WaitForMultipleObjectsEx
    WaitForMultipleObjectsEx.argtypes = [DWORD, POINTER(HANDLE), WINBOOL, DWORD, WINBOOL]
    WaitForMultipleObjectsEx.restype = DWORD
    res = WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable)
    return res


def OpenMutex(dwDesiredAccess: int, bInheritHandle: bool, lpName: str | bytes, unicode: bool = True, errcheck: bool = True):
    OpenMutex = kernel32.OpenMutexW if unicode else kernel32.OpenMutexA
    OpenMutex.argtypes = [DWORD, WINBOOL, (LPCWSTR if unicode else LPCSTR)]
    OpenMutex.restype = HANDLE
    res = OpenMutex(dwDesiredAccess, bInheritHandle, lpName)
    return win32_to_errcheck(res, errcheck)


def OpenEvent(dwDesiredAccess: int, bInheritHandle: bool, lpName: str | bytes, unicode: bool = True, errcheck: bool = True):
    OpenEvent = kernel32.OpenEventW if unicode else kernel32.OpenEventA
    OpenEvent.argtypes = [DWORD, WINBOOL, (LPCWSTR if unicode else LPCSTR)]
    OpenEvent.restype = HANDLE
    res = OpenEvent(dwDesiredAccess, bInheritHandle, lpName)
    return win32_to_errcheck(res, errcheck)


def OpenSemaphore(dwDesiredAccess: int, bInheritHandle: bool, lpName: str | bytes, unicode: bool = True, errcheck: bool = True):
    OpenSemaphore = kernel32.OpenSemaphoreW if unicode else kernel32.OpenSemaphoreA
    OpenSemaphore.argtypes = [DWORD, WINBOOL, (LPCWSTR if unicode else LPCSTR)]
    OpenSemaphore.restype = HANDLE
    res = OpenSemaphore(dwDesiredAccess, bInheritHandle, lpName)
    return win32_to_errcheck(res, errcheck)


def WaitForSingleObject(hHandle: int | None, dwMilliseconds: int, errcheck: bool = True) -> int:
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [HANDLE, DWORD]
    WaitForSingleObject.restype = BOOL 
    res = WaitForSingleObject(hHandle, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


def WaitOnAddress(Address: int, CompareAddress: int, AddressSize: int, dwMilliseconds: int, errcheck: bool = True):
    WaitOnAddress = kernel32.WaitOnAddress
    WaitOnAddress.argtypes = [PVOID, PVOID, SIZE_T, DWORD]
    WaitOnAddress.restype = WINBOOL
    res = WaitOnAddress(Address, CompareAddress, AddressSize, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


def WakeByAddressSingle(Address: int):
    WakeByAddressSingle = kernel32.WakeByAddressSingle
    WakeByAddressSingle.argtypes = [PVOID]
    WakeByAddressSingle.restype = VOID
    WakeByAddressSingle(Address)


def WakeByAddressAll(Address: int):
    WakeByAddressAll = kernel32.WakeByAddressAll
    WakeByAddressAll.argtypes = [PVOID]
    WakeByAddressAll.restype = VOID
    WakeByAddressAll(Address)


CREATE_MUTEX_INITIAL_OWNER = 0x1
CREATE_EVENT_MANUAL_RESET = 0x1
CREATE_EVENT_INITIAL_SET = 0x2


def Sleep(dwMilliseconds: int):     # 该函数无法使用
    Sleep = kernel32.Sleep
    Sleep.argtypes = [DWORD]
    Sleep.restype = VOID
    Sleep(dwMilliseconds)
