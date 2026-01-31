# coding = 'utf-8'
# synchapi.h

from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck


def WaitForSingleObject(hHandle: int, dwMilliseconds: int, errcheck: bool = True) -> int:
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [HANDLE, DWORD]
    WaitForSingleObject.restype = BOOL 
    res = WaitForSingleObject(hHandle, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


def Sleep(dwMilliseconds: int) -> None:
    Sleep = kernel32.Sleep
    Sleep.argtypes = [DWORD]
    Sleep.restype = VOID
    Sleep(dwMilliseconds)
