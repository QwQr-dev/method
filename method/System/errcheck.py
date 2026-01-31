# coding = 'utf-8'

import sys
from typing import Any
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.winerror import FAILED
from method.System.ntstatus import NT_ERROR


def GetLastError() -> int:
    GetLastError = kernel32.GetLastError
    GetLastError.restype = DWORD
    return GetLastError()


def SetLastError(dwErrCode: int) -> None:
    SetLastError = kernel32.SetLastError
    SetLastError.argtypes = [DWORD]
    SetLastError(dwErrCode)


def SetLastErrorEx(dwErrCode: int, dwType: Any = NULL) -> None:
    SetLastErrorEx = user32.SetLastErrorEx
    SetLastErrorEx.argtypes = [DWORD, DWORD]
    SetLastErrorEx(dwErrCode, dwType)


def GetErrorInfo(dwReserved: int, pperrinfo: Any) -> int:
    GetErrorInfo = oleaut32.GetErrorInfo
    GetErrorInfo.argtypes = [ULONG, POINTER(VOID)]
    GetErrorInfo.restype = HRESULT
    return GetErrorInfo(dwReserved, pperrinfo)


def RtlNtStatusToDosError(Status: int) -> int:
    RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
    RtlNtStatusToDosError.argtypes = [VOID]
    return RtlNtStatusToDosError(Status)


FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
FORMAT_MESSAGE_FROM_STRING     = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x00002000
FORMAT_MESSAGE_MAX_WIDTH_MASK  = 0x000000FF


def FormatMessage(
    dwFlags: int, 
    lpSource: Any, 
    dwMessageId: int, 
    dwLanguageId: int, 
    lpBuffer, 
    nSize: int, 
    Arguments, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    FormatMessage = (kernel32.FormatMessageW 
                     if unicode else kernel32.FormatMessageA
    )

    res = FormatMessage(
        dwFlags, 
        lpSource, 
        dwMessageId, 
        dwLanguageId, 
        lpBuffer, 
        nSize, 
        Arguments
    )

    return win32_to_errcheck(res, errcheck)


def strerror(errnum: int) -> bytes:
    strerror = msvcrt.strerror
    strerror.argtypes = [c_int]
    strerror.restype = c_char_p
    res = strerror(errnum)
    return res


def null_to_zero(value) -> (int | Any):
    if value == None:
        return 0
    return value


def  zero_to_null(value) -> (None | Any):
    if value == 0:
        return None
    return value


def null_to_nullstr(value) -> (str | Any):
    if value == None:
        return ''
    return value


def nullstr_to_null(value) -> (None | Any):
    if value == '':
        return None
    return value


def zero_to_nullstr(value) -> (str | Any):
    if value == 0:
        return ''
    return value


def nullstr_to_zero(value) -> (int | Any):
    if value == '':
        return 0
    return value


def hresult_to_errcheck(code: int, errcheck: bool = True) -> int:
    if FAILED(code) and errcheck:
        raise WinError(code)
    return code
    

def ntstatus_to_errcheck(code: int, errcheck: bool = True) -> int:
    if NT_ERROR(code) and errcheck:
        raise WinError(RtlNtStatusToDosError(code))
    return code
    

def win32_to_errcheck(code: int, errcheck: bool = True) -> int:
    error_code = GetLastError()
    if error_code != 0 and errcheck:
        raise WinError(error_code)
    return code
    

def errno_to_errcheck(code: int, errcheck: bool = True) -> int:
    if code and errcheck:
        raise OSError(strerror(code).decode(sys.getdefaultencoding()))
    return code
    

def winreg_to_errcheck(code: int, errcheck: bool = True) -> int:
    if code and errcheck:
        raise WinError(code)
    return code
    

def com_to_errcheck(code: int, errcheck: bool = True) -> int:
    return hresult_to_errcheck(code, errcheck)
