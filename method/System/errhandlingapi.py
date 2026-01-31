# coding = 'utf-8'
# errhandlingapi.h

from typing import Any
from method.System.errcheck import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.winnt import _EXCEPTION_POINTERS, PVECTORED_EXCEPTION_HANDLER

PTOP_LEVEL_EXCEPTION_FILTER = POINTER(WINAPI(LONG, POINTER(_EXCEPTION_POINTERS)))
LPTOP_LEVEL_EXCEPTION_FILTER = PTOP_LEVEL_EXCEPTION_FILTER


def SetUnhandledExceptionFilter(lpTopLevelExceptionFilter, errcheck: bool = True):
    SetUnhandledExceptionFilter = kernel32.SetUnhandledExceptionFilter
    SetUnhandledExceptionFilter.argtypes = [LPTOP_LEVEL_EXCEPTION_FILTER]
    SetUnhandledExceptionFilter.restype = LPTOP_LEVEL_EXCEPTION_FILTER
    res = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter)
    return hresult_to_errcheck(res, errcheck)


def UnhandledExceptionFilter(ExceptionInfo, errcheck: bool = True):
    UnhandledExceptionFilter = kernel32.UnhandledExceptionFilter
    UnhandledExceptionFilter.argtypes = [POINTER(_EXCEPTION_POINTERS)]
    UnhandledExceptionFilter.restype = LONG
    res = UnhandledExceptionFilter(ExceptionInfo)
    return hresult_to_errcheck(res, errcheck)


def AddVectoredExceptionHandler(First, Handler, errcheck: bool = True):
    AddVectoredExceptionHandler = kernel32.AddVectoredExceptionHandler
    AddVectoredExceptionHandler.argtypes = [
        ULONG,
        PVECTORED_EXCEPTION_HANDLER
    ]

    AddVectoredExceptionHandler.restype = PVOID
    res = AddVectoredExceptionHandler(First, Handler)
    return hresult_to_errcheck(res, errcheck)


def RemoveVectoredExceptionHandler(Handle, errcheck: bool = True):
    RemoveVectoredExceptionHandler = kernel32.RemoveVectoredExceptionHandler
    RemoveVectoredExceptionHandler.argtypes = [PVOID]
    RemoveVectoredExceptionHandler.restype = ULONG
    res = RemoveVectoredExceptionHandler(Handle)
    return win32_to_errcheck(res, errcheck)


def AddVectoredContinueHandler(First, Handler, errcheck: bool = True):
    AddVectoredContinueHandler = kernel32.AddVectoredContinueHandler
    AddVectoredContinueHandler.argtypes = [
        ULONG,
        PVECTORED_EXCEPTION_HANDLER
    ]

    AddVectoredContinueHandler.restype = PVOID
    res = AddVectoredContinueHandler(First, Handler)
    return win32_to_errcheck(res, errcheck)


def RemoveVectoredContinueHandler(Handle, errcheck: bool = True):
    RemoveVectoredContinueHandler = kernel32.RemoveVectoredContinueHandler
    RemoveVectoredContinueHandler.argtypes = [PVOID]
    RemoveVectoredContinueHandler.restype = ULONG
    res = RemoveVectoredContinueHandler(Handle)
    return win32_to_errcheck(res, errcheck)


def RestoreLastError(dwErrCode):
    RestoreLastError = kernel32.RestoreLastError
    RestoreLastError.argtypes = [DWORD]
    RestoreLastError.restype = VOID
    RestoreLastError(dwErrCode)


RESTORE_LAST_ERROR_NAME_A = b"RestoreLastError"
RESTORE_LAST_ERROR_NAME_W = "RestoreLastError"


def GetErrorMode() -> int:
    GetErrorMode = kernel32.GetErrorMode
    GetErrorMode.restype = UINT
    return GetErrorMode()


def RaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments):
    RaiseException = kernel32.RaiseException
    RaiseException.argtypes = [
        DWORD,
        DWORD,
        DWORD,
        PULONG_PTR
    ]

    RaiseException.restype = VOID
    RaiseException(
        dwExceptionCode,
        dwExceptionFlags,
        nNumberOfArguments,
        lpArguments
    )


def SetErrorMode(uMode: int) -> int:
    SetErrorMode = kernel32.SetErrorMode
    SetErrorMode.argtypes = [UINT]
    SetErrorMode.restype = UINT
    res = SetErrorMode(uMode)
    return res


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

