# coding = 'utf-8'

from ctypes import FormatError, WinError

try:
    from public_dll import *
    from win_cbasictypes import *
except ImportError:
    from .public_dll import *
    from .win_cbasictypes import *

NULL = 0


def GetLastError() -> int:
    return Kernel32.GetLastError()


def SetLastError(dwErrCode: int) -> None:
    Kernel32.SetLastError(dwErrCode)


def SetLastErrorEx(dwErrCode: int, dwType = NULL) -> None:
    User32.SetLastErrorEx(dwErrCode, dwType)


def RtlNtStatusToDosError(Status: int) -> int:
    RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
    RtlNtStatusToDosError.argtypes = [VOID]
    return RtlNtStatusToDosError(Status)


def CommDlgExtendedError() -> int:
    return comdlg32.CommDlgExtendedError()


FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
FORMAT_MESSAGE_FROM_STRING     = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x00002000
FORMAT_MESSAGE_MAX_WIDTH_MASK  = 0x000000FF


def FormatMessage(dwFlags: int, 
                  lpSource, 
                  dwMessageId: int, 
                  dwLanguageId: int, 
                  lpBuffer, 
                  nSize: int, 
                  Arguments, 
                  unicode: bool = True) -> int:
    
    FormatMessage = (Kernel32.FormatMessageW 
                     if unicode else Kernel32.FormatMessageA
    )

    res = FormatMessage(dwFlags, 
                        lpSource, 
                        dwMessageId, 
                        dwLanguageId, 
                        lpBuffer, 
                        nSize, 
                        Arguments
    )

    if res == NULL:
        raise WinError(GetLastError())
    return res
