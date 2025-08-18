# coding = 'utf-8'

from ctypes import FormatError

try:
    from public_dll import *
    from win_cbasictypes import *
except ImportError:
    from .public_dll import *
    from .win_cbasictypes import *

NULL = 0


def GetLastError(error_code: int = None) -> int:
    if error_code is None:
        return Kernel32.GetLastError()
    return Kernel32.GetLastError(error_code)


def SetLastError(dwErrCode: int) -> None:
    Kernel32.SetLastError(dwErrCode)


def SetLastErrorEx(dwErrCode: int, dwType = NULL) -> None:
    User32.SetLastErrorEx(dwErrCode, dwType)


def RtlNtStatusToDosError(Status: int) -> int:
    return ntdll.RtlNtStatusToDosError(Status)
