# coding = 'utf-8'

from ctypes import FormatError

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
    return ntdll.RtlNtStatusToDosError(Status)


def CommDlgExtendedError() -> int:
    return comdlg32.CommDlgExtendedError()

