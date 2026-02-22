# coding = 'utf-8'
# commdlg.h

from method.System.errcheck import *
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.shlobj_core import LPOPENFILENAMEA, LPOPENFILENAMEW


def CommDlgExtendedError() -> int:
    CommDlgExtendedError = comdlg32.CommDlgExtendedError
    CommDlgExtendedError.restype = DWORD
    return CommDlgExtendedError()


def commdlg_to_errcheck(code: int, errcheck: bool = True) -> int:
    error_code = CommDlgExtendedError()
    if (not code and  error_code != 0) and errcheck:
        raise WinError(error_code)
    return code


def GetOpenFileName(unnamedParam1, unicode: bool = True, errcheck: bool = True):
    GetOpenFileName = (comdlg32.GetOpenFileNameW 
                       if unicode else comdlg32.GetOpenFileNameA
    )
    
    GetOpenFileName.argtypes = [(LPOPENFILENAMEW if unicode else LPOPENFILENAMEA)]
    GetOpenFileName.restype = BOOL
    res = GetOpenFileName(unnamedParam1)
    return commdlg_to_errcheck(res, errcheck)


def GetSaveFileName(unnamedParam1, unicode: bool = True, errcheck: bool = True):
    GetSaveFileName = (comdlg32.GetSaveFileNameW 
                       if unicode else comdlg32.GetSaveFileNameA
    )

    GetSaveFileName.argtypes = [(LPOPENFILENAMEW if unicode else LPOPENFILENAMEA)]
    GetSaveFileName.restype = BOOL
    res = GetSaveFileName(unnamedParam1)
    return commdlg_to_errcheck(res, errcheck)
