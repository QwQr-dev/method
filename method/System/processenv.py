# coding = 'utf-8'
# processenv.h

from method.System.winnt import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck


def GetCommandLine(unicode: bool = True) -> (str | bytes):
    GetCommandLine = kernel32.GetCommandLineW if unicode else kernel32.GetCommandLineA
    GetCommandLine.restype = LPWSTR if unicode else LPSTR
    res = GetCommandLine()
    return res


def SetCurrentDirectory(lpPathName, unicode: bool = True, errcheck: bool = True):
    SetCurrentDirectory = kernel32.SetCurrentDirectoryW if unicode else kernel32.SetCurrentDirectoryA
    SetCurrentDirectory.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    SetCurrentDirectory.restype = WINBOOL
    res = SetCurrentDirectory(lpPathName)
    return win32_to_errcheck(res, errcheck)


def GetCurrentDirectory(nBufferLength, lpBuffer, unicode: bool = True):
    GetCurrentDirectory = kernel32.GetCurrentDirectoryW if unicode else kernel32.GetCurrentDirectoryA
    GetCurrentDirectory.argtypes = [DWORD, (LPWSTR if unicode else LPSTR)]
    GetCurrentDirectory.restype = DWORD
    res = GetCurrentDirectory(nBufferLength, lpBuffer)
    return res


def SetEnvironmentStrings(NewEnvironment, unicode: bool = True, errcheck: bool = True):
    SetEnvironmentStrings = kernel32.SetEnvironmentStringsW if unicode else kernel32.SetEnvironmentStringsA
    SetEnvironmentStrings.argtypes = [LPWCH]
    SetEnvironmentStrings.restype = WINBOOL
    res = SetEnvironmentStrings(NewEnvironment)
    return win32_to_errcheck(res, errcheck)


def SearchPath(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, lpFilePart, unicode: bool = True):
    SearchPath = kernel32.SearchPathW if unicode else kernel32.SearchPathA
    SearchPath.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPCWSTR if unicode else LPCSTR), (LPCWSTR if unicode else LPCSTR), DWORD, (LPWSTR if unicode else LPSTR), POINTER(LPWSTR)]
    SearchPath.restype = DWORD
    res = SearchPath(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, lpFilePart)
    return res


def NeedCurrentDirectoryForExePath(ExeName, unicode: bool = True, errcheck: bool = True):
    NeedCurrentDirectoryForExePath = kernel32.NeedCurrentDirectoryForExePathW if unicode else kernel32.NeedCurrentDirectoryForExePathA
    NeedCurrentDirectoryForExePath.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    NeedCurrentDirectoryForExePath.restype = WINBOOL
    res = NeedCurrentDirectoryForExePath(ExeName)
    return win32_to_errcheck(res, errcheck)


def GetEnvironmentStrings(unicode: bool = True):
    GetEnvironmentStrings = kernel32.GetEnvironmentStringsW if unicode else kernel32.GetEnvironmentStrings
    GetEnvironmentStrings.restype = LPWCH if unicode else LPCH
    res = GetEnvironmentStrings()
    return res


def GetStdHandle(nStdHandle):
    GetStdHandle = kernel32.GetStdHandle
    GetStdHandle.argtypes = [DWORD]
    GetStdHandle.restype = HANDLE
    res = GetStdHandle(nStdHandle)
    return res


def ExpandEnvironmentStrings(lpSrc, lpDst, nSize, unicode: bool = True):
    ExpandEnvironmentStrings = kernel32.ExpandEnvironmentStringsW if unicode else kernel32.ExpandEnvironmentStringsA
    ExpandEnvironmentStrings.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    ExpandEnvironmentStrings.restype = DWORD
    res = ExpandEnvironmentStrings(lpSrc, lpDst, nSize)
    return res


def FreeEnvironmentStrings(penv, unicode: bool = True, errcheck: bool = True):
    FreeEnvironmentStrings = kernel32.FreeEnvironmentStringsW if unicode else kernel32.FreeEnvironmentStringsA
    FreeEnvironmentStrings.argtypes = [(LPWCH if unicode else LPCH)]
    FreeEnvironmentStrings.restype = WINBOOL
    res = FreeEnvironmentStrings(penv)
    return win32_to_errcheck(res, errcheck)


def GetEnvironmentVariable(lpName, lpBuffer, nSize, unicode: bool = True):
    GetEnvironmentVariable = kernel32.GetEnvironmentVariableW if unicode else kernel32.GetEnvironmentVariableA
    GetEnvironmentVariable.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    GetEnvironmentVariable.restype = DWORD
    res = GetEnvironmentVariable(lpName, lpBuffer, nSize)
    return res


def SetEnvironmentVariable(lpName, lpValue, unicode: bool = True, errcheck: bool = True):
    SetEnvironmentVariable = kernel32.SetEnvironmentVariableW if unicode else kernel32.SetEnvironmentVariableA
    SetEnvironmentVariable.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPCWSTR if unicode else LPCSTR)]
    SetEnvironmentVariable.restype = WINBOOL
    res = SetEnvironmentVariable(lpName, lpValue)
    return win32_to_errcheck(res, errcheck)


def SetStdHandle(nStdHandle, hHandle, errcheck: bool = True):
    SetStdHandle = kernel32.SetStdHandle
    SetStdHandle.argtypes = [DWORD, HANDLE]
    SetStdHandle.restype = WINBOOL
    res = SetStdHandle(nStdHandle, hHandle)
    return win32_to_errcheck(res, errcheck)


def SetStdHandleEx(nStdHandle, hHandle, phPrevValue, errcheck: bool = True):
    SetStdHandleEx = kernel32.SetStdHandleEx
    SetStdHandleEx.argtypes = [DWORD, HANDLE, PHANDLE]
    SetStdHandleEx.restype = WINBOOL
    res = SetStdHandleEx(nStdHandle, hHandle, phPrevValue)
    return win32_to_errcheck(res, errcheck)