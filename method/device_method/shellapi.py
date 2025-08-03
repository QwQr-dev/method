# coding = 'utf-8'

''' The shellapi was used Windows API to make. '''

import ctypes
from .windows import *
from typing import Any

GetLastError = Kernel32.GetLastError
MAX_PATH = 260

verbs = ['edit', 
         'explore', 
         'find', 
         'open', 
         'openas', 
         'print', 
         'properties', 
         'runas'
]


def ShellExecute(hwnd: int = HWND(),
                 lpOperation: str = '',
                 lpFile: str = '',
                 lpParameters: str = '',
                 lpDirectory: str = '',
                 nShowCmd: int = SW_NORMAL,
                 unicode: bool = True) -> None:
    
    ShellExecuteA = shell32.ShellExecuteA
    ShellExecuteW = shell32.ShellExecuteW
    
    if unicode:
        result = ShellExecuteW(hwnd, lpOperation, lpFile, 
                               lpParameters, lpDirectory, nShowCmd
        )
    else:
        result = ShellExecuteA(hwnd, lpOperation, lpFile, 
                               lpParameters, lpDirectory, nShowCmd
        )
    
    if result <= 32:
        raise ctypes.WinError(GetLastError(result))
    

def ShellExecuteEx(fMask: int = SEE_MASK_FLAG_NO_UI | SEE_MASK_FORCENOIDLIST, 
                   hwnd: int = HWND(), 
                   lpVerb: str = '', 
                   lpFile: str = '', 
                   lpParameters: str = '', 
                   lpDirectory: str = '', 
                   nShow: int = SW_NORMAL, 
                   hInstApp = HINSTANCE(), 
                   lpIDList: VOID = VOID(), 
                   lpClass: str = '', 
                   hkeyClass: Any = HKEY(), 
                   dwHotKey: int = DWORD(), 
                   hIcon_Monitor: tuple = (None, None), 
                   unicode: bool = True) -> (int | None):
    
    ShellExecuteExA = shell32.ShellExecuteExA
    ShellExecuteExW = shell32.ShellExecuteExW

    mbr = SHELLEXECUTEINFOW() if unicode else SHELLEXECUTEINFOA()
    mbr.cbSize = ctypes.sizeof(mbr)
    mbr.fMask = fMask
    mbr.hwnd = hwnd
    mbr.lpVerb = lpVerb
    mbr.lpFile = lpFile
    mbr.lpParameters = lpParameters
    mbr.lpDirectory = lpDirectory
    mbr.nShow = nShow
    mbr.lpIDList = lpIDList
    mbr.lpClass = lpClass
    mbr.hkeyClass = hkeyClass
    mbr.dwHotKey = dwHotKey
    mbr.hIcon_Monitor = mbr.SHELLEXECUTEICON(*hIcon_Monitor)
    res = ShellExecuteExW(ctypes.byref(mbr)) if unicode else ShellExecuteExA(ctypes.byref(mbr))
    hProcess = mbr.hProcess
    hInstApp = mbr.hInstApp

    if hInstApp is not None and hInstApp <= 32:
        raise ctypes.WinError(GetLastError(hInstApp)) 
    
    if res == NULL:
        raise ctypes.WinError(GetLastError(res)) 
    
    return hProcess


def OpenProcess(dwDesiredAccess: int, 
                bInheritHandle: bool, 
                dwProcessId: int) -> int:
    
    handle = Kernel32.OpenProcess(dwDesiredAccess, 
                                  bInheritHandle, 
                                  dwProcessId
    )

    if handle == NULL:
        raise ctypes.WinError(GetLastError(handle))
    return handle


def CloseHandle(hObject: int) -> None:
    result = Kernel32.CloseHandle(hObject)
    if result == NULL:
        raise ctypes.WinError(GetLastError(result))


def QueryFullProcessImageName(hProcess: int, 
                              dwFlags: int, 
                              lpExeName: Any = MAX_PATH,
                              unicode: bool = True) -> str:
    
    lpExeName = ctypes.create_unicode_buffer(lpExeName)
    lpdwSize = DWORD(ctypes.sizeof(lpExeName))

    if unicode:
        error_code = Kernel32.QueryFullProcessImageNameW(hProcess, 
                                                         dwFlags, 
                                                         ctypes.byref(lpExeName), 
                                                         ctypes.byref(lpdwSize)
        )
    else:
        error_code = Kernel32.QueryFullProcessImageNameA(hProcess,
                                                         dwFlags,
                                                         ctypes.byref(lpExeName), 
                                                         ctypes.byref(lpdwSize)
        )

    if error_code == NULL:
        raise ctypes.WinError(GetLastError(error_code))
    return lpExeName.value

