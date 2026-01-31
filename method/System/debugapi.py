# coding = 'utf-8'
# debugapi.h

from method.System.public_dll import *
from method.System.minwinbase import *
from method.System.winusutypes import *


def DebugBreak():
    DebugBreak = kernel32.DebugBreak
    DebugBreak.restype = VOID
    DebugBreak()


def IsDebuggerPresent() -> int:
    IsDebuggerPresent = kernel32.IsDebuggerPresent
    IsDebuggerPresent.restype = WINBOOL
    return IsDebuggerPresent()


def OutputDebugString(lpOutputString: str | bytes, unicode: bool = True):
    OutputDebugString = kernel32.OutputDebugStringW if unicode else kernel32.OutputDebugStringA
    OutputDebugString.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    OutputDebugString.restype = VOID
    OutputDebugString(lpOutputString)


def ContinueDebugEvent(dwProcessId: int, dwThreadId: int, dwContinueStatus: int, errcheck: bool = True):
    ContinueDebugEvent = kernel32.ContinueDebugEvent
    ContinueDebugEvent.argtypes = [
        DWORD,
        DWORD,
        DWORD
    ]

    ContinueDebugEvent.restype = WINBOOL
    res = ContinueDebugEvent(
        dwProcessId,
        dwThreadId,
        dwContinueStatus
    )

    return win32_to_errcheck(res, errcheck)


def WaitForDebugEvent(lpDebugEvent, dwMilliseconds: int, errcheck: bool = True):
    WaitForDebugEvent = kernel32.WaitForDebugEvent
    WaitForDebugEvent.argtypes = [
        LPDEBUG_EVENT,
        DWORD
    ]

    WaitForDebugEvent.restype = WINBOOL
    res = WaitForDebugEvent(lpDebugEvent, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


def WaitForDebugEventEx(lpDebugEvent, dwMilliseconds: int, errcheck: bool = True):
    WaitForDebugEventEx = kernel32.WaitForDebugEvent
    WaitForDebugEventEx.argtypes = [
        LPDEBUG_EVENT,
        DWORD
    ]

    WaitForDebugEventEx.restype = WINBOOL
    res = WaitForDebugEventEx(lpDebugEvent, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


def DebugActiveProcess(dwProcessId: int, errcheck: bool = True):
    DebugActiveProcess = kernel32.DebugActiveProcess
    DebugActiveProcess.argtypes = [DWORD]
    DebugActiveProcess.restype = WINBOOL
    res = DebugActiveProcess(dwProcessId)
    return win32_to_errcheck(res, errcheck)


def DebugActiveProcessStop(dwProcessId: int, errcheck: bool = True):
    DebugActiveProcessStop = kernel32.DebugActiveProcess
    DebugActiveProcessStop.argtypes = [DWORD]
    DebugActiveProcessStop.restype = WINBOOL
    res = DebugActiveProcessStop(dwProcessId)
    return win32_to_errcheck(res, errcheck)


def CheckRemoteDebuggerPresent(hProcess: int, pbDebuggerPresent, errcheck: bool = True):
    CheckRemoteDebuggerPresent = kernel32.CheckRemoteDebuggerPresent
    CheckRemoteDebuggerPresent.argtypes = [HANDLE, PBOOL]
    CheckRemoteDebuggerPresent.restype = WINBOOL
    res = CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent)
    return win32_to_errcheck(res, errcheck)