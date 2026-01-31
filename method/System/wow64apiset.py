# coding = 'utf-8'
# wow64apiset.h

from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck


def IsWow64Process(hProcess, Wow64Process, errcheck: bool = True):
    IsWow64Process = kernel32.IsWow64Process
    IsWow64Process.argtypes = [HANDLE, PBOOL]
    IsWow64Process.restype = BOOL
    res = IsWow64Process(hProcess, Wow64Process)
    return win32_to_errcheck(res, errcheck)    


def IsWow64Process2(hProcess, pProcessMachine, pNativeMachine, errcheck: bool = True):
    IsWow64Process2 = kernel32.IsWow64Process2
    IsWow64Process2.argtypes = [HANDLE, PUSHORT, PUSHORT]
    IsWow64Process2.restype = BOOL
    res = IsWow64Process2(hProcess, pProcessMachine, pNativeMachine)
    return win32_to_errcheck(res, errcheck)

