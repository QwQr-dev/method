# coding = 'utf-8'
# wow64apiset.h

from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck
from method.System.winnt import WOW64_CONTEXT, PWOW64_CONTEXT


def Wow64DisableWow64FsRedirection(OldValue, errcheck: bool = True):
    Wow64DisableWow64FsRedirection = kernel32.Wow64DisableWow64FsRedirection
    Wow64DisableWow64FsRedirection.argtypes = [PVOID]
    Wow64DisableWow64FsRedirection.restype = WINBOOL
    res = Wow64DisableWow64FsRedirection(OldValue)
    return win32_to_errcheck(res, errcheck)


def Wow64RevertWow64FsRedirection(OlValue, errcheck: bool = True):
    Wow64RevertWow64FsRedirection = kernel32.Wow64RevertWow64FsRedirection
    Wow64RevertWow64FsRedirection.argtypes = [PVOID]
    Wow64RevertWow64FsRedirection.restype = WINBOOL
    res = Wow64RevertWow64FsRedirection(OlValue)
    return win32_to_errcheck(res, errcheck)


def GetSystemWow64Directory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    GetSystemWow64Directory = (kernel32.GetSystemWow64DirectoryW 
                               if unicode else kernel32.GetSystemWow64DirectoryA
    )
    
    GetSystemWow64Directory.argtypes = [
        (LPWSTR if unicode else LPSTR),
        UINT
    ]

    GetSystemWow64Directory.restype = UINT
    res = GetSystemWow64Directory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)


def Wow64GetThreadContext(hThread, lpContext, errcheck: bool = True):
    Wow64GetThreadContext = kernel32.Wow64GetThreadContext
    Wow64GetThreadContext.argtypes = [HANDLE, PWOW64_CONTEXT]
    Wow64GetThreadContext.restype = WINBOOL
    res = Wow64GetThreadContext(hThread, lpContext)
    return win32_to_errcheck(res, errcheck)


def Wow64SetThreadContext(hThread, lpContext, errcheck: bool = True):
    Wow64SetThreadContext = kernel32.Wow64SetThreadContext
    Wow64SetThreadContext.argtypes = [HANDLE, POINTER(WOW64_CONTEXT)]
    Wow64SetThreadContext.restype = WINBOOL
    res = Wow64SetThreadContext(hThread, lpContext)
    return win32_to_errcheck(res, errcheck)


def Wow64SuspendThread(hThread: int) -> int:
    Wow64SuspendThread = kernel32.Wow64SuspendThread
    Wow64SuspendThread.argtypes = [HANDLE]
    Wow64SuspendThread.restype = DWORD
    res = Wow64SuspendThread(hThread)
    return res


def Wow64SetThreadDefaultGuestMachine(Machine: int) -> int:
    Wow64SetThreadDefaultGuestMachine = kernel32.Wow64SetThreadDefaultGuestMachine
    Wow64SetThreadDefaultGuestMachine.argtypes = [USHORT]
    Wow64SetThreadDefaultGuestMachine.restype = USHORT
    res = Wow64SetThreadDefaultGuestMachine(Machine)
    return res


def GetSystemWow64Directory2(lpBuffer, uSize, ImageFileMachineType, unicode: bool = True, errcheck: bool = True):
    GetSystemWow64Directory2 = kernel32.GetSystemWow64Directory2W if unicode else kernel32.GetSystemWow64Directory2A
    GetSystemWow64Directory2.argtypes = [(LPWSTR if unicode else LPSTR), UINT, WORD]
    GetSystemWow64Directory2.restype = UINT
    res = GetSystemWow64Directory2(lpBuffer, uSize, ImageFileMachineType)
    return win32_to_errcheck(res, errcheck)


def IsWow64GuestMachineSupported(WowGuestMachine, MachineIsSupported) -> int:
    IsWow64GuestMachineSupported = kernel32.IsWow64GuestMachineSupported
    IsWow64GuestMachineSupported.argtypes = [USHORT, POINTER(WINBOOL)]
    IsWow64GuestMachineSupported.restype = HRESULT
    res = IsWow64GuestMachineSupported(WowGuestMachine, MachineIsSupported)
    return res


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

