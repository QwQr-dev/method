# coding = 'utf-8'

import enum
from typing import Any, NoReturn
from ctypes import (WinError, 
                    Structure, 
                    byref, 
                    sizeof, 
                    POINTER
)

try:
    from sdkddkver import *
    from public_dll import *
    from win_NT import LPCONTEXT
    from win_cbasictypes import *
    from error import GetLastError
except ImportError:
    from .sdkddkver import *
    from .public_dll import *
    from .win_NT import LPCONTEXT
    from .win_cbasictypes import *
    from .error import GetLastError

NULL = 0
_WIN32_WINNT = WIN32_WINNT

class _FILETIME(Structure):
    _fields_ = [('dwLowDateTime', DWORD),
                ('dwHighDateTime', DWORD)
    ]

FILETIME = _FILETIME
PFILETIME = POINTER(FILETIME)
LPFILETIME = PFILETIME

FLS_OUT_OF_INDEXES = DWORD(0xffffffff).value
TLS_OUT_OF_INDEXES = DWORD(0xffffffff).value


def OpenProcess(dwDesiredAccess: int, 
                bInheritHandle: bool, 
                dwProcessId: int) -> int:
    
    OpenProcess = Kernel32.OpenProcess
    OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    OpenProcess.restype = HANDLE
    handle = OpenProcess(dwDesiredAccess, 
                         bInheritHandle, 
                         dwProcessId
    )

    if not handle:
        raise WinError(GetLastError())
    return handle


def QueueUserAPC(pfnAPC, hThread, dwData):
    res = Kernel32.QueueUserAPC(pfnAPC, hThread, dwData)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetProcessTimes(hProcess: int,
                    lpCreationTime: Any,
                    lpExitTime: Any,
                    lpKernelTime: Any,
                    lpUserTime: Any):
    
    res = Kernel32.GetProcessTimes(hProcess,
                                   lpCreationTime,
                                   lpExitTime,
                                   lpKernelTime,
                                   lpUserTime
    )

    if res == NULL:
        raise WinError(GetLastError())
    

def ExitProcess(uExitCode: int) -> NoReturn:
    Kernel32.ExitProcess(uExitCode)


def GetExitCodeProcess(hProcess, LPlpExitCode):
    res = Kernel32.GetExitCodeProcess(hProcess, byref(LPlpExitCode))
    if res == NULL:
        WinError(GetLastError())
    return LPlpExitCode.value


def SwitchToThread() -> int:
    return Kernel32.SwitchToThread()


def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    res = Kernel32.OpenThread(dwDesiredAccess, 
                              bInheritHandle, 
                              dwThreadId
    )

    if res == NULL:
        raise WinError(GetLastError())
    return res


def SetThreadPriorityBoost(hThread, bDisablePriorityBoost):
    res = Kernel32.SetThreadPriorityBoost(hThread, bDisablePriorityBoost)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetThreadPriorityBoost(hThread, pDisablePriorityBoost):
    res = Kernel32.GetThreadPriorityBoost(hThread, pDisablePriorityBoost)
    if res == NULL:
        raise WinError(GetLastError())


def SetThreadToken(PThread, Token):
    SetThreadToken = advapi32.SetThreadToken
    # SetThreadToken.argtypes = [PHANDLE, HANDLE]
    res = SetThreadToken(PThread, Token)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def OpenProcessToken(ProcessHandle, DesiredAccess, PTokenHandle):
    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [HANDLE, DWORD, HANDLE]
    OpenProcessToken.restype = BOOL
    res = OpenProcessToken(ProcessHandle, 
                           DesiredAccess, 
                           PTokenHandle
    )

    if res == NULL:
        raise WinError(GetLastError())
    return PTokenHandle


def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
    res = advapi32.OpenThreadToken(ThreadHandle, 
                                   DesiredAccess, 
                                   OpenAsSelf, 
                                   TokenHandle
    )

    if res == NULL:
        raise WinError(GetLastError())


def GetCurrentProcess() -> int:
    GetCurrentProcess = Kernel32.GetCurrentProcess
    GetCurrentProcess.restype = HANDLE
    return GetCurrentProcess()


def SetPriorityClass(hProcess, dwPriorityClass):
    res = Kernel32.SetPriorityClass(hProcess, dwPriorityClass)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetPriorityClass(hProcess):
    res = Kernel32.GetPriorityClass(hProcess)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetProcessId(Process):
    res = Kernel32.GetProcessId(Process)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetThreadId(Thread):
    res = Kernel32.GetThreadId(Thread)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetThreadContext(hThread, lpContext):
    res = Kernel32.GetThreadContext(hThread, 
                                    lpContext
    )

    if res == NULL:
        raise WinError(GetLastError())


def FlushInstructionCache(hProcess, lpBaseAddress, dwSize):
    res = Kernel32.FlushInstructionCache(hProcess, 
                                         lpBaseAddress, 
                                         dwSize
    )

    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetCurrentProcessorNumber() -> int:
    return Kernel32.GetCurrentProcessorNumber()


def TerminateProcess(hProcess: int, uExitCode: int) -> None:
    TerminateProcess = Kernel32.TerminateProcess
    TerminateProcess.argtypes = [HANDLE, UINT]
    TerminateProcess.restype = BOOL
    res = TerminateProcess(hProcess, uExitCode)
    if res == NULL:
        raise WinError(GetLastError())


class _STARTUPINFOA(Structure):
    _fields_ = [('cb', DWORD),
                ('lpReserved', LPSTR),
                ('lpDesktop', LPSTR),
                ('lpTitle', LPSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE)
    ]

STARTUPINFOA = _STARTUPINFOA
LPSTARTUPINFOA = POINTER(STARTUPINFOA)

class _STARTUPINFOW(Structure):
    _fields_ = [('cb', DWORD),
                ('lpReserved', LPWSTR),
                ('lpDesktop', LPWSTR),
                ('lpTitle', LPWSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE)
    ]

STARTUPINFOW = _STARTUPINFOW
LPSTARTUPINFOW = POINTER(STARTUPINFOW)

class _PROCESS_INFORMATION(Structure):
    _fields_ = [('hProcess', HANDLE),
                ('hThread', HANDLE),
                ('dwProcessId', DWORD),
                ('dwThreadId', DWORD),
    ]

PROCESS_INFORMATION = _PROCESS_INFORMATION
PPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)
LPPROCESS_INFORMATION = PPROCESS_INFORMATION

ProcessMemoryPriority = 0
ProcessMemoryExhaustionInfo = 1
ProcessAppMemoryInfo = 2
ProcessInPrivateInfo = 3
ProcessPowerThrottling = 4
ProcessReservedValue1 = 5
ProcessTelemetryCoverageInfo = 6
ProcessProtectionLevelInfo = 7
ProcessLeapSecondInfo = 8
ProcessMachineTypeInfo = 9
ProcessInformationClassMax = 10

class _PROCESS_INFORMATION_CLASS(enum.IntFlag):
    ProcessMemoryPriority = 0
    ProcessMemoryExhaustionInfo = 1
    ProcessAppMemoryInfo = 2
    ProcessInPrivateInfo = 3
    ProcessPowerThrottling = 4
    ProcessReservedValue1 = 5
    ProcessTelemetryCoverageInfo = 6
    ProcessProtectionLevelInfo = 7
    ProcessLeapSecondInfo = 8
    ProcessMachineTypeInfo = 9
    ProcessInformationClassMax = 10

PROCESS_INFORMATION_CLASS = _PROCESS_INFORMATION_CLASS

class _APP_MEMORY_INFORMATION(Structure):
    _fields_ = [('AvailableCommit', ULONG64),
                ('PrivateCommitUsage', ULONG64),
                ('PeakPrivateCommitUsage', ULONG64),
                ('TotalCommitUsage', ULONG64),
    ]

APP_MEMORY_INFORMATION = _APP_MEMORY_INFORMATION
PAPP_MEMORY_INFORMATION = POINTER(APP_MEMORY_INFORMATION)

UserEnabled = 0x00000001
KernelEnabled = 0x00000002
Wow64Container = 0x00000004

class _MACHINE_ATTRIBUTES(enum.IntFlag):
    UserEnabled = 0x00000001
    KernelEnabled = 0x00000002
    Wow64Container = 0x00000004

MACHINE_ATTRIBUTES = _MACHINE_ATTRIBUTES

class _PROCESS_MACHINE_INFORMATION(Structure):
    _fields_ = [('ProcessMachine', USHORT),
                ('Res0', USHORT),
                ('MachineAttributes', UINT),
    ]

PROCESS_MACHINE_INFORMATION = _PROCESS_MACHINE_INFORMATION

PME_CURRENT_VERSION = 1

class _PROCESS_MEMORY_EXHAUSTION_TYPE(enum.IntFlag):
    PMETypeFailFastOnCommitFailure = 0
    PMETypeMax = 1

PROCESS_MEMORY_EXHAUSTION_TYPE = _PROCESS_MEMORY_EXHAUSTION_TYPE

PME_FAILFAST_ON_COMMIT_FAIL_DISABLE = 0x0
PME_FAILFAST_ON_COMMIT_FAIL_ENABLE = 0x1

class _PROCESS_MEMORY_EXHAUSTION_INFO(Structure):
    _fields_ = [('Version', USHORT),
                ('Reserved', USHORT),
                ('Type', UINT),
                ('Value', ULONG_PTR),
    ]

PROCESS_MEMORY_EXHAUSTION_INFO = _PROCESS_MEMORY_EXHAUSTION_INFO
PPROCESS_MEMORY_EXHAUSTION_INFO = POINTER(PROCESS_MEMORY_EXHAUSTION_INFO)

PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1

PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1
PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION = 0x4

PROCESS_POWER_THROTTLING_VALID_FLAGS = (PROCESS_POWER_THROTTLING_EXECUTION_SPEED | 
                                        PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
)

class _PROCESS_POWER_THROTTLING_STATE(Structure):
    _fields_ = [('Version', ULONG),
                ('ControlMask', ULONG),
                ('StateMask', ULONG),
    ]

PROCESS_POWER_THROTTLING_STATE = _PROCESS_POWER_THROTTLING_STATE
PPROCESS_POWER_THROTTLING_STATE = POINTER(PROCESS_POWER_THROTTLING_STATE)

class PROCESS_PROTECTION_LEVEL_INFORMATION(Structure):
    _fields_ = [('ProtectionLevel', DWORD)]

PROCESS_LEAP_SECOND_INFO_FLAG_ENABLE_SIXTY_SECOND = 0x1
PROCESS_LEAP_SECOND_INFO_VALID_FLAGS = PROCESS_LEAP_SECOND_INFO_FLAG_ENABLE_SIXTY_SECOND

class _PROCESS_LEAP_SECOND_INFO(Structure):
    _fields_ = [('Flags', ULONG),
                ('Reserved', ULONG)
    ]

PROCESS_LEAP_SECOND_INFO = _PROCESS_LEAP_SECOND_INFO
PPROCESS_LEAP_SECOND_INFO = POINTER(PROCESS_LEAP_SECOND_INFO)

if _WIN32_WINNT >= WIN32_WINNT_WIN10:
    def GetProcessDefaultCpuSetMasks(Process, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount, 
                                     RequiredMaskCount):
        
        res = Kernel32.GetProcessDefaultCpuSetMasks(Process, 
                                                    CpuSetMasks, 
                                                    CpuSetMaskCount, 
                                                    RequiredMaskCount
        )

        if res == NULL:
            raise WinError(res)


    def SetProcessDefaultCpuSetMasks(Process, CpuSetMasks, CpuSetMaskCount):
        return


    def GetThreadSelectedCpuSetMasks(Thread, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount, 
                                     RequiredMaskCount):
        
        res = Kernel32.GetThreadSelectedCpuSetMasks(Thread, 
                                                    CpuSetMasks, 
                                                    CpuSetMaskCount, 
                                                    RequiredMaskCount
        )

        if res == NULL:
            raise WinError(GetLastError())


    def SetThreadSelectedCpuSetMasks(Thread, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount):
        
        res = Kernel32.SetThreadSelectedCpuSetMasks(Thread, 
                                                    CpuSetMasks, 
                                                    CpuSetMaskCount
        )

        if res == NULL:
            raise WinError(GetLastError())


class _PROC_THREAD_ATTRIBUTE_LIST(Structure):
    pass

PPROC_THREAD_ATTRIBUTE_LIST = POINTER(_PROC_THREAD_ATTRIBUTE_LIST)
LPPROC_THREAD_ATTRIBUTE_LIST = PPROC_THREAD_ATTRIBUTE_LIST


def CreateRemoteThread(hProcess, 
                       lpThreadAttributes, 
                       dwStackSize, 
                       lpStartAddress, 
                       lpParameter, 
                       dwCreationFlags,
                       lpThreadId):
    
    res = Kernel32.CreateRemoteThread(hProcess, 
                                      lpThreadAttributes, 
                                      dwStackSize, 
                                      lpStartAddress, 
                                      lpParameter, 
                                      dwCreationFlags, 
                                      lpThreadId
    )

    if res == NULL:
        raise WinError(GetLastError())


def TerminateThread(hThread, dwExitCode):
    res = Kernel32.TerminateThread(hThread, dwExitCode)

    if res == NULL:
        raise WinError(GetLastError())
    return hThread


def SetProcessShutdownParameters(dwLevel, dwFlags):
    res = Kernel32.SetProcessShutdownParameters(dwLevel, dwFlags)
    if res == NULL:
        raise WinError(GetLastError())


def GetProcessVersion(ProcessId):
    res = Kernel32.GetProcessVersion(ProcessId)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetStartupInfoW(lpStartupInfo):
    Kernel32.GetStartupInfoW(lpStartupInfo)


def SetThreadStackGuarantee(StackSizeInBytes):
    res = Kernel32.SetThreadStackGuarantee(StackSizeInBytes)
    if res == NULL:
        raise WinError(GetLastError())


def ProcessIdToSessionId(dwProcessId, pSessionId):
    res = Kernel32.ProcessIdToSessionId(dwProcessId, 
                                        pSessionId
    )

    if res == NULL:
        raise WinError(GetLastError())
    return pSessionId.value


def CreateRemoteThreadEx(hProcess, 
                         lpThreadAttributes, 
                         dwStackSize, 
                         lpStartAddress, 
                         lpParameter, 
                         dwCreationFlags, 
                         lpAttributeList,
                         lpThreadId):
    
    res = Kernel32.CreateRemoteThreadEx(hProcess, 
                                        lpThreadAttributes, 
                                        dwStackSize, 
                                        lpStartAddress, 
                                        lpParameter, 
                                        dwCreationFlags, 
                                        lpAttributeList, 
                                        lpThreadId
    )

    if res == NULL:
        raise WinError(GetLastError())
    return res


def SetThreadContext(hThread: int, lpContext):
    res = Kernel32.SetThreadContext(hThread, lpContext)
    if res == NULL:
        raise WinError(GetLastError())


def GetProcessHandleCount(hProcess: int, pdwHandleCount: Any):
    res = Kernel32.GetProcessHandleCount(hProcess, pdwHandleCount)
    if res == NULL:
        raise WinError(GetLastError())
    return pdwHandleCount


GetStartupInfo = GetStartupInfoW


def CreateProcessAsUser(hToken: int, 
                        lpApplicationName: str, 
                        lpCommandLine: str, 
                        lpProcessAttributes: Any, 
                        lpThreadAttributes: Any, 
                        bInheritHandles: bool, 
                        dwCreationFlags: int, 
                        lpEnvironment: Any, 
                        lpCurrentDirectory: str, 
                        lpStartupInfo: Any, 
                        lpProcessInformation: Any,
                        unicode: bool = True):
    
    CreateProcessAsUser = (advapi32.CreateProcessAsUserW 
                           if unicode else advapi32.CreateProcessAsUserA
    )

    res = CreateProcessAsUser(hToken, 
                              lpApplicationName, 
                              lpCommandLine, 
                              lpProcessAttributes, 
                              lpThreadAttributes, 
                              bInheritHandles, 
                              dwCreationFlags, 
                              lpEnvironment, 
                              lpCurrentDirectory, 
                              lpStartupInfo,
                              lpProcessInformation
    )

    if res == NULL:
        raise WinError(GetLastError())


#if _WIN32_WINNT >= 0x0600
PROCESS_AFFINITY_ENABLE_AUTO_UPDATE = 0x1
PROC_THREAD_ATTRIBUTE_REPLACE_VALUE = 0x00000001


def GetProcessIdOfThread(Thread: int) -> int:
    res = Kernel32.GetProcessIdOfThread(Thread)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def InitializeProcThreadAttributeList(lpAttributeList, 
                                      dwAttributeCount, 
                                      dwFlags, 
                                      lpSize):
    
    return


def DeleteProcThreadAttributeList(lpAttributeList):
    return


def SetProcessAffinityUpdateMode(hProcess, dwFlags):
    return


def QueryProcessAffinityUpdateMode(hProcess, lpdwFlags):
    return


def UpdateProcThreadAttribute(lpAttributeList, 
                              dwFlags, 
                              Attribute, 
                              lpValue, 
                              cbSize, 
                              lpPreviousValue, 
                              lpReturnSize):
    
    return


#if _WIN32_WINNT >= _WIN32_WINNT_WIN8
def SetProcessMitigationPolicy (MitigationPolicy, lpBuffer, dwLength):
    return


def GetCurrentProcessToken():
    return HANDLE(LONG_PTR(-4).value).value


def GetCurrentThreadToken():
    return HANDLE(LONG_PTR(-5).value).value


def GetCurrentThreadEffectiveToken():
    return HANDLE(LONG_PTR(-6).value).value


class _MEMORY_PRIORITY_INFORMATION(Structure):
    _fields_ = [('MemoryPriority', ULONG)]

MEMORY_PRIORITY_INFORMATION = _MEMORY_PRIORITY_INFORMATION
PMEMORY_PRIORITY_INFORMATION = POINTER(MEMORY_PRIORITY_INFORMATION)

MEMORY_PRIORITY_VERY_LOW      = 1
MEMORY_PRIORITY_LOW           = 2
MEMORY_PRIORITY_MEDIUM        = 3
MEMORY_PRIORITY_BELOW_NORMAL  = 4
MEMORY_PRIORITY_NORMAL        = 5

if _WIN32_WINNT >= WIN32_WINNT_WINBLUE:
    def IsProcessCritical (hProcess, Critical):
        return


if _WIN32_WINNT >= WIN32_WINNT_WIN10:
    def SetProtectedPolicy (PolicyGuid, PolicyValue, OldPolicyValue):
        return


def QueryProtectedPolicy (PolicyGuid, PolicyValue):
    return


def CreateProcess(lpApplicationName: str, 
                  lpCommandLine: str, 
                  lpProcessAttributes: Any, 
                  lpThreadAttributes: Any, 
                  bInheritHandles: bool, 
                  dwCreationFlags: int, 
                  lpEnvironment: Any, 
                  lpCurrentDirectory: str, 
                  lpStartupInfo: Any,
                  lpProcessInformation: Any,
                  unicode: bool = True):
    
    CreateProcess = (Kernel32.CreateProcessW 
                     if unicode else Kernel32.CreateProcessA
    )

    res = CreateProcess(lpApplicationName, 
                        lpCommandLine, 
                        lpProcessAttributes, 
                        lpThreadAttributes, 
                        bInheritHandles, 
                        dwCreationFlags, 
                        lpEnvironment, 
                        lpCurrentDirectory, 
                        lpStartupInfo, 
                        lpProcessInformation
    )

    if res == NULL:
        raise WinError(GetLastError())


if _WIN32_WINNT >= 0x0602:
    def GetCurrentThreadStackLimits (LowLimit, HighLimit):
        return


    def GetProcessMitigationPolicy (hProcess, MitigationPolicy, lpBuffer, dwLength):
        return


class _STARTUPINFOA(Structure):     
    _fields_ = [('cb', DWORD),
                ('lpReserved', LPSTR),
                ('lpDesktop', LPSTR),
                ('lpTitle', LPSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE),
    ]

STARTUPINFOA = _STARTUPINFOA
LPSTARTUPINFOA = POINTER(STARTUPINFOA)

class _STARTUPINFOW(Structure):        
    _fields_ = [('cb', DWORD),
                ('lpReserved', LPWSTR),
                ('lpDesktop', LPWSTR),
                ('lpTitle', LPWSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE),
    ]

STARTUPINFOW = _STARTUPINFOW
LPSTARTUPINFOW = POINTER(STARTUPINFOW)

class _PROCESS_INFORMATION(Structure):      
    _fields_ = [('hProcess', HANDLE),
                ('hThread', HANDLE),
                ('dwProcessId', DWORD),
                ('dwThreadId', DWORD),
    ]

PROCESS_INFORMATION = _PROCESS_INFORMATION
PPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)

ProcessMemoryPriority = 0
ProcessMemoryExhaustionInfo = 1
ProcessAppMemoryInfo = 2
ProcessInPrivateInfo = 3
ProcessPowerThrottling = 4
ProcessReservedValue1 = 5
ProcessTelemetryCoverageInfo = 6
ProcessProtectionLevelInfo = 7
ProcessLeapSecondInfo = 8
ProcessMachineTypeInfo = 9
ProcessInformationClassMax = 10

class _PROCESS_INFORMATION_CLASS(enum.IntFlag):     
    ProcessMemoryPriority = 0
    ProcessMemoryExhaustionInfo = 1
    ProcessAppMemoryInfo = 2
    ProcessInPrivateInfo = 3
    ProcessPowerThrottling = 4
    ProcessReservedValue1 = 5
    ProcessTelemetryCoverageInfo = 6
    ProcessProtectionLevelInfo = 7
    ProcessLeapSecondInfo = 8
    ProcessMachineTypeInfo = 9
    ProcessInformationClassMax = 10

PROCESS_INFORMATION_CLASS = _PROCESS_INFORMATION_CLASS
