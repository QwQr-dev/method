# coding = 'utf-8'

import enum
from typing import Any, NoReturn
from ctypes import WinError, Structure, POINTER

try:
    from sdkddkver import *
    from public_dll import *
    from win_cbasictypes import *
    from error import GetLastError
except ImportError:
    from .sdkddkver import *
    from .public_dll import *
    from .win_cbasictypes import *
    from .error import GetLastError

NULL = 0
_WIN32_WINNT = WIN32_WINNT

FLS_OUT_OF_INDEXES = DWORD(0xffffffff).value
TLS_OUT_OF_INDEXES = DWORD(0xffffffff).value


def OpenProcess(dwDesiredAccess: int, 
                bInheritHandle: bool, 
                dwProcessId: int) -> int:
    
    OpenProcess = Kernel32.OpenProcess
    OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    OpenProcess.restype = HANDLE
    res = OpenProcess(dwDesiredAccess, 
                         bInheritHandle, 
                         dwProcessId
    )

    if not res:
        raise WinError(GetLastError())
    return res


def QueueUserAPC(pfnAPC, hThread, dwData):
    QueueUserAPC = Kernel32.QueueUserAPC
    res = QueueUserAPC(pfnAPC, hThread, dwData)
    if not res:
        raise WinError(GetLastError())
    return res


def GetProcessTimes(hProcess: int,
                    lpCreationTime: Any,
                    lpExitTime: Any,
                    lpKernelTime: Any,
                    lpUserTime: Any):
    
    GetProcessTimes = Kernel32.GetProcessTimes
    res = GetProcessTimes(hProcess,
                         lpCreationTime,
                         lpExitTime,
                         lpKernelTime,
                         lpUserTime
    )

    if not res:
        raise WinError(GetLastError())
    

def ExitProcess(uExitCode: int) -> NoReturn:
    Kernel32.ExitProcess(uExitCode)


def GetExitCodeProcess(hProcess, LPlpExitCode) -> None:
    GetExitCodeProcess = Kernel32.GetExitCodeProcess
    res = GetExitCodeProcess(hProcess, LPlpExitCode)
    if not res:
        WinError(GetLastError())


def SwitchToThread() -> int:
    return Kernel32.SwitchToThread()


def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    OpenThread = Kernel32.OpenThread
    res = OpenThread(dwDesiredAccess, 
                     bInheritHandle, 
                     dwThreadId
    )

    if not res:
        raise WinError(GetLastError())
    return res


def SetThreadPriorityBoost(hThread, bDisablePriorityBoost):
    SetThreadPriorityBoost = Kernel32.SetThreadPriorityBoost
    res = SetThreadPriorityBoost(hThread, bDisablePriorityBoost)
    if not res:
        raise WinError(GetLastError())
    return res


def GetThreadPriorityBoost(hThread, pDisablePriorityBoost):
    GetThreadPriorityBoost = Kernel32.GetThreadPriorityBoost
    res = GetThreadPriorityBoost(hThread, pDisablePriorityBoost)
    if not res:
        raise WinError(GetLastError())


def SetThreadToken(PThread, Token):
    SetThreadToken = advapi32.SetThreadToken
    # SetThreadToken.argtypes = [PHANDLE, HANDLE]
    res = SetThreadToken(PThread, Token)
    if not res:
        raise WinError(GetLastError())
    return res


def OpenProcessToken(ProcessHandle: int, DesiredAccess: int, PTokenHandle: Any):
    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [HANDLE, DWORD, HANDLE]
    OpenProcessToken.restype = BOOL
    res = OpenProcessToken(ProcessHandle, 
                           DesiredAccess, 
                           PTokenHandle
    )

    if not res:
        raise WinError(GetLastError())


def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
    OpenThreadToken = advapi32.OpenThreadToken
    res = OpenThreadToken(ThreadHandle, 
                         DesiredAccess, 
                         OpenAsSelf, 
                         TokenHandle
    )

    if not res:
        raise WinError(GetLastError())


def GetCurrentProcess() -> int:
    GetCurrentProcess = Kernel32.GetCurrentProcess
    GetCurrentProcess.restype = HANDLE
    return GetCurrentProcess()


def GetCurrentProcessId() -> int:
	GetCurrentProcessId = Kernel32.GetCurrentProcessId
	GetCurrentProcessId.restype = DWORD
	return GetCurrentProcessId()


def SetPriorityClass(hProcess, dwPriorityClass):
    SetPriorityClass = Kernel32.SetPriorityClass
    res = SetPriorityClass(hProcess, dwPriorityClass)
    if not res:
        raise WinError(GetLastError())
    return res


def GetPriorityClass(hProcess):
    GetPriorityClass = Kernel32.GetPriorityClass
    res = GetPriorityClass(hProcess)
    if not res:
        raise WinError(GetLastError())
    return res


def GetProcessId(Process) -> int:
    GetProcessId = Kernel32.GetProcessId
    res = GetProcessId(Process)
    if not res:
        raise WinError(GetLastError())
    return res


def GetThreadId(Thread) -> int:
    GetThreadId = Kernel32.GetThreadId
    res = GetThreadId(Thread)
    if not res:
        raise WinError(GetLastError())
    return res


def GetThreadContext(hThread, lpContext):
    GetThreadContext = Kernel32.GetThreadContext
    res = GetThreadContext(hThread, 
                          lpContext
    )

    if not res:
        raise WinError(GetLastError())


def FlushInstructionCache(hProcess, lpBaseAddress, dwSize):
    FlushInstructionCache = Kernel32.FlushInstructionCache
    res = FlushInstructionCache(hProcess, 
                                lpBaseAddress, 
                                dwSize
    )

    if not res:
        raise WinError(GetLastError())
    return res


def GetCurrentProcessorNumber() -> int:
    return Kernel32.GetCurrentProcessorNumber()


def TerminateProcess(hProcess: int, uExitCode: int) -> None:
    TerminateProcess = Kernel32.TerminateProcess
    TerminateProcess.argtypes = [HANDLE, UINT]
    TerminateProcess.restype = BOOL
    res = TerminateProcess(hProcess, uExitCode)
    if not res:
        raise WinError(GetLastError())


def CreateProcessWithToken(hToken, 
                           dwLogonFlags, 
                           lpApplicationName, 
                           lpCommandLine, 
                           dwCreationFlags, 
                           lpEnvironment, 
                           lpCurrentDirectory, 
                           lpStartupInfo, 
                           lpProcessInformation,
                           unicode: bool = True):
    
    CreateProcessWithToken = (advapi32.CreateProcessWithTokenW 
                              if unicode else advapi32.CreateProcessWithTokenA
    )
    
    res = CreateProcessWithToken(hToken, 
                                 dwLogonFlags, 
                                 lpApplicationName, 
                                 lpCommandLine, 
                                 dwCreationFlags, 
                                 lpEnvironment, 
                                 lpCurrentDirectory, 
                                 lpStartupInfo, 
                                 lpProcessInformation
    )

    if not res:
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
        
        GetProcessDefaultCpuSetMasks = Kernel32.GetProcessDefaultCpuSetMasks
        res = GetProcessDefaultCpuSetMasks(Process, 
                                          CpuSetMasks, 
                                          CpuSetMaskCount, 
                                          RequiredMaskCount
        )

        if not res:
            raise WinError(res)


    def SetProcessDefaultCpuSetMasks(Process, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount):
        SetProcessDefaultCpuSetMasks = Kernel32.SetProcessDefaultCpuSetMasks   
        res = SetProcessDefaultCpuSetMasks(Process, 
                                           CpuSetMasks, 
                                           CpuSetMaskCount)
        return res


    def GetThreadSelectedCpuSetMasks(Thread, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount, 
                                     RequiredMaskCount):
        
        GetThreadSelectedCpuSetMasks = Kernel32.GetThreadSelectedCpuSetMasks
        res = GetThreadSelectedCpuSetMasks(Thread, 
                                         CpuSetMasks, 
                                         CpuSetMaskCount, 
                                         RequiredMaskCount
        )

        if not res:
            raise WinError(GetLastError())


    def SetThreadSelectedCpuSetMasks(Thread, 
                                     CpuSetMasks, 
                                     CpuSetMaskCount):
        
        SetThreadSelectedCpuSetMasks = Kernel32.SetThreadSelectedCpuSetMasks
        res = SetThreadSelectedCpuSetMasks(Thread, 
                                        CpuSetMasks, 
                                        CpuSetMaskCount
        )

        if not res:
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
    
    CreateRemoteThread = Kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [HANDLE, 
                                   VOID, 
                                   SIZE_T, 
                                   VOID, 
                                   VOID, 
                                   DWORD, 
                                   DWORD
    ]

    CreateRemoteThread.restype = HANDLE
    res = CreateRemoteThread(hProcess, 
                            lpThreadAttributes, 
                            dwStackSize, 
                            lpStartAddress, 
                            lpParameter, 
                            dwCreationFlags, 
                            lpThreadId
    )

    if not res:
        raise WinError(GetLastError())


def TerminateThread(hThread, dwExitCode):
    TerminateThread = Kernel32.TerminateThread
    res = TerminateThread(hThread, dwExitCode)
    if not res:
        raise WinError(GetLastError())
    return hThread


def SetProcessShutdownParameters(dwLevel, dwFlags):
    SetProcessShutdownParameters = Kernel32.SetProcessShutdownParameters
    res = SetProcessShutdownParameters(dwLevel, dwFlags)
    if not res:
        raise WinError(GetLastError())


def GetProcessVersion(ProcessId) -> int:
    GetProcessVersion = Kernel32.GetProcessVersion
    res = GetProcessVersion(ProcessId)
    if not res:
        raise WinError(GetLastError())
    return res


def GetStartupInfoW(lpStartupInfo):
    Kernel32.GetStartupInfoW(lpStartupInfo)


def SetThreadStackGuarantee(StackSizeInBytes):
    SetThreadStackGuarantee = Kernel32.SetThreadStackGuarantee
    res = SetThreadStackGuarantee(StackSizeInBytes)
    if not res:
        raise WinError(GetLastError())


def ProcessIdToSessionId(dwProcessId: int, pSessionId: Any):
    ProcessIdToSessionId = Kernel32.ProcessIdToSessionId
    res = ProcessIdToSessionId(dwProcessId, 
                               pSessionId
    )

    if not res:
        raise WinError(GetLastError())


def CreateRemoteThreadEx(hProcess, 
                         lpThreadAttributes, 
                         dwStackSize, 
                         lpStartAddress, 
                         lpParameter, 
                         dwCreationFlags, 
                         lpAttributeList,
                         lpThreadId):
    
    CreateRemoteThreadEx = Kernel32.CreateRemoteThreadEx
    res = CreateRemoteThreadEx(hProcess, 
                               lpThreadAttributes, 
                               dwStackSize, 
                               lpStartAddress, 
                               lpParameter, 
                               dwCreationFlags, 
                               lpAttributeList, 
                               lpThreadId
    )

    if not res:
        raise WinError(GetLastError())
    return res


def SetThreadContext(hThread: int, lpContext):
    SetThreadContext = Kernel32.SetThreadContext
    res = SetThreadContext(hThread, lpContext)
    if not res:
        raise WinError(GetLastError())


def GetProcessHandleCount(hProcess: int, pdwHandleCount: Any):
    GetProcessHandleCount = Kernel32.GetProcessHandleCount
    res = GetProcessHandleCount(hProcess, pdwHandleCount)
    if not res:
        raise WinError(GetLastError())


GetStartupInfo = GetStartupInfoW

LOGON_WITH_PROFILE              = 0x00000001
LOGON_NETCREDENTIALS_ONLY       = 0x00000002
LOGON_ZERO_PASSWORD_BUFFER      = 0x80000000


def CreateProcessWithToken(hToken: int, 
                           dwLogonFlags: int, 
                           lpApplicationName: str | bytes, 
                           lpCommandLine: str | bytes, 
                           dwCreationFlags: int, 
                           lpEnvironment: str | bytes, 
                           lpCurrentDirectory: str | bytes, 
                           lpStartupInfo: Any, 
                           lpProcessInformation: Any,
                           unicode: bool = True):
    
    CreateProcessWithToken = (advapi32.CreateProcessWithTokenW 
                              if unicode else advapi32.CreateProcessWithTokenA
    )
    
    res = CreateProcessWithToken(hToken, 
                                 dwLogonFlags, 
                                 lpApplicationName, 
                                 lpCommandLine, 
                                 dwCreationFlags, 
                                 lpEnvironment, 
                                 lpCurrentDirectory, 
                                 lpStartupInfo, 
                                 lpProcessInformation
    )

    if not res:
        raise WinError(GetLastError())


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

    if not res:
        raise WinError(GetLastError())


PROCESS_AFFINITY_ENABLE_AUTO_UPDATE = 0x1
PROC_THREAD_ATTRIBUTE_REPLACE_VALUE = 0x00000001


def GetProcessIdOfThread(Thread: int) -> int:
    GetProcessIdOfThread = Kernel32.GetProcessIdOfThread
    res = GetProcessIdOfThread(Thread)
    if not res:
        raise WinError(GetLastError())
    return res


def InitializeProcThreadAttributeList(lpAttributeList, 
                                      dwAttributeCount, 
                                      dwFlags, 
                                      lpSize):
    
    InitializeProcThreadAttributeList = Kernel32.InitializeProcThreadAttributeList
    res = InitializeProcThreadAttributeList(lpAttributeList, 
                                            dwAttributeCount, 
                                            dwFlags, 
                                            lpSize
    )

    if not res:
        raise WinError(GetLastError())


def DeleteProcThreadAttributeList(lpAttributeList) -> None:
    DeleteProcThreadAttributeList = Kernel32.DeleteProcThreadAttributeList
    DeleteProcThreadAttributeList(lpAttributeList)


def SetProcessAffinityUpdateMode(hProcess, dwFlags):
    SetProcessAffinityUpdateMode = Kernel32.SetProcessAffinityUpdateMode
    res = SetProcessAffinityUpdateMode(hProcess, dwFlags)
    if not res:
        raise WinError(GetLastError())


def QueryProcessAffinityUpdateMode(hProcess, lpdwFlags):
    QueryProcessAffinityUpdateMode = Kernel32.QueryProcessAffinityUpdateMode
    res = QueryProcessAffinityUpdateMode(hProcess, lpdwFlags)
    if not res:
        raise WinError(GetLastError())


def UpdateProcThreadAttribute(lpAttributeList, 
                              dwFlags, 
                              Attribute, 
                              lpValue, 
                              cbSize, 
                              lpPreviousValue, 
                              lpReturnSize):
    
    UpdateProcThreadAttribute = Kernel32.UpdateProcThreadAttribute
    res = UpdateProcThreadAttribute(lpAttributeList, 
                                    dwFlags, 
                                    Attribute, 
                                    lpValue, 
                                    cbSize, 
                                    lpPreviousValue, 
                                    lpReturnSize
    )

    if not res:
        raise WinError(GetLastError())


if _WIN32_WINNT >= WIN32_WINNT_WIN8:
    def SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength):
        SetProcessMitigationPolicy = Kernel32.SetProcessMitigationPolicy
        res = SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength)
        if not res:
            raise WinError(GetLastError())


    def GetCurrentProcessToken() -> int:
        return HANDLE(LONG_PTR(-4).value).value


    def GetCurrentThreadToken() -> int:
        return HANDLE(LONG_PTR(-5).value).value


    def GetCurrentThreadEffectiveToken() -> int:
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
        IsProcessCritical = Kernel32.IsProcessCritical
        res = IsProcessCritical (hProcess, Critical)
        if not res:
            raise WinError(GetLastError())


if _WIN32_WINNT >= WIN32_WINNT_WIN10:
    def SetProtectedPolicy (PolicyGuid, PolicyValue, OldPolicyValue):
        SetProtectedPolicy = Kernel32.SetProtectedPolicy
        res = SetProtectedPolicy (PolicyGuid, PolicyValue, OldPolicyValue)
        if not res:
            raise WinError(GetLastError())


def QueryProtectedPolicy (PolicyGuid, PolicyValue):
    QueryProtectedPolicy = Kernel32.QueryProtectedPolicy
    res = QueryProtectedPolicy (PolicyGuid, PolicyValue)
    if not res:
        raise WinError(GetLastError())


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

    if not res:
        raise WinError(GetLastError())


if _WIN32_WINNT >= 0x0602:
    def GetCurrentThreadStackLimits(LowLimit, HighLimit):
        GetCurrentThreadStackLimits = Kernel32.GetCurrentThreadStackLimits
        GetCurrentThreadStackLimits.argtypes = [PULONG_PTR, PULONG_PTR]
        GetCurrentThreadStackLimits.restype = VOID
        return GetCurrentThreadStackLimits(LowLimit, HighLimit)


    def GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength):
        GetProcessMitigationPolicy = Kernel32.GetProcessMitigationPolicy
        res = GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength)
        if not res:
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

STARTUPINFO = STARTUPINFOW if UNICODE else STARTUPINFOA

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
