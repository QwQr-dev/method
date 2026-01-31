# coding = 'utf-8'

import enum
from typing import Any, NoReturn
from method.System.winnt import *
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.wtypesbase import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck, hresult_to_errcheck

_WIN32_WINNT = WIN32_WINNT

FLS_OUT_OF_INDEXES = DWORD(0xffffffff).value
TLS_OUT_OF_INDEXES = DWORD(0xffffffff).value


def OpenProcess(
    dwDesiredAccess: int, 
    bInheritHandle: bool, 
    dwProcessId: int,
    errcheck: bool = True
) -> int:
    
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    OpenProcess.restype = HANDLE
    res = OpenProcess(
        dwDesiredAccess, 
        bInheritHandle, 
        dwProcessId
    )

    return win32_to_errcheck(res, errcheck)


def QueueUserAPC(pfnAPC, hThread, dwData, errcheck: bool = True):
    QueueUserAPC = kernel32.QueueUserAPC
    QueueUserAPC.argtypes = [
        PAPCFUNC,
        HANDLE,
        ULONG_PTR
    ]

    QueueUserAPC.restype = DWORD
    res = QueueUserAPC(pfnAPC, hThread, dwData)
    return win32_to_errcheck(res, errcheck)


def GetProcessTimes(
    hProcess: int,
    lpCreationTime: Any,
    lpExitTime: Any,
    lpKernelTime: Any,
    lpUserTime: Any,
    errcheck: bool = True
):
    
    GetProcessTimes = kernel32.GetProcessTimes
    GetProcessTimes.argtypes = [
        HANDLE,
        LPFILETIME,
        LPFILETIME,
        LPFILETIME,
        LPFILETIME
    ]
    
    GetProcessTimes.restype = WINBOOL
    res = GetProcessTimes(
        hProcess,
        lpCreationTime,
        lpExitTime,
        lpKernelTime,
        lpUserTime
    )

    return win32_to_errcheck(res, errcheck)


def ExitProcess(uExitCode: int) -> NoReturn:
    ExitProcess = kernel32.ExitProcess
    ExitProcess.argtypes = [UINT]
    ExitProcess.restype = VOID
    ExitProcess(uExitCode)


def GetExitCodeProcess(hProcess, LPlpExitCode, errcheck: bool = True) -> None:
    GetExitCodeProcess = kernel32.GetExitCodeProcess
    GetExitCodeProcess.argtypes = [HANDLE, LPDWORD]
    GetExitCodeProcess.restype = WINBOOL
    res = GetExitCodeProcess(hProcess, LPlpExitCode)
    return win32_to_errcheck(res, errcheck)


def SwitchToThread() -> int:
    SwitchToThread = kernel32.SwitchToThread
    SwitchToThread.restype = WINBOOL
    return SwitchToThread()


def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId, errcheck: bool = True):
    OpenThread = kernel32.OpenThread
    OpenThread.argtypes = [DWORD, WINBOOL, DWORD]
    OpenThread.restype = HANDLE
    res = OpenThread(
        dwDesiredAccess, 
        bInheritHandle, 
        dwThreadId
    )

    return win32_to_errcheck(res, errcheck)


def SetThreadPriorityBoost(hThread, bDisablePriorityBoost, errcheck: bool = True):
    SetThreadPriorityBoost = kernel32.SetThreadPriorityBoost
    SetThreadPriorityBoost.argtypes = [HANDLE, WINBOOL]
    SetThreadPriorityBoost.restype = WINBOOL
    res = SetThreadPriorityBoost(hThread, bDisablePriorityBoost)
    return win32_to_errcheck(res, errcheck)


def GetThreadPriorityBoost(hThread, pDisablePriorityBoost, errcheck: bool = True):
    GetThreadPriorityBoost = kernel32.GetThreadPriorityBoost
    GetThreadPriorityBoost.argtypes = [HANDLE, PBOOL]
    res = GetThreadPriorityBoost(hThread, pDisablePriorityBoost)
    return win32_to_errcheck(res, errcheck)


def SetThreadToken(PThread, Token, errcheck: bool = True):
    SetThreadToken = advapi32.SetThreadToken
    SetThreadToken.argtypes = [PHANDLE, HANDLE]
    SetThreadToken.restype = WINBOOL
    res = SetThreadToken(PThread, Token)
    return win32_to_errcheck(res, errcheck)


def OpenProcessToken(ProcessHandle: int, DesiredAccess: int, PTokenHandle: Any, errcheck: bool = True):
    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [HANDLE, DWORD, HANDLE]
    OpenProcessToken.restype = BOOL
    res = OpenProcessToken(
        ProcessHandle, 
        DesiredAccess, 
        PTokenHandle
    )

    return win32_to_errcheck(res, errcheck)


def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle, errcheck: bool = True):
    OpenThreadToken = advapi32.OpenThreadToken
    OpenThreadToken.argtypes = [HANDLE, DWORD, WINBOOL]
    OpenThreadToken.restype = WINBOOL
    res = OpenThreadToken(
        ThreadHandle, 
        DesiredAccess, 
        OpenAsSelf, 
        TokenHandle
    )

    return win32_to_errcheck(res, errcheck)


def GetCurrentProcess() -> int:
    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = HANDLE
    return GetCurrentProcess()


def GetCurrentProcessId() -> int:
	GetCurrentProcessId = kernel32.GetCurrentProcessId
	GetCurrentProcessId.restype = DWORD
	return GetCurrentProcessId()


def SetPriorityClass(hProcess, dwPriorityClass, errcheck: bool = True):
    SetPriorityClass = kernel32.SetPriorityClass
    SetPriorityClass.argtypes = [HANDLE, DWORD]
    SetPriorityClass.restype = WINBOOL
    res = SetPriorityClass(hProcess, dwPriorityClass)
    return win32_to_errcheck(res, errcheck)


def GetPriorityClass(hProcess, errcheck: bool = True):
    GetPriorityClass = kernel32.GetPriorityClass
    GetPriorityClass.argtypes = [HANDLE]
    GetPriorityClass.restype = WINBOOL
    res = GetPriorityClass(hProcess)
    return win32_to_errcheck(res, errcheck)


def GetProcessId(Process, errcheck: bool = True) -> int:
    GetProcessId = kernel32.GetProcessId
    GetProcessId.argtypes = [HANDLE]
    GetProcessId.restype = DWORD
    res = GetProcessId(Process)
    return win32_to_errcheck(res, errcheck)


def GetThreadId(Thread, errcheck: bool = True) -> int:
    GetThreadId = kernel32.GetThreadId
    GetThreadId.argtypes = [HANDLE]
    GetThreadId.restype = DWORD
    res = GetThreadId(Thread)
    return win32_to_errcheck(res, errcheck)


def GetThreadContext(hThread, lpContext, errcheck: bool = True):
    GetThreadContext = kernel32.GetThreadContext
    GetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    GetThreadContext.restype = WINBOOL
    res = GetThreadContext(
        hThread, 
        lpContext
    )

    return win32_to_errcheck(res, errcheck)


def FlushInstructionCache(hProcess, lpBaseAddress, dwSize, errcheck: bool = True):
    FlushInstructionCache = kernel32.FlushInstructionCache
    FlushInstructionCache.argtypes = [
        HANDLE,
        LPCVOID,
        SIZE_T
    ]

    FlushInstructionCache.restype = WINBOOL
    res = FlushInstructionCache(
        hProcess, 
        lpBaseAddress, 
        dwSize
    )

    return win32_to_errcheck(res, errcheck)


def GetCurrentProcessorNumber() -> int:
    GetCurrentProcessorNumber = kernel32.GetCurrentProcessorNumber
    GetCurrentProcessorNumber.restype = DWORD
    return GetCurrentProcessorNumber()


def TerminateProcess(hProcess: int, uExitCode: int, errcheck: bool = True) -> None:
    TerminateProcess = kernel32.TerminateProcess
    TerminateProcess.argtypes = [HANDLE, UINT]
    TerminateProcess.restype = BOOL
    res = TerminateProcess(hProcess, uExitCode)
    return win32_to_errcheck(res, errcheck)


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

PMETypeFailFastOnCommitFailure = 0
PMETypeMax = 1

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


def GetProcessInformation(
    hProcess: int, 
    ProcessInformationClass: int, 
    ProcessInformation: Any, 
    ProcessInformationSize: int,
    errcheck: bool = True
) -> int:
    
    GetProcessInformation = kernel32.GetProcessInformation
    GetProcessInformation.argtypes = [
        HANDLE,
        UINT,
        LPVOID,
        DWORD
    ]

    GetProcessInformation.restype = WINBOOL
    res = GetProcessInformation(
        hProcess,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationSize
    )

    return win32_to_errcheck(res, errcheck)


def SetProcessInformation(
    hProcess: int, 
    ProcessInformationClass: int, 
    ProcessInformation: Any, 
    ProcessInformationSize: int,
    errcheck: bool = True
) -> int:
    
    SetProcessInformation = kernel32.SetProcessInformation
    SetProcessInformation.argtypes = [
        HANDLE,
        UINT,
        LPVOID,
        DWORD
    ]

    SetProcessInformation.restype = WINBOOL
    res = SetProcessInformation(
        hProcess,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationSize
    )

    return win32_to_errcheck(res, errcheck)


if _WIN32_WINNT >= WIN32_WINNT_WIN10:
    def GetSystemCpuSetInformation(
        Information,
        BufferLength,
        ReturnedLength,
        Process,
        Flags,
        errcheck: bool = True
    ):
        
        GetSystemCpuSetInformation = kernel32.GetSystemCpuSetInformation
        GetSystemCpuSetInformation.argtypes = [
            PSYSTEM_CPU_SET_INFORMATION,
            ULONG,
            PULONG,
            HANDLE,
            ULONG
        ]
        
        GetSystemCpuSetInformation.restype = WINBOOL
        res = GetSystemCpuSetInformation(
            Information,
            BufferLength,
            ReturnedLength,
            Process,
            Flags
        )

        return win32_to_errcheck(res, errcheck)
    

    def GetProcessDefaultCpuSets(
        Process,
        CpuSetIds,
        CpuSetIdCount,
        RequiredIdCount,
        errcheck: bool = True
    ):
        
        GetProcessDefaultCpuSets = kernel32.GetProcessDefaultCpuSets
        GetProcessDefaultCpuSets.argtypes = [
            HANDLE,
            PULONG,
            ULONG,
            PULONG
        ]

        GetProcessDefaultCpuSets.restype = WINBOOL
        res = GetProcessDefaultCpuSets(
            Process,
            CpuSetIds,
            CpuSetIdCount,
            RequiredIdCount
        )

        return win32_to_errcheck(res, errcheck)
    
    
    def SetProcessDefaultCpuSets(
        Process,
        CpuSetIds,
        CpuSetIdCount,
        errcheck: bool = True
    ):
        
        SetProcessDefaultCpuSets = kernel32.SetProcessDefaultCpuSets
        SetProcessDefaultCpuSets.argtypes = [
            HANDLE,
            PULONG,
            ULONG
        ]

        SetProcessDefaultCpuSets.restype = WINBOOL
        res = SetProcessDefaultCpuSets(
            Process,
            CpuSetIds,
            CpuSetIdCount
        )

        return win32_to_errcheck(res, errcheck)
    

    def GetThreadSelectedCpuSets(
        Thread,
        CpuSetIds,
        CpuSetIdCount,
        RequiredIdCount,
        errcheck: bool = True
    ):
        
        GetThreadSelectedCpuSets = kernel32.GetThreadSelectedCpuSets
        GetThreadSelectedCpuSets.argtypes = [
            HANDLE,
            PULONG,
            ULONG,
            PULONG
        ]

        GetThreadSelectedCpuSets.restype = WINBOOL
        res = GetThreadSelectedCpuSets(
            Thread,
            CpuSetIds,
            CpuSetIdCount,
            RequiredIdCount
        )

        return win32_to_errcheck(res, errcheck)


    def SetThreadSelectedCpuSets(
        Thread,
        CpuSetIds,
        CpuSetIdCount,
        errcheck: bool = True
    ):
        
        SetThreadSelectedCpuSets = kernel32.SetThreadSelectedCpuSets
        SetThreadSelectedCpuSets.argtypes = [
            HANDLE,
            PULONG,
            ULONG
        ]

        SetThreadSelectedCpuSets.restype = WINBOOL
        res = SetThreadSelectedCpuSets(
            Thread,
            CpuSetIds,
            CpuSetIdCount
        )
        
        return win32_to_errcheck(res, errcheck)
    
    
    def GetMachineTypeAttributes(
        Machine,
        MachineTypeAttributes,
        errcheck: bool = True
    ):
        
        GetMachineTypeAttributes = kernel32.GetMachineTypeAttributes
        GetMachineTypeAttributes.argtypes = [USHORT, POINTER(MACHINE_ATTRIBUTES)]
        GetMachineTypeAttributes.restype = HRESULT
        res = GetMachineTypeAttributes(Machine, MachineTypeAttributes)
        return hresult_to_errcheck(res, errcheck)


    def GetProcessDefaultCpuSetMasks(
        Process, 
        CpuSetMasks, 
        CpuSetMaskCount, 
        RequiredMaskCount,
        errcheck: bool = True
    ):
        
        GetProcessDefaultCpuSetMasks = kernel32.GetProcessDefaultCpuSetMasks
        GetProcessDefaultCpuSetMasks.argtypes = [
            HANDLE,
            PGROUP_AFFINITY,
            USHORT,
            PUSHORT
        ]

        GetProcessDefaultCpuSetMasks.restype = WINBOOL
        res = GetProcessDefaultCpuSetMasks(
            Process, 
            CpuSetMasks, 
            CpuSetMaskCount, 
            RequiredMaskCount
        )

        return hresult_to_errcheck(res, errcheck)
    

    def SetProcessDefaultCpuSetMasks(
        Process, 
        CpuSetMasks, 
        CpuSetMaskCount
    ):
        
        SetProcessDefaultCpuSetMasks = kernel32.SetProcessDefaultCpuSetMasks 
        SetProcessDefaultCpuSetMasks.argtypes = [
            HANDLE,
            PGROUP_AFFINITY,
            USHORT
        ]  

        SetProcessDefaultCpuSetMasks.restype = WINBOOL
        res = SetProcessDefaultCpuSetMasks(
            Process, 
            CpuSetMasks, 
            CpuSetMaskCount
        )

        return res


    def GetThreadSelectedCpuSetMasks(
        Thread, 
        CpuSetMasks, 
        CpuSetMaskCount, 
        RequiredMaskCount,
        errcheck: bool = True
    ):
        
        GetThreadSelectedCpuSetMasks = kernel32.GetThreadSelectedCpuSetMasks
        GetThreadSelectedCpuSetMasks.argtypes = [
            HANDLE,
            PGROUP_AFFINITY,
            USHORT,
            PUSHORT
        ]
        
        GetThreadSelectedCpuSetMasks.restype = WINBOOL
        res = GetThreadSelectedCpuSetMasks(
            Thread, 
            CpuSetMasks, 
            CpuSetMaskCount, 
            RequiredMaskCount
        )

        return win32_to_errcheck(res, errcheck)


    def SetThreadSelectedCpuSetMasks(
        Thread, 
        CpuSetMasks, 
        CpuSetMaskCount,
        errcheck: bool = True
    ):
        
        SetThreadSelectedCpuSetMasks = kernel32.SetThreadSelectedCpuSetMasks
        SetThreadSelectedCpuSetMasks.argtypes = [
            HANDLE,
            PGROUP_AFFINITY,
            USHORT
        ]

        SetThreadSelectedCpuSetMasks.restype = WINBOOL
        res = SetThreadSelectedCpuSetMasks(
            Thread, 
            CpuSetMasks, 
            CpuSetMaskCount
        )

        return win32_to_errcheck(res, errcheck)


class _PROC_THREAD_ATTRIBUTE_LIST(Structure):
    pass

PPROC_THREAD_ATTRIBUTE_LIST = POINTER(_PROC_THREAD_ATTRIBUTE_LIST)
LPPROC_THREAD_ATTRIBUTE_LIST = PPROC_THREAD_ATTRIBUTE_LIST


def CreateRemoteThread(
    hProcess, 
    lpThreadAttributes, 
    dwStackSize, 
    lpStartAddress, 
    lpParameter, 
    dwCreationFlags,
    lpThreadId,
    errcheck: bool = True
):
    
    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [
        HANDLE, 
        VOID, 
        SIZE_T, 
        VOID, 
        VOID, 
        DWORD, 
        DWORD
    ]

    CreateRemoteThread.restype = HANDLE
    res = CreateRemoteThread(
        hProcess, 
        lpThreadAttributes, 
        dwStackSize, 
        lpStartAddress, 
        lpParameter, 
        dwCreationFlags, 
        lpThreadId
    )

    return win32_to_errcheck(res, errcheck)


def TerminateThread(hThread, dwExitCode, errcheck: bool = True):
    TerminateThread = kernel32.TerminateThread
    res = TerminateThread(hThread, dwExitCode)
    return win32_to_errcheck(res, errcheck)


def SetProcessShutdownParameters(dwLevel, dwFlags, errcheck: bool = True):
    SetProcessShutdownParameters = kernel32.SetProcessShutdownParameters
    res = SetProcessShutdownParameters(dwLevel, dwFlags)
    return win32_to_errcheck(res, errcheck)


def GetProcessVersion(ProcessId, errcheck: bool = True) -> int:
    GetProcessVersion = kernel32.GetProcessVersion
    res = GetProcessVersion(ProcessId)
    return win32_to_errcheck(res, errcheck)


def GetStartupInfoW(lpStartupInfo):
    GetStartupInfoW = kernel32.GetStartupInfoW
    GetStartupInfoW(lpStartupInfo)


def SetThreadStackGuarantee(StackSizeInBytes, errcheck: bool = True):
    SetThreadStackGuarantee = kernel32.SetThreadStackGuarantee
    res = SetThreadStackGuarantee(StackSizeInBytes)
    return win32_to_errcheck(res, errcheck)


def ProcessIdToSessionId(dwProcessId: int, pSessionId: Any, errcheck: bool = True):
    ProcessIdToSessionId = kernel32.ProcessIdToSessionId
    res = ProcessIdToSessionId(dwProcessId, pSessionId)
    return win32_to_errcheck(res, errcheck)


def CreateRemoteThreadEx(
    hProcess, 
    lpThreadAttributes, 
    dwStackSize, 
    lpStartAddress, 
    lpParameter, 
    dwCreationFlags, 
    lpAttributeList,
    lpThreadId,
    errcheck: bool = True
):
    
    CreateRemoteThreadEx = kernel32.CreateRemoteThreadEx
    res = CreateRemoteThreadEx(
        hProcess, 
        lpThreadAttributes, 
        dwStackSize, 
        lpStartAddress, 
        lpParameter, 
        dwCreationFlags, 
        lpAttributeList, 
        lpThreadId
    )

    return win32_to_errcheck(res, errcheck)


def SetThreadContext(hThread: int, lpContext, errcheck: bool = True):
    SetThreadContext = kernel32.SetThreadContext
    res = SetThreadContext(hThread, lpContext)
    return win32_to_errcheck(res, errcheck)


def GetProcessHandleCount(hProcess: int, pdwHandleCount: Any, errcheck: bool = True):
    GetProcessHandleCount = kernel32.GetProcessHandleCount
    res = GetProcessHandleCount(hProcess, pdwHandleCount)
    return win32_to_errcheck(res, errcheck)


GetStartupInfo = GetStartupInfoW

LOGON_WITH_PROFILE              = 0x00000001
LOGON_NETCREDENTIALS_ONLY       = 0x00000002
LOGON_ZERO_PASSWORD_BUFFER      = 0x80000000


def CreateProcessAsUser(
    hToken: int, 
    lpApplicationName: str | bytes, 
    lpCommandLine: str | bytes, 
    lpProcessAttributes: Any, 
    lpThreadAttributes: Any, 
    bInheritHandles: bool, 
    dwCreationFlags: int, 
    lpEnvironment: Any, 
    lpCurrentDirectory: str | bytes, 
    lpStartupInfo: Any, 
    lpProcessInformation: Any,
    unicode: bool = True,
    errcheck: bool = True
):
    
    CreateProcessAsUser = (advapi32.CreateProcessAsUserW 
                           if unicode else advapi32.CreateProcessAsUserA
    )
    
    CreateProcessAsUser.argtypes = [
        HANDLE,
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES,
        WINBOOL,
        DWORD,
        LPVOID,
        (LPCWSTR if unicode else LPCSTR),
        (LPSTARTUPINFOW if unicode else LPSTARTUPINFOA),
        LPPROCESS_INFORMATION
    ]

    CreateProcessAsUser.restype = WINBOOL
    res = CreateProcessAsUser(
        hToken, 
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

    return win32_to_errcheck(res, errcheck)


PROCESS_AFFINITY_ENABLE_AUTO_UPDATE = 0x1
PROC_THREAD_ATTRIBUTE_REPLACE_VALUE = 0x00000001


def GetProcessIdOfThread(Thread: int, errcheck: bool = True) -> int:
    GetProcessIdOfThread = kernel32.GetProcessIdOfThread
    res = GetProcessIdOfThread(Thread)
    return win32_to_errcheck(res, errcheck)


def InitializeProcThreadAttributeList(
    lpAttributeList, 
    dwAttributeCount, 
    dwFlags, 
    lpSize,
    errcheck: bool = True
):

    InitializeProcThreadAttributeList = kernel32.InitializeProcThreadAttributeList
    res = InitializeProcThreadAttributeList(
        lpAttributeList, 
        dwAttributeCount, 
        dwFlags, 
        lpSize
    )

    return win32_to_errcheck(res, errcheck)


def DeleteProcThreadAttributeList(lpAttributeList) -> None:
    DeleteProcThreadAttributeList = kernel32.DeleteProcThreadAttributeList
    DeleteProcThreadAttributeList(lpAttributeList)


def SetProcessAffinityUpdateMode(hProcess, dwFlags, errcheck: bool = True):
    SetProcessAffinityUpdateMode = kernel32.SetProcessAffinityUpdateMode
    res = SetProcessAffinityUpdateMode(hProcess, dwFlags)
    return win32_to_errcheck(res, errcheck)


def QueryProcessAffinityUpdateMode(hProcess, lpdwFlags, errcheck: bool = True):
    QueryProcessAffinityUpdateMode = kernel32.QueryProcessAffinityUpdateMode
    res = QueryProcessAffinityUpdateMode(hProcess, lpdwFlags)
    return win32_to_errcheck(res, errcheck)


def UpdateProcThreadAttribute(
    lpAttributeList, 
    dwFlags, 
    Attribute, 
    lpValue, 
    cbSize, 
    lpPreviousValue, 
    lpReturnSize,
    errcheck: bool = True
):
    
    UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute
    res = UpdateProcThreadAttribute(
        lpAttributeList, 
        dwFlags, 
        Attribute, 
        lpValue, 
        cbSize, 
        lpPreviousValue, 
        lpReturnSize
    )

    return win32_to_errcheck(res, errcheck)


if _WIN32_WINNT >= WIN32_WINNT_WIN8:
    def SetProcessMitigationPolicy(MitigationPolicy: int, lpBuffer: Any, dwLength: Any, errcheck: bool = True):
        SetProcessMitigationPolicy = kernel32.SetProcessMitigationPolicy
        SetProcessMitigationPolicy.argtypes = [UINT, PVOID, SIZE_T]
        SetProcessMitigationPolicy.restype = BOOL
        res = SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength)
        return win32_to_errcheck(res, errcheck)


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
    def IsProcessCritical (hProcess, Critical, errcheck: bool = True):
        IsProcessCritical = kernel32.IsProcessCritical
        res = IsProcessCritical (hProcess, Critical)
        return win32_to_errcheck(res, errcheck)


if _WIN32_WINNT >= WIN32_WINNT_WIN10:
    def SetProtectedPolicy (PolicyGuid, PolicyValue, OldPolicyValue, errcheck: bool = True):
        SetProtectedPolicy = kernel32.SetProtectedPolicy
        res = SetProtectedPolicy (PolicyGuid, PolicyValue, OldPolicyValue)
        return win32_to_errcheck(res, errcheck)


def QueryProtectedPolicy (PolicyGuid, PolicyValue, errcheck: bool = True):
    QueryProtectedPolicy = kernel32.QueryProtectedPolicy
    res = QueryProtectedPolicy (PolicyGuid, PolicyValue)
    return win32_to_errcheck(res, errcheck)


def GetCurrentThreadStackLimits(LowLimit, HighLimit):
    GetCurrentThreadStackLimits = kernel32.GetCurrentThreadStackLimits
    GetCurrentThreadStackLimits.argtypes = [PULONG_PTR, PULONG_PTR]
    GetCurrentThreadStackLimits.restype = VOID
    return GetCurrentThreadStackLimits(LowLimit, HighLimit)


def GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength, errcheck: bool = True):
    GetProcessMitigationPolicy = kernel32.GetProcessMitigationPolicy
    res = GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength)
    return win32_to_errcheck(res, errcheck)


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


def CreateProcess(
    lpApplicationName: str | bytes, 
    lpCommandLine: str | bytes, 
    lpProcessAttributes: Any, 
    lpThreadAttributes: Any, 
    bInheritHandles: bool, 
    dwCreationFlags: int, 
    lpEnvironment: Any, 
    lpCurrentDirectory: str | bytes, 
    lpStartupInfo: Any,
    lpProcessInformation: Any,
    unicode: bool = True,
    errcheck: bool = True
):
    
    CreateProcess = (kernel32.CreateProcessW 
                     if unicode else kernel32.CreateProcessA
    )

    CreateProcess.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES,
        WINBOOL,
        DWORD,
        LPVOID,
        (LPCWSTR if unicode else LPCSTR),
        (LPSTARTUPINFOW if unicode else LPSTARTUPINFOA),
        LPPROCESS_INFORMATION
    ]

    CreateProcess.restype = WINBOOL
    res = CreateProcess(
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

    return win32_to_errcheck(res, errcheck)


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
