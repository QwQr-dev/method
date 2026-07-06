# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import winsta
from method.System.winnt import LARGE_INTEGER
from method.System.errcheck import win32_to_errcheck


def WinStationTerminateProcess(
    ServerHandle: int | None, 
    ProcessId: int, 
    ExitCode: int,
    errcheck: bool = True
):
    
    WinStationTerminateProcess = winsta.WinStationTerminateProcess
    WinStationTerminateProcess.argtypes = [HANDLE, ULONG, ULONG]
    WinStationTerminateProcess.restype = BOOLEAN
    res = WinStationTerminateProcess(
        ServerHandle, 
        ProcessId, 
        ExitCode
    )

    return win32_to_errcheck(res, errcheck)


def WinStationShutdownSystem(
    hServer: int | None,
    ShutdownFlags: int,
    errcheck: bool = True
):
    
    WinStationShutdownSystem = winsta.WinStationShutdownSystem
    WinStationShutdownSystem.argtypes = [HANDLE, ULONG]
    WinStationShutdownSystem.restype = BOOLEAN
    res = WinStationShutdownSystem(hServer, ShutdownFlags)
    return win32_to_errcheck(res, errcheck)


def WinStationGetAllProcesses(
    hServer,
    Level,
    pNumberOfProcesses,
    ppProcessArray,
    errcheck: bool = True
):
    
    WinStationGetAllProcesses = winsta.WinStationGetAllProcesses
    WinStationGetAllProcesses.argtypes = [HANDLE, ULONG, PULONG, PVOID]
    WinStationGetAllProcesses.restype = BOOLEAN
    res = WinStationGetAllProcesses(hServer, Level, pNumberOfProcesses, ppProcessArray)
    return win32_to_errcheck(res, errcheck)


def WinStationFreeGAPMemory(Level, pProcArray, NumberOfProcesses, errcheck: bool = True):
    WinStationFreeGAPMemory = winsta.WinStationFreeGAPMemory
    WinStationFreeGAPMemory.argtypes = [ULONG, PVOID, ULONG]
    WinStationFreeGAPMemory.restype = BOOLEAN
    res = WinStationFreeGAPMemory(Level, pProcArray, NumberOfProcesses)
    return win32_to_errcheck(res, errcheck)


def WinStationEnumerateProcesses(hServer, ppProcessBuffer, errcheck: bool = True):
    WinStationEnumerateProcesses = winsta.WinStationEnumerateProcesses
    WinStationEnumerateProcesses.argtypes = [HANDLE, PVOID]
    WinStationEnumerateProcesses.restype = BOOLEAN
    res = WinStationEnumerateProcesses(hServer, ppProcessBuffer)
    return win32_to_errcheck(res, errcheck)


def WinStationFreeMemory(pBuffer, errcheck: bool = True):
    WinStationFreeMemory = winsta.WinStationFreeMemory
    WinStationFreeMemory.argtypes = [PVOID]
    WinStationFreeMemory.restype = BOOLEAN
    res = WinStationFreeMemory(pBuffer)
    return win32_to_errcheck(res, errcheck)


CITRIX_PROCESS_INFO_MAGIC  = 0x23495452

SIZEOF_TS4_SYSTEM_THREAD_INFORMATION = 64
SIZEOF_TS4_SYSTEM_PROCESS_INFORMATION = 136

GAP_LEVEL_BASIC = 0

class _TS_UNICODE_STRING(Structure):
    _fields_ = [
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', PWSTR)
    ]

TS_UNICODE_STRING = _TS_UNICODE_STRING

class _TS_SYS_PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('NextEntryOffset', ULONG),
        ('NumberOfThreads', ULONG),
        ('SpareLi1', LARGE_INTEGER),
        ('SpareLi2', LARGE_INTEGER),
        ('SpareLi3', LARGE_INTEGER),
        ('CreateTime', LARGE_INTEGER),
        ('UserTime', LARGE_INTEGER),
        ('KernelTime', LARGE_INTEGER),
        ('ImageName', TS_UNICODE_STRING),
        ('BasePriority', LONG),
        ('UniqueProcessId', DWORD),
        ('InheritedFromUniqueProcessId', DWORD),
        ('HandleCount', ULONG),
        ('SessionId', ULONG),
        ('SpareUl3', ULONG),
        ('PeakVirtualSize', SIZE_T),
        ('VirtualSize', SIZE_T),
        ('PageFaultCount', ULONG),
        ('PeakWorkingSetSize', ULONG),
        ('WorkingSetSize', ULONG),
        ('QuotaPeakPagedPoolUsage', SIZE_T),
        ('QuotaPagedPoolUsage', SIZE_T),
        ('QuotaPeakNonPagedPoolUsage', SIZE_T),
        ('QuotaNonPagedPoolUsage', SIZE_T),
        ('PagefileUsage', SIZE_T),
        ('PeakPagefileUsage', SIZE_T),
        ('PrivatePageCount', SIZE_T)
    ]

TS_SYS_PROCESS_INFORMATION = _TS_SYS_PROCESS_INFORMATION
PTS_SYS_PROCESS_INFORMATION = POINTER(TS_SYS_PROCESS_INFORMATION)

class _CITRIX_PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('MagicNumber', ULONG),
        ('LogonId', ULONG),
        ('ProcessSid', PVOID),
        ('Pad', ULONG)
    ]

CITRIX_PROCESS_INFORMATION = _CITRIX_PROCESS_INFORMATION
PCITRIX_PROCESS_INFORMATION = POINTER(CITRIX_PROCESS_INFORMATION)

class _TS_ALL_PROCESSES_INFO(Structure):
    _fields_ = [
        ('pTsProcessInfo', PTS_SYS_PROCESS_INFORMATION),
        ('SizeOfSid', DWORD),
        ('pSid', PBYTE)
    ]

TS_ALL_PROCESSES_INFO = _TS_ALL_PROCESSES_INFO
PTS_ALL_PROCESSES_INFO = POINTER(TS_ALL_PROCESSES_INFO)

class _SID_INFO(Structure):
    _fields_ = [('pSid', PBYTE)]

_SID_INFO._fields_.append(('pNext', _SID_INFO))

SID_INFO = _SID_INFO
