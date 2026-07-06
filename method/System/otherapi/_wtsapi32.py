# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import wtsapi32
from method.System.errcheck import win32_to_errcheck

PSID = PVOID

class _WTS_PROCESS_INFOA(Structure):
    _fields_ = [
        ('SessionId', DWORD),
        ('ProcessId', DWORD),
        ('pProcessName', LPSTR),
        ('pUserSid', PSID)
    ]

WTS_PROCESS_INFOA = _WTS_PROCESS_INFOA
PWTS_PROCESS_INFOA = POINTER(WTS_PROCESS_INFOA)

class _WTS_PROCESS_INFOW(Structure):
    _fields_ = [
        ('SessionId', DWORD),
        ('ProcessId', DWORD),
        ('pProcessName', LPWSTR),
        ('pUserSid', PSID)
    ]

WTS_PROCESS_INFOW = _WTS_PROCESS_INFOW
PWTS_PROCESS_INFOW = POINTER(WTS_PROCESS_INFOW)

WTS_PROCESS_INFO = WTS_PROCESS_INFOW if UNICODE else WTS_PROCESS_INFOA
PWTS_PROCESS_INFO = PWTS_PROCESS_INFOW if UNICODE else PWTS_PROCESS_INFOA


def WTSOpenServer(pServerName: str | bytes, unicode: bool = True, errcheck: bool = True):
    WTSOpenServer = wtsapi32.WTSOpenServerW if unicode else wtsapi32.WTSOpenServerA
    WTSOpenServer.argtypes = [(LPWSTR if unicode else LPSTR)]
    WTSOpenServer.restype = HANDLE
    res = WTSOpenServer(pServerName)
    return win32_to_errcheck(res, errcheck)


def WTSEnumerateProcesses(
    hServer: int | None,
    Reserved: int,
    Version: int,
    ppProcessInfo,
    pCount,
    unicode: bool = True,
    errcheck: bool = True
):
    
    WTSEnumerateProcesses = wtsapi32.WTSEnumerateProcessesW if unicode else wtsapi32.WTSEnumerateProcessesA
    WTSEnumerateProcesses.argtypes = [
        HANDLE,
        DWORD,
        DWORD,
        POINTER(WTS_PROCESS_INFOW if unicode else WTS_PROCESS_INFOA),
        PDWORD
    ]
    
    WTSEnumerateProcesses.restype = BOOL
    res = WTSEnumerateProcesses(
        hServer,
        Reserved,
        Version,
        ppProcessInfo,
        pCount
    )

    return win32_to_errcheck(res, errcheck)