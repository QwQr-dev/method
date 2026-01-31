# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import winsta
from method.System.errcheck import win32_to_errcheck


def WinStationTerminateProcess(
    ServerHandle: int, 
    ProcessId: int, 
    ExitCode: int,
    errcheck: bool = True
):
    
    WinStationTerminateProcess = winsta.WinStationTerminateProcess
    WinStationTerminateProcess.argtypes = [HANDLE, ULONG, ULONG]
    WinStationTerminateProcess.restype = BOOL
    res = WinStationTerminateProcess(
        ServerHandle, 
        ProcessId, 
        ExitCode
    )

    return win32_to_errcheck(res, errcheck)

