# coding = 'utf-8'

from method.core.windows import *


def NtOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = HANDLE()
    ClientId.UniqueProcess = pid
    NtOpenProcess(byref(hProcess), PROCESS_ALL_ACCESS, byref(ObjectAttributes), byref(ClientId))
    try:
        NtTerminateProcess(hProcess, 0)
    finally:
        CloseHandle(hProcess)


def ZwOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = HANDLE()
    ClientId.UniqueProcess = pid
    ZwOpenProcess(byref(hProcess), PROCESS_ALL_ACCESS, byref(ObjectAttributes), byref(ClientId))
    try:
        ZwTerminateProcess(hProcess, 0)
    finally:
        CloseHandle(hProcess)
