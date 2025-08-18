# coding = 'utf-8'

from method.core.windows import *


def NtOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = PHANDLE()
    ClientId.UniqueProcess = pid
    hProcess = NtOpenProcess(hProcess, PROCESS_ALL_ACCESS, ObjectAttributes, ClientId)
    NtTerminateProcess(hProcess, 0)
    CloseHandle(hProcess)


def ZwOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = PHANDLE()
    ClientId.UniqueProcess = pid
    hProcess = ZwOpenProcess(hProcess, PROCESS_ALL_ACCESS, ObjectAttributes, ClientId)
    ZwTerminateProcess(hProcess, 0)
    CloseHandle(hProcess)
