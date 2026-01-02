# coding = 'utf-8'


from method.System.winusutypes import *
from method.System.shellapi import CloseHandle
from method.System.winnt import OBJECT_ATTRIBUTES, CLIENT_ID, PROCESS_ALL_ACCESS
from method.System.ntddk import (
    NtOpenProcess, NtTerminateProcess, ZwOpenProcess, ZwTerminateProcess
)


def NtOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = HANDLE()
    ClientId.UniqueProcess = pid
    NtOpenProcess(byref(hProcess), PROCESS_ALL_ACCESS, byref(ObjectAttributes), byref(ClientId), False)
    try:
        NtTerminateProcess(hProcess, 0)
    finally:
        CloseHandle(hProcess)


def ZwOpenTerminateProcess(pid: int) -> None:
    ObjectAttributes = OBJECT_ATTRIBUTES()
    ClientId = CLIENT_ID()
    hProcess = HANDLE()
    ClientId.UniqueProcess = pid
    ZwOpenProcess(byref(hProcess), PROCESS_ALL_ACCESS, byref(ObjectAttributes), byref(ClientId), False)
    try:
        ZwTerminateProcess(hProcess, 0)
    finally:
        CloseHandle(hProcess)
