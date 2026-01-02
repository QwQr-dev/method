# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.shellapi import CloseHandle
from method.System.winnt import PROCESS_ALL_ACCESS
from method.System.processthreadsapi import OpenProcess, TerminateProcess
from method.System.otherapi import CreateJobObject, AssignProcessToJobObject, TerminateJobObject


def OpenTerminateProcess(pid: int) -> None:
    try:
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid, False)
        TerminateProcess(handle, 0)
    finally:
        CloseHandle(handle)


def TerminateProcessViaJob(pid: int) -> None:
    hJob = CreateJobObject(NULL, NULL, errcheck=False)
    try:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid, False)
        try:
            AssignProcessToJobObject(hJob, hProcess)
            TerminateJobObject(hJob, 0)
        finally:
            CloseHandle(hJob)
            CloseHandle(hProcess)
    finally:
        CloseHandle(hJob)
        CloseHandle(hProcess)
