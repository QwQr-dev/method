# coding = 'utf-8'

from method.core.windows import *


def OpenTerminateProcess(pid: int) -> None:
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    try:
        TerminateProcess(handle, 0)
    finally:
        CloseHandle(handle)


def TerminateProcessViaJob(pid: int) -> None:
    hJob = CreateJobObject(NULL, NULL)
    try:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        try:
            AssignProcessToJobObject(hJob, hProcess)
            TerminateJobObject(hJob, 0)
        finally:
            CloseHandle(hJob)
            CloseHandle(hProcess)
    finally:
        CloseHandle(hJob)
        CloseHandle(hProcess)
