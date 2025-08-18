# coding = 'utf-8'

from method.core.windows import *


def OpenTerminateProcess(pid: int) -> None:
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    TerminateProcess(handle, 0)
    CloseHandle(handle)


def TerminateProcessViaJob(pid: int) -> None:
    hJob = CreateJobObject(NULL, NULL)
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    if hProcess and hJob:
        AssignProcessToJobObject(hJob, hProcess)
        TerminateJobObject(hJob, 0)
        CloseHandle(hJob)
        CloseHandle(hProcess)
