# coding = 'utf-8'

from typing import NoReturn, Any
from method.System.winusutypes import *
from method.System.public_dll import ntdll
from method.System.errcheck import ntstatus_to_errcheck


def NtRaiseHardError(
    ErrorStatus: int, 
    NumberOfParameters: int, 
    UnicodeStringParameterMask: int, 
    Parameters: int, 
    ValidResponseOptions: int, 
    Response: int,
    errcheck: bool = True
) -> NoReturn:        # BSOD function
    
    NtRaiseHardError = ntdll.NtRaiseHardError
    NtRaiseHardError.argtypes = [
        NTSTATUS,
        ULONG,
        ULONG,
        PULONG_PTR,
        ULONG,
        PULONG
    ]

    NtRaiseHardError.restype = NTSTATUS
    res = NtRaiseHardError(
        ErrorStatus, 
        NumberOfParameters, 
        UnicodeStringParameterMask, 
        Parameters, 
        ValidResponseOptions, 
        Response
    )

    return ntstatus_to_errcheck(res, errcheck)
    

def NtCreateThread(
    ThreadHandle, 
    DesiredAccess, 
    ObjectAttributes, 
    ProcessHandle, 
    ClientId, 
    ThreadContext, 
    InitialTeb, 
    CreateSuspended,
    errcheck: bool = True
):
    
    NtCreateThread = ntdll.NtCreateThread
    res = NtCreateThread(
        ThreadHandle, 
        DesiredAccess, 
        ObjectAttributes, 
        ProcessHandle, 
        ClientId, 
        ThreadContext, 
        InitialTeb, 
        CreateSuspended
    )

    return ntstatus_to_errcheck(res, errcheck)
        


def NtCreateThreadEx(
    ThreadHandle, 
    DesiredAccess, 
    ObjectAttributes, 
    ProcessHandle, 
    StartRoutine, 
    Argument, 
    CreateFlags, 
    ZeroBits, 
    StackSize, 
    MaximumStackSize, 
    AttributeList,
    errcheck: bool = True
):
    
    NtCreateThreadEx = ntdll.NtCreateThreadEx
    res = NtCreateThreadEx(
        ThreadHandle, 
        DesiredAccess, 
        ObjectAttributes, 
        ProcessHandle, 
        StartRoutine, 
        Argument, 
        CreateFlags, 
        ZeroBits, 
        StackSize, 
        MaximumStackSize, 
        AttributeList
    )

    return ntstatus_to_errcheck(res, errcheck)
