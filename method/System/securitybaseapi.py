# coding = 'utf-8'
# securitybaseapi.h

from typing import Any
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck, ntstatus_to_errcheck

PSID = PVOID


def ImpersonateLoggedOnUser(hToken: int, errcheck: bool = True) -> None:
    ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
    ImpersonateLoggedOnUser.argtypes = [HANDLE]
    res = ImpersonateLoggedOnUser(hToken)
    return win32_to_errcheck(res, errcheck)    


def ConvertSidToStringSid(Sid, StringSid, unicode: bool = True, errcheck: bool = True) -> None:
    ConvertSidToStringSid = (advapi32.ConvertSidToStringSidW 
                             if unicode else advapi32.ConvertSidToStringSidA
    )
    ConvertSidToStringSid.argtypes = [PSID, POINTER(LPWSTR if unicode else LPSTR)]
    ConvertSidToStringSid.restype = BOOL
    res = ConvertSidToStringSid(Sid, StringSid)
    return win32_to_errcheck(res, errcheck)    


def IsValidSid(pSid: int) -> bool:
    IsValidSid = advapi32.IsValidSid
    IsValidSid.argtypes = [PSID]
    IsValidSid.restype = BOOL
    res = IsValidSid(pSid)
    return bool(res)


def LookupAccountSid(
    lpSystemName: str | bytes, 
    Sid: int, 
    Name, 
    cchName, 
    ReferencedDomainName, 
    cchReferencedDomainName, 
    peUse, 
    unicode: bool = True,
    errcheck: bool = True
) -> None:
    
    LookupAccountSid = (advapi32.LookupAccountSidW 
                        if unicode else advapi32.LookupAccountSidA
    )

    LookupAccountSid.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        PSID,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        (LPWSTR if unicode else LPSTR),
        LPDWORD,
        PUINT
    ]

    LookupAccountSid.restype = BOOL
    res = LookupAccountSid(
        lpSystemName, 
        Sid, 
        Name, 
        cchName, 
        ReferencedDomainName, 
        cchReferencedDomainName, 
        peUse
    )
    return win32_to_errcheck(res, errcheck)


def LocalFree(hMem: int) -> None:
    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [HLOCAL]
    LocalFree.restype = HLOCAL
    LocalFree(hMem)


def RtlAdjustPrivilege(
    Privilege: int, 
    Enable: int, 
    CurrentThread: int, 
    OldValue: int,
    errcheck: bool = True
) -> None:
    
    RtlAdjustPrivilege = ntdll.RtlAdjustPrivilege
    res = RtlAdjustPrivilege(Privilege, 
                             Enable, 
                             CurrentThread, 
                             OldValue
    )

    return ntstatus_to_errcheck(res, errcheck)
    

def CheckTokenMembership(
    TokenHandle: int, 
    SidToCheck: Any, 
    IsMember: Any,
    errcheck: bool = True
) -> None:
    
    CheckTokenMembership = advapi32.CheckTokenMembership
    CheckTokenMembership.argtypes = [HANDLE, PVOID, PBOOL]
    CheckTokenMembership.restype = BOOL
    res = CheckTokenMembership(TokenHandle, SidToCheck, IsMember)
    return win32_to_errcheck(res, errcheck)


def AdjustTokenPrivileges(
    TokenHandle: int, 
    DisableAllPrivileges: bool, 
    NewState: Any, 
    BufferLength: int, 
    PreviousState: Any, 
    ReturnLength: int,
    errcheck: bool = True
) -> None:
    
    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    res = AdjustTokenPrivileges(
        TokenHandle, 
        DisableAllPrivileges, 
        NewState, 
        BufferLength, 
        PreviousState, 
        ReturnLength
    )

    return win32_to_errcheck(res, errcheck)


def LookupPrivilegeValue(
    lpSystemName: str | bytes, 
    lpName: str | bytes, 
    lpLuid: Any,
    unicode: bool = True,
    errcheck: bool = True
):
    
    LookupPrivilegeValue = (advapi32.LookupPrivilegeValueW 
                            if unicode else advapi32.LookupPrivilegeValueA
    )

    res = LookupPrivilegeValue(lpSystemName, lpName, lpLuid)
    return win32_to_errcheck(res, errcheck)


def PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult, errcheck: bool = True):
    PrivilegeCheck = advapi32.PrivilegeCheck
    res = PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult)
    return win32_to_errcheck(res, errcheck)


def GetTokenInformation(
    TokenHandle: int, 
    TokenInformationClass: int,  
    TokenInformation: Any, 
    TokenInformationLength: int,
    ReturnLength: Any,
    errcheck: bool = True
):
    
    GetTokenInformation = advapi32.GetTokenInformation
    GetTokenInformation.argtypes = [
        HANDLE, 
        UINT, 
        LPVOID, 
        DWORD, 
        PDWORD
    ]

    GetTokenInformation.restype = BOOL
    res = GetTokenInformation(
        TokenHandle, 
        TokenInformationClass, 
        TokenInformation, 
        TokenInformationLength, 
        ReturnLength
    )
    
    return win32_to_errcheck(res, errcheck)


def DuplicateTokenEx(
    hExistingToken: int, 
    dwDesiredAccess: int, 
    lpTokenAttributes: Any, 
    ImpersonationLevel: int, 
    TokenType: int,
    phNewToken: Any,
    errcheck: bool = True
):
    
    DuplicateTokenEx = advapi32.DuplicateTokenEx
    DuplicateTokenEx.argtypes = [HANDLE, DWORD, VOID, UINT, UINT, HANDLE]
    DuplicateTokenEx.restype = BOOL
    res = DuplicateTokenEx(
        hExistingToken, 
        dwDesiredAccess, 
        lpTokenAttributes, 
        ImpersonationLevel, 
        TokenType, 
        phNewToken
    )

    return win32_to_errcheck(res, errcheck)


def SetTokenInformation(
    TokenHandle: int, 
    TokenInformationClass: int, 
    TokenInformation: Any, 
    TokenInformationLength: int,
    errcheck: bool = True
) -> None:
    
    SetTokenInformation = advapi32.SetTokenInformation
    SetTokenInformation.argtypes = [HANDLE, UINT, LPVOID, DWORD]
    SetTokenInformation.restype = BOOL
    res = SetTokenInformation(
        TokenHandle, 
        TokenInformationClass, 
        TokenInformation, 
        TokenInformationLength
    )

    return win32_to_errcheck(res, errcheck)


def RevertToSelf(errcheck: bool = True) -> None:
    res = advapi32.RevertToSelf()
    return win32_to_errcheck(res, errcheck)

