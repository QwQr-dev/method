# coding = 'utf-8'

from ctypes import *

try:
    from error import *
    from win_NT import *
    from ntstatus import *
    from win_cbasictypes import *
    from public_dll import Kernel32, ntdll, shell32, advapi32, User32, winsta
except ImportError:
    from .error import *
    from .win_NT import *
    from .ntstatus import *
    from .win_cbasictypes import *
    from .public_dll import Kernel32, ntdll, shell32, advapi32, User32, winsta

FARPROC = INT_PTR

# wdm.h

SE_MIN_WELL_KNOWN_PRIVILEGE         = 2
SE_CREATE_TOKEN_PRIVILEGE           = 2
SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     = 3
SE_LOCK_MEMORY_PRIVILEGE            = 4
SE_INCREASE_QUOTA_PRIVILEGE         = 5
SE_MACHINE_ACCOUNT_PRIVILEGE        = 6
SE_TCB_PRIVILEGE                    = 7
SE_SECURITY_PRIVILEGE               = 8
SE_TAKE_OWNERSHIP_PRIVILEGE         = 9
SE_LOAD_DRIVER_PRIVILEGE            = 10
SE_SYSTEM_PROFILE_PRIVILEGE         = 11
SE_SYSTEMTIME_PRIVILEGE             = 12
SE_PROF_SINGLE_PROCESS_PRIVILEGE    = 13
SE_INC_BASE_PRIORITY_PRIVILEGE      = 14
SE_CREATE_PAGEFILE_PRIVILEGE        = 15
SE_CREATE_PERMANENT_PRIVILEGE       = 16
SE_BACKUP_PRIVILEGE                 = 17
SE_RESTORE_PRIVILEGE                = 18
SE_SHUTDOWN_PRIVILEGE               = 19
SE_DEBUG_PRIVILEGE                  = 20
SE_AUDIT_PRIVILEGE                  = 21
SE_SYSTEM_ENVIRONMENT_PRIVILEGE     = 22
SE_CHANGE_NOTIFY_PRIVILEGE          = 23
SE_REMOTE_SHUTDOWN_PRIVILEGE        = 24
SE_UNDOCK_PRIVILEGE                 = 25
SE_SYNC_AGENT_PRIVILEGE             = 26
SE_ENABLE_DELEGATION_PRIVILEGE      = 27
SE_MANAGE_VOLUME_PRIVILEGE          = 28
SE_IMPERSONATE_PRIVILEGE            = 29
SE_CREATE_GLOBAL_PRIVILEGE          = 30
SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE = 31
SE_RELABEL_PRIVILEGE                = 32
SE_INC_WORKING_SET_PRIVILEGE        = 33
SE_TIME_ZONE_PRIVILEGE              = 34
SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   = 35
SE_MAX_WELL_KNOWN_PRIVILEGE         = SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

# ==========================================================================================
# winbase.h

def CreateJobObject(lpJobAttributes, lpName, unicode: bool = True) -> int:
    CreateJobObjectA = Kernel32.CreateJobObjectA
    CreateJobObjectW = Kernel32.CreateJobObjectW
    res = (CreateJobObjectW if unicode else CreateJobObjectA)(lpJobAttributes, lpName)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def AssignProcessToJobObject(hJob, hProcess) -> int:
    res = Kernel32.AssignProcessToJobObject(hJob, hProcess)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def TerminateJobObject(hJob, uExitCode) -> int:
    res = Kernel32.TerminateJobObject(hJob, uExitCode)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


# =================================================================
# tlhelp32.h

INVALID_HANDLE_VALUE = HANDLE(LONG_PTR(-1).value).value

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS =  0x00000002
TH32CS_SNAPTHREAD =   0x00000004
TH32CS_SNAPMODULE =   0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPALL =      (TH32CS_SNAPHEAPLIST | 
                       TH32CS_SNAPPROCESS | 
                       TH32CS_SNAPTHREAD | 
                       TH32CS_SNAPMODULE
)

TH32CS_INHERIT =      0x80000000


def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
    res = Kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if res == INVALID_HANDLE_VALUE:
        raise WinError(GetLastError())
    return res


def Thread32First(hSnapshot, lpte):
    res = Kernel32.Thread32First(hSnapshot, lpte)
    if res not in [0, 1]:
        raise WinError(GetLastError(res))
    return res


class tagTHREADENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ThreadID', DWORD),
                ('th32OwnerProcessID', DWORD),
                ('tpBasePri', LONG),
                ('tpDeltaPri', LONG),
                ('dwFlags', DWORD)
    ]

THREADENTRY32 = tagTHREADENTRY32


def Thread32Next(hSnapshot, lpte):
    res = Kernel32.Thread32Next(hSnapshot, lpte)
    if res not in [0, 1]:
        raise WinError(GetLastError(res))
    return res


# =================================================================
# ???

def WinStationTerminateProcess(ServerHandle = HANDLE(), 
                               ProcessId = ULONG(), 
                               ExitCode = ULONG()):
    
    res = winsta.WinStationTerminateProcess(ServerHandle, 
                                            ProcessId, 
                                            ExitCode
    )

    if res == NULL:
        raise WinError(GetLastError(res))
    return res


# =================================================================
# ???

def RtlAdjustPrivilege(Privilege = ULONG(), 
                       Enable = BOOLEAN(), 
                       CurrentThread = BOOLEAN(), 
                       OldValue = PBOOLEAN()):
    
    res = ntdll.RtlAdjustPrivilege(Privilege, 
                                   Enable, 
                                   CurrentThread, 
                                   OldValue
    )

    if res != STATUS_SUCCESS:
        raise WinError(RtlNtStatusToDosError(res))


# ==================================================================
# ???
# BSOD function

def NtRaiseHardError(ErrorStatus = LONG(), 
                     NumberOfParameters = ULONG(), 
                     UnicodeStringParameterMask = ULONG(), 
                     Parameters = PULONG_PTR(), 
                     ValidResponseOptions = ULONG(), 
                     Response = PULONG()):
    
    res = ntdll.NtRaiseHardError(ErrorStatus, 
                                 NumberOfParameters, 
                                 UnicodeStringParameterMask, 
                                 Parameters, 
                                 ValidResponseOptions, 
                                 Response
    )

    if res != STATUS_SUCCESS:
        raise WinError(RtlNtStatusToDosError(res))


# =====================================================================
# libloaderapi.h

def AddDllDirectory(NewDirectory):
    res = Kernel32.AddDllDirectory(NewDirectory)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def DisableThreadLibraryCalls(hLibModule):
    res = Kernel32.DisableThreadLibraryCalls(hLibModule)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def FreeLibrary(hLibModule):
    res = Kernel32.FreeLibrary(hLibModule)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def FreeLibraryAndExitThread(hLibModule, dwExitCode) -> None:
    Kernel32.FreeLibraryAndExitThread(hLibModule, dwExitCode)


def GetModuleFileName(hModule, lpFilename, nSize, unicode: bool = True):
    lpFilename = byref(lpFilename)
    if unicode:
        res = Kernel32.GetModuleFileNameW(hModule, lpFilename, nSize)
    else:
        res = Kernel32.GetModuleFileNameA(hModule, lpFilename, nSize)
    
    if res == NULL:
        raise WinError(GetLastError(res))
    return lpFilename


def GetModuleHandle(lpModuleName: str, unicode: bool = True) -> int:
    GetModuleHandle = (Kernel32.GetModuleHandleW 
                       if unicode else Kernel32.GetModuleHandleA
    )

    GetModuleHandle.argtypes = [LPCWSTR if unicode else LPCSTR]
    GetModuleHandle.restype = HMODULE
    res = GetModuleHandle(lpModuleName)

    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def GetModuleHandleEx(dwFlags, lpModuleName, phModule, unicode: bool = True) -> int:
    phModule = byref(phModule)

    if unicode:
        res = Kernel32.GetModuleHandleExW(dwFlags, lpModuleName, phModule)
    else:
        res = Kernel32.GetModuleHandleExA(dwFlags, lpModuleName, phModule)

    if res == NULL:
        raise WinError(GetLastError(res))
    return phModule
    

def GetProcAddress(hModule: int, lpProcName: str, encoding: str = 'ansi') -> int:
    GetProcAddress = Kernel32.GetProcAddress
    lpProcName = lpProcName.encode(encoding)
    GetProcAddress.argtypes = [HMODULE, LPCSTR]
    GetProcAddress.restype = FARPROC
    res = GetProcAddress(hModule, lpProcName)
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def LoadLibrary(lpLibFileName: str, unicode: bool = True) -> int:
    LoadLibrary = (Kernel32.LoadLibraryW 
                   if unicode else Kernel32.LoadLibraryA
    )

    LoadLibrary.argtypes = [LPCWSTR if unicode else LPCSTR]
    LoadLibrary.restype = HMODULE
    res = LoadLibrary(lpLibFileName)
    
    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def LoadLibraryEx(lpLibFileName: str, hFile, dwFlags, unicode: bool = True):
    if unicode:
        res = Kernel32.LoadLibraryExW(lpLibFileName, hFile, dwFlags)
    else:
        res = Kernel32.LoadLibraryExA(lpLibFileName, hFile, dwFlags)

    if res == NULL:
        raise WinError(GetLastError(res))
    return res


def RemoveDllDirectory(Cookie):
    res = Kernel32.RemoveDllDirectory(Cookie)
    if res == NULL:
        raise WinError(GetLastError(res))
    

def SetDefaultDllDirectories(DirectoryFlags):
    res = Kernel32.SetDefaultDllDirectories(DirectoryFlags)
    if res == NULL:
        raise WinError(GetLastError(res))


# ===================================================================

