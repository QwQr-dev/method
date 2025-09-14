# coding = 'utf-8'

# ???: 指暂时未分类的部分类或函数、或 Microsoft 未公开的 Windows API

from typing import NoReturn, Any
from ctypes import sizeof, Structure, Union, byref, WinError

try:
    from win_NT import *
    from ntstatus import *
    from sdkddkver import *
    from winuser import WM_USER
    from win_cbasictypes import *
    from winerror import S_OK, ERROR_INSUFFICIENT_BUFFER, FAILED
    from public_dll import Kernel32, ntdll, shell32, advapi32, User32, winsta
    from error import GetLastError, RtlNtStatusToDosError, CommDlgExtendedError
except ImportError:
    from .win_NT import *
    from .ntstatus import *
    from .sdkddkver import *
    from .winuser import WM_USER
    from .win_cbasictypes import *
    from .winerror import S_OK, ERROR_INSUFFICIENT_BUFFER, FAILED
    from .public_dll import Kernel32, ntdll, shell32, advapi32, User32, winsta
    from .error import GetLastError, RtlNtStatusToDosError, CommDlgExtendedError

MAX_PATH = 260
FARPROC = INT_PTR
_WIN32_WINNT = WIN32_WINNT

ZeroMemory = RtlZeroMemory

# winbase.h

FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

WAIT_FAILED = 0xffffffff
WAIT_OBJECT_0 = STATUS_WAIT_0 + 0

WAIT_ABANDONED = STATUS_ABANDONED_WAIT_0 + 0
WAIT_ABANDONED_0 = STATUS_ABANDONED_WAIT_0 + 0

WAIT_IO_COMPLETION = STATUS_USER_APC

# SecureZeroMemory = RtlSecureZeroMemory
CaptureStackBackTrace = RtlCaptureStackBackTrace

FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_RANDOM_ACCESS = 0x10000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x8000000
FILE_FLAG_DELETE_ON_CLOSE = 0x4000000
FILE_FLAG_BACKUP_SEMANTICS = 0x2000000
FILE_FLAG_POSIX_SEMANTICS = 0x1000000
FILE_FLAG_SESSION_AWARE = 0x800000
FILE_FLAG_OPEN_REPARSE_POINT = 0x200000
FILE_FLAG_OPEN_NO_RECALL = 0x100000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x80000

if _WIN32_WINNT >= WIN32_WINNT_WIN8:
    FILE_FLAG_OPEN_REQUIRING_OPLOCK = 0x40000

NUMA_NO_PREFERRED_NODE = DWORD(-1).value

DEBUG_PROCESS = 0x1
DEBUG_ONLY_THIS_PROCESS = 0x2
CREATE_SUSPENDED = 0x4
DETACHED_PROCESS = 0x8
CREATE_NEW_CONSOLE = 0x10
NORMAL_PRIORITY_CLASS = 0x20
IDLE_PRIORITY_CLASS = 0x40
HIGH_PRIORITY_CLASS = 0x80
REALTIME_PRIORITY_CLASS = 0x100
CREATE_NEW_PROCESS_GROUP = 0x200
CREATE_UNICODE_ENVIRONMENT = 0x400
CREATE_SEPARATE_WOW_VDM = 0x800
CREATE_SHARED_WOW_VDM = 0x1000
CREATE_FORCEDOS = 0x2000
BELOW_NORMAL_PRIORITY_CLASS = 0x4000
ABOVE_NORMAL_PRIORITY_CLASS = 0x8000
INHERIT_PARENT_AFFINITY = 0x10000
INHERIT_CALLER_PRIORITY = 0x20000
CREATE_PROTECTED_PROCESS = 0x40000
EXTENDED_STARTUPINFO_PRESENT = 0x80000
PROCESS_MODE_BACKGROUND_BEGIN = 0x100000
PROCESS_MODE_BACKGROUND_END = 0x200000
CREATE_SECURE_PROCESS = 0x400000
CREATE_BREAKAWAY_FROM_JOB = 0x1000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x2000000
CREATE_DEFAULT_ERROR_MODE = 0x4000000
CREATE_NO_WINDOW = 0x8000000
PROFILE_USER = 0x10000000
PROFILE_KERNEL = 0x20000000
PROFILE_SERVER = 0x40000000
CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000

STACK_SIZE_PARAM_IS_A_RESERVATION = 0x10000

THREAD_PRIORITY_LOWEST = THREAD_BASE_PRIORITY_MIN
THREAD_PRIORITY_BELOW_NORMAL = THREAD_PRIORITY_LOWEST+1
THREAD_PRIORITY_NORMAL = 0
THREAD_PRIORITY_HIGHEST = THREAD_BASE_PRIORITY_MAX
THREAD_PRIORITY_ABOVE_NORMAL = THREAD_PRIORITY_HIGHEST-1
THREAD_PRIORITY_ERROR_RETURN = MAXLONG

THREAD_PRIORITY_TIME_CRITICAL = THREAD_BASE_PRIORITY_LOWRT
THREAD_PRIORITY_IDLE = THREAD_BASE_PRIORITY_IDLE

THREAD_MODE_BACKGROUND_BEGIN = 0x00010000
THREAD_MODE_BACKGROUND_END = 0x00020000

VOLUME_NAME_DOS = 0x0
VOLUME_NAME_GUID = 0x1
VOLUME_NAME_NT = 0x2
VOLUME_NAME_NONE = 0x4

FILE_NAME_NORMALIZED = 0x0
FILE_NAME_OPENED = 0x8

BACKUP_INVALID = 0x00000000
BACKUP_DATA = 0x00000001
BACKUP_EA_DATA = 0x00000002
BACKUP_SECURITY_DATA = 0x00000003
BACKUP_ALTERNATE_DATA = 0x00000004
BACKUP_LINK = 0x00000005
BACKUP_PROPERTY_DATA = 0x00000006
BACKUP_OBJECT_ID = 0x00000007
BACKUP_REPARSE_DATA = 0x00000008
BACKUP_SPARSE_BLOCK = 0x00000009
BACKUP_TXFS_DATA = 0x0000000a
BACKUP_GHOSTED_FILE_EXTENTS = 0x0000000b

STREAM_NORMAL_ATTRIBUTE = 0x00000000
STREAM_MODIFIED_WHEN_READ = 0x00000001
STREAM_CONTAINS_SECURITY = 0x00000002
STREAM_CONTAINS_PROPERTIES = 0x00000004
STREAM_SPARSE_ATTRIBUTE = 0x00000008
STREAM_CONTAINS_GHOSTED_FILE_EXTENTS = 0x00000010

STARTF_USESHOWWINDOW = 0x00000001
STARTF_USESIZE = 0x00000002
STARTF_USEPOSITION = 0x00000004
STARTF_USECOUNTCHARS = 0x00000008
STARTF_USEFILLATTRIBUTE = 0x00000010
STARTF_RUNFULLSCREEN = 0x00000020
STARTF_FORCEONFEEDBACK = 0x00000040
STARTF_FORCEOFFFEEDBACK = 0x00000080
STARTF_USESTDHANDLES = 0x00000100

if WINVER >= 0x0400:
    STARTF_USEHOTKEY = 0x00000200
    STARTF_TITLEISLINKNAME = 0x00000800
    STARTF_TITLEISAPPID = 0x00001000
    STARTF_PREVENTPINNING = 0x00002000

if WINVER >= 0x0600:
    STARTF_UNTRUSTEDSOURCE = 0x00008000

if NTDDI_VERSION >= NTDDI_WIN10_FE:
    STARTF_HOLOGRAPHIC = 0x00040000


def CreateJobObject(lpJobAttributes: Any, lpName: str, unicode: bool = True) -> int:
    CreateJobObject = (Kernel32.CreateJobObjectW 
                       if unicode else Kernel32.CreateJobObjectA
    )

    res = CreateJobObject(lpJobAttributes, lpName)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def AssignProcessToJobObject(hJob: int, hProcess: int) -> int:
    res = Kernel32.AssignProcessToJobObject(hJob, hProcess)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def TerminateJobObject(hJob: int, uExitCode: int) -> int:
    res = Kernel32.TerminateJobObject(hJob, uExitCode)
    if res == NULL:
        raise WinError(GetLastError())
    return res


# ==========================================================================================
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

# =====================================================================
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


def CreateToolhelp32Snapshot(dwFlags: int, th32ProcessID: int) -> int:
    res = Kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if res == INVALID_HANDLE_VALUE:
        raise WinError(GetLastError())
    return res


def Thread32First(hSnapshot, lpte):
    res = Kernel32.Thread32First(hSnapshot, lpte)
    if res not in [0, 1]:
        raise WinError(GetLastError())
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
        raise WinError(GetLastError())
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
        raise WinError(GetLastError())
    return res


# =================================================================
# ???

def RtlAdjustPrivilege(Privilege: int, 
                       Enable: int, 
                       CurrentThread: int, 
                       OldValue: int) -> None:
    
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

def NtRaiseHardError(ErrorStatus: int = LONG(), 
                     NumberOfParameters: int = ULONG(), 
                     UnicodeStringParameterMask: int = ULONG(), 
                     Parameters: int = PULONG_PTR(), 
                     ValidResponseOptions: int = ULONG(), 
                     Response: int = PULONG()) -> NoReturn:
    
    res = ntdll.NtRaiseHardError(ErrorStatus, 
                                 NumberOfParameters, 
                                 UnicodeStringParameterMask, 
                                 Parameters, 
                                 ValidResponseOptions, 
                                 Response
    )

    if res != STATUS_SUCCESS:
        raise WinError(RtlNtStatusToDosError(res))


# ==========================================================================

# ==========================================================================
# 蓝屏（BSOD）示例代码（请勿在实体机上使用，以免造成数据丢失）
#
# RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, byref(BOOLEAN()))
# NtRaiseHardError(STATUS_ASSERTION_FAILURE, NULL, NULL, NULL, 6, byref(ULONG()))
# 
# ==========================================================================

# ==========================================================================
# libloaderapi.h

DONT_RESOLVE_DLL_REFERENCES = 0x1
LOAD_LIBRARY_AS_DATAFILE = 0x2
LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x10
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20
LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x40
LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x80
LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100
LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200
LOAD_LIBRARY_SEARCH_USER_DIRS = 0x400
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x1000

if NTDDI_VERSION >= NTDDI_WIN10_RS1:
    LOAD_LIBRARY_SAFE_CURRENT_DIRS = 0x00002000
    LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = 0x00004000
else:
    LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = LOAD_LIBRARY_SEARCH_SYSTEM32

if NTDDI_VERSION >= NTDDI_WIN10_RS2:
    LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY = 0x00008000


def AddDllDirectory(NewDirectory):
    res = Kernel32.AddDllDirectory(NewDirectory)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def DisableThreadLibraryCalls(hLibModule):
    res = Kernel32.DisableThreadLibraryCalls(hLibModule)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def FreeLibrary(hLibModule):
    res = Kernel32.FreeLibrary(hLibModule)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def FreeLibraryAndExitThread(hLibModule, dwExitCode) -> None:
    Kernel32.FreeLibraryAndExitThread(hLibModule, dwExitCode)


def GetModuleFileName(hModule, lpFilename, nSize, unicode: bool = True):
    if unicode:
        res = Kernel32.GetModuleFileNameW(hModule, lpFilename, nSize)
    else:
        res = Kernel32.GetModuleFileNameA(hModule, lpFilename, nSize)
    
    if res == NULL:
        raise WinError(GetLastError())
    return lpFilename


def GetModuleHandle(lpModuleName: str, unicode: bool = True) -> int:
    GetModuleHandle = (Kernel32.GetModuleHandleW 
                       if unicode else Kernel32.GetModuleHandleA
    )

    GetModuleHandle.argtypes = [LPCWSTR if unicode else LPCSTR]
    GetModuleHandle.restype = HMODULE
    res = GetModuleHandle(lpModuleName)

    if res == NULL:
        raise WinError(GetLastError())
    return res


def GetModuleHandleEx(dwFlags: int, lpModuleName: str, unicode: bool = True) -> int:
    GetModuleHandleEx = (Kernel32.GetModuleHandleExW 
                         if unicode else Kernel32.GetModuleHandleExA
    )

    GetModuleHandleEx.argtypes = [DWORD, 
                                  (LPCWSTR if unicode else LPCSTR), 
                                  HMODULE
    ]

    GetModuleHandleEx.restype = BOOL
    phModule = HMODULE()
    res = GetModuleHandleEx(dwFlags, lpModuleName, byref(phModule))

    if res == NULL:
        raise WinError(GetLastError())
    return phModule.value
    

def GetProcAddress(hModule: int, lpProcName: str | int, encoding: str = 'ansi') -> int:
    GetProcAddress = Kernel32.GetProcAddress

    if isinstance(lpProcName, str):
        lpProcName = lpProcName.encode(encoding)

    GetProcAddress.argtypes = [HMODULE, LPCSTR]
    GetProcAddress.restype = FARPROC
    res = GetProcAddress(hModule, lpProcName)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def LoadLibrary(lpLibFileName: str, unicode: bool = True) -> int:
    LoadLibrary = (Kernel32.LoadLibraryW 
                   if unicode else Kernel32.LoadLibraryA
    )

    LoadLibrary.argtypes = [LPCWSTR if unicode else LPCSTR]
    LoadLibrary.restype = HMODULE
    res = LoadLibrary(lpLibFileName)
    
    if res == NULL:
        raise WinError(GetLastError())
    return res


def LoadLibraryEx(lpLibFileName: str, 
                  hFile: int, 
                  dwFlags: int, 
                  unicode: bool = True) -> int:
    
    LoadLibraryEx = (Kernel32.LoadLibraryExW 
                     if unicode else Kernel32.LoadLibraryExA
    )

    LoadLibraryEx.argtypes = [(LPCWSTR if unicode else LPCSTR), HANDLE, DWORD]
    LoadLibraryEx.restype = HMODULE
    res = LoadLibraryEx(lpLibFileName, hFile, dwFlags)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def RemoveDllDirectory(Cookie):
    res = Kernel32.RemoveDllDirectory(Cookie)
    if res == NULL:
        raise WinError(GetLastError())
    

def SetDefaultDllDirectories(DirectoryFlags):
    res = Kernel32.SetDefaultDllDirectories(DirectoryFlags)
    if res == NULL:
        raise WinError(GetLastError())


# ===================================================================
# ???

RFD_NOBROWSE            = 0x00000001
RFD_NODEFFILE           = 0x00000002
RFD_USEFULLPATHDIR      = 0x00000004
RFD_NOSHOWOPEN          = 0x00000008
RFD_WOW_APP             = 0x00000010
RFD_NOSEPMEMORY_BOX     = 0x00000020


def RunfileDlg(hwndOwner: int, 
               hIcon: int, 
               lpszDirectory: str, 
               lpszTitle: str, 
               lpszDescription: str, 
               uFlags: int = RFD_USEFULLPATHDIR | RFD_WOW_APP,
               number: int = 61) -> None:
    
    RUNFILEDLG = WINAPI(VOID, HWND, HICON, LPCWSTR, LPCWSTR, LPCWSTR, UINT)
    shell32 = LoadLibrary('shell32.dll')
    RunfileDlg = GetProcAddress(shell32, LPCSTR(number))
    RunfileDlg = RUNFILEDLG(RunfileDlg)
    RunfileDlg(hwndOwner, hIcon, lpszDirectory, lpszTitle, lpszDescription, uFlags)


# ==================================================================
# synchapi.h

def WaitForSingleObject(hHandle: int, dwMilliseconds: int) -> int:
    WaitForSingleObject = Kernel32.WaitForSingleObject
    res = WaitForSingleObject(hHandle, dwMilliseconds)
    if res == WAIT_FAILED:
        raise WinError(GetLastError())
    return res


# ===============================================================================
# reason.h

SHTDN_REASON_FLAG_COMMENT_REQUIRED = 0x01000000
SHTDN_REASON_FLAG_DIRTY_PROBLEM_ID_REQUIRED = 0x02000000
SHTDN_REASON_FLAG_CLEAN_UI = 0x04000000
SHTDN_REASON_FLAG_DIRTY_UI = 0x08000000
SHTDN_REASON_FLAG_USER_DEFINED = 0x40000000
SHTDN_REASON_FLAG_PLANNED = 0x80000000
SHTDN_REASON_MAJOR_OTHER = 0x00000000
SHTDN_REASON_MAJOR_NONE = 0x00000000
SHTDN_REASON_MAJOR_HARDWARE = 0x00010000
SHTDN_REASON_MAJOR_OPERATINGSYSTEM = 0x00020000
SHTDN_REASON_MAJOR_SOFTWARE = 0x00030000
SHTDN_REASON_MAJOR_APPLICATION = 0x00040000
SHTDN_REASON_MAJOR_SYSTEM = 0x00050000
SHTDN_REASON_MAJOR_POWER = 0x00060000
SHTDN_REASON_MAJOR_LEGACY_API = 0x00070000
SHTDN_REASON_MINOR_OTHER = 0x00000000
SHTDN_REASON_MINOR_NONE = 0x000000ff
SHTDN_REASON_MINOR_MAINTENANCE = 0x00000001
SHTDN_REASON_MINOR_INSTALLATION = 0x00000002
SHTDN_REASON_MINOR_UPGRADE = 0x00000003
SHTDN_REASON_MINOR_RECONFIG = 0x00000004
SHTDN_REASON_MINOR_HUNG = 0x00000005
SHTDN_REASON_MINOR_UNSTABLE = 0x00000006
SHTDN_REASON_MINOR_DISK = 0x00000007
SHTDN_REASON_MINOR_PROCESSOR = 0x00000008
SHTDN_REASON_MINOR_NETWORKCARD = 0x00000009
SHTDN_REASON_MINOR_POWER_SUPPLY = 0x0000000a
SHTDN_REASON_MINOR_CORDUNPLUGGED = 0x0000000b
SHTDN_REASON_MINOR_ENVIRONMENT = 0x0000000c
SHTDN_REASON_MINOR_HARDWARE_DRIVER = 0x0000000d
SHTDN_REASON_MINOR_OTHERDRIVER = 0x0000000e
SHTDN_REASON_MINOR_BLUESCREEN = 0x0000000F
SHTDN_REASON_MINOR_SERVICEPACK = 0x00000010
SHTDN_REASON_MINOR_HOTFIX = 0x00000011
SHTDN_REASON_MINOR_SECURITYFIX = 0x00000012
SHTDN_REASON_MINOR_SECURITY = 0x00000013
SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY = 0x00000014
SHTDN_REASON_MINOR_WMI = 0x00000015
SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL = 0x00000016
SHTDN_REASON_MINOR_HOTFIX_UNINSTALL = 0x00000017
SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL = 0x00000018
SHTDN_REASON_MINOR_MMC = 0x00000019
SHTDN_REASON_MINOR_SYSTEMRESTORE = 0x0000001a
SHTDN_REASON_MINOR_TERMSRV = 0x00000020
SHTDN_REASON_MINOR_DC_PROMOTION = 0x00000021
SHTDN_REASON_MINOR_DC_DEMOTION = 0x00000022
SHTDN_REASON_UNKNOWN = SHTDN_REASON_MINOR_NONE
SHTDN_REASON_LEGACY_API = (SHTDN_REASON_MAJOR_LEGACY_API | SHTDN_REASON_FLAG_PLANNED)
SHTDN_REASON_VALID_BIT_MASK = 0xc0ffffff

PCLEANUI = (SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_FLAG_CLEAN_UI)
UCLEANUI = (SHTDN_REASON_FLAG_CLEAN_UI)
PDIRTYUI = (SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_FLAG_DIRTY_UI)
UDIRTYUI = (SHTDN_REASON_FLAG_DIRTY_UI)

MAX_REASON_NAME_LEN = 64
MAX_REASON_DESC_LEN = 256
MAX_REASON_BUGID_LEN = 32
MAX_REASON_COMMENT_LEN = 512
SHUTDOWN_TYPE_LEN = 32

POLICY_SHOWREASONUI_NEVER = 0
POLICY_SHOWREASONUI_ALWAYS = 1
POLICY_SHOWREASONUI_WORKSTATIONONLY = 2
POLICY_SHOWREASONUI_SERVERONLY = 3

SNAPSHOT_POLICY_NEVER = 0
SNAPSHOT_POLICY_ALWAYS = 1
SNAPSHOT_POLICY_UNPLANNED = 2

MAX_NUM_REASONS = 256

# ===================================================================================
# winreg.h

REASON_SWINSTALL = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_INSTALLATION
REASON_HWINSTALL = SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_INSTALLATION
REASON_SERVICEHANG = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_HUNG
REASON_UNSTABLE = SHTDN_REASON_MAJOR_SYSTEM | SHTDN_REASON_MINOR_UNSTABLE
REASON_SWHWRECONF = SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIG
REASON_OTHER = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER
REASON_UNKNOWN = SHTDN_REASON_UNKNOWN
REASON_LEGACY_API = SHTDN_REASON_LEGACY_API
REASON_PLANNED_FLAG = SHTDN_REASON_FLAG_PLANNED

MAX_SHUTDOWN_TIMEOUT = 10*365*24*60*60

SHUTDOWN_FORCE_OTHERS = 0x00000001
SHUTDOWN_FORCE_SELF = 0x00000002
SHUTDOWN_RESTART = 0x00000004
SHUTDOWN_POWEROFF = 0x00000008
SHUTDOWN_NOREBOOT = 0x00000010
SHUTDOWN_GRACE_OVERRIDE = 0x00000020
SHUTDOWN_INSTALL_UPDATES = 0x00000040
SHUTDOWN_RESTARTAPPS = 0x00000080
SHUTDOWN_SKIP_SVC_PRESHUTDOWN = 0x00000100
SHUTDOWN_HYBRID = 0x00000200
SHUTDOWN_RESTART_BOOTOPTIONS = 0x00000400
SHUTDOWN_SOFT_REBOOT = 0x00000800
SHUTDOWN_MOBILE_UI = 0x00001000
SHUTDOWN_ARSO = 0x00002000


def InitiateSystemShutdown(lpMachineName: str, 
                           lpMessage: str, 
                           dwTimeout: int, 
                           bForceAppsClosed: bool, 
                           bRebootAfterShutdown: bool,
                           unicode: bool = True) -> NoReturn:
    
    InitiateSystemShutdown = (advapi32.InitiateSystemShutdownW 
                              if unicode else advapi32.InitiateSystemShutdownA
    )

    res = InitiateSystemShutdown(lpMachineName, 
                                 lpMessage, 
                                 dwTimeout, 
                                 bForceAppsClosed, 
                                 bRebootAfterShutdown,
    )

    if not res:
        raise WinError(GetLastError())
    

def InitiateSystemShutdownEx(lpMachineName: str, 
                             lpMessage: str, 
                             dwTimeout: int, 
                             bForceAppsClosed: bool, 
                             bRebootAfterShutdown: bool, 
                             dwReason: int, 
                             unicode: bool = True) -> NoReturn:
    
    InitiateSystemShutdownEx = (advapi32.InitiateSystemShutdownExW 
                                if unicode else advapi32.InitiateSystemShutdownExA
    )

    res = InitiateSystemShutdownEx(lpMachineName, 
                                   lpMessage, 
                                   dwTimeout, 
                                   bForceAppsClosed, 
                                   bRebootAfterShutdown, 
                                   dwReason
    )

    if not res:
        raise WinError(GetLastError())


# ============================================================================
# ???

class _SHITEMID(Structure):
    _fields_ = [('cb', USHORT),
                ('abID', BYTE * 1)
    ]

SHITEMID = _SHITEMID

class _ITEMIDLIST(Structure):
    _fields_ = [('mkid', SHITEMID)]

ITEMIDLIST = _ITEMIDLIST

PCIDLIST_ABSOLUTE = ITEMIDLIST

PCUITEMID_CHILD_ARRAY = ITEMIDLIST


def SHOpenFolderAndSelectItems(pidlFolder: int, 
                               cidl: int, 
                               apidl: Any, 
                               dwFlags: int) -> None:
    
    SHOpenFolderAndSelectItems = shell32.SHOpenFolderAndSelectItems
    SHOpenFolderAndSelectItems.argtypes = [VOID, UINT, VOID, DWORD]
    SHOpenFolderAndSelectItems.restype = HRESULT
    res = SHOpenFolderAndSelectItems(pidlFolder, cidl, apidl, dwFlags)

    if res != S_OK:
        raise WinError(GetLastError())
    

def ILFindLastID(pidl: int):
    res = shell32.ILFindLastID(pidl)
    return res


def ILCreateFromPath(pszPath: str, unicode: bool = True) -> int:
    ILCreateFromPath = (shell32.ILCreateFromPathW 
                        if unicode else shell32.ILCreateFromPathA
    )

    ILCreateFromPath.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    ILCreateFromPath.restype = VOID

    res = ILCreateFromPath(pszPath)
    return res


def CoInitialize(pvReserved: int = NULL) -> None:
    res = ole32.CoInitialize(pvReserved)
    if FAILED(res):
        raise WinError(res)


def CoInitializeEx(pvReserved: int, dwCoInit: int) -> None:
    CoInitializeEx = ole32.CoInitializeEx
    res = CoInitializeEx(pvReserved, dwCoInit)
    if FAILED(res):
        raise WinError(res)


def CoUninitialize() -> None:
    res =  ole32.CoUninitialize()
    if FAILED(res):
        raise WinError(res)


def ILFree(pidl) -> None:
    ILFree = shell32.ILFree
    ILFree.argtypes = [VOID]
    ILFree.restype = None
    ILFree(pidl)


# ================================================================================
# ???

BIF_RETURNONLYFSDIRS =     0x00000001   # For finding a folder to start document searching
BIF_DONTGOBELOWDOMAIN =    0x00000002   # For starting the Find Computer
BIF_STATUSTEXT =           0x00000004   # Top of the dialog has 2 lines of text for BROWSEINFO.lpszTitle and one line if
                                        # this flag is set.  Passing the message BFFM_SETSTATUSTEXTA to the hwnd can set the
                                        # rest of the text.  This is not used with BIF_USENEWUI and BROWSEINFO.lpszTitle gets
                                        # all three lines of text.
BIF_RETURNFSANCESTORS =    0x00000008
BIF_EDITBOX =              0x00000010   # Add an editbox to the dialog
BIF_VALIDATE =             0x00000020   # insist on valid result (or CANCEL)

BIF_NEWDIALOGSTYLE =       0x00000040   # Use the new dialog layout with the ability to resize
                                        # Caller needs to call OleInitialize() before using this API

BIF_USENEWUI =             (BIF_NEWDIALOGSTYLE | BIF_EDITBOX)

BIF_BROWSEINCLUDEURLS =    0x00000080   # Allow URLs to be displayed or entered. (Requires BIF_USENEWUI)
BIF_UAHINT =               0x00000100   # Add a UA hint to the dialog, in place of the edit box. May not be combined with BIF_EDITBOX
BIF_NONEWFOLDERBUTTON =    0x00000200   # Do not add the "New Folder" button to the dialog.  Only applicable with BIF_NEWDIALOGSTYLE.
BIF_NOTRANSLATETARGETS =   0x00000400   # don't traverse target as shortcut

BIF_BROWSEFORCOMPUTER =    0x00001000  # Browsing for Computers.
BIF_BROWSEFORPRINTER =     0x00002000  # Browsing for Printers
BIF_BROWSEINCLUDEFILES =   0x00004000  # Browsing for Everything
BIF_SHAREABLE =            0x00008000  # sharable resources displayed (remote shares, requires BIF_USENEWUI)
BIF_BROWSEFILEJUNCTIONS =  0x00010000  # allow folder junctions like zip files and libraries to be browsed

# message from browser
BFFM_INITIALIZED =         1
BFFM_SELCHANGED =          2
BFFM_VALIDATEFAILEDA =     3   # lParam:szPath ret:1(cont),0(EndDialog)
BFFM_VALIDATEFAILEDW =     4   # lParam:wzPath ret:1(cont),0(EndDialog)
BFFM_IUNKNOWN =            5   # provides IUnknown to client. lParam: IUnknown*

# messages to browser
BFFM_SETSTATUSTEXTA =      (WM_USER + 100)
BFFM_ENABLEOK =            (WM_USER + 101)
BFFM_SETSELECTIONA =       (WM_USER + 102)
BFFM_SETSELECTIONW =       (WM_USER + 103)
BFFM_SETSTATUSTEXTW =      (WM_USER + 104)
BFFM_SETOKTEXT =           (WM_USER + 105) # Unicode only
BFFM_SETEXPANDED =         (WM_USER + 106) # Unicode only

OFN_READONLY =                 0x00000001
OFN_OVERWRITEPROMPT =          0x00000002
OFN_HIDEREADONLY =             0x00000004
OFN_NOCHANGEDIR =              0x00000008
OFN_SHOWHELP =                 0x00000010
OFN_ENABLEHOOK =               0x00000020
OFN_ENABLETEMPLATE =           0x00000040
OFN_ENABLETEMPLATEHANDLE =     0x00000080
OFN_NOVALIDATE =               0x00000100
OFN_ALLOWMULTISELECT =         0x00000200
OFN_EXTENSIONDIFFERENT =       0x00000400
OFN_PATHMUSTEXIST =            0x00000800
OFN_FILEMUSTEXIST =            0x00001000
OFN_CREATEPROMPT =             0x00002000
OFN_SHAREAWARE =               0x00004000
OFN_NOREADONLYRETURN =         0x00008000
OFN_NOTESTFILECREATE =         0x00010000
OFN_NONETWORKBUTTON =          0x00020000
OFN_NOLONGNAMES =              0x00040000     # force no long names for 4.x modules

if WINVER >= 0x0400:
    OFN_EXPLORER =                 0x00080000     # new look commdlg
    OFN_NODEREFERENCELINKS =       0x00100000
    OFN_LONGNAMES =                0x00200000     # force long names for 3.x modules
    # OFN_ENABLEINCLUDENOTIFY and OFN_ENABLESIZING require
    # Windows 2000 or higher to have any effect.
    OFN_ENABLEINCLUDENOTIFY =      0x00400000     # send include message to callback
    OFN_ENABLESIZING =             0x00800000

if (_WIN32_WINNT >= 0x0500):
    OFN_DONTADDTORECENT =          0x02000000
    OFN_FORCESHOWHIDDEN =          0x10000000    # Show All files including System and hidden files

#FlagsEx Values
if (_WIN32_WINNT >= 0x0500):
    OFN_EX_NOPLACESBAR =         0x00000001

# Return values for the registered message sent to the hook function
# when a sharing violation occurs.  OFN_SHAREFALLTHROUGH allows the
# filename to be accepted, OFN_SHARENOWARN rejects the name but puts
# up no warning (returned when the app has already put up a warning
# message), and OFN_SHAREWARN puts up the default warning message
# for sharing violations.
#
# Note:  Undefined return values map to OFN_SHAREWARN, but are
#        reserved for future use.

OFN_SHAREFALLTHROUGH =     2
OFN_SHARENOWARN =          1
OFN_SHAREWARN =            0


LPOFNHOOKPROC = CALLBACK(UINT_PTR, HWND, UINT, WPARAM, LPARAM)
BFFCALLBACK = CALLBACK(INT, HWND, UINT, LPARAM, LPARAM)

class tagEDITMENU(Structure):
    _fields_ = [('hmenu', HMENU),
                ('idEdit', WORD),
                ('idCut', WORD),
                ('idCopy', WORD),
                ('idPaste', WORD),
                ('idClear', WORD),
                ('idUndo', WORD)
    ]

EDITMENU = tagEDITMENU
LPEDITMENU = POINTER(EDITMENU)

class tagOFNA(Structure):
    _fields_ = [('lStructSize', DWORD),
                ('hwndOwner', HWND),
                ('hInstance', HINSTANCE),
                ('lpstrFilter', LPCSTR),
                ('lpstrCustomFilter', LPSTR),
                ('nMaxCustFilter', DWORD),
                ('nFilterIndex', DWORD),
                ('lpstrFile', LPSTR),
                ('nMaxFile', DWORD),
                ('lpstrFileTitle', LPSTR),
                ('nMaxFileTitle', DWORD),
                ('lpstrInitialDir', LPCSTR),
                ('lpstrTitle', LPCSTR),
                ('Flags', DWORD),
                ('nFileOffset', WORD),
                ('nFileExtension', WORD),
                ('lpstrDefExt', LPCSTR),
                ('lCustData', LPARAM),
                ('lpfnHook', LPOFNHOOKPROC),
                ('lpTemplateName', LPCSTR),
                # ('lpEditInfo', LPEDITMENU),
                # ('lpstrPrompt', LPCWSTR),         
    ]

    if WIN32_WINNT >= 0x0500:
        _fields_.append(('pvReserved', PVOID))
        _fields_.append(('dwReserved', DWORD))
        _fields_.append(('FlagsEx', DWORD))

OPENFILENAMEA = tagOFNA
LPOPENFILENAMEA = POINTER(OPENFILENAMEA)

class tagOFNW(Structure):
    _fields_ = [('lStructSize', DWORD),
                ('hwndOwner', HWND),
                ('hInstance', HINSTANCE),
                ('lpstrFilter', LPCWSTR),
                ('lpstrCustomFilter', LPWSTR),
                ('nMaxCustFilter', DWORD),
                ('nFilterIndex', DWORD),
                ('lpstrFile', LPWSTR),
                ('nMaxFile', DWORD),
                ('lpstrFileTitle', LPWSTR),
                ('nMaxFileTitle', DWORD),
                ('lpstrInitialDir', LPCWSTR),
                ('lpstrTitle', LPCWSTR),
                ('Flags', DWORD),
                ('nFileOffset', WORD),
                ('nFileExtension', WORD),
                ('lpstrDefExt', LPCWSTR),
                ('lCustData', LPARAM),
                ('lpfnHook', LPOFNHOOKPROC),
                ('lpTemplateName', LPCWSTR),
                # ('lpEditInfo', LPEDITMENU),
                # ('lpstrPrompt', LPCWSTR), 
    ]

    if WIN32_WINNT >= 0x0500:
        _fields_.append(('pvReserved', PVOID))
        _fields_.append(('dwReserved', DWORD))
        _fields_.append(('FlagsEx', DWORD))


OPENFILENAMEW = tagOFNW
LPOPENFILENAMEW = POINTER(OPENFILENAMEW)

LPCITEMIDLIST = ITEMIDLIST

PCIDLIST_ABSOLUT = LPCITEMIDLIST

class _browseinfoA(Structure):
    _fields_ = [('hwndOwner', HWND),
                ('pidlRoot', PCIDLIST_ABSOLUT),
                ('pszDisplayName', LPSTR),
                ('lpszTitle', LPCSTR),
                ('ulFlags', UINT),
                ('lpfn', BFFCALLBACK),
                ('lParam', LPARAM),
                ('iImage', INT)
    ]

BROWSEINFOA = _browseinfoA
PBROWSEINFOA = POINTER(BROWSEINFOA)
LPBROWSEINFOA = PBROWSEINFOA

class _browseinfoW(Structure):
    _fields_ = [('hwndOwner', HWND),
                ('pidlRoot', PCIDLIST_ABSOLUT),
                ('pszDisplayName', LPWSTR),
                ('lpszTitle', LPCWSTR),
                ('ulFlags', UINT),
                ('lpfn', BFFCALLBACK),
                ('lParam', LPARAM),
                ('iImage', INT)
    ]

BROWSEINFOW = _browseinfoW
PBROWSEINFOW = POINTER(BROWSEINFOW)
LPBROWSEINFOW = PBROWSEINFOW

def GetOpenFileName(unnamedParam1, unicode: bool = True):
    GetOpenFileName = (comdlg32.GetOpenFileNameW 
                       if unicode else comdlg32.GetOpenFileNameA
    )
    
    res = GetOpenFileName(unnamedParam1)
    if not res and CommDlgExtendedError() != 0:
        raise WinError(CommDlgExtendedError())


def GetSaveFileName(unnamedParam1, unicode: bool = True):
    GetSaveFileName = (comdlg32.GetSaveFileNameW 
                       if unicode else comdlg32.GetSaveFileNameA
    )

    res = GetSaveFileName(unnamedParam1)
    if not res and CommDlgExtendedError() != 0:
        raise WinError(CommDlgExtendedError())
    

def lstrcpyn(lpString1, lpString2, iMaxLength, unicode: bool = True):
    lstrcpyn = Kernel32.lstrcpynW if unicode else Kernel32.lstrcpynA
    lstrcpyn.argtypes = [(LPWSTR if unicode else LPSTR), 
                        (LPCWSTR if unicode else LPCSTR), 
                        INT
    ]

    lstrcpyn.restype = (LPWSTR if unicode else LPSTR)
    res = lstrcpyn(lpString1, lpString2, iMaxLength)
    
    if res == NULL:
        raise WinError()
    return res


def lstrlen(lpString, unicode: bool = True):
    lstrlen = Kernel32.lstrlenW if unicode else Kernel32.lstrlenA
    res = lstrlen(lpString)
    return res


def lstrcat(lpString1, lpString2, unicode: bool = True):
    lstrcat = Kernel32.lstrcatW if unicode else Kernel32.lstrcatA
    res = lstrcat(lpString1, lpString2)
    if res == NULL:
        raise WinError(GetLastError())
    return lpString1


def SHBrowseForFolder(lpbi, unicode: bool = True):
    SHBrowseForFolder = (shell32.SHBrowseForFolderW 
                         if unicode else shell32.SHBrowseForFolderA
    )

    SHBrowseForFolder.argtypes = [POINTER(BROWSEINFOW) if unicode else POINTER(BROWSEINFOA)]
    SHBrowseForFolder.restype = VOID
    res = SHBrowseForFolder(lpbi)
    return res


def SHGetPathFromIDList(pidl, pszPath, unicode: bool = True):
    SHGetPathFromIDList = (shell32.SHGetPathFromIDListW 
                           if unicode else shell32.SHGetPathFromIDListA
    )

    SHGetPathFromIDList.argtypes = [VOID, 
                                    (LPWSTR if unicode else LPSTR)
    ]
    
    SHGetPathFromIDList.restype = BOOL
    SHGetPathFromIDList(pidl, pszPath)
    return pszPath


# ==============================================================================
# sysinfoapi.h


def GetSystemFirmwareTable(FirmwareTableProviderSignature: str, 
                           FirmwareTableID: int, 
                           BufferSize: int,
                           pFirmwareTableBuffer: int,
                           byteorder: str = "big",
                           encoding: str = 'utf-8') -> int:
    
    GetSystemFirmwareTable = Kernel32.GetSystemFirmwareTable
    FirmwareTableProviderSignature = FirmwareTableProviderSignature.encode(encoding=encoding)
    res = GetSystemFirmwareTable(int.from_bytes(FirmwareTableProviderSignature, byteorder=byteorder), 
                                 FirmwareTableID, 
                                 pFirmwareTableBuffer,
                                 BufferSize
    )
    
    if res == NULL:
        raise WinError(GetLastError())
    return res


class _SMBIOS_HEADER(Structure):
    _fields_ = [('Type', BYTE),
                ('Length', BYTE),
                ('Handle', WORD)
    ]

SMBIOS_HEADER = _SMBIOS_HEADER

# ==================================================================================
# ConsoleApi3.h

def GetConsoleWindow() -> int:
    return Kernel32.GetConsoleWindow()


# =================================================================================
# ???

class tagPROCESSENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', CHAR * MAX_PATH),
    ]

tagPROCESSENTRY32A = tagPROCESSENTRY32
PROCESSENTRY32A = tagPROCESSENTRY32A

class tagPROCESSENTRY32W(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', WCHAR * MAX_PATH),
    ]

PROCESSENTRY32W = tagPROCESSENTRY32W


def Process32First(hSnapshot, lppe, unicode: bool = True):
    Process32First = (Kernel32.Process32FirstW 
                      if unicode else Kernel32.Process32First
    )

    res = Process32First(hSnapshot, lppe)
    if not res:
        raise WinError(GetLastError())
    return lppe


def Process32Next(hSnapshot, lppe, unicode: bool = True):
    Process32Next = (Kernel32.Process32NextW 
                      if unicode else Kernel32.Process32Next
    )

    res = Process32Next(hSnapshot, lppe)
    if not res:
        raise WinError(GetLastError())
    return lppe


def LookupPrivilegeValue(lpSystemName: str | bytes, 
                         lpName: str | bytes, 
                         lpLuid: Any,
                         unicode: bool = True):
    
    LookupPrivilegeValue = (advapi32.LookupPrivilegeValueW 
                            if unicode else advapi32.LookupPrivilegeValueA
    )

    res = LookupPrivilegeValue(lpSystemName, lpName, lpLuid)
    if not res:
        raise WinError(GetLastError())


def PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult):
    PrivilegeCheck = advapi32.PrivilegeCheck
    res = PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult)
    if not res:
        raise WinError(GetLastError())


def GetTokenInformation(TokenHandle: int, 
                        TokenInformationClass: int,  
                        TokenInformation: Any, 
                        TokenInformationLength: int,
                        ReturnLength: Any):
    
    GetTokenInformation = advapi32.GetTokenInformation
    res = GetTokenInformation(TokenHandle, 
                              TokenInformationClass, 
                              TokenInformation, 
                              TokenInformationLength, 
                              ReturnLength
    )
    
    if not res:
        raise WinError(GetLastError())


def DuplicateTokenEx(hExistingToken: int, 
                     dwDesiredAccess: int, 
                     lpTokenAttributes: Any, 
                     ImpersonationLevel: int, 
                     TokenType: int,
                     phNewToken: Any):
    
    DuplicateTokenEx = advapi32.DuplicateTokenEx
    DuplicateTokenEx.argtypes = [HANDLE, DWORD, VOID, UINT, UINT, HANDLE]
    DuplicateTokenEx.restype = BOOL
    res = DuplicateTokenEx(hExistingToken, 
                           dwDesiredAccess, 
                           lpTokenAttributes, 
                           ImpersonationLevel, 
                           TokenType, 
                           phNewToken
    )

    if not res:
        raise WinError(GetLastError())


def SetTokenInformation(TokenHandle: int, 
                        TokenInformationClass: int, 
                        TokenInformation: Any, 
                        TokenInformationLength: int) -> None:
    
    SetTokenInformation = advapi32.SetTokenInformation
    SetTokenInformation.argtypes = [HANDLE, UINT, LPVOID, DWORD]
    SetTokenInformation.restype = BOOL
    res = SetTokenInformation(TokenHandle, 
                              TokenInformationClass, 
                              TokenInformation, 
                              TokenInformationLength
    )

    if not res:
        raise WinError(GetLastError())


def RevertToSelf() -> None:
    res = advapi32.RevertToSelf()
    if not res:
        raise WinError(GetLastError())


def GetCommandLine(unicode: bool = True) -> (str | bytes):
    GetCommandLine = Kernel32.GetCommandLineW if unicode else Kernel32.GetCommandLineA
    GetCommandLine.restype = LPWSTR if unicode else LPSTR
    res = GetCommandLine()
    return res


# ==================================================================================
# ???

def GetWindowLongPtr(hwnd: int, nIndex: int, unicode: bool = True) -> int:
    GetWindowLongPtr = (User32.GetWindowLongPtrW 
                        if unicode else User32.GetWindowLongPtrA
    )

    GetWindowLongPtr.argtypes = [HWND, INT]
    GetWindowLongPtr.restype = LONG_PTR
    res = GetWindowLongPtr(hwnd, nIndex)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def SetWindowPos(hwnd: int, 
                 hWndInsertAfter: int, 
                 X: int, 
                 Y: int, 
                 cx: int, 
                 cy: int, 
                 uFlags: int) -> None:
    
    SetWindowPos = User32.SetWindowPos
    SetWindowPos.argtypes = [HWND, HWND, INT, INT, INT, INT, UINT]
    SetWindowPos.restype = BOOL
    res = SetWindowPos(hwnd, 
                       hWndInsertAfter, 
                       X, 
                       Y, 
                       cx, 
                       cy, 
                       uFlags
    )

    if not res:
        raise WinError(GetLastError())


def CheckDlgButton(hDlg, nIDButton, uCheck):
    CheckDlgButton = User32.CheckDlgButton
    res = CheckDlgButton(hDlg, nIDButton, uCheck)
    if not res:
        raise WinError(GetLastError())
    

# =====================================================================
# ???

def SetWindowPos(hwnd: int, 
                 hWndInsertAfter: int, 
                 X: int, 
                 Y: int, 
                 cx: int, 
                 cy: int, 
                 uFlags: int):
    
    SetWindowPos = User32.SetWindowPos
    SetWindowPos.argtypes = [HWND, HWND, INT, INT, INT, INT, UINT]
    res = SetWindowPos(hwnd, hWndInsertAfter, X, Y, cx, cy, uFlags)
    if not res:
        raise WinError(GetLastError())


def SetForegroundWindow(hwnd: int) -> bool:
    SetForegroundWindow = User32.SetForegroundWindow
    res = SetForegroundWindow(hwnd)
    return bool(res)


# =======================================================================
# ???

def GetWindowBand(hwnd: int, pdwBand: int) -> None:
    GetWindowBand = User32.GetWindowBand
    # GetWindowBand.argtypes = [HWND, DWORD]
    # GetWindowBand.restype = BOOL
    res = GetWindowBand(hwnd, pdwBand)
    if not res:
        raise WinError(GetLastError())


def CreateWindowInBand(dwExStyle: int, 
                       lpClassName: str, 
                       lpWindowName: str, 
                       dwStyle: int, 
                       x: int, 
                       y: int, 
                       nWidth: int, 
                       nHeight: int, 
                       hWndParent: int, 
                       hMenu: int, 
                       hInstance: int, 
                       lpParam: Any, 
                       dwBand: int) -> int:
    
    CreateWindowInBand = User32.CreateWindowInBand
    res = CreateWindowInBand(dwExStyle, 
                             lpClassName, 
                             lpWindowName, 
                             dwStyle, 
                             x, 
                             y, 
                             nWidth, 
                             nHeight, 
                             hWndParent, 
                             hMenu, 
                             hInstance, 
                             lpParam, 
                             dwBand
    )

    if res == NULL:
        raise WinError(GetLastError())
    return res


def CreateWindowInBandEx(dwExStyle: int, 
                         lpClassName: str, 
                         lpWindowName: str, 
                         dwStyle: int, 
                         x: int, 
                         y: int, 
                         nWidth: int, 
                         nHeight: int, 
                         hWndParent: int, 
                         hMenu: int, 
                         hInstance: int, 
                         lpParam: Any, 
                         dwBand: int,
                         dwTypeFlags: int) -> int:
    
    CreateWindowInBandEx = User32.CreateWindowInBandEx
    res = CreateWindowInBandEx(dwExStyle, 
                               lpClassName, 
                               lpWindowName, 
                               dwStyle, 
                               x, 
                               y, 
                               nWidth, 
                               nHeight, 
                               hWndParent, 
                               hMenu, 
                               hInstance, 
                               lpParam, 
                               dwBand,
                               dwTypeFlags
    )

    if not res:
        raise WinError(GetLastError())
    return res


def SetWindowBand(hwnd: int, hwndInsertAfter: int, dwBand: int) -> None:
    SetWindowBand = User32.SetWindowBand
    SetWindowBand.argtypes = [HWND, HWND, DWORD]
    SetWindowBand.restype = BOOL
    res = SetWindowBand(hwnd, hwndInsertAfter, dwBand)
    if not res:
        raise WinError(GetLastError())


def UpdateWindow(hwnd: int) -> bool:
    res = User32.UpdateWindow(hwnd)
    return bool(res)
    

if _WIN32_WINNT >= WIN32_WINNT_WIN8:
    ZBID_DEFAULT = 0
    ZBID_DESKTOP = 1
    ZBID_UIACCESS = 2
    ZBID_IMMERSIVE_IHM = 3
    ZBID_IMMERSIVE_NOTIFICATION = 4
    ZBID_IMMERSIVE_APPCHROME = 5
    ZBID_IMMERSIVE_MOGO = 6
    ZBID_IMMERSIVE_EDGY = 7
    ZBID_IMMERSIVE_INACTIVEMOBODY = 8
    ZBID_IMMERSIVE_INACTIVEDOCK = 9
    ZBID_IMMERSIVE_ACTIVEMOBODY = 10
    ZBID_IMMERSIVE_ACTIVEDOCK = 11
    ZBID_IMMERSIVE_BACKGROUND = 12
    ZBID_IMMERSIVE_SEARCH = 13
    ZBID_GENUINE_WINDOWS = 14
    ZBID_IMMERSIVE_RESTRICTED = 15
    ZBID_SYSTEM_TOOLS = 16

    # WINDOWS 10+ 
    if _WIN32_WINNT >= WIN32_WINNT_WIN10:
        ZBID_LOCK = 17
        ZBID_ABOVELOCK_UX = 18


def zorder_band_names(zbid: int = NULL) -> str:
    if WIN32_WINNT < WIN32_WINNT_WIN8:
        raise OSError('Do not supported system')
    
    res = {
        "Default": ZBID_DEFAULT,
	    "Desktop": ZBID_DESKTOP,
	    "UIAccess": ZBID_UIACCESS,
	    "Immersive IHM": ZBID_IMMERSIVE_IHM,
	    "Immersive Notification": ZBID_IMMERSIVE_NOTIFICATION,
	    "Immersive AppChrome": ZBID_IMMERSIVE_APPCHROME,
	    "Immersive MoGo": ZBID_IMMERSIVE_MOGO,
	    "Immersive Edgy": ZBID_IMMERSIVE_EDGY,
	    "Immersive InactiveMoBody": ZBID_IMMERSIVE_INACTIVEMOBODY,
	    "Immersive InactiveDock": ZBID_IMMERSIVE_INACTIVEDOCK,
	    "Immersive ActiveMoBody": ZBID_IMMERSIVE_ACTIVEMOBODY,
	    "Immersive ActiveDock": ZBID_IMMERSIVE_ACTIVEDOCK,
	    "Immersive Background": ZBID_IMMERSIVE_BACKGROUND,
	    "Immersive Search": ZBID_IMMERSIVE_SEARCH,
	    "Genuine Windows": ZBID_GENUINE_WINDOWS,
	    "Immersive Restricted": ZBID_IMMERSIVE_RESTRICTED,
	    "System Tools": ZBID_SYSTEM_TOOLS
    }

    # Windows 10+
    if WIN32_WINNT >= WIN32_WINNT_WIN10:
        res["Lock Screen"] = ZBID_LOCK
        res["Above Lock UX"] = ZBID_ABOVELOCK_UX

    num = 0
    for j in res:
        if num == zbid:
            return j
        num += 1
    raise IndexError('Dict index out of range')


# ========================================================================
# ???

class DLGITEMTEMPLATE(ctypes.Structure):
    _fields_ = [('style', DWORD),
                ('dwExtendedStyle', DWORD),
                ('x', SHORT),
                ('y', SHORT),
                ('cx', SHORT),
                ('cy', SHORT),
                ('id', WORD)
    ]

class DLGTEMPLATE(ctypes.Structure):
    _fields_ = [('style', DWORD),
                ('dwExtendedStyle', DWORD),
                ('cdit', WORD),
                ('x', SHORT),
                ('y', SHORT),
                ('cx', SHORT),
                ('cy', SHORT)
    ]


def BringWindowToTop(hwnd: int) -> None:
    BringWindowToTop = User32.BringWindowToTop
    res = BringWindowToTop(hwnd)
    if not res:
        raise WinError(GetLastError())
