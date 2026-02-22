# coding = 'utf-8'
# winbase.h

from method.System.fileapi import *
from method.System.ntstatus import *
from method.System.synchapi import *
from method.System.errcheck import *
from method.System.debugapi import *
from method.System.sdkddkver import *
from method.System.memoryapi import *
from method.System.processenv import *
from method.System.minwinbase import *
from method.System.public_dll import *
from method.System.sysinfoapi import *
from method.System.winusutypes import *
from method.System.wow64apiset import *
from method.System.libloaderapi import *
from method.System.errhandlingapi import *
from method.System.securitybaseapi import *
from method.System.processthreadsapi import *

va_list = c_char_p
_WIN32_WINNT = WIN32_WINNT

GetCurrentTime = GetTickCount

FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

WAIT_FAILED = 0xffffffff
WAIT_OBJECT_0 = STATUS_WAIT_0 + 0

WAIT_ABANDONED = STATUS_ABANDONED_WAIT_0 + 0
WAIT_ABANDONED_0 = STATUS_ABANDONED_WAIT_0 + 0

WAIT_IO_COMPLETION = STATUS_USER_APC

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

THREAD_DYNAMIC_CODE_ALLOW = 1

THREAD_BASE_PRIORITY_LOWRT = 15
THREAD_BASE_PRIORITY_MAX = 2
THREAD_BASE_PRIORITY_MIN = -2
THREAD_BASE_PRIORITY_IDLE = -15

MAXLONG = 0x7fffffff
MAXULONG64 = 18446744073709551615
MAXLONG64 = 9223372036854775807
MINLONG64 = -9223372036854775808

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


def CreateJobObject(lpJobAttributes: Any, lpName: str, unicode: bool = True, errcheck: bool = True) -> int:
    CreateJobObject = (kernel32.CreateJobObjectW 
                       if unicode else kernel32.CreateJobObjectA
    )

    CreateJobObject.argtypes = [
        LPSECURITY_ATTRIBUTES,
        (LPCWSTR if unicode else LPCSTR)
    ]

    CreateJobObject.restype = HANDLE
    res = CreateJobObject(lpJobAttributes, lpName)
    return win32_to_errcheck(res, errcheck)


def AssignProcessToJobObject(hJob: int, hProcess: int, errcheck: bool = True) -> int:
    AssignProcessToJobObject = kernel32.AssignProcessToJobObject
    AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
    AssignProcessToJobObject.restype = WINBOOL
    res = AssignProcessToJobObject(hJob, hProcess)
    return win32_to_errcheck(res, errcheck)


def TerminateJobObject(hJob: int, uExitCode: int, errcheck: bool = True) -> int:
    TerminateJobObject = kernel32.TerminateJobObject
    TerminateJobObject.argtypes = [HANDLE, UINT]
    TerminateJobObject.restype = WINBOOL
    res = TerminateJobObject(hJob, uExitCode)
    return win32_to_errcheck(res, errcheck)


def GetCurrentDirectory(nBufferLength: int, lpBuffer: Any, unicode: bool = True, errcheck: bool = True) -> int:
    GetCurrentDirectory = (kernel32.GetCurrentDirectoryW 
                           if unicode else kernel32.GetCurrentDirectoryA
    )

    GetCurrentDirectory.argtypes = [
        DWORD, 
        (LPWSTR if unicode else LPSTR)
    ]

    GetCurrentDirectory.restype = DWORD
    res = GetCurrentDirectory(nBufferLength, lpBuffer)
    return win32_to_errcheck(res, errcheck)


def lstrcpyn(lpString1, lpString2, iMaxLength, unicode: bool = True, errcheck: bool = True):
    lstrcpyn = kernel32.lstrcpynW if unicode else kernel32.lstrcpynA
    lstrcpyn.argtypes = [(LPWSTR if unicode else LPSTR), 
                        (LPCWSTR if unicode else LPCSTR), 
                        INT
    ]

    lstrcpyn.restype = (LPWSTR if unicode else LPSTR)
    res = lstrcpyn(lpString1, lpString2, iMaxLength)
    return win32_to_errcheck(res, errcheck)


def lstrlen(lpString, unicode: bool = True):
    lstrlen = kernel32.lstrlenW if unicode else kernel32.lstrlenA
    lstrlen.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    lstrlen.restype = INT
    res = lstrlen(lpString)
    return res


def lstrcat(lpString1, lpString2, unicode: bool = True, errcheck: bool = True):
    lstrcat = kernel32.lstrcatW if unicode else kernel32.lstrcatA
    lstrcat.argtypes = [
        (LPWSTR if unicode else LPSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    lstrcat.restype = LPWSTR if unicode else LPSTR
    res = lstrcat(lpString1, lpString2)
    return win32_to_errcheck(res, errcheck)   


def CreateProcessWithLogonW(
    lpUsername: str,
    lpDomain: str,
    lpPassword: str,
    dwLogonFlags: int,
    lpApplicationName: str,
    lpCommandLine: str,
    dwCreationFlags: int,
    lpEnvironment: Any,
    lpCurrentDirectory: str,
    lpStartupInfo: Any,
    lpProcessInformation: Any,
    errcheck: bool = True
):
    
    CreateProcessWithLogonW = advapi32.CreateProcessWithLogonW
    CreateProcessWithLogonW.argtypes = [
        LPCWSTR,
        LPCWSTR,
        LPCWSTR,
        DWORD,
        LPCWSTR,
        LPWSTR,
        DWORD,
        LPVOID,
        LPCWSTR,
        LPSTARTUPINFOW,
        LPPROCESS_INFORMATION
    ]

    CreateProcessWithLogonW.restype = BOOL
    res = CreateProcessWithLogonW(
        lpUsername,
        lpDomain,
        lpPassword,
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    )

    return win32_to_errcheck(res, errcheck)


def CreateProcessWithTokenW(
    hToken: int, 
    dwLogonFlags: int, 
    lpApplicationName: str, 
    lpCommandLine: str, 
    dwCreationFlags: int, 
    lpEnvironment: int, 
    lpCurrentDirectory: str, 
    lpStartupInfo: Any, 
    lpProcessInformation: Any,
    errcheck: bool = True
):
    
    CreateProcessWithTokenW = advapi32.CreateProcessWithTokenW
    CreateProcessWithTokenW.argtypes = [
        HANDLE,
        DWORD,
        LPCWSTR,
        LPWSTR,
        DWORD,
        LPVOID,
        LPCWSTR,
        LPSTARTUPINFOW,
        LPPROCESS_INFORMATION
    ]

    CreateProcessWithTokenW.restype = WINBOOL
    res = CreateProcessWithTokenW(
        hToken, 
        dwLogonFlags, 
        lpApplicationName, 
        lpCommandLine, 
        dwCreationFlags, 
        lpEnvironment, 
        lpCurrentDirectory, 
        lpStartupInfo, 
        lpProcessInformation
    )

    return win32_to_errcheck(res, errcheck)


CreateProcessWithLogon = CreateProcessWithLogonW
CreateProcessWithToken = CreateProcessWithTokenW

FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
FORMAT_MESSAGE_FROM_STRING     = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x00002000
FORMAT_MESSAGE_MAX_WIDTH_MASK  = 0x000000FF


def FormatMessage(
    dwFlags: int, 
    lpSource: Any, 
    dwMessageId: int, 
    dwLanguageId: int, 
    lpBuffer, 
    nSize: int, 
    Arguments, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    FormatMessage = (kernel32.FormatMessageW 
                     if unicode else kernel32.FormatMessageA
    )

    FormatMessage.argtypes = [
        DWORD,
        LPCVOID,
        DWORD,
        DWORD,
        (LPWSTR if unicode else LPSTR),
        DWORD,
        POINTER(va_list)
    ]

    res = FormatMessage(
        dwFlags, 
        lpSource, 
        dwMessageId, 
        dwLanguageId, 
        lpBuffer, 
        nSize, 
        Arguments
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

    LookupPrivilegeValue.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        PLUID
    ]

    LookupPrivilegeValue.restype = BOOL
    res = LookupPrivilegeValue(lpSystemName, lpName, lpLuid)
    return win32_to_errcheck(res, errcheck)


def LookupAccountSid(
    lpSystemName: str | bytes, 
    Sid: int, 
    Name: str | bytes, 
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


def LocalAlloc(uFlags: int, uBytes: int, errcheck: bool = True):
    LocalAlloc = kernel32.LocalAlloc
    LocalAlloc.argtypes = [UINT, SIZE_T]
    LocalAlloc.restype = HLOCAL
    res = LocalAlloc(uFlags, uBytes)
    return win32_to_errcheck(res, errcheck)


def LocalFree(hMem: int) -> None:
    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [HLOCAL]
    LocalFree.restype = HLOCAL
    LocalFree(hMem)

