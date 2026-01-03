# coding = 'utf-8'

# ???: 指暂时未分类的部分类或函数、或 Microsoft 未公开的 Windows API

from typing import NoReturn, Any
from method.System.shiobj import *
from method.System.ntstatus import *
from method.System.winuser import WM_USER
from method.System.libloaderapi import LoadLibrary, GetProcAddress
from method.System.public_dll import kernel32, ntdll, shell32, advapi32, user32, winsta
from method.System.errcheck import win32_to_errcheck, RtlNtStatusToDosError, CommDlgExtendedError

FARPROC = INT_PTR
_WIN32_WINNT = WIN32_WINNT

################################################################
# winbase.h

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

    res = CreateJobObject(lpJobAttributes, lpName)
    return win32_to_errcheck(res, errcheck)



def AssignProcessToJobObject(hJob: int, hProcess: int, errcheck: bool = True) -> int:
    AssignProcessToJobObject = kernel32.AssignProcessToJobObject
    res = AssignProcessToJobObject(hJob, hProcess)
    return win32_to_errcheck(res, errcheck)



def TerminateJobObject(hJob: int, uExitCode: int, errcheck: bool = True) -> int:
    TerminateJobObject = kernel32.TerminateJobObject
    res = TerminateJobObject(hJob, uExitCode)
    return win32_to_errcheck(res, errcheck)



def GetCurrentDirectory(nBufferLength: int, lpBuffer: Any, unicode: bool = True, errcheck: bool = True) -> int:
    GetCurrentDirectory = (kernel32.GetCurrentDirectoryW 
                           if unicode else kernel32.GetCurrentDirectoryA
    )

    GetCurrentDirectory.restype = DWORD
    res = GetCurrentDirectory(nBufferLength, lpBuffer)
    return win32_to_errcheck(res, errcheck)


#################################################################
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

########################################################
# ???


def WinStationTerminateProcess(
    ServerHandle: int, 
    ProcessId: int, 
    ExitCode: int,
    errcheck: bool = True
):
    
    WinStationTerminateProcess = winsta.WinStationTerminateProcess
    WinStationTerminateProcess.argtypes = [HANDLE, ULONG, ULONG]
    res = WinStationTerminateProcess(
        ServerHandle, 
        ProcessId, 
        ExitCode
    )

    return win32_to_errcheck(res, errcheck)

#######################################################
# ???


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
    

##################################################################
# ???


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
        

##################################################################
# ???

RFD_NOBROWSE            = 0x00000001
RFD_NODEFFILE           = 0x00000002
RFD_USEFULLPATHDIR      = 0x00000004
RFD_NOSHOWOPEN          = 0x00000008
RFD_WOW_APP             = 0x00000010
RFD_NOSEPMEMORY_BOX     = 0x00000020



def RunfileDlg(
    hwndOwner: int, 
    hIcon: int, 
    lpszDirectory: str, 
    lpszTitle: str, 
    lpszDescription: str, 
    uFlags: int = RFD_USEFULLPATHDIR | RFD_WOW_APP,
    number: int = 61
) -> None:      # “运行”对话框
    
    RUNFILEDLG = WINAPI(VOID, HWND, HICON, LPCWSTR, LPCWSTR, LPCWSTR, UINT)
    shell32 = LoadLibrary('shell32.dll')
    RunfileDlg = GetProcAddress(shell32, LPCSTR(number))
    RunfileDlg = RUNFILEDLG(RunfileDlg)
    RunfileDlg(hwndOwner, hIcon, lpszDirectory, lpszTitle, lpszDescription, uFlags)


##################################################################
# synchapi.h


def WaitForSingleObject(hHandle: int, dwMilliseconds: int, errcheck: bool = True) -> int:
    WaitForSingleObject = kernel32.WaitForSingleObject
    res = WaitForSingleObject(hHandle, dwMilliseconds)
    return win32_to_errcheck(res, errcheck)


##################################################################
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
    res = lstrlen(lpString)
    return res



def lstrcat(lpString1, lpString2, unicode: bool = True, errcheck: bool = True):
    lstrcat = kernel32.lstrcatW if unicode else kernel32.lstrcatA
    res = lstrcat(lpString1, lpString2)
    return win32_to_errcheck(res, errcheck)   



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


##################################################################
# sysinfoapi.h


def GetSystemDirectory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:

    GetSystemDirectory = (kernel32.GetSystemDirectoryW 
                          if unicode else kernel32.GetSystemDirectoryA
    )

    res = GetSystemDirectory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)



def GetSystemWow64Directory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    GetSystemWow64Directory = (kernel32.GetSystemWow64DirectoryW 
                               if unicode else kernel32.GetSystemWow64DirectoryA
    )
    
    GetSystemWow64Directory.restype = UINT
    res = GetSystemWow64Directory(lpBuffer, uSize)
    if res == ERROR_CALL_NOT_IMPLEMENTED:
        raise WinError(res)
    return win32_to_errcheck(res, errcheck)


def GetWindowsDirectory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> None:
    
    GetWindowsDirectory = (kernel32.GetWindowsDirectoryW 
                           if unicode else kernel32.GetWindowsDirectoryA
    )
    
    res = GetWindowsDirectory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)


RSMB = b'RSMB'
ACPI = b'ACPI'
FIRM = b'FIRM'
PCAF = b'PCAF'


def GetSystemFirmwareTable(
    FirmwareTableProviderSignature: str | bytes, 
    FirmwareTableID: int, 
    BufferSize: int,
    pFirmwareTableBuffer: int,
    byteorder: str = "big",
    encoding: str = 'utf-8',
    errcheck: bool = True
) -> int:
    
    if isinstance(FirmwareTableProviderSignature, str):
        FirmwareTableProviderSignature = FirmwareTableProviderSignature.encode(encoding=encoding)

    GetSystemFirmwareTable = kernel32.GetSystemFirmwareTable
    res = GetSystemFirmwareTable(int.from_bytes(FirmwareTableProviderSignature, byteorder=byteorder), 
                                 FirmwareTableID, 
                                 pFirmwareTableBuffer,
                                 BufferSize
    )
    
    return win32_to_errcheck(res, errcheck)


class _SMBIOS_HEADER(Structure):
    _fields_ = [('Type', BYTE),
                ('Length', BYTE),
                ('Handle', WORD)
    ]

SMBIOS_HEADER = _SMBIOS_HEADER

##################################################################
# ConsoleApi3.h


def GetConsoleWindow() -> int:
    GetConsoleWindow = kernel32.GetConsoleWindow
    return GetConsoleWindow()


##################################################################
# ???


def GetVersion() -> int:
    GetVersion = kernel32.GetVersion
    GetVersion.restype = DWORD
    return GetVersion()



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


def GetCommandLine(unicode: bool = True) -> (str | bytes):
    GetCommandLine = kernel32.GetCommandLineW if unicode else kernel32.GetCommandLineA
    GetCommandLine.restype = LPWSTR if unicode else LPSTR
    res = GetCommandLine()
    return res


##################################################################
# ???


def GetWindowLongPtr(hwnd: int, nIndex: int, unicode: bool = True, errcheck: bool = True) -> int:
    GetWindowLongPtr = (user32.GetWindowLongPtrW 
                        if unicode else user32.GetWindowLongPtrA
    )

    GetWindowLongPtr.argtypes = [HWND, INT]
    GetWindowLongPtr.restype = LONG_PTR
    res = GetWindowLongPtr(hwnd, nIndex)
    return win32_to_errcheck(res, errcheck)



def SetWindowPos(
    hwnd: int, 
    hWndInsertAfter: int, 
    X: int, 
    Y: int, 
    cx: int, 
    cy: int, 
    uFlags: int,
    errcheck: bool = True
) -> None:
    
    SetWindowPos = user32.SetWindowPos
    SetWindowPos.argtypes = [HWND, HWND, INT, INT, INT, INT, UINT]
    SetWindowPos.restype = BOOL
    res = SetWindowPos(
        hwnd, 
        hWndInsertAfter, 
        X, 
        Y, 
        cx, 
        cy, 
        uFlags
    )

    return win32_to_errcheck(res, errcheck)


def CheckDlgButton(hDlg, nIDButton, uCheck, errcheck: bool = True):
    CheckDlgButton = user32.CheckDlgButton
    res = CheckDlgButton(hDlg, nIDButton, uCheck)
    return win32_to_errcheck(res, errcheck)    

##################################################################
# ???


def SetWindowPos(
    hwnd: int, 
    hWndInsertAfter: int, 
    X: int, 
    Y: int, 
    cx: int, 
    cy: int, 
    uFlags: int,
    errcheck: bool = True
):
    
    SetWindowPos = user32.SetWindowPos
    SetWindowPos.argtypes = [HWND, HWND, INT, INT, INT, INT, UINT]
    res = SetWindowPos(hwnd, hWndInsertAfter, X, Y, cx, cy, uFlags)
    return win32_to_errcheck(res, errcheck)


def SetForegroundWindow(hwnd: int) -> bool:
    SetForegroundWindow = user32.SetForegroundWindow
    res = SetForegroundWindow(hwnd)
    return bool(res)


##################################################################
# ???


def GetWindowBand(hwnd: int, pdwBand: int, errcheck: bool = True) -> None:
    GetWindowBand = user32.GetWindowBand
    GetWindowBand.argtypes = [HWND, DWORD]
    GetWindowBand.restype = BOOL
    res = GetWindowBand(hwnd, pdwBand)
    return win32_to_errcheck(res, errcheck)


def CreateWindowInBand(
    dwExStyle: int, 
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
    errcheck: bool = True
) -> int:
    
    CreateWindowInBand = user32.CreateWindowInBand
    res = CreateWindowInBand(
        dwExStyle, 
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

    return win32_to_errcheck(res, errcheck)



def CreateWindowInBandEx(
    dwExStyle: int, 
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
    dwTypeFlags: int,
    errcheck: bool = True
) -> int:
    
    CreateWindowInBandEx = user32.CreateWindowInBandEx
    res = CreateWindowInBandEx(
        dwExStyle, 
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

    return win32_to_errcheck(res, errcheck)



def SetWindowBand(hwnd: int, hwndInsertAfter: int, dwBand: int, errcheck: bool = True) -> None:
    SetWindowBand = user32.SetWindowBand
    SetWindowBand.argtypes = [HWND, HWND, DWORD]
    SetWindowBand.restype = BOOL
    res = SetWindowBand(hwnd, hwndInsertAfter, dwBand)
    return win32_to_errcheck(res, errcheck)


def UpdateWindow(hwnd: int) -> bool:
    res = user32.UpdateWindow(hwnd)
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


##################################################################
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



def BringWindowToTop(hwnd: int, errcheck: bool = True) -> None:
    BringWindowToTop = user32.BringWindowToTop
    res = BringWindowToTop(hwnd)
    return win32_to_errcheck(res, errcheck)

##################################################################
# ???


def IsWow64Process(hProcess, Wow64Process, errcheck: bool = True):
    IsWow64Process = kernel32.IsWow64Process
    IsWow64Process.argtypes = [HANDLE, PBOOL]
    res = IsWow64Process(hProcess, Wow64Process)
    return win32_to_errcheck(res, errcheck)    


def IsWow64Process2(hProcess, pProcessMachine, pNativeMachine, errcheck: bool = True):
    IsWow64Process2 = kernel32.IsWow64Process2
    IsWow64Process2.argtypes = [HANDLE, PUSHORT, PUSHORT]
    res = IsWow64Process2(hProcess, pProcessMachine, pNativeMachine)
    return win32_to_errcheck(res, errcheck)

###################################################################
# securitybaseapi.h
PSID = PVOID

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
    

##################################################################
# ???


def ImpersonateLoggedOnUser(hToken: int, errcheck: bool = True) -> None:
    ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
    ImpersonateLoggedOnUser.argtypes = [HANDLE]
    res = ImpersonateLoggedOnUser(hToken)
    return win32_to_errcheck(res, errcheck)    


def Sleep(dwMilliseconds: int) -> None:
    Sleep = kernel32.Sleep
    Sleep.argtypes = [DWORD]
    Sleep(dwMilliseconds)



def _wtoi(string: str) -> int:
    _wtoi = ntdll._wtoi
    res = _wtoi(string)
    return res

